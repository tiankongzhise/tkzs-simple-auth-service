package auth

import (
	"context"
	"errors"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/jwtx"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidInput       = errors.New("invalid login input")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is locked")
	ErrAuthUnavailable    = errors.New("auth dependency unavailable")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenRevoked       = errors.New("token revoked")
)

type UserStore interface {
	FindUserByUsername(ctx context.Context, username string) (*model.User, error)
	FindUserByID(ctx context.Context, userID string) (*model.User, error)
	SaveAuthTokens(ctx context.Context, tokens []model.AuthToken) error
	RevokeAuthTokens(ctx context.Context, jtis []string, at time.Time) error
	UpdateLastLogin(ctx context.Context, userID string, at time.Time) error
}

type Cache interface {
	KeyBuilder() *redisx.KeyBuilder
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
	Exists(ctx context.Context, key string) (bool, error)
	Expire(ctx context.Context, key string, ttl time.Duration) error
	Incr(ctx context.Context, key string) (int64, error)
}

type Service struct {
	cfg   *config.Config
	store UserStore
	cache Cache
	jwt   *jwtx.Manager
	now   func() time.Time
}

type LoginInput struct {
	Username  string
	Password  string
	IP        string
	UserAgent string
}

type LoginResult struct {
	TokenType             string    `json:"tokenType"`
	AccessToken           string    `json:"accessToken"`
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`
	RefreshToken          string    `json:"refreshToken"`
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt"`
}

type VerifyResult struct {
	UserID                   string    `json:"userId"`
	Roles                    []string  `json:"roles"`
	Permissions              []string  `json:"permissions"`
	ExpiresAt                time.Time `json:"expiresAt"`
	RenewedAccessToken       string    `json:"-"`
	RenewedAccessTokenExpiry time.Time `json:"-"`
}

func NewService(cfg *config.Config, store UserStore, cache Cache, jwtManager *jwtx.Manager) *Service {
	return &Service{
		cfg:   cfg,
		store: store,
		cache: cache,
		jwt:   jwtManager,
		now:   time.Now,
	}
}

func (s *Service) SetNow(now func() time.Time) {
	s.now = now
	s.jwt.SetNow(now)
}

func (s *Service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	if !validUsername(input.Username) || !validPassword(input.Password) {
		return nil, ErrInvalidInput
	}

	user, err := s.store.FindUserByUsername(ctx, input.Username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if user.Status != model.StatusEnabled {
		return nil, ErrInvalidCredentials
	}
	if locked, err := s.isLocked(ctx, user.ID); err != nil {
		return nil, ErrAuthUnavailable
	} else if locked {
		return nil, ErrAccountLocked
	}

	passwordHash, err := s.passwordHash(ctx, user)
	if err != nil {
		return nil, ErrAuthUnavailable
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(input.Password)) != nil {
		if err := s.registerFailure(ctx, user.ID); err != nil {
			return nil, ErrAuthUnavailable
		}
		return nil, ErrInvalidCredentials
	}

	if err := s.clearFailures(ctx, user.ID); err != nil {
		return nil, ErrAuthUnavailable
	}
	subject := jwtx.Subject{
		ID:          user.ID,
		Roles:       roleCodes(user.Roles),
		Permissions: permissionCodes(user.Roles),
	}
	pair, err := s.jwt.IssuePair(subject)
	if err != nil {
		return nil, err
	}
	tokens := []model.AuthToken{
		{
			UserID:    user.ID,
			JTI:       pair.AccessJTI,
			TokenType: model.TokenTypeAccess,
			Status:    model.TokenStatusActive,
			ExpiresAt: pair.AccessExpiresAt,
		},
		{
			UserID:    user.ID,
			JTI:       pair.RefreshJTI,
			TokenType: model.TokenTypeRefresh,
			Status:    model.TokenStatusActive,
			ExpiresAt: pair.RefreshExpiresAt,
		},
	}
	if err := s.store.SaveAuthTokens(ctx, tokens); err != nil {
		return nil, err
	}
	if err := s.writeTokenState(ctx, pair.AccessJTI, model.TokenTypeAccess, user.ID, pair.AccessExpiresAt); err != nil {
		return nil, ErrAuthUnavailable
	}
	if err := s.writeTokenState(ctx, pair.RefreshJTI, model.TokenTypeRefresh, user.ID, pair.RefreshExpiresAt); err != nil {
		return nil, ErrAuthUnavailable
	}
	if err := s.store.UpdateLastLogin(ctx, user.ID, s.now().UTC()); err != nil {
		return nil, err
	}

	return &LoginResult{
		TokenType:             "Bearer",
		AccessToken:           pair.AccessToken,
		AccessTokenExpiresAt:  pair.AccessExpiresAt,
		RefreshToken:          pair.RefreshToken,
		RefreshTokenExpiresAt: pair.RefreshExpiresAt,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (*LoginResult, error) {
	claims, err := s.jwt.Parse(refreshToken, model.TokenTypeRefresh)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if err := s.ensureTokenUsable(ctx, claims.ID, model.TokenTypeRefresh); err != nil {
		return nil, err
	}
	user, err := s.store.FindUserByID(ctx, claims.Subject)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if user.Status != model.StatusEnabled {
		return nil, ErrInvalidToken
	}

	subject := jwtx.Subject{
		ID:          user.ID,
		Roles:       roleCodes(user.Roles),
		Permissions: permissionCodes(user.Roles),
	}
	if s.cfg.JWT.RefreshRotate {
		pair, err := s.jwt.IssuePair(subject)
		if err != nil {
			return nil, err
		}
		if err := s.saveAndCachePair(ctx, user.ID, pair); err != nil {
			return nil, err
		}
		if err := s.revokeToken(ctx, claims.ID, model.TokenTypeRefresh, claims.ExpiresAt.Time); err != nil {
			return nil, err
		}
		if err := s.store.RevokeAuthTokens(ctx, []string{claims.ID}, s.now().UTC()); err != nil {
			return nil, err
		}
		return loginResultFromPair(pair), nil
	}

	access, err := s.jwt.Issue(subject, model.TokenTypeAccess)
	if err != nil {
		return nil, err
	}
	if err := s.store.SaveAuthTokens(ctx, []model.AuthToken{{
		UserID:    user.ID,
		JTI:       access.JTI,
		TokenType: model.TokenTypeAccess,
		Status:    model.TokenStatusActive,
		ExpiresAt: access.ExpiresAt,
	}}); err != nil {
		return nil, err
	}
	if err := s.writeTokenState(ctx, access.JTI, model.TokenTypeAccess, user.ID, access.ExpiresAt); err != nil {
		return nil, ErrAuthUnavailable
	}
	return &LoginResult{
		TokenType:             "Bearer",
		AccessToken:           access.Token,
		AccessTokenExpiresAt:  access.ExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: claims.ExpiresAt.Time,
	}, nil
}

func (s *Service) IssueForUser(ctx context.Context, userID string) (*LoginResult, error) {
	user, err := s.store.FindUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}
	if user.Status != model.StatusEnabled {
		return nil, ErrInvalidToken
	}
	pair, err := s.jwt.IssuePair(jwtx.Subject{
		ID:          user.ID,
		Roles:       roleCodes(user.Roles),
		Permissions: permissionCodes(user.Roles),
	})
	if err != nil {
		return nil, err
	}
	if err := s.saveAndCachePair(ctx, user.ID, pair); err != nil {
		return nil, err
	}
	return loginResultFromPair(pair), nil
}

func (s *Service) Verify(ctx context.Context, accessToken string) (*VerifyResult, error) {
	claims, err := s.jwt.Parse(accessToken, model.TokenTypeAccess)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if err := s.ensureTokenUsable(ctx, claims.ID, model.TokenTypeAccess); err != nil {
		return nil, err
	}
	result := &VerifyResult{
		UserID:      claims.Subject,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		ExpiresAt:   claims.ExpiresAt.Time,
	}
	if s.jwt.ShouldAutoRefresh(claims) {
		issued, err := s.jwt.Issue(jwtx.Subject{
			ID:          claims.Subject,
			Roles:       claims.Roles,
			Permissions: claims.Permissions,
		}, model.TokenTypeAccess)
		if err != nil {
			return nil, err
		}
		if err := s.store.SaveAuthTokens(ctx, []model.AuthToken{{
			UserID:    claims.Subject,
			JTI:       issued.JTI,
			TokenType: model.TokenTypeAccess,
			Status:    model.TokenStatusActive,
			ExpiresAt: issued.ExpiresAt,
		}}); err != nil {
			return nil, err
		}
		if err := s.writeTokenState(ctx, issued.JTI, model.TokenTypeAccess, claims.Subject, issued.ExpiresAt); err != nil {
			return nil, ErrAuthUnavailable
		}
		result.RenewedAccessToken = issued.Token
		result.RenewedAccessTokenExpiry = issued.ExpiresAt
	}
	return result, nil
}

func (s *Service) Logout(ctx context.Context, accessToken string, refreshToken string) error {
	accessClaims, err := s.jwt.Parse(accessToken, model.TokenTypeAccess)
	if err != nil {
		return ErrInvalidToken
	}
	refreshClaims, err := s.jwt.Parse(refreshToken, model.TokenTypeRefresh)
	if err != nil {
		return ErrInvalidToken
	}
	jtis := []string{accessClaims.ID, refreshClaims.ID}
	if err := s.revokeToken(ctx, accessClaims.ID, model.TokenTypeAccess, accessClaims.ExpiresAt.Time); err != nil {
		return err
	}
	if err := s.revokeToken(ctx, refreshClaims.ID, model.TokenTypeRefresh, refreshClaims.ExpiresAt.Time); err != nil {
		return err
	}
	return s.store.RevokeAuthTokens(ctx, jtis, s.now().UTC())
}

func (s *Service) isLocked(ctx context.Context, userID string) (bool, error) {
	key, err := s.cache.KeyBuilder().Build("auth", "lock", "user", userID)
	if err != nil {
		return false, err
	}
	return s.cache.Exists(ctx, key)
}

func (s *Service) passwordHash(ctx context.Context, user *model.User) (string, error) {
	key, err := s.cache.KeyBuilder().Build("user", "password", user.ID)
	if err != nil {
		return "", err
	}
	hash, err := s.cache.Get(ctx, key)
	if err != nil {
		return "", err
	}
	if hash != "" {
		return hash, nil
	}
	if err := s.cache.Set(ctx, key, user.PasswordHash, time.Duration(s.cfg.Security.AuthFailWindowMinutes)*time.Minute*3); err != nil {
		return "", err
	}
	return user.PasswordHash, nil
}

func (s *Service) registerFailure(ctx context.Context, userID string) error {
	failKey, err := s.cache.KeyBuilder().Build("auth", "fail", "user", userID)
	if err != nil {
		return err
	}
	count, err := s.cache.Incr(ctx, failKey)
	if err != nil {
		return err
	}
	if count == 1 {
		if err := s.cache.Expire(ctx, failKey, time.Duration(s.cfg.Security.AuthFailWindowMinutes)*time.Minute); err != nil {
			return err
		}
	}
	if count >= int64(s.cfg.Security.AuthFailMaxCount) {
		lockKey, err := s.cache.KeyBuilder().Build("auth", "lock", "user", userID)
		if err != nil {
			return err
		}
		if err := s.cache.Set(ctx, lockKey, "1", time.Duration(s.cfg.Security.LockMinutes)*time.Minute); err != nil {
			return err
		}
		return s.cache.Del(ctx, failKey)
	}
	return nil
}

func (s *Service) clearFailures(ctx context.Context, userID string) error {
	key, err := s.cache.KeyBuilder().Build("auth", "fail", "user", userID)
	if err != nil {
		return err
	}
	return s.cache.Del(ctx, key)
}

func (s *Service) writeTokenState(ctx context.Context, jti string, tokenType string, userID string, expiresAt time.Time) error {
	key, err := s.cache.KeyBuilder().Build("jwt", tokenType, jti)
	if err != nil {
		return err
	}
	ttl := expiresAt.Sub(s.now())
	if ttl <= 0 {
		ttl = time.Second
	}
	return s.cache.Set(ctx, key, userID, ttl)
}

func (s *Service) ensureTokenUsable(ctx context.Context, jti string, tokenType string) error {
	blacklistKey, err := s.cache.KeyBuilder().Build("jwt", "blacklist", jti)
	if err != nil {
		return err
	}
	blacklisted, err := s.cache.Exists(ctx, blacklistKey)
	if err != nil {
		return ErrAuthUnavailable
	}
	if blacklisted {
		return ErrTokenRevoked
	}
	stateKey, err := s.cache.KeyBuilder().Build("jwt", tokenType, jti)
	if err != nil {
		return err
	}
	exists, err := s.cache.Exists(ctx, stateKey)
	if err != nil {
		return ErrAuthUnavailable
	}
	if !exists {
		return ErrInvalidToken
	}
	return nil
}

func (s *Service) revokeToken(ctx context.Context, jti string, tokenType string, expiresAt time.Time) error {
	blacklistKey, err := s.cache.KeyBuilder().Build("jwt", "blacklist", jti)
	if err != nil {
		return err
	}
	ttl := expiresAt.Sub(s.now())
	if ttl <= 0 {
		ttl = time.Second
	}
	if err := s.cache.Set(ctx, blacklistKey, "1", ttl); err != nil {
		return ErrAuthUnavailable
	}
	stateKey, err := s.cache.KeyBuilder().Build("jwt", tokenType, jti)
	if err != nil {
		return err
	}
	if err := s.cache.Del(ctx, stateKey); err != nil {
		return ErrAuthUnavailable
	}
	return nil
}

func (s *Service) saveAndCachePair(ctx context.Context, userID string, pair *jwtx.TokenPair) error {
	tokens := []model.AuthToken{
		{
			UserID:    userID,
			JTI:       pair.AccessJTI,
			TokenType: model.TokenTypeAccess,
			Status:    model.TokenStatusActive,
			ExpiresAt: pair.AccessExpiresAt,
		},
		{
			UserID:    userID,
			JTI:       pair.RefreshJTI,
			TokenType: model.TokenTypeRefresh,
			Status:    model.TokenStatusActive,
			ExpiresAt: pair.RefreshExpiresAt,
		},
	}
	if err := s.store.SaveAuthTokens(ctx, tokens); err != nil {
		return err
	}
	if err := s.writeTokenState(ctx, pair.AccessJTI, model.TokenTypeAccess, userID, pair.AccessExpiresAt); err != nil {
		return ErrAuthUnavailable
	}
	if err := s.writeTokenState(ctx, pair.RefreshJTI, model.TokenTypeRefresh, userID, pair.RefreshExpiresAt); err != nil {
		return ErrAuthUnavailable
	}
	return nil
}

func loginResultFromPair(pair *jwtx.TokenPair) *LoginResult {
	return &LoginResult{
		TokenType:             "Bearer",
		AccessToken:           pair.AccessToken,
		AccessTokenExpiresAt:  pair.AccessExpiresAt,
		RefreshToken:          pair.RefreshToken,
		RefreshTokenExpiresAt: pair.RefreshExpiresAt,
	}
}

func roleCodes(roles []model.Role) []string {
	codes := make([]string, 0, len(roles))
	for _, role := range roles {
		codes = append(codes, role.Code)
	}
	return codes
}

func permissionCodes(roles []model.Role) []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, role := range roles {
		for _, permission := range role.Permissions {
			if !seen[permission.Code] {
				codes = append(codes, permission.Code)
				seen[permission.Code] = true
			}
		}
	}
	return codes
}
