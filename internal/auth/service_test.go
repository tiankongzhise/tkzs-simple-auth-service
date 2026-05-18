package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/jwtx"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
	"golang.org/x/crypto/bcrypt"
)

func TestLoginSuccessIssuesTokensAndWritesRedisState(t *testing.T) {
	service, store, cache := testService(t)

	result, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" || result.TokenType != "Bearer" {
		t.Fatalf("result = %#v", result)
	}
	if len(store.savedTokens) != 2 {
		t.Fatalf("saved tokens = %#v", store.savedTokens)
	}
	if cache.values["authlimit:jwt:access:"+store.savedTokens[0].JTI] == "" {
		t.Fatalf("missing access token redis state: %#v", cache.values)
	}
	if store.lastLoginUserID != "user-001" {
		t.Fatalf("last login user id = %q", store.lastLoginUserID)
	}
}

func TestLoginWrongPasswordLocksAccount(t *testing.T) {
	service, _, cache := testService(t)
	service.cfg.Security.AuthFailMaxCount = 1

	_, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Wrong_123456",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v", err)
	}
	if cache.values["authlimit:auth:lock:user:user-001"] != "1" {
		t.Fatalf("lock key not set: %#v", cache.values)
	}

	_, err = service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("Login() locked error = %v", err)
	}
}

func TestLoginRejectsInvalidInput(t *testing.T) {
	service, _, _ := testService(t)
	_, err := service.Login(context.Background(), LoginInput{
		Username: "bad-name",
		Password: "short",
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Login() error = %v", err)
	}
}

func TestLoginReturnsUnavailableOnRedisError(t *testing.T) {
	service, _, cache := testService(t)
	cache.err = errors.New("redis down")

	_, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if !errors.Is(err, ErrAuthUnavailable) {
		t.Fatalf("Login() error = %v", err)
	}
}

func TestRefreshRotatesRefreshToken(t *testing.T) {
	service, store, cache := testService(t)
	login, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	oldRefreshJTI := store.savedTokens[1].JTI

	refreshed, err := service.Refresh(context.Background(), login.RefreshToken)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == login.RefreshToken {
		t.Fatalf("refreshed = %#v", refreshed)
	}
	if cache.values["authlimit:jwt:blacklist:"+oldRefreshJTI] != "1" {
		t.Fatalf("old refresh token was not blacklisted: %#v", cache.values)
	}
	if len(store.revokedJTIs) != 1 || store.revokedJTIs[0] != oldRefreshJTI {
		t.Fatalf("revoked jtis = %#v", store.revokedJTIs)
	}
}

func TestVerifyRejectsMissingRedisState(t *testing.T) {
	service, _, cache := testService(t)
	login, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	for key := range cache.values {
		if key != "authlimit:user:password:user-001" {
			delete(cache.values, key)
		}
	}

	_, err = service.Verify(context.Background(), login.AccessToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestLogoutRevokesAccessAndRefreshTokens(t *testing.T) {
	service, store, cache := testService(t)
	login, err := service.Login(context.Background(), LoginInput{
		Username: "admin",
		Password: "Zqlt_123456789",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	accessJTI := store.savedTokens[0].JTI
	refreshJTI := store.savedTokens[1].JTI

	if err := service.Logout(context.Background(), login.AccessToken, login.RefreshToken); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if cache.values["authlimit:jwt:blacklist:"+accessJTI] != "1" {
		t.Fatalf("access token not blacklisted: %#v", cache.values)
	}
	if cache.values["authlimit:jwt:blacklist:"+refreshJTI] != "1" {
		t.Fatalf("refresh token not blacklisted: %#v", cache.values)
	}
	if len(store.revokedJTIs) != 2 {
		t.Fatalf("revoked jtis = %#v", store.revokedJTIs)
	}
}

func testService(t *testing.T) (*Service, *fakeUserStore, *fakeCache) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("Zqlt_123456789"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	store := &fakeUserStore{user: &model.User{
		BaseModel:    model.BaseModel{ID: "user-001"},
		Username:     "admin",
		PasswordHash: string(hash),
		Status:       model.StatusEnabled,
		Roles: []model.Role{
			{
				Code: "admin",
				Permissions: []model.Permission{
					{Code: "user:manage"},
				},
			},
		},
	}}
	cache := newFakeCache(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	manager := jwtx.NewManagerWithKeys(config.Default().JWT, privateKey, &privateKey.PublicKey)
	service := NewService(config.Default(), store, cache, manager)
	return service, store, cache
}

type fakeUserStore struct {
	user            *model.User
	savedTokens     []model.AuthToken
	revokedJTIs     []string
	lastLoginUserID string
}

func (s *fakeUserStore) FindUserByUsername(_ context.Context, username string) (*model.User, error) {
	if s.user == nil || s.user.Username != username {
		return nil, ErrUserNotFound
	}
	return s.user, nil
}

func (s *fakeUserStore) FindUserByID(_ context.Context, userID string) (*model.User, error) {
	if s.user == nil || s.user.ID != userID {
		return nil, ErrUserNotFound
	}
	return s.user, nil
}

func (s *fakeUserStore) SaveAuthTokens(_ context.Context, tokens []model.AuthToken) error {
	s.savedTokens = append(s.savedTokens, tokens...)
	return nil
}

func (s *fakeUserStore) RevokeAuthTokens(_ context.Context, jtis []string, _ time.Time) error {
	s.revokedJTIs = append(s.revokedJTIs, jtis...)
	return nil
}

func (s *fakeUserStore) UpdateLastLogin(_ context.Context, userID string, _ time.Time) error {
	s.lastLoginUserID = userID
	return nil
}

type fakeCache struct {
	keys   *redisx.KeyBuilder
	values map[string]string
	ttls   map[string]time.Duration
	err    error
}

func newFakeCache(t *testing.T) *fakeCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeCache{
		keys:   keys,
		values: map[string]string{},
		ttls:   map[string]time.Duration{},
	}
}

func (c *fakeCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeCache) Get(_ context.Context, key string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	return c.values[key], nil
}

func (c *fakeCache) Set(_ context.Context, key string, value string, ttl time.Duration) error {
	if c.err != nil {
		return c.err
	}
	c.values[key] = value
	c.ttls[key] = ttl
	return nil
}

func (c *fakeCache) Del(_ context.Context, keys ...string) error {
	if c.err != nil {
		return c.err
	}
	for _, key := range keys {
		delete(c.values, key)
	}
	return nil
}

func (c *fakeCache) Exists(_ context.Context, key string) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	_, ok := c.values[key]
	return ok, nil
}

func (c *fakeCache) Expire(_ context.Context, key string, ttl time.Duration) error {
	if c.err != nil {
		return c.err
	}
	c.ttls[key] = ttl
	return nil
}

func (c *fakeCache) Incr(_ context.Context, key string) (int64, error) {
	if c.err != nil {
		return 0, c.err
	}
	next := int64(1)
	if c.values[key] != "" {
		next = 2
	}
	c.values[key] = "1"
	return next, nil
}
