package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
)

var (
	ErrOIDCDisabled            = errors.New("oidc disabled")
	ErrPublicKeyNotLoaded      = errors.New("oidc public key not loaded")
	ErrUnsupportedGrant        = errors.New("unsupported oidc grant")
	ErrInvalidToken            = errors.New("invalid oidc token")
	ErrTokenServiceUnavailable = errors.New("oidc token service unavailable")
	ErrInvalidAuthorizeRequest = errors.New("invalid oidc authorize request")
	ErrInvalidClient           = errors.New("invalid oidc client")
	ErrInvalidAuthCode         = errors.New("invalid oidc auth code")
	ErrOIDCStoreUnavailable    = errors.New("oidc store unavailable")
)

type KeyProvider interface {
	PublicKey() *rsa.PublicKey
}

type TokenService interface {
	IssueForUser(ctx context.Context, userID string) (*TokenResult, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenResult, error)
	Verify(ctx context.Context, accessToken string) (*VerifyResult, error)
}

type Store interface {
	FindClientByID(ctx context.Context, clientID string) (*Client, error)
	SaveAuthCode(ctx context.Context, code AuthCode) error
	UseAuthCode(ctx context.Context, code string, now time.Time) (*AuthCode, error)
}

type Cache interface {
	KeyBuilder() *redisx.KeyBuilder
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	Exists(ctx context.Context, key string) (bool, error)
	Del(ctx context.Context, keys ...string) error
}

type Service struct {
	cfg    *config.Config
	keys   KeyProvider
	tokens TokenService
	store  Store
	cache  Cache
	now    func() time.Time
}

type Option func(*Service)

func WithStore(store Store) Option {
	return func(s *Service) {
		s.store = store
	}
}

func WithCache(cache Cache) Option {
	return func(s *Service) {
		s.cache = cache
	}
}

func WithNow(now func() time.Time) Option {
	return func(s *Service) {
		s.now = now
	}
}

type TokenResult struct {
	TokenType             string `json:"token_type"`
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token,omitempty"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in,omitempty"`
}

type VerifyResult struct {
	UserID      string
	Roles       []string
	Permissions []string
	ExpiresIn   int64
}

type TokenInput struct {
	GrantType    string
	RefreshToken string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
}

type AuthorizeInput struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	AccessToken  string
}

type AuthorizeResult struct {
	Code        string
	State       string
	RedirectURI string
	ExpiresAt   time.Time
}

type Client struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Status       string
}

type AuthCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scope       string
	ExpiresAt   time.Time
	Used        bool
}

type UserInfo struct {
	Subject     string   `json:"sub"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

type DiscoveryDocument struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	TokenEndpointAuthMethods         []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func NewService(cfg *config.Config, keys KeyProvider, tokens TokenService, options ...Option) *Service {
	service := &Service{cfg: cfg, keys: keys, tokens: tokens, now: time.Now}
	for _, option := range options {
		option(service)
	}
	return service
}

func (s *Service) Discovery() (*DiscoveryDocument, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	issuer := s.issuer()
	return &DiscoveryDocument{
		Issuer:                           issuer,
		AuthorizationEndpoint:            issuer + "/oauth2/authorize",
		TokenEndpoint:                    issuer + "/oauth2/token",
		UserInfoEndpoint:                 issuer + "/oauth2/userinfo",
		JWKSURI:                          issuer + "/oauth2/jwks",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethods:         []string{"client_secret_post", "client_secret_basic", "none"},
		GrantTypesSupported:              []string{"authorization_code", "refresh_token"},
	}, nil
}

func (s *Service) JWKS() (*JWKS, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	publicKey := s.keys.PublicKey()
	if publicKey == nil {
		return nil, ErrPublicKeyNotLoaded
	}
	return &JWKS{Keys: []JWK{jwkFromPublicKey(publicKey)}}, nil
}

func (s *Service) Token(ctx context.Context, input TokenInput) (*TokenResult, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	switch input.GrantType {
	case "refresh_token":
		if strings.TrimSpace(input.RefreshToken) == "" {
			return nil, ErrUnsupportedGrant
		}
		if s.tokens == nil {
			return nil, ErrTokenServiceUnavailable
		}
		return s.tokens.Refresh(ctx, input.RefreshToken)
	case "authorization_code":
		return s.exchangeAuthorizationCode(ctx, input)
	default:
		return nil, ErrUnsupportedGrant
	}
}

func (s *Service) Authorize(ctx context.Context, input AuthorizeInput) (*AuthorizeResult, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	if input.ResponseType != "code" || strings.TrimSpace(input.ClientID) == "" ||
		strings.TrimSpace(input.RedirectURI) == "" || strings.TrimSpace(input.AccessToken) == "" {
		return nil, ErrInvalidAuthorizeRequest
	}
	if s.tokens == nil {
		return nil, ErrTokenServiceUnavailable
	}
	client, err := s.validClient(ctx, input.ClientID, input.RedirectURI, "")
	if err != nil {
		return nil, err
	}
	verified, err := s.tokens.Verify(ctx, input.AccessToken)
	if err != nil {
		return nil, err
	}
	code, err := randomCode()
	if err != nil {
		return nil, err
	}
	expiresAt := s.now().UTC().Add(time.Duration(s.cfg.OIDC.AuthorizationCodeExpireMinutes) * time.Minute)
	authCode := AuthCode{
		Code:        code,
		ClientID:    client.ClientID,
		UserID:      verified.UserID,
		RedirectURI: input.RedirectURI,
		Scope:       strings.TrimSpace(input.Scope),
		ExpiresAt:   expiresAt,
	}
	if err := s.ensureCodeDeps(); err != nil {
		return nil, err
	}
	if err := s.store.SaveAuthCode(ctx, authCode); err != nil {
		return nil, err
	}
	key, err := s.cache.KeyBuilder().Build("oidc", "code", code)
	if err != nil {
		return nil, err
	}
	if err := s.cache.Set(ctx, key, verified.UserID, expiresAt.Sub(s.now().UTC())); err != nil {
		return nil, ErrOIDCStoreUnavailable
	}
	return &AuthorizeResult{
		Code:        code,
		State:       input.State,
		RedirectURI: authorizationRedirect(input.RedirectURI, code, input.State),
		ExpiresAt:   expiresAt,
	}, nil
}

func (s *Service) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if !s.cfg.OIDC.Enable {
		return nil, ErrOIDCDisabled
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, ErrInvalidToken
	}
	if s.tokens == nil {
		return nil, ErrTokenServiceUnavailable
	}
	result, err := s.tokens.Verify(ctx, accessToken)
	if err != nil {
		return nil, err
	}
	return &UserInfo{
		Subject:     result.UserID,
		Roles:       result.Roles,
		Permissions: result.Permissions,
	}, nil
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, input TokenInput) (*TokenResult, error) {
	if strings.TrimSpace(input.Code) == "" || strings.TrimSpace(input.ClientID) == "" ||
		strings.TrimSpace(input.RedirectURI) == "" {
		return nil, ErrInvalidAuthCode
	}
	if s.tokens == nil {
		return nil, ErrTokenServiceUnavailable
	}
	if _, err := s.validClient(ctx, input.ClientID, input.RedirectURI, input.ClientSecret); err != nil {
		return nil, err
	}
	if err := s.ensureCodeDeps(); err != nil {
		return nil, err
	}
	key, err := s.cache.KeyBuilder().Build("oidc", "code", input.Code)
	if err != nil {
		return nil, err
	}
	exists, err := s.cache.Exists(ctx, key)
	if err != nil {
		return nil, ErrOIDCStoreUnavailable
	}
	if !exists {
		return nil, ErrInvalidAuthCode
	}
	authCode, err := s.store.UseAuthCode(ctx, input.Code, s.now().UTC())
	if err != nil {
		return nil, err
	}
	if authCode.ClientID != input.ClientID || authCode.RedirectURI != input.RedirectURI ||
		authCode.ExpiresAt.Before(s.now().UTC()) || authCode.Used {
		return nil, ErrInvalidAuthCode
	}
	if err := s.cache.Del(ctx, key); err != nil {
		return nil, ErrOIDCStoreUnavailable
	}
	return s.tokens.IssueForUser(ctx, authCode.UserID)
}

func (s *Service) validClient(ctx context.Context, clientID string, redirectURI string, clientSecret string) (*Client, error) {
	if s.store == nil {
		return nil, ErrOIDCStoreUnavailable
	}
	client, err := s.store.FindClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client.Status != model.StatusEnabled || client.RedirectURI != redirectURI {
		return nil, ErrInvalidClient
	}
	if client.ClientSecret != "" && client.ClientSecret != clientSecret {
		return nil, ErrInvalidClient
	}
	return client, nil
}

func (s *Service) ensureCodeDeps() error {
	if s.store == nil || s.cache == nil {
		return ErrOIDCStoreUnavailable
	}
	return nil
}

func (s *Service) issuer() string {
	issuer := strings.TrimRight(s.cfg.OIDC.Issuer, "/")
	if issuer == "" {
		return strings.TrimRight(s.cfg.Server.Host, "/")
	}
	return issuer
}

func jwkFromPublicKey(key *rsa.PublicKey) JWK {
	return JWK{
		KeyType:   "RSA",
		Use:       "sig",
		KeyID:     keyID(key),
		Algorithm: "RS256",
		Modulus:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		Exponent:  base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func keyID(key *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		sum := sha256.Sum256(key.N.Bytes())
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func authorizationRedirect(raw string, code string, state string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	values := parsed.Query()
	values.Set("code", code)
	if state != "" {
		values.Set("state", state)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}
