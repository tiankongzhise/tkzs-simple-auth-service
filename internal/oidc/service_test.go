package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/redisx"
	"golang.org/x/crypto/bcrypt"
)

func TestDiscoveryReturnsOIDCEndpoints(t *testing.T) {
	service := NewService(config.Default(), mustKeyProvider(t), nil)

	document, err := service.Discovery()
	if err != nil {
		t.Fatalf("Discovery() error = %v", err)
	}
	if document.Issuer != "http://127.0.0.1:8080" {
		t.Fatalf("issuer = %q", document.Issuer)
	}
	if document.JWKSURI != "http://127.0.0.1:8080/oauth2/jwks" {
		t.Fatalf("jwks uri = %q", document.JWKSURI)
	}
}

func TestJWKSExportsRSAPublicKey(t *testing.T) {
	service := NewService(config.Default(), mustKeyProvider(t), nil)

	keys, err := service.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if len(keys.Keys) != 1 {
		t.Fatalf("keys = %#v", keys.Keys)
	}
	key := keys.Keys[0]
	if key.KeyType != "RSA" || key.Use != "sig" || key.Algorithm != "RS256" {
		t.Fatalf("key metadata = %#v", key)
	}
	if key.Modulus == "" || key.Exponent == "" || key.KeyID == "" {
		t.Fatalf("key material missing: %#v", key)
	}
}

func TestOIDCDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.OIDC.Enable = false
	service := NewService(cfg, mustKeyProvider(t), nil)

	if _, err := service.Discovery(); err != ErrOIDCDisabled {
		t.Fatalf("Discovery() error = %v", err)
	}
}

func TestTokenRefreshGrant(t *testing.T) {
	service := NewService(config.Default(), mustKeyProvider(t), &fakeTokenService{
		token: &TokenResult{TokenType: "Bearer", AccessToken: "access-token", RefreshToken: "refresh-token"},
	})

	result, err := service.Token(t.Context(), TokenInput{
		GrantType:    "refresh_token",
		RefreshToken: "old-refresh",
	})
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if result.AccessToken != "access-token" {
		t.Fatalf("result = %#v", result)
	}
}

func TestTokenRejectsUnsupportedGrant(t *testing.T) {
	service := NewService(config.Default(), mustKeyProvider(t), &fakeTokenService{})

	_, err := service.Token(t.Context(), TokenInput{GrantType: "client_credentials"})
	if err != ErrUnsupportedGrant {
		t.Fatalf("Token() error = %v", err)
	}
}

func TestUserInfoUsesAccessToken(t *testing.T) {
	service := NewService(config.Default(), mustKeyProvider(t), &fakeTokenService{
		verify: &VerifyResult{UserID: "user-001", Roles: []string{"admin"}, Permissions: []string{"user:manage"}},
	})

	info, err := service.UserInfo(t.Context(), "access-token")
	if err != nil {
		t.Fatalf("UserInfo() error = %v", err)
	}
	if info.Subject != "user-001" || len(info.Roles) != 1 || len(info.Permissions) != 1 {
		t.Fatalf("userinfo = %#v", info)
	}
}

func TestAuthorizeIssuesCodeAndCachesIt(t *testing.T) {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	store := &fakeStore{client: &Client{
		ClientID:    "client-001",
		RedirectURI: "http://app/callback",
		Status:      "enabled",
	}}
	cache := newFakeOIDCCache(t)
	service := NewService(
		config.Default(),
		mustKeyProvider(t),
		&fakeTokenService{verify: &VerifyResult{UserID: "user-001"}},
		WithStore(store),
		WithCache(cache),
		WithNow(func() time.Time { return now }),
	)

	result, err := service.Authorize(t.Context(), AuthorizeInput{
		ResponseType: "code",
		ClientID:     "client-001",
		RedirectURI:  "http://app/callback",
		State:        "state-001",
		AccessToken:  "access-token",
	})
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	if result.Code == "" || result.ExpiresAt != now.Add(5*time.Minute) {
		t.Fatalf("result = %#v", result)
	}
	if len(store.savedCodes) != 1 || store.savedCodes[0].UserID != "user-001" {
		t.Fatalf("saved codes = %#v", store.savedCodes)
	}
	if cache.values["authlimit:oidc:code:"+result.Code] != "user-001" {
		t.Fatalf("cache values = %#v", cache.values)
	}
}

func TestAuthorizationCodeExchangeIssuesTokenAndDeletesCode(t *testing.T) {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	store := &fakeStore{
		client: &Client{
			ClientID:     "client-001",
			ClientSecret: "secret",
			RedirectURI:  "http://app/callback",
			Status:       "enabled",
		},
		code: &AuthCode{
			Code:        "code-001",
			ClientID:    "client-001",
			UserID:      "user-001",
			RedirectURI: "http://app/callback",
			ExpiresAt:   now.Add(time.Minute),
		},
	}
	cache := newFakeOIDCCache(t)
	cache.values["authlimit:oidc:code:code-001"] = "user-001"
	service := NewService(
		config.Default(),
		mustKeyProvider(t),
		&fakeTokenService{token: &TokenResult{AccessToken: "access-token"}},
		WithStore(store),
		WithCache(cache),
		WithNow(func() time.Time { return now }),
	)

	result, err := service.Token(t.Context(), TokenInput{
		GrantType:    "authorization_code",
		Code:         "code-001",
		ClientID:     "client-001",
		ClientSecret: "secret",
		RedirectURI:  "http://app/callback",
	})
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if result.AccessToken != "access-token" {
		t.Fatalf("result = %#v", result)
	}
	if cache.values["authlimit:oidc:code:code-001"] != "" {
		t.Fatalf("auth code was not deleted: %#v", cache.values)
	}
}

func TestAuthorizationCodeExchangeAcceptsBcryptClientSecret(t *testing.T) {
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	store := &fakeStore{
		client: &Client{
			ClientID:     "client-001",
			ClientSecret: string(hash),
			RedirectURI:  "http://app/callback",
			Status:       "enabled",
		},
		code: &AuthCode{
			Code:        "code-001",
			ClientID:    "client-001",
			UserID:      "user-001",
			RedirectURI: "http://app/callback",
			ExpiresAt:   now.Add(time.Minute),
		},
	}
	cache := newFakeOIDCCache(t)
	cache.values["authlimit:oidc:code:code-001"] = "user-001"
	service := NewService(
		config.Default(),
		mustKeyProvider(t),
		&fakeTokenService{token: &TokenResult{AccessToken: "access-token"}},
		WithStore(store),
		WithCache(cache),
		WithNow(func() time.Time { return now }),
	)

	result, err := service.Token(t.Context(), TokenInput{
		GrantType:    "authorization_code",
		Code:         "code-001",
		ClientID:     "client-001",
		ClientSecret: "secret",
		RedirectURI:  "http://app/callback",
	})
	if err != nil {
		t.Fatalf("Token() error = %v", err)
	}
	if result.AccessToken != "access-token" {
		t.Fatalf("result = %#v", result)
	}
}

type fakeTokenService struct {
	token  *TokenResult
	verify *VerifyResult
	err    error
}

func (s *fakeTokenService) Refresh(_ context.Context, _ string) (*TokenResult, error) {
	return s.token, s.err
}

func (s *fakeTokenService) IssueForUser(_ context.Context, _ string) (*TokenResult, error) {
	return s.token, s.err
}

func (s *fakeTokenService) Verify(_ context.Context, _ string) (*VerifyResult, error) {
	return s.verify, s.err
}

type fakeStore struct {
	client     *Client
	code       *AuthCode
	savedCodes []AuthCode
}

func (s *fakeStore) FindClientByID(_ context.Context, clientID string) (*Client, error) {
	if s.client == nil || s.client.ClientID != clientID {
		return nil, ErrClientNotFound
	}
	return s.client, nil
}

func (s *fakeStore) SaveAuthCode(_ context.Context, code AuthCode) error {
	s.savedCodes = append(s.savedCodes, code)
	return nil
}

func (s *fakeStore) UseAuthCode(_ context.Context, code string, _ time.Time) (*AuthCode, error) {
	if s.code == nil || s.code.Code != code {
		return nil, ErrInvalidAuthCode
	}
	return s.code, nil
}

type fakeOIDCCache struct {
	keys   *redisx.KeyBuilder
	values map[string]string
}

func newFakeOIDCCache(t *testing.T) *fakeOIDCCache {
	t.Helper()
	keys, err := redisx.NewKeyBuilder("authlimit")
	if err != nil {
		t.Fatalf("NewKeyBuilder() error = %v", err)
	}
	return &fakeOIDCCache{keys: keys, values: map[string]string{}}
}

func (c *fakeOIDCCache) KeyBuilder() *redisx.KeyBuilder {
	return c.keys
}

func (c *fakeOIDCCache) Set(_ context.Context, key string, value string, _ time.Duration) error {
	c.values[key] = value
	return nil
}

func (c *fakeOIDCCache) Exists(_ context.Context, key string) (bool, error) {
	_, ok := c.values[key]
	return ok, nil
}

func (c *fakeOIDCCache) Del(_ context.Context, keys ...string) error {
	for _, key := range keys {
		delete(c.values, key)
	}
	return nil
}

type staticKeyProvider struct {
	key *rsa.PublicKey
}

func (p staticKeyProvider) PublicKey() *rsa.PublicKey {
	return p.key
}

func mustKeyProvider(t *testing.T) staticKeyProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return staticKeyProvider{key: &privateKey.PublicKey}
}
