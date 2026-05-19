package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
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

type fakeTokenService struct {
	token  *TokenResult
	verify *VerifyResult
	err    error
}

func (s *fakeTokenService) Refresh(_ context.Context, _ string) (*TokenResult, error) {
	return s.token, s.err
}

func (s *fakeTokenService) Verify(_ context.Context, _ string) (*VerifyResult, error) {
	return s.verify, s.err
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
