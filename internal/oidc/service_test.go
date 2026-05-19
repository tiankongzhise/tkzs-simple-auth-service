package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
)

func TestDiscoveryReturnsOIDCEndpoints(t *testing.T) {
	service := NewService(config.Default(), mustKeyProvider(t))

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
	service := NewService(config.Default(), mustKeyProvider(t))

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
	service := NewService(cfg, mustKeyProvider(t))

	if _, err := service.Discovery(); err != ErrOIDCDisabled {
		t.Fatalf("Discovery() error = %v", err)
	}
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
