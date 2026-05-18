package jwtx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
)

func TestIssuePairAndParse(t *testing.T) {
	manager := testManager(t)

	pair, err := manager.IssuePair(Subject{
		ID:          "user-001",
		Roles:       []string{"admin"},
		Permissions: []string{"user:manage"},
	})
	if err != nil {
		t.Fatalf("IssuePair() error = %v", err)
	}

	accessClaims, err := manager.Parse(pair.AccessToken, TokenTypeAccess)
	if err != nil {
		t.Fatalf("Parse(access) error = %v", err)
	}
	if accessClaims.Subject != "user-001" || accessClaims.ID != pair.AccessJTI {
		t.Fatalf("access claims = %#v", accessClaims)
	}
	if len(accessClaims.Roles) != 1 || accessClaims.Roles[0] != "admin" {
		t.Fatalf("roles = %#v", accessClaims.Roles)
	}

	refreshClaims, err := manager.Parse(pair.RefreshToken, TokenTypeRefresh)
	if err != nil {
		t.Fatalf("Parse(refresh) error = %v", err)
	}
	if refreshClaims.Subject != "user-001" || len(refreshClaims.Roles) != 0 {
		t.Fatalf("refresh claims = %#v", refreshClaims)
	}
}

func TestParseRejectsUnexpectedType(t *testing.T) {
	manager := testManager(t)
	issued, err := manager.Issue(Subject{ID: "user-001"}, TokenTypeAccess)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	_, err = manager.Parse(issued.Token, TokenTypeRefresh)
	if !errors.Is(err, ErrUnexpectedTokenType) {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseRejectsExpiredToken(t *testing.T) {
	manager := testManager(t)
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	manager.SetNow(func() time.Time { return now })
	issued, err := manager.Issue(Subject{ID: "user-001"}, TokenTypeAccess)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	manager.SetNow(func() time.Time { return now.Add(31 * time.Minute) })
	_, err = manager.Parse(issued.Token, TokenTypeAccess)
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestShouldAutoRefresh(t *testing.T) {
	manager := testManager(t)
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	manager.SetNow(func() time.Time { return now })

	claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(now.Add(4 * time.Minute)),
	}}
	if !manager.ShouldAutoRefresh(claims) {
		t.Fatal("ShouldAutoRefresh() = false")
	}
}

func TestLoadKeysFromPEM(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")

	privateBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	writePEM(t, privatePath, "RSA PRIVATE KEY", privateBytes)
	publicBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	writePEM(t, publicPath, "RSA PUBLIC KEY", publicBytes)

	if _, err := LoadPrivateKey(privatePath); err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}
	if _, err := LoadPublicKey(publicPath); err != nil {
		t.Fatalf("LoadPublicKey() error = %v", err)
	}
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return NewManagerWithKeys(config.JWTConfig{
		Issuer:                   "authlimit",
		AccessExpireMinutes:      30,
		RefreshExpireHours:       24,
		AutoRefreshBeforeMinutes: 5,
	}, privateKey, &privateKey.PublicKey)
}

func writePEM(t *testing.T, path string, typ string, bytes []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pem: %v", err)
	}
	defer file.Close()
	if err := pem.Encode(file, &pem.Block{Type: typ, Bytes: bytes}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
}
