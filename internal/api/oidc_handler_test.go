package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/oidc"
)

func TestOIDCHandlerDiscovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCHandler(&fakeOIDCService{
		discovery: &oidc.DiscoveryDocument{Issuer: "http://issuer", JWKSURI: "http://issuer/oauth2/jwks"},
	})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body oidc.DiscoveryDocument
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Issuer != "http://issuer" {
		t.Fatalf("issuer = %q", body.Issuer)
	}
}

func TestOIDCHandlerJWKS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCHandler(&fakeOIDCService{
		jwks: &oidc.JWKS{Keys: []oidc.JWK{{KeyType: "RSA", KeyID: "kid"}}},
	})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body oidc.JWKS
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Keys) != 1 || body.Keys[0].KeyID != "kid" {
		t.Fatalf("body = %#v", body)
	}
}

type fakeOIDCService struct {
	discovery *oidc.DiscoveryDocument
	jwks      *oidc.JWKS
	err       error
}

func (s *fakeOIDCService) Discovery() (*oidc.DiscoveryDocument, error) {
	return s.discovery, s.err
}

func (s *fakeOIDCService) JWKS() (*oidc.JWKS, error) {
	return s.jwks, s.err
}
