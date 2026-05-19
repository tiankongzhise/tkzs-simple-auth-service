package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestOIDCHandlerTokenRefreshGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCHandler(&fakeOIDCService{
		token: &oidc.TokenResult{TokenType: "Bearer", AccessToken: "new-access", RefreshToken: "new-refresh"},
	})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader("grant_type=refresh_token&refresh_token=old-refresh"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body oidc.TokenResult
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.AccessToken != "new-access" {
		t.Fatalf("body = %#v", body)
	}
}

func TestOIDCHandlerUserInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCHandler(&fakeOIDCService{
		userInfo: &oidc.UserInfo{Subject: "user-001", Roles: []string{"admin"}},
	})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body oidc.UserInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Subject != "user-001" {
		t.Fatalf("body = %#v", body)
	}
}

func TestOIDCHandlerAuthorizeRedirectsWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCHandler(&fakeOIDCService{
		authorize: &oidc.AuthorizeResult{RedirectURI: "http://app/callback?code=code-001&state=state-001"},
	})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?response_type=code&client_id=client-001&redirect_uri=http://app/callback&state=state-001", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "http://app/callback?code=code-001&state=state-001" {
		t.Fatalf("location = %q", rec.Header().Get("Location"))
	}
}

func TestOIDCHandlerTokenAuthorizationCodeGrant(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCHandler(&fakeOIDCService{
		token: &oidc.TokenResult{TokenType: "Bearer", AccessToken: "access-token"},
	})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader("grant_type=authorization_code&code=code-001&redirect_uri=http://app/callback"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("client-001", "secret")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body oidc.TokenResult
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.AccessToken != "access-token" {
		t.Fatalf("body = %#v", body)
	}
}

type fakeOIDCService struct {
	authorize *oidc.AuthorizeResult
	discovery *oidc.DiscoveryDocument
	jwks      *oidc.JWKS
	token     *oidc.TokenResult
	userInfo  *oidc.UserInfo
	err       error
}

func (s *fakeOIDCService) Authorize(_ context.Context, _ oidc.AuthorizeInput) (*oidc.AuthorizeResult, error) {
	return s.authorize, s.err
}

func (s *fakeOIDCService) Discovery() (*oidc.DiscoveryDocument, error) {
	return s.discovery, s.err
}

func (s *fakeOIDCService) JWKS() (*oidc.JWKS, error) {
	return s.jwks, s.err
}

func (s *fakeOIDCService) Token(_ context.Context, _ oidc.TokenInput) (*oidc.TokenResult, error) {
	return s.token, s.err
}

func (s *fakeOIDCService) UserInfo(_ context.Context, _ string) (*oidc.UserInfo, error) {
	return s.userInfo, s.err
}
