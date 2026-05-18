package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/auth"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

func TestAuthHandlerLoginSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAuthHandler(&fakeAuthService{result: &auth.LoginResult{
		TokenType:             "Bearer",
		AccessToken:           "access-token",
		AccessTokenExpiresAt:  time.Date(2026, 5, 18, 12, 30, 0, 0, time.UTC),
		RefreshToken:          "refresh-token",
		RefreshTokenExpiresAt: time.Date(2026, 5, 19, 12, 0, 0, 0, time.UTC),
	}})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"admin","password":"Zqlt_123456789"}`))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body response.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != response.CodeOK {
		t.Fatalf("body = %#v", body)
	}
}

func TestAuthHandlerLoginInvalidCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAuthHandler(&fakeAuthService{err: auth.ErrInvalidCredentials})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"admin","password":"Wrong_123456"}`))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandlerLoginUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAuthHandler(&fakeAuthService{err: auth.ErrAuthUnavailable})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"admin","password":"Zqlt_123456789"}`))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandlerLoginBadJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAuthHandler(&fakeAuthService{err: errors.New("should not call")})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{bad json}`))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandlerRefreshSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAuthHandler(&fakeAuthService{result: &auth.LoginResult{
		TokenType:    "Bearer",
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
	}})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", strings.NewReader(`{"refreshToken":"refresh-token"}`))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandlerVerifyWritesRenewedTokenHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	expireAt := time.Date(2026, 5, 18, 12, 30, 0, 0, time.UTC)
	handler := NewAuthHandler(&fakeAuthService{verifyResult: &auth.VerifyResult{
		UserID:                   "user-001",
		RenewedAccessToken:       "new-access",
		RenewedAccessTokenExpiry: expireAt,
	}})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/verify", nil)
	req.Header.Set("Authorization", "Bearer access-token")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get(HeaderAccessToken) != "new-access" {
		t.Fatalf("renewed token header = %q", rec.Header().Get(HeaderAccessToken))
	}
	if rec.Header().Get(HeaderAccessTokenExpireAt) != "2026-05-18T12:30:00Z" {
		t.Fatalf("renewed token expiry header = %q", rec.Header().Get(HeaderAccessTokenExpireAt))
	}
}

func TestAuthHandlerLogoutSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAuthHandler(&fakeAuthService{})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api/auth"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", strings.NewReader(`{"refreshToken":"refresh-token"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer access-token")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

type fakeAuthService struct {
	result       *auth.LoginResult
	verifyResult *auth.VerifyResult
	err          error
}

func (s *fakeAuthService) Login(_ context.Context, _ auth.LoginInput) (*auth.LoginResult, error) {
	return s.result, s.err
}

func (s *fakeAuthService) Refresh(_ context.Context, _ string) (*auth.LoginResult, error) {
	return s.result, s.err
}

func (s *fakeAuthService) Verify(_ context.Context, _ string) (*auth.VerifyResult, error) {
	return s.verifyResult, s.err
}

func (s *fakeAuthService) Logout(_ context.Context, _ string, _ string) error {
	return s.err
}
