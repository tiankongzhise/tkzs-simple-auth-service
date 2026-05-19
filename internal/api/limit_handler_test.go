package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/limiter"
)

func TestLimitHandlerVerifyAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewLimitHandler(&fakeLimitService{result: &limiter.VerifyResult{
		Allowed:   true,
		Remaining: 9,
		ResetAt:   1779091200,
	}})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/limit/verify", strings.NewReader(`{"serviceId":"svc-001","ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-RateLimit-Remaining") != "9" {
		t.Fatalf("remaining header = %q", rec.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestLimitHandlerVerifyBlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewLimitHandler(&fakeLimitService{result: &limiter.VerifyResult{
		Allowed:   false,
		Remaining: 0,
		ResetAt:   1779091210,
	}})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/limit/verify", strings.NewReader(`{"serviceId":"svc-001","ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestLimitHandlerBlacklisted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewLimitHandler(&fakeLimitService{err: limiter.ErrBlacklisted})
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oidc/limit/verify", strings.NewReader(`{"serviceId":"svc-001","ip":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

type fakeLimitService struct {
	result *limiter.VerifyResult
	err    error
}

func (s *fakeLimitService) Verify(_ context.Context, _ limiter.VerifyInput) (*limiter.VerifyResult, error) {
	return s.result, s.err
}
