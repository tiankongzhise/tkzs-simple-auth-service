package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/auth"
)

func TestAuthMiddlewareSetsContextAndRenewedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	expireAt := time.Date(2026, 5, 18, 12, 30, 0, 0, time.UTC)
	service := &fakeAuthService{verifyResult: &auth.VerifyResult{
		UserID:                   "user-001",
		Roles:                    []string{"admin"},
		Permissions:              []string{"user:manage"},
		RenewedAccessToken:       "new-access",
		RenewedAccessTokenExpiry: expireAt,
	}}
	router := gin.New()
	router.GET("/protected", AuthMiddleware(service), func(c *gin.Context) {
		if c.GetString(ContextUserID) != "user-001" {
			t.Fatalf("context user id = %q", c.GetString(ContextUserID))
		}
		c.Status(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer access-token")

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get(HeaderAccessToken) != "new-access" {
		t.Fatalf("renewed token header = %q", rec.Header().Get(HeaderAccessToken))
	}
}
