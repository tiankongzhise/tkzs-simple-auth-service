package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/audit"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

func TestHealthCheckHandlerList(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewHealthCheckHandler(&fakeHealthCheckQueryService{items: []model.HealthCheckLog{{
		ServiceID: "svc-001",
		Status:    "healthy",
	}}})
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "admin")
		c.Set(ContextRoles, []string{"admin"})
		c.Next()
	})
	handler.RegisterRoutes(group)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health-checks?serviceId=svc-001", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "healthy") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

type fakeHealthCheckQueryService struct {
	items []model.HealthCheckLog
	err   error
}

func (s *fakeHealthCheckQueryService) ListHealthChecks(_ context.Context, _ audit.Actor, _ audit.LogFilter) ([]model.HealthCheckLog, error) {
	return s.items, s.err
}
