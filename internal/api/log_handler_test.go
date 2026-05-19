package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/audit"
)

func TestLogHandlerList(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewLogHandler(&fakeAuditService{result: &audit.LogResult{
		Type:  audit.TypeLimit,
		Items: []map[string]any{{"serviceId": "svc-001"}},
		Page:  2,
		Size:  5,
	}})
	router := testLogRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/logs?type=limit&page=2&pageSize=5&startAt=2026-05-19T09:00:00Z", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "svc-001") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestLogHandlerRejectsInvalidTime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewLogHandler(&fakeAuditService{})
	router := testLogRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/logs?startAt=bad-time", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func testLogRouter(handler *LogHandler) *gin.Engine {
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "user-001")
		c.Set(ContextRoles, []string{"admin"})
		c.Next()
	})
	handler.RegisterRoutes(group)
	return router
}

type fakeAuditService struct {
	result *audit.LogResult
	err    error
}

func (s *fakeAuditService) ListLogs(_ context.Context, _ audit.Actor, _ audit.LogFilter) (*audit.LogResult, error) {
	return s.result, s.err
}
