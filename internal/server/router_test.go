package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

func TestHealthReturnsUnifiedResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(config.Default())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set(requestIDHeader, "req-001")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get(requestIDHeader); got != "req-001" {
		t.Fatalf("request id header = %q", got)
	}

	var body response.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Code != response.CodeOK || body.Message != "ok" || body.RequestID != "req-001" {
		t.Fatalf("body = %#v", body)
	}
	if body.Data == nil {
		t.Fatal("body data is nil")
	}
}

func TestRequestIDMiddlewareGeneratesMissingRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(config.Default())

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Header().Get(requestIDHeader) == "" {
		t.Fatal("request id header is empty")
	}
}

func TestMetricsEndpointExposed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(config.Default())

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("metrics body is empty")
	}
}

func TestUIRoutesServedWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(config.Default(), WithUIRoutes(testUIRegistrar{}))

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestUIRoutesSkippedWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.Default()
	cfg.UI.Enable = false
	router := NewRouter(cfg, WithUIRoutes(testUIRegistrar{}))

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAPIRoutesUseMiddlewares(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(config.Default(), WithAPIRoutes(
		testRegistrar{},
		func(c *gin.Context) {
			c.Set("middleware_ran", true)
			c.Next()
		},
	))

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestOperationAuditMiddlewareRecordsMutation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := &testAuditRecorder{}
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set("auth_user_id", "user-001")
		c.Next()
	}, OperationAuditMiddleware(recorder))
	group.POST("/apps", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/api/apps", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if recorder.log.ActorID != "user-001" || recorder.log.Resource != "apps" || recorder.log.Result != "success" {
		t.Fatalf("log = %#v", recorder.log)
	}
}

type testRegistrar struct{}

func (testRegistrar) RegisterRoutes(group *gin.RouterGroup) {
	group.GET("/test", func(c *gin.Context) {
		if !c.GetBool("middleware_ran") {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.Status(http.StatusOK)
	})
}

type testUIRegistrar struct{}

func (testUIRegistrar) RegisterRoutes(router *gin.Engine) {
	router.GET("/ui/", func(c *gin.Context) {
		c.String(http.StatusOK, "ui")
	})
}

type testAuditRecorder struct {
	log model.OperationLog
}

func (r *testAuditRecorder) RecordOperation(_ context.Context, log model.OperationLog) error {
	r.log = log
	return nil
}
