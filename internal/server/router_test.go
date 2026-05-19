package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
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
