package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNewHandlerNormalizesPrefix(t *testing.T) {
	handler, err := NewHandler("/ui")
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	if handler.prefix != "/ui/" {
		t.Fatalf("prefix = %q", handler.prefix)
	}
}

func TestHandlerServesManagementUIAssets(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, err := NewHandler("/ui/")
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	router := gin.New()
	handler.RegisterRoutes(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "modal") || !strings.Contains(rec.Body.String(), "鉴权限流管理后台") {
		t.Fatalf("ui body missing management shell")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/ui/app.js", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("app.js status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "limitRules") || !strings.Contains(rec.Body.String(), "refreshSession") {
		t.Fatalf("app.js missing management behavior")
	}
}
