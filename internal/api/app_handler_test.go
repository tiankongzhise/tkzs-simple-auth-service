package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	appsvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/app"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

func TestAppHandlerCreateReturnsSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC)
	handler := NewAppHandler(&fakeAppService{result: &appsvc.Result{
		App: model.App{
			BaseModel:   model.BaseModel{ID: "app-001", CreatedAt: now, UpdatedAt: now},
			AppID:       "app00001",
			Name:        "demo app",
			OwnerUserID: "user-001",
			Status:      model.StatusEnabled,
		},
		AppSecret: "secret-value",
	}})
	router := testAppRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/apps", strings.NewReader(`{"name":"demo app"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body response.Body
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	data := body.Data.(map[string]any)
	if data["appSecret"] != "secret-value" {
		t.Fatalf("data = %#v", data)
	}
}

func TestAppHandlerListDoesNotReturnSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAppHandler(&fakeAppService{apps: []model.App{{
		BaseModel:   model.BaseModel{ID: "app-001"},
		AppID:       "app00001",
		Name:        "demo app",
		OwnerUserID: "user-001",
		Status:      model.StatusEnabled,
		SecretHash:  "secret-value",
	}}})
	router := testAppRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/apps", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-value") || strings.Contains(rec.Body.String(), "appSecret") {
		t.Fatalf("response leaked secret: %s", rec.Body.String())
	}
}

func TestAppHandlerForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewAppHandler(&fakeAppService{err: appsvc.ErrForbidden})
	router := testAppRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/apps/app-001", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func testAppRouter(handler *AppHandler) *gin.Engine {
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

type fakeAppService struct {
	result *appsvc.Result
	apps   []model.App
	app    *model.App
	err    error
}

func (s *fakeAppService) Create(_ context.Context, _ appsvc.Actor, _ appsvc.CreateInput) (*appsvc.Result, error) {
	return s.result, s.err
}

func (s *fakeAppService) List(_ context.Context, _ appsvc.Actor) ([]model.App, error) {
	return s.apps, s.err
}

func (s *fakeAppService) Get(_ context.Context, _ appsvc.Actor, _ string) (*model.App, error) {
	return s.app, s.err
}

func (s *fakeAppService) Update(_ context.Context, _ appsvc.Actor, _ appsvc.UpdateInput) (*model.App, error) {
	return s.app, s.err
}

func (s *fakeAppService) Delete(_ context.Context, _ appsvc.Actor, _ string) error {
	return s.err
}

func (s *fakeAppService) ResetSecret(_ context.Context, _ appsvc.Actor, _ string) (*appsvc.Result, error) {
	return s.result, s.err
}
