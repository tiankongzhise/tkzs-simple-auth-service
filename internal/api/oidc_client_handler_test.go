package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	oidcclientsvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/oidcclient"
)

func TestOIDCClientHandlerCreateReturnsSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCClientHandler(&fakeOIDCClientService{result: &oidcclientsvc.Result{
		Client: model.OIDCClient{
			BaseModel:   model.BaseModel{ID: "client-001"},
			ClientID:    "client0000000001",
			Name:        "web client",
			RedirectURI: "http://app.local/callback",
			OwnerUserID: "user-001",
			Status:      model.StatusEnabled,
		},
		ClientSecret: "secret-value",
	}})
	router := testOIDCClientRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/oidc-clients", strings.NewReader(`{"name":"web client","redirectUri":"http://app.local/callback"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "secret-value") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestOIDCClientHandlerListDoesNotReturnSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCClientHandler(&fakeOIDCClientService{clients: []model.OIDCClient{{
		BaseModel:    model.BaseModel{ID: "client-001"},
		ClientID:     "client0000000001",
		ClientSecret: "secret-value",
		Name:         "web client",
		OwnerUserID:  "user-001",
		Status:       model.StatusEnabled,
	}}})
	router := testOIDCClientRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oidc-clients", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-value") || strings.Contains(rec.Body.String(), "clientSecret") {
		t.Fatalf("response leaked secret: %s", rec.Body.String())
	}
}

func TestOIDCClientHandlerForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewOIDCClientHandler(&fakeOIDCClientService{err: oidcclientsvc.ErrForbidden})
	router := testOIDCClientRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/oidc-clients/client-002", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func testOIDCClientRouter(handler *OIDCClientHandler) *gin.Engine {
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

type fakeOIDCClientService struct {
	result  *oidcclientsvc.Result
	client  *model.OIDCClient
	clients []model.OIDCClient
	err     error
}

func (s *fakeOIDCClientService) Create(_ context.Context, _ oidcclientsvc.Actor, _ oidcclientsvc.CreateInput) (*oidcclientsvc.Result, error) {
	return s.result, s.err
}

func (s *fakeOIDCClientService) List(_ context.Context, _ oidcclientsvc.Actor) ([]model.OIDCClient, error) {
	return s.clients, s.err
}

func (s *fakeOIDCClientService) Get(_ context.Context, _ oidcclientsvc.Actor, _ string) (*model.OIDCClient, error) {
	return s.client, s.err
}
