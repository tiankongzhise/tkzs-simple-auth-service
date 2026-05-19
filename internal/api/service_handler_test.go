package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
)

func TestServiceHandlerCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewServiceHandler(&fakeServiceService{service: &model.Service{
		BaseModel:   model.BaseModel{ID: "svc-001"},
		Name:        "orders",
		Code:        "orders",
		OwnerUserID: "user-001",
		Status:      servicesvc.StatusPending,
	}})
	router := testServiceRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/services", strings.NewReader(`{"name":"orders","code":"orders","baseUrl":"http://orders.local:8080"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestServiceHandlerApproveForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewServiceHandler(&fakeServiceService{err: servicesvc.ErrForbidden})
	router := testServiceRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/services/svc-001/approve", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestServiceHandlerDiscover(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewServiceHandler(&fakeServiceService{services: []model.Service{{Name: "orders"}}})
	router := testServiceRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/services/discover", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "orders") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func testServiceRouter(handler *ServiceHandler) *gin.Engine {
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

type fakeServiceService struct {
	service  *model.Service
	services []model.Service
	err      error
}

func (s *fakeServiceService) Create(_ context.Context, _ servicesvc.Actor, _ servicesvc.CreateInput) (*model.Service, error) {
	return s.service, s.err
}

func (s *fakeServiceService) List(_ context.Context, _ servicesvc.Actor, _ servicesvc.ListFilter) ([]model.Service, error) {
	return s.services, s.err
}

func (s *fakeServiceService) Get(_ context.Context, _ servicesvc.Actor, _ string) (*model.Service, error) {
	return s.service, s.err
}

func (s *fakeServiceService) Update(_ context.Context, _ servicesvc.Actor, _ servicesvc.UpdateInput) (*model.Service, error) {
	return s.service, s.err
}

func (s *fakeServiceService) Delete(_ context.Context, _ servicesvc.Actor, _ string) error {
	return s.err
}

func (s *fakeServiceService) Approve(_ context.Context, _ servicesvc.Actor, _ string) (*model.Service, error) {
	return s.service, s.err
}

func (s *fakeServiceService) Discover(_ context.Context, _ string, _ string) ([]model.Service, error) {
	return s.services, s.err
}
