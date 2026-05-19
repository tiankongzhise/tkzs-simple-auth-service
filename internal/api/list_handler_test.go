package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/listing"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

func TestListHandlerCreateBlacklist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewListHandler(&fakeListService{blacklist: &model.Blacklist{ServiceID: "svc-001", Type: "ip", Key: "127.0.0.1"}})
	router := testListRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/blacklists", strings.NewReader(`{"serviceId":"svc-001","type":"ip","key":"127.0.0.1","permanent":true}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestListHandlerForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewListHandler(&fakeListService{err: listing.ErrForbidden})
	router := testListRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/blacklists/bl-001", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func testListRouter(handler *ListHandler) *gin.Engine {
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "admin")
		c.Set(ContextRoles, []string{"admin"})
		c.Next()
	})
	handler.RegisterRoutes(group)
	return router
}

type fakeListService struct {
	blacklist  *model.Blacklist
	whitelist  *model.Whitelist
	blacklists []model.Blacklist
	whitelists []model.Whitelist
	err        error
}

func (s *fakeListService) CreateBlacklist(_ context.Context, _ listing.Actor, _ listing.CreateInput) (*model.Blacklist, error) {
	return s.blacklist, s.err
}

func (s *fakeListService) CreateWhitelist(_ context.Context, _ listing.Actor, _ listing.CreateInput) (*model.Whitelist, error) {
	return s.whitelist, s.err
}

func (s *fakeListService) ListBlacklists(_ context.Context, _ listing.Actor, _ string) ([]model.Blacklist, error) {
	return s.blacklists, s.err
}

func (s *fakeListService) ListWhitelists(_ context.Context, _ listing.Actor, _ string) ([]model.Whitelist, error) {
	return s.whitelists, s.err
}

func (s *fakeListService) DeleteBlacklist(_ context.Context, _ listing.Actor, _ string) error {
	return s.err
}

func (s *fakeListService) DeleteWhitelist(_ context.Context, _ listing.Actor, _ string) error {
	return s.err
}
