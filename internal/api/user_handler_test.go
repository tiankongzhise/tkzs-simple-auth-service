package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	usersvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/user"
)

func TestUserPublicHandlerRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewUserPublicHandler(&fakeUserService{user: &model.User{
		BaseModel:   model.BaseModel{ID: "user-001"},
		Username:    "user_001",
		DisplayName: "User One",
		Status:      model.StatusEnabled,
	}})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/users/register", strings.NewReader(`{"username":"user_001","password":"Pass_123","displayName":"User One"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "password") {
		t.Fatalf("response leaked password: %s", rec.Body.String())
	}
}

func TestUserHandlerList(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewUserHandler(&fakeUserService{users: []model.User{{
		BaseModel: model.BaseModel{ID: "user-001"},
		Username:  "user_001",
		Status:    model.StatusEnabled,
	}}})
	router := testUserRouter(handler, []string{}, []string{"user:manage"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestUserHandlerForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewUserHandler(&fakeUserService{err: usersvc.ErrForbidden})
	router := testUserRouter(handler, nil, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/users/user-002", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func testUserRouter(handler *UserHandler, roles []string, permissions []string) *gin.Engine {
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "user-001")
		c.Set(ContextRoles, roles)
		c.Set(ContextPermissions, permissions)
		c.Next()
	})
	handler.RegisterRoutes(group)
	return router
}

type fakeUserService struct {
	user  *model.User
	users []model.User
	err   error
}

func (s *fakeUserService) Register(_ context.Context, _ usersvc.RegisterInput) (*model.User, error) {
	return s.user, s.err
}

func (s *fakeUserService) List(_ context.Context, _ usersvc.Actor) ([]model.User, error) {
	return s.users, s.err
}

func (s *fakeUserService) Get(_ context.Context, _ usersvc.Actor, _ string) (*model.User, error) {
	return s.user, s.err
}
