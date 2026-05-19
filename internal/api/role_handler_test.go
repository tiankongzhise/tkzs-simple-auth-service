package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	rolesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/role"
)

func TestPermissionHandlerList(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewPermissionHandler(&fakeRoleService{permissions: []model.Permission{{
		BaseModel: model.BaseModel{ID: "perm-001"},
		Code:      "user:manage",
		Name:      "用户管理",
		Module:    "user",
		Action:    "manage",
	}}})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/permissions", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "user:manage") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestRoleHandlerCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewRoleHandler(&fakeRoleService{role: &model.Role{
		BaseModel: model.BaseModel{ID: "role-001"},
		Code:      "ops",
		Name:      "Ops",
	}})
	router := testRoleRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/roles", strings.NewReader(`{"code":"ops","name":"Ops"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRoleHandlerForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewRoleHandler(&fakeRoleService{err: rolesvc.ErrForbidden})
	router := testRoleRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/roles/role-admin", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRoleAssignmentHandlerAssignUserRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewRoleAssignmentHandler(&fakeRoleService{user: &model.User{
		BaseModel: model.BaseModel{ID: "user-002"},
		Username:  "user_002",
		Roles:     []model.Role{{Code: "ops"}},
	}})
	router := testRoleAssignmentRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/users/user-002/roles", strings.NewReader(`{"roleIds":["role-001"]}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ops") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestRoleAssignmentHandlerAssignAppRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewRoleAssignmentHandler(&fakeRoleService{app: &model.App{
		BaseModel:   model.BaseModel{ID: "app-001"},
		AppID:       "app00001",
		Name:        "demo app",
		OwnerUserID: "user-001",
		Status:      model.StatusEnabled,
		Roles:       []model.Role{{Code: "ops"}},
	}})
	router := testRoleAssignmentRouter(handler)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/apps/app-001/roles", strings.NewReader(`{"roleIds":["role-001"]}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func testRoleRouter(handler *RoleHandler) *gin.Engine {
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "user-001")
		c.Set(ContextRoles, []string{"admin"})
		c.Set(ContextPermissions, []string{"role:manage"})
		c.Next()
	})
	handler.RegisterRoutes(group)
	return router
}

func testRoleAssignmentRouter(handler *RoleAssignmentHandler) *gin.Engine {
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "user-001")
		c.Set(ContextRoles, []string{"admin"})
		c.Set(ContextPermissions, []string{"role:manage"})
		c.Next()
	})
	handler.RegisterRoutes(group)
	return router
}

type fakeRoleService struct {
	role        *model.Role
	roles       []model.Role
	permissions []model.Permission
	user        *model.User
	app         *model.App
	err         error
}

func (s *fakeRoleService) ListPermissions(_ context.Context) ([]model.Permission, error) {
	return s.permissions, s.err
}

func (s *fakeRoleService) Create(_ context.Context, _ rolesvc.Actor, _ rolesvc.CreateInput) (*model.Role, error) {
	return s.role, s.err
}

func (s *fakeRoleService) List(_ context.Context, _ rolesvc.Actor) ([]model.Role, error) {
	return s.roles, s.err
}

func (s *fakeRoleService) Get(_ context.Context, _ rolesvc.Actor, _ string) (*model.Role, error) {
	return s.role, s.err
}

func (s *fakeRoleService) Update(_ context.Context, _ rolesvc.Actor, _ rolesvc.UpdateInput) (*model.Role, error) {
	return s.role, s.err
}

func (s *fakeRoleService) Delete(_ context.Context, _ rolesvc.Actor, _ string) error {
	return s.err
}

func (s *fakeRoleService) AssignUserRoles(_ context.Context, _ rolesvc.Actor, _ rolesvc.AssignRolesInput) (*model.User, error) {
	return s.user, s.err
}

func (s *fakeRoleService) AssignAppRoles(_ context.Context, _ rolesvc.Actor, _ rolesvc.AssignRolesInput) (*model.App, error) {
	return s.app, s.err
}
