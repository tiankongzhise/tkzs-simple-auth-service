package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	rolesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/role"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type RoleService interface {
	ListPermissions(ctx context.Context) ([]model.Permission, error)
	Create(ctx context.Context, actor rolesvc.Actor, input rolesvc.CreateInput) (*model.Role, error)
	List(ctx context.Context, actor rolesvc.Actor) ([]model.Role, error)
	Get(ctx context.Context, actor rolesvc.Actor, id string) (*model.Role, error)
	Update(ctx context.Context, actor rolesvc.Actor, input rolesvc.UpdateInput) (*model.Role, error)
	Delete(ctx context.Context, actor rolesvc.Actor, id string) error
}

type PermissionHandler struct {
	service RoleService
}

type RoleHandler struct {
	service RoleService
}

type roleCreateRequest struct {
	Code          string   `json:"code" binding:"required"`
	Name          string   `json:"name" binding:"required"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permissionIds"`
}

type roleUpdateRequest struct {
	Name          string   `json:"name" binding:"required"`
	Description   string   `json:"description"`
	PermissionIDs []string `json:"permissionIds"`
}

type roleResponse struct {
	ID            string               `json:"id"`
	Code          string               `json:"code"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	OwnerUserID   *string              `json:"ownerUserId,omitempty"`
	System        bool                 `json:"system"`
	Permissions   []permissionResponse `json:"permissions,omitempty"`
	PermissionIDs []string             `json:"permissionIds,omitempty"`
	CreatedAt     string               `json:"createdAt"`
	UpdatedAt     string               `json:"updatedAt"`
}

type permissionResponse struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Name   string `json:"name"`
	Module string `json:"module"`
	Action string `json:"action"`
}

func NewPermissionHandler(service RoleService) *PermissionHandler {
	return &PermissionHandler{service: service}
}

func NewRoleHandler(service RoleService) *RoleHandler {
	return &RoleHandler{service: service}
}

func (h *PermissionHandler) RegisterRoutes(group *gin.RouterGroup) {
	group.GET("/permissions", h.List)
}

func (h *RoleHandler) RegisterRoutes(group *gin.RouterGroup) {
	roles := group.Group("/roles")
	roles.POST("", h.Create)
	roles.GET("", h.List)
	roles.GET("/:id", h.Get)
	roles.PUT("/:id", h.Update)
	roles.DELETE("/:id", h.Delete)
}

func (h *PermissionHandler) List(c *gin.Context) {
	permissions, err := h.service.ListPermissions(c.Request.Context())
	if err != nil {
		writeRoleError(c, err)
		return
	}
	items := make([]permissionResponse, 0, len(permissions))
	for _, item := range permissions {
		items = append(items, permissionModelResponse(item))
	}
	response.OK(c, items)
}

func (h *RoleHandler) Create(c *gin.Context) {
	var req roleCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Create(c.Request.Context(), roleActorFromContext(c), rolesvc.CreateInput{
		Code:          req.Code,
		Name:          req.Name,
		Description:   req.Description,
		PermissionIDs: req.PermissionIDs,
	})
	if err != nil {
		writeRoleError(c, err)
		return
	}
	response.OK(c, roleModelResponse(*result))
}

func (h *RoleHandler) List(c *gin.Context) {
	roles, err := h.service.List(c.Request.Context(), roleActorFromContext(c))
	if err != nil {
		writeRoleError(c, err)
		return
	}
	items := make([]roleResponse, 0, len(roles))
	for _, item := range roles {
		items = append(items, roleModelResponse(item))
	}
	response.OK(c, items)
}

func (h *RoleHandler) Get(c *gin.Context) {
	result, err := h.service.Get(c.Request.Context(), roleActorFromContext(c), c.Param("id"))
	if err != nil {
		writeRoleError(c, err)
		return
	}
	response.OK(c, roleModelResponse(*result))
}

func (h *RoleHandler) Update(c *gin.Context) {
	var req roleUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Update(c.Request.Context(), roleActorFromContext(c), rolesvc.UpdateInput{
		ID:            c.Param("id"),
		Name:          req.Name,
		Description:   req.Description,
		PermissionIDs: req.PermissionIDs,
	})
	if err != nil {
		writeRoleError(c, err)
		return
	}
	response.OK(c, roleModelResponse(*result))
}

func (h *RoleHandler) Delete(c *gin.Context) {
	if err := h.service.Delete(c.Request.Context(), roleActorFromContext(c), c.Param("id")); err != nil {
		writeRoleError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func roleActorFromContext(c *gin.Context) rolesvc.Actor {
	permissions := []string{}
	if value, ok := c.Get(ContextPermissions); ok {
		if parsed, ok := value.([]string); ok {
			permissions = parsed
		}
	}
	return rolesvc.Actor{
		UserID:      c.GetString(ContextUserID),
		IsAdmin:     contextHasRole(c, model.RoleAdminCode),
		Permissions: permissions,
	}
}

func roleModelResponse(role model.Role) roleResponse {
	permissions := make([]permissionResponse, 0, len(role.Permissions))
	permissionIDs := make([]string, 0, len(role.Permissions))
	for _, permission := range role.Permissions {
		permissions = append(permissions, permissionModelResponse(permission))
		permissionIDs = append(permissionIDs, permission.ID)
	}
	return roleResponse{
		ID:            role.ID,
		Code:          role.Code,
		Name:          role.Name,
		Description:   role.Description,
		OwnerUserID:   role.OwnerUserID,
		System:        role.System,
		Permissions:   permissions,
		PermissionIDs: permissionIDs,
		CreatedAt:     role.CreatedAt.Format(timeFormatRFC3339),
		UpdatedAt:     role.UpdatedAt.Format(timeFormatRFC3339),
	}
}

func permissionModelResponse(permission model.Permission) permissionResponse {
	return permissionResponse{
		ID:     permission.ID,
		Code:   permission.Code,
		Name:   permission.Name,
		Module: permission.Module,
		Action: permission.Action,
	}
}

func writeRoleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, rolesvc.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "角色参数无效")
	case errors.Is(err, rolesvc.ErrConflict):
		response.Error(c, http.StatusConflict, "角色标识已存在")
	case errors.Is(err, rolesvc.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权访问角色")
	case errors.Is(err, rolesvc.ErrNotFound):
		response.Error(c, http.StatusNotFound, "角色不存在")
	default:
		response.Error(c, http.StatusInternalServerError, "角色操作失败")
	}
}
