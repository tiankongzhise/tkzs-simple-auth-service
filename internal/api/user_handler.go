package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	usersvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/user"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type UserService interface {
	Register(ctx context.Context, input usersvc.RegisterInput) (*model.User, error)
	List(ctx context.Context, actor usersvc.Actor) ([]model.User, error)
	Get(ctx context.Context, actor usersvc.Actor, id string) (*model.User, error)
	Update(ctx context.Context, actor usersvc.Actor, input usersvc.UpdateInput) (*model.User, error)
	UpdateStatus(ctx context.Context, actor usersvc.Actor, input usersvc.UpdateStatusInput) (*model.User, error)
	UpdatePassword(ctx context.Context, actor usersvc.Actor, input usersvc.UpdatePasswordInput) error
	Unlock(ctx context.Context, actor usersvc.Actor, input usersvc.UnlockInput) error
	Delete(ctx context.Context, actor usersvc.Actor, id string) error
}

type UserPublicHandler struct {
	service UserService
}

type UserHandler struct {
	service UserService
}

type userRegisterRequest struct {
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	DisplayName string `json:"displayName"`
}

type userUpdateRequest struct {
	DisplayName string `json:"displayName"`
}

type userStatusRequest struct {
	Status string `json:"status" binding:"required"`
}

type userPasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword" binding:"required"`
}

type userResponse struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	DisplayName  string   `json:"displayName"`
	Status       string   `json:"status"`
	IsSuperAdmin bool     `json:"isSuperAdmin"`
	Roles        []string `json:"roles,omitempty"`
	CreatedAt    string   `json:"createdAt"`
	UpdatedAt    string   `json:"updatedAt"`
}

func NewUserPublicHandler(service UserService) *UserPublicHandler {
	return &UserPublicHandler{service: service}
}

func NewUserHandler(service UserService) *UserHandler {
	return &UserHandler{service: service}
}

func (h *UserPublicHandler) RegisterRoutes(group *gin.RouterGroup) {
	group.POST("/users/register", h.Register)
}

func (h *UserHandler) RegisterRoutes(group *gin.RouterGroup) {
	users := group.Group("/users")
	users.GET("", h.List)
	users.GET("/:id", h.Get)
	users.PUT("/:id", h.Update)
	users.DELETE("/:id", h.Delete)
	users.PUT("/:id/status", h.UpdateStatus)
	users.PUT("/:id/password", h.UpdatePassword)
	users.POST("/:id/unlock", h.Unlock)
}

func (h *UserPublicHandler) Register(c *gin.Context) {
	var req userRegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Register(c.Request.Context(), usersvc.RegisterInput{
		Username:    req.Username,
		Password:    req.Password,
		DisplayName: req.DisplayName,
	})
	if err != nil {
		writeUserError(c, err)
		return
	}
	response.OK(c, userModelResponse(*result))
}

func (h *UserHandler) List(c *gin.Context) {
	users, err := h.service.List(c.Request.Context(), userActorFromContext(c))
	if err != nil {
		writeUserError(c, err)
		return
	}
	items := make([]userResponse, 0, len(users))
	for _, item := range users {
		items = append(items, userModelResponse(item))
	}
	response.OK(c, items)
}

func (h *UserHandler) Get(c *gin.Context) {
	result, err := h.service.Get(c.Request.Context(), userActorFromContext(c), c.Param("id"))
	if err != nil {
		writeUserError(c, err)
		return
	}
	response.OK(c, userModelResponse(*result))
}

func (h *UserHandler) Update(c *gin.Context) {
	var req userUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Update(c.Request.Context(), userActorFromContext(c), usersvc.UpdateInput{
		ID:          c.Param("id"),
		DisplayName: req.DisplayName,
	})
	if err != nil {
		writeUserError(c, err)
		return
	}
	response.OK(c, userModelResponse(*result))
}

func (h *UserHandler) UpdateStatus(c *gin.Context) {
	var req userStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.UpdateStatus(c.Request.Context(), userActorFromContext(c), usersvc.UpdateStatusInput{
		ID:     c.Param("id"),
		Status: req.Status,
	})
	if err != nil {
		writeUserError(c, err)
		return
	}
	response.OK(c, userModelResponse(*result))
}

func (h *UserHandler) UpdatePassword(c *gin.Context) {
	var req userPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	if err := h.service.UpdatePassword(c.Request.Context(), userActorFromContext(c), usersvc.UpdatePasswordInput{
		ID:          c.Param("id"),
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	}); err != nil {
		writeUserError(c, err)
		return
	}
	response.OK(c, gin.H{"updated": true})
}

func (h *UserHandler) Unlock(c *gin.Context) {
	if err := h.service.Unlock(c.Request.Context(), userActorFromContext(c), usersvc.UnlockInput{
		ID: c.Param("id"),
	}); err != nil {
		writeUserError(c, err)
		return
	}
	response.OK(c, gin.H{"unlocked": true})
}

func (h *UserHandler) Delete(c *gin.Context) {
	if err := h.service.Delete(c.Request.Context(), userActorFromContext(c), c.Param("id")); err != nil {
		writeUserError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func userActorFromContext(c *gin.Context) usersvc.Actor {
	return usersvc.Actor{
		UserID:    c.GetString(ContextUserID),
		CanManage: contextHasRole(c, model.RoleAdminCode) || contextHasPermission(c, "user:manage"),
	}
}

func userModelResponse(user model.User) userResponse {
	roles := make([]string, 0, len(user.Roles))
	for _, role := range user.Roles {
		roles = append(roles, role.Code)
	}
	return userResponse{
		ID:           user.ID,
		Username:     user.Username,
		DisplayName:  user.DisplayName,
		Status:       user.Status,
		IsSuperAdmin: user.IsSuperAdmin,
		Roles:        roles,
		CreatedAt:    user.CreatedAt.Format(timeFormatRFC3339),
		UpdatedAt:    user.UpdatedAt.Format(timeFormatRFC3339),
	}
}

func writeUserError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, usersvc.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "用户参数无效")
	case errors.Is(err, usersvc.ErrConflict):
		response.Error(c, http.StatusConflict, "用户名已存在")
	case errors.Is(err, usersvc.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权访问用户")
	case errors.Is(err, usersvc.ErrNotFound):
		response.Error(c, http.StatusNotFound, "用户不存在")
	default:
		response.Error(c, http.StatusInternalServerError, "用户操作失败")
	}
}
