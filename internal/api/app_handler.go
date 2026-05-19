package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	appsvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/app"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type AppService interface {
	Create(ctx context.Context, actor appsvc.Actor, input appsvc.CreateInput) (*appsvc.Result, error)
	List(ctx context.Context, actor appsvc.Actor) ([]model.App, error)
	Get(ctx context.Context, actor appsvc.Actor, id string) (*model.App, error)
	Update(ctx context.Context, actor appsvc.Actor, input appsvc.UpdateInput) (*model.App, error)
	Delete(ctx context.Context, actor appsvc.Actor, id string) error
	ResetSecret(ctx context.Context, actor appsvc.Actor, id string) (*appsvc.Result, error)
}

type AppHandler struct {
	service AppService
}

type appCreateRequest struct {
	Name string `json:"name" binding:"required"`
}

type appUpdateRequest struct {
	Name   string `json:"name" binding:"required"`
	Status string `json:"status"`
}

type appResponse struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	Name        string `json:"name"`
	OwnerUserID string `json:"ownerUserId"`
	Status      string `json:"status"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	AppSecret   string `json:"appSecret,omitempty"`
}

func NewAppHandler(service AppService) *AppHandler {
	return &AppHandler{service: service}
}

func (h *AppHandler) RegisterRoutes(group *gin.RouterGroup) {
	apps := group.Group("/apps")
	apps.POST("", h.Create)
	apps.GET("", h.List)
	apps.GET("/:id", h.Get)
	apps.PUT("/:id", h.Update)
	apps.DELETE("/:id", h.Delete)
	apps.POST("/:id/reset-secret", h.ResetSecret)
}

func (h *AppHandler) Create(c *gin.Context) {
	var req appCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Create(c.Request.Context(), actorFromContext(c), appsvc.CreateInput{Name: req.Name})
	if err != nil {
		writeAppError(c, err)
		return
	}
	response.OK(c, appResultResponse(result))
}

func (h *AppHandler) List(c *gin.Context) {
	apps, err := h.service.List(c.Request.Context(), actorFromContext(c))
	if err != nil {
		writeAppError(c, err)
		return
	}
	items := make([]appResponse, 0, len(apps))
	for _, item := range apps {
		items = append(items, appModelResponse(item, ""))
	}
	response.OK(c, items)
}

func (h *AppHandler) Get(c *gin.Context) {
	app, err := h.service.Get(c.Request.Context(), actorFromContext(c), c.Param("id"))
	if err != nil {
		writeAppError(c, err)
		return
	}
	response.OK(c, appModelResponse(*app, ""))
}

func (h *AppHandler) Update(c *gin.Context) {
	var req appUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	app, err := h.service.Update(c.Request.Context(), actorFromContext(c), appsvc.UpdateInput{
		ID:     c.Param("id"),
		Name:   req.Name,
		Status: req.Status,
	})
	if err != nil {
		writeAppError(c, err)
		return
	}
	response.OK(c, appModelResponse(*app, ""))
}

func (h *AppHandler) Delete(c *gin.Context) {
	if err := h.service.Delete(c.Request.Context(), actorFromContext(c), c.Param("id")); err != nil {
		writeAppError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func (h *AppHandler) ResetSecret(c *gin.Context) {
	result, err := h.service.ResetSecret(c.Request.Context(), actorFromContext(c), c.Param("id"))
	if err != nil {
		writeAppError(c, err)
		return
	}
	response.OK(c, appResultResponse(result))
}

func actorFromContext(c *gin.Context) appsvc.Actor {
	return appsvc.Actor{
		UserID:  c.GetString(ContextUserID),
		IsAdmin: contextHasRole(c, model.RoleAdminCode),
	}
}

func contextHasRole(c *gin.Context, role string) bool {
	value, ok := c.Get(ContextRoles)
	if !ok {
		return false
	}
	roles, ok := value.([]string)
	if !ok {
		return false
	}
	for _, item := range roles {
		if item == role {
			return true
		}
	}
	return false
}

func appResultResponse(result *appsvc.Result) appResponse {
	if result == nil {
		return appResponse{}
	}
	return appModelResponse(result.App, result.AppSecret)
}

func appModelResponse(app model.App, secret string) appResponse {
	return appResponse{
		ID:          app.ID,
		AppID:       app.AppID,
		Name:        app.Name,
		OwnerUserID: app.OwnerUserID,
		Status:      app.Status,
		CreatedAt:   app.CreatedAt.Format(timeFormatRFC3339),
		UpdatedAt:   app.UpdatedAt.Format(timeFormatRFC3339),
		AppSecret:   secret,
	}
}

func writeAppError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, appsvc.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "APP 参数无效")
	case errors.Is(err, appsvc.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权访问 APP")
	case errors.Is(err, appsvc.ErrNotFound):
		response.Error(c, http.StatusNotFound, "APP 不存在")
	case errors.Is(err, appsvc.ErrUnavailable):
		response.Error(c, http.StatusServiceUnavailable, "APP 依赖不可用")
	default:
		response.Error(c, http.StatusInternalServerError, "APP 操作失败")
	}
}
