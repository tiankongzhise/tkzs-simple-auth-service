package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type ServiceService interface {
	Create(ctx context.Context, actor servicesvc.Actor, input servicesvc.CreateInput) (*model.Service, error)
	List(ctx context.Context, actor servicesvc.Actor, filter servicesvc.ListFilter) ([]model.Service, error)
	Get(ctx context.Context, actor servicesvc.Actor, id string) (*model.Service, error)
	Update(ctx context.Context, actor servicesvc.Actor, input servicesvc.UpdateInput) (*model.Service, error)
	Delete(ctx context.Context, actor servicesvc.Actor, id string) error
	Approve(ctx context.Context, actor servicesvc.Actor, id string) (*model.Service, error)
	Discover(ctx context.Context, name string, health string) ([]model.Service, error)
}

type ServiceHandler struct {
	service ServiceService
}

type serviceCreateRequest struct {
	Name                string `json:"name" binding:"required"`
	Code                string `json:"code" binding:"required"`
	BaseURL             string `json:"baseUrl" binding:"required"`
	HealthPath          string `json:"healthPath"`
	HealthCheckInterval int    `json:"healthCheckInterval"`
}

type serviceUpdateRequest struct {
	Name                string `json:"name"`
	BaseURL             string `json:"baseUrl"`
	HealthPath          string `json:"healthPath"`
	HealthCheckInterval int    `json:"healthCheckInterval"`
	Status              string `json:"status"`
	HealthStatus        string `json:"healthStatus"`
}

func NewServiceHandler(service ServiceService) *ServiceHandler {
	return &ServiceHandler{service: service}
}

func (h *ServiceHandler) RegisterRoutes(group *gin.RouterGroup) {
	services := group.Group("/services")
	services.POST("", h.Create)
	services.GET("", h.List)
	services.GET("/discover", h.Discover)
	services.GET("/:id", h.Get)
	services.PUT("/:id", h.Update)
	services.DELETE("/:id", h.Delete)
	services.POST("/:id/approve", h.Approve)
}

func (h *ServiceHandler) Create(c *gin.Context) {
	var req serviceCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Create(c.Request.Context(), serviceActorFromContext(c), servicesvc.CreateInput{
		Name:                req.Name,
		Code:                req.Code,
		BaseURL:             req.BaseURL,
		HealthPath:          req.HealthPath,
		HealthCheckInterval: req.HealthCheckInterval,
	})
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ServiceHandler) List(c *gin.Context) {
	result, err := h.service.List(c.Request.Context(), serviceActorFromContext(c), servicesvc.ListFilter{
		Name:   c.Query("name"),
		Health: c.Query("health"),
	})
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ServiceHandler) Get(c *gin.Context) {
	result, err := h.service.Get(c.Request.Context(), serviceActorFromContext(c), c.Param("id"))
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ServiceHandler) Update(c *gin.Context) {
	var req serviceUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Update(c.Request.Context(), serviceActorFromContext(c), servicesvc.UpdateInput{
		ID:                  c.Param("id"),
		Name:                req.Name,
		BaseURL:             req.BaseURL,
		HealthPath:          req.HealthPath,
		HealthCheckInterval: req.HealthCheckInterval,
		Status:              req.Status,
		HealthStatus:        req.HealthStatus,
	})
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ServiceHandler) Delete(c *gin.Context) {
	if err := h.service.Delete(c.Request.Context(), serviceActorFromContext(c), c.Param("id")); err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func (h *ServiceHandler) Approve(c *gin.Context) {
	result, err := h.service.Approve(c.Request.Context(), serviceActorFromContext(c), c.Param("id"))
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ServiceHandler) Discover(c *gin.Context) {
	result, err := h.service.Discover(c.Request.Context(), c.Query("name"), c.Query("health"))
	if err != nil {
		writeServiceError(c, err)
		return
	}
	response.OK(c, result)
}

func serviceActorFromContext(c *gin.Context) servicesvc.Actor {
	return servicesvc.Actor{
		UserID:  c.GetString(ContextUserID),
		IsAdmin: contextHasRole(c, model.RoleAdminCode),
	}
}

func writeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, servicesvc.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "服务参数无效")
	case errors.Is(err, servicesvc.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权访问服务")
	case errors.Is(err, servicesvc.ErrNotFound):
		response.Error(c, http.StatusNotFound, "服务不存在")
	case errors.Is(err, servicesvc.ErrUnavailable):
		response.Error(c, http.StatusServiceUnavailable, "服务依赖不可用")
	default:
		response.Error(c, http.StatusInternalServerError, "服务操作失败")
	}
}
