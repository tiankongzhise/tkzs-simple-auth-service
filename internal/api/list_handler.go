package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/listing"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type ListService interface {
	CreateBlacklist(ctx context.Context, actor listing.Actor, input listing.CreateInput) (*model.Blacklist, error)
	CreateWhitelist(ctx context.Context, actor listing.Actor, input listing.CreateInput) (*model.Whitelist, error)
	ListBlacklists(ctx context.Context, actor listing.Actor, serviceID string) ([]model.Blacklist, error)
	ListWhitelists(ctx context.Context, actor listing.Actor, serviceID string) ([]model.Whitelist, error)
	DeleteBlacklist(ctx context.Context, actor listing.Actor, id string) error
	DeleteWhitelist(ctx context.Context, actor listing.Actor, id string) error
}

type ListHandler struct {
	service ListService
}

type listCreateRequest struct {
	ServiceID string     `json:"serviceId" binding:"required"`
	Type      string     `json:"type" binding:"required"`
	Key       string     `json:"key" binding:"required"`
	Reason    string     `json:"reason"`
	Permanent bool       `json:"permanent"`
	ExpiresAt *time.Time `json:"expiresAt"`
}

func NewListHandler(service ListService) *ListHandler {
	return &ListHandler{service: service}
}

func (h *ListHandler) RegisterRoutes(group *gin.RouterGroup) {
	blacklists := group.Group("/blacklists")
	blacklists.POST("", h.CreateBlacklist)
	blacklists.GET("", h.ListBlacklists)
	blacklists.DELETE("/:id", h.DeleteBlacklist)

	whitelists := group.Group("/whitelists")
	whitelists.POST("", h.CreateWhitelist)
	whitelists.GET("", h.ListWhitelists)
	whitelists.DELETE("/:id", h.DeleteWhitelist)
}

func (h *ListHandler) CreateBlacklist(c *gin.Context) {
	var req listCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.CreateBlacklist(c.Request.Context(), listActorFromContext(c), listing.CreateInput{
		ServiceID: req.ServiceID,
		Type:      req.Type,
		Key:       req.Key,
		Reason:    req.Reason,
		Permanent: req.Permanent,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		writeListError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ListHandler) ListBlacklists(c *gin.Context) {
	result, err := h.service.ListBlacklists(c.Request.Context(), listActorFromContext(c), c.Query("serviceId"))
	if err != nil {
		writeListError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ListHandler) DeleteBlacklist(c *gin.Context) {
	if err := h.service.DeleteBlacklist(c.Request.Context(), listActorFromContext(c), c.Param("id")); err != nil {
		writeListError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func (h *ListHandler) CreateWhitelist(c *gin.Context) {
	var req listCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.CreateWhitelist(c.Request.Context(), listActorFromContext(c), listing.CreateInput{
		ServiceID: req.ServiceID,
		Type:      req.Type,
		Key:       req.Key,
		Reason:    req.Reason,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		writeListError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ListHandler) ListWhitelists(c *gin.Context) {
	result, err := h.service.ListWhitelists(c.Request.Context(), listActorFromContext(c), c.Query("serviceId"))
	if err != nil {
		writeListError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *ListHandler) DeleteWhitelist(c *gin.Context) {
	if err := h.service.DeleteWhitelist(c.Request.Context(), listActorFromContext(c), c.Param("id")); err != nil {
		writeListError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func listActorFromContext(c *gin.Context) listing.Actor {
	return listing.Actor{
		UserID:  c.GetString(ContextUserID),
		IsAdmin: contextHasRole(c, model.RoleAdminCode),
	}
}

func writeListError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, listing.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "名单参数无效")
	case errors.Is(err, listing.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权操作名单")
	case errors.Is(err, listing.ErrNotFound):
		response.Error(c, http.StatusNotFound, "名单不存在")
	case errors.Is(err, listing.ErrUnavailable):
		response.Error(c, http.StatusServiceUnavailable, "名单依赖不可用")
	default:
		response.Error(c, http.StatusInternalServerError, "名单操作失败")
	}
}
