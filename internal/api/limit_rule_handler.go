package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/limitrule"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	servicesvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/service"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type LimitRuleService interface {
	Create(ctx context.Context, actor limitrule.Actor, input limitrule.CreateInput) (*model.RateLimitRule, error)
	List(ctx context.Context, actor limitrule.Actor, filter limitrule.ListFilter) ([]model.RateLimitRule, error)
	Get(ctx context.Context, actor limitrule.Actor, id string) (*model.RateLimitRule, error)
	Update(ctx context.Context, actor limitrule.Actor, input limitrule.UpdateInput) (*model.RateLimitRule, error)
	Delete(ctx context.Context, actor limitrule.Actor, id string) error
}

type LimitRuleHandler struct {
	service LimitRuleService
}

type limitRuleCreateRequest struct {
	ServiceID     string `json:"serviceId" binding:"required"`
	Dimension     string `json:"dimension" binding:"required"`
	Granularity   string `json:"granularity" binding:"required"`
	Capacity      int    `json:"capacity" binding:"required"`
	RatePerSecond int    `json:"ratePerSecond" binding:"required"`
	BlacklistHits int    `json:"blacklistHits"`
	BlockSeconds  int    `json:"blockSeconds"`
	Enabled       *bool  `json:"enabled"`
}

type limitRuleUpdateRequest struct {
	Dimension     string `json:"dimension" binding:"required"`
	Granularity   string `json:"granularity" binding:"required"`
	Capacity      int    `json:"capacity" binding:"required"`
	RatePerSecond int    `json:"ratePerSecond" binding:"required"`
	BlacklistHits int    `json:"blacklistHits"`
	BlockSeconds  int    `json:"blockSeconds"`
	Enabled       *bool  `json:"enabled"`
}

func NewLimitRuleHandler(service LimitRuleService) *LimitRuleHandler {
	return &LimitRuleHandler{service: service}
}

func (h *LimitRuleHandler) RegisterRoutes(group *gin.RouterGroup) {
	rules := group.Group("/limit-rules")
	rules.POST("", h.Create)
	rules.GET("", h.List)
	rules.GET("/:id", h.Get)
	rules.PUT("/:id", h.Update)
	rules.DELETE("/:id", h.Delete)
}

func (h *LimitRuleHandler) Create(c *gin.Context) {
	var req limitRuleCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Create(c.Request.Context(), limitRuleActorFromContext(c), limitrule.CreateInput{
		ServiceID:     req.ServiceID,
		Dimension:     req.Dimension,
		Granularity:   req.Granularity,
		Capacity:      req.Capacity,
		RatePerSecond: req.RatePerSecond,
		BlacklistHits: req.BlacklistHits,
		BlockSeconds:  req.BlockSeconds,
		Enabled:       boolFromPointer(req.Enabled, true),
	})
	if err != nil {
		writeLimitRuleError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *LimitRuleHandler) List(c *gin.Context) {
	var enabled *bool
	if c.Query("enabled") != "" {
		parsed := c.Query("enabled") == "true"
		enabled = &parsed
	}
	result, err := h.service.List(c.Request.Context(), limitRuleActorFromContext(c), limitrule.ListFilter{
		ServiceID: c.Query("serviceId"),
		Dimension: c.Query("dimension"),
		Enabled:   enabled,
	})
	if err != nil {
		writeLimitRuleError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *LimitRuleHandler) Get(c *gin.Context) {
	result, err := h.service.Get(c.Request.Context(), limitRuleActorFromContext(c), c.Param("id"))
	if err != nil {
		writeLimitRuleError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *LimitRuleHandler) Update(c *gin.Context) {
	var req limitRuleUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Update(c.Request.Context(), limitRuleActorFromContext(c), limitrule.UpdateInput{
		ID:            c.Param("id"),
		Dimension:     req.Dimension,
		Granularity:   req.Granularity,
		Capacity:      req.Capacity,
		RatePerSecond: req.RatePerSecond,
		BlacklistHits: req.BlacklistHits,
		BlockSeconds:  req.BlockSeconds,
		Enabled:       boolFromPointer(req.Enabled, true),
	})
	if err != nil {
		writeLimitRuleError(c, err)
		return
	}
	response.OK(c, result)
}

func (h *LimitRuleHandler) Delete(c *gin.Context) {
	if err := h.service.Delete(c.Request.Context(), limitRuleActorFromContext(c), c.Param("id")); err != nil {
		writeLimitRuleError(c, err)
		return
	}
	response.OK(c, gin.H{"deleted": true})
}

func limitRuleActorFromContext(c *gin.Context) limitrule.Actor {
	return limitrule.Actor{
		UserID:  c.GetString(ContextUserID),
		IsAdmin: contextHasRole(c, model.RoleAdminCode),
	}
}

func boolFromPointer(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func writeLimitRuleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, limitrule.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "限流规则参数无效")
	case errors.Is(err, limitrule.ErrConflict):
		response.Error(c, http.StatusConflict, "启用的限流规则已存在")
	case errors.Is(err, limitrule.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权操作限流规则")
	case errors.Is(err, limitrule.ErrNotFound), errors.Is(err, servicesvc.ErrNotFound):
		response.Error(c, http.StatusNotFound, "限流规则或服务不存在")
	default:
		response.Error(c, http.StatusInternalServerError, "限流规则操作失败")
	}
}
