package api

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/audit"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type HealthCheckQueryService interface {
	ListHealthChecks(ctx context.Context, actor audit.Actor, filter audit.LogFilter) ([]model.HealthCheckLog, error)
}

type HealthCheckHandler struct {
	service HealthCheckQueryService
}

func NewHealthCheckHandler(service HealthCheckQueryService) *HealthCheckHandler {
	return &HealthCheckHandler{service: service}
}

func (h *HealthCheckHandler) RegisterRoutes(group *gin.RouterGroup) {
	group.GET("/health-checks", h.List)
}

func (h *HealthCheckHandler) List(c *gin.Context) {
	filter, err := auditFilterFromQuery(c)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "健康检测参数无效")
		return
	}
	filter.Type = audit.TypeHealth
	result, err := h.service.ListHealthChecks(c.Request.Context(), auditActorFromContext(c), filter)
	if err != nil {
		writeAuditError(c, err)
		return
	}
	response.OK(c, result)
}
