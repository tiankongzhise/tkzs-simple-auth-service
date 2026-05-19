package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/audit"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type AuditService interface {
	ListLogs(ctx context.Context, actor audit.Actor, filter audit.LogFilter) (*audit.LogResult, error)
}

type LogHandler struct {
	service AuditService
}

func NewLogHandler(service AuditService) *LogHandler {
	return &LogHandler{service: service}
}

func (h *LogHandler) RegisterRoutes(group *gin.RouterGroup) {
	group.GET("/logs", h.List)
}

func (h *LogHandler) List(c *gin.Context) {
	filter, err := auditFilterFromQuery(c)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "日志参数无效")
		return
	}
	result, err := h.service.ListLogs(c.Request.Context(), auditActorFromContext(c), filter)
	if err != nil {
		writeAuditError(c, err)
		return
	}
	response.OK(c, result)
}

func auditActorFromContext(c *gin.Context) audit.Actor {
	return audit.Actor{
		UserID:  c.GetString(ContextUserID),
		IsAdmin: contextHasRole(c, model.RoleAdminCode),
	}
}

func auditFilterFromQuery(c *gin.Context) (audit.LogFilter, error) {
	page, err := optionalInt(c.Query("page"))
	if err != nil {
		return audit.LogFilter{}, err
	}
	pageSize, err := optionalInt(c.Query("pageSize"))
	if err != nil {
		return audit.LogFilter{}, err
	}
	startAt, err := optionalTime(c.Query("startAt"))
	if err != nil {
		return audit.LogFilter{}, err
	}
	endAt, err := optionalTime(c.Query("endAt"))
	if err != nil {
		return audit.LogFilter{}, err
	}
	return audit.LogFilter{
		Type:      c.Query("type"),
		ServiceID: c.Query("serviceId"),
		Result:    c.Query("result"),
		StartAt:   startAt,
		EndAt:     endAt,
		Page:      page,
		PageSize:  pageSize,
	}, nil
}

func optionalInt(raw string) (int, error) {
	if raw == "" {
		return 0, nil
	}
	return strconv.Atoi(raw)
}

func optionalTime(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	parsed, err := time.Parse(timeFormatRFC3339, raw)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func writeAuditError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, audit.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "日志参数无效")
	case errors.Is(err, audit.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权访问日志")
	default:
		response.Error(c, http.StatusInternalServerError, "日志查询失败")
	}
}
