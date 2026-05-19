package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/statistics"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type StatisticsService interface {
	ListLimitStatistics(ctx context.Context, filter statistics.LimitStatisticFilter) ([]model.LimitStatistic, error)
}

type StatisticsHandler struct {
	service StatisticsService
}

func NewStatisticsHandler(service StatisticsService) *StatisticsHandler {
	return &StatisticsHandler{service: service}
}

func (h *StatisticsHandler) RegisterRoutes(group *gin.RouterGroup) {
	group.GET("/limit-statistics", h.ListLimitStatistics)
}

func (h *StatisticsHandler) ListLimitStatistics(c *gin.Context) {
	filter, err := statisticsFilterFromQuery(c)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "统计参数无效")
		return
	}
	result, err := h.service.ListLimitStatistics(c.Request.Context(), filter)
	if err != nil {
		writeStatisticsError(c, err)
		return
	}
	response.OK(c, result)
}

func statisticsFilterFromQuery(c *gin.Context) (statistics.LimitStatisticFilter, error) {
	page, err := optionalInt(c.Query("page"))
	if err != nil {
		return statistics.LimitStatisticFilter{}, err
	}
	pageSize, err := optionalInt(c.Query("pageSize"))
	if err != nil {
		return statistics.LimitStatisticFilter{}, err
	}
	startAt, err := optionalTime(c.Query("startAt"))
	if err != nil {
		return statistics.LimitStatisticFilter{}, err
	}
	endAt, err := optionalTime(c.Query("endAt"))
	if err != nil {
		return statistics.LimitStatisticFilter{}, err
	}
	return statistics.LimitStatisticFilter{
		ServiceID: c.Query("serviceId"),
		Dimension: c.Query("dimension"),
		StartAt:   startAt,
		EndAt:     endAt,
		Page:      page,
		PageSize:  pageSize,
	}, nil
}

func writeStatisticsError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, statistics.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "统计参数无效")
	default:
		response.Error(c, http.StatusInternalServerError, "统计查询失败")
	}
}
