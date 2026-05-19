package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/statistics"
)

func TestStatisticsHandlerListLimitStatistics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewStatisticsHandler(&fakeStatisticsService{items: []model.LimitStatistic{{
		ServiceID:    "svc-001",
		Dimension:    "ip",
		BucketTime:   time.Date(2026, 5, 19, 9, 0, 0, 0, time.UTC),
		TotalCount:   10,
		BlockedCount: 2,
	}}})
	router := gin.New()
	handler.RegisterRoutes(router.Group("/api"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/limit-statistics?serviceId=svc-001&dimension=ip", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "svc-001") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

type fakeStatisticsService struct {
	items []model.LimitStatistic
	err   error
}

func (s *fakeStatisticsService) ListLimitStatistics(_ context.Context, _ statistics.LimitStatisticFilter) ([]model.LimitStatistic, error) {
	return s.items, s.err
}
