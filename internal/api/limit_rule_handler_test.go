package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/limitrule"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

func TestLimitRuleHandlerCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewLimitRuleHandler(&fakeLimitRuleService{
		rule: &model.RateLimitRule{BaseModel: model.BaseModel{ID: "rule-001"}, ServiceID: "svc-001"},
	})
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "user-001")
		c.Next()
	})
	handler.RegisterRoutes(group)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/limit-rules", strings.NewReader(`{"serviceId":"svc-001","dimension":"ip","granularity":"minute","capacity":60,"ratePerSecond":1}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestLimitRuleHandlerConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := NewLimitRuleHandler(&fakeLimitRuleService{err: limitrule.ErrConflict})
	router := gin.New()
	group := router.Group("/api")
	group.Use(func(c *gin.Context) {
		c.Set(ContextUserID, "user-001")
		c.Next()
	})
	handler.RegisterRoutes(group)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/limit-rules", strings.NewReader(`{"serviceId":"svc-001","dimension":"ip","granularity":"minute","capacity":60,"ratePerSecond":1}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

type fakeLimitRuleService struct {
	rule  *model.RateLimitRule
	rules []model.RateLimitRule
	err   error
}

func (s *fakeLimitRuleService) Create(_ context.Context, _ limitrule.Actor, _ limitrule.CreateInput) (*model.RateLimitRule, error) {
	return s.rule, s.err
}

func (s *fakeLimitRuleService) List(_ context.Context, _ limitrule.Actor, _ limitrule.ListFilter) ([]model.RateLimitRule, error) {
	return s.rules, s.err
}

func (s *fakeLimitRuleService) Get(_ context.Context, _ limitrule.Actor, _ string) (*model.RateLimitRule, error) {
	return s.rule, s.err
}

func (s *fakeLimitRuleService) Update(_ context.Context, _ limitrule.Actor, _ limitrule.UpdateInput) (*model.RateLimitRule, error) {
	return s.rule, s.err
}

func (s *fakeLimitRuleService) Delete(_ context.Context, _ limitrule.Actor, _ string) error {
	return s.err
}
