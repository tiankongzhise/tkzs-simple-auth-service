package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/limiter"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type LimitService interface {
	Verify(ctx context.Context, input limiter.VerifyInput) (*limiter.VerifyResult, error)
}

type LimitHandler struct {
	service LimitService
}

type limitVerifyRequest struct {
	ServiceID string `json:"serviceId" binding:"required"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	IP        string `json:"ip"`
	UserID    string `json:"userId"`
	AppID     string `json:"appId"`
}

func NewLimitHandler(service LimitService) *LimitHandler {
	return &LimitHandler{service: service}
}

func (h *LimitHandler) RegisterRoutes(router *gin.Engine) {
	router.POST("/oidc/limit/verify", h.Verify)
}

func (h *LimitHandler) Verify(c *gin.Context) {
	var req limitVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Verify(c.Request.Context(), limiter.VerifyInput{
		ServiceID: req.ServiceID,
		Path:      req.Path,
		Method:    req.Method,
		IP:        req.IP,
		UserID:    req.UserID,
		AppID:     req.AppID,
	})
	if err != nil {
		writeLimitError(c, err)
		return
	}
	writeRateLimitHeaders(c, result)
	if !result.Allowed {
		response.Error(c, http.StatusTooManyRequests, "请求过于频繁")
		return
	}
	c.JSON(http.StatusOK, result)
}

func writeLimitError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, limiter.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "限流参数无效")
	default:
		response.Error(c, http.StatusInternalServerError, "限流校验失败")
	}
}

func writeRateLimitHeaders(c *gin.Context, result *limiter.VerifyResult) {
	if result == nil {
		return
	}
	c.Header("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(result.ResetAt, 10))
	if !result.Allowed {
		retryAfter := result.ResetAt - timeNowUnix()
		if retryAfter < 0 {
			retryAfter = 0
		}
		c.Header("Retry-After", strconv.FormatInt(retryAfter, 10))
	}
}

func timeNowUnix() int64 {
	return time.Now().Unix()
}
