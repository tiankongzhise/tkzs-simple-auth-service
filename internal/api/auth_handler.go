package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/auth"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type AuthService interface {
	Login(ctx context.Context, input auth.LoginInput) (*auth.LoginResult, error)
}

type AuthHandler struct {
	service AuthService
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func NewAuthHandler(service AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

func (h *AuthHandler) RegisterRoutes(group *gin.RouterGroup) {
	group.POST("/login", h.Login)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}

	result, err := h.service.Login(c.Request.Context(), auth.LoginInput{
		Username:  req.Username,
		Password:  req.Password,
		IP:        c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		writeAuthError(c, err)
		return
	}
	response.OK(c, result)
}

func writeAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "用户名或密码格式无效")
	case errors.Is(err, auth.ErrInvalidCredentials):
		response.Error(c, http.StatusUnauthorized, "用户名或密码错误")
	case errors.Is(err, auth.ErrAccountLocked):
		response.Error(c, http.StatusLocked, "账号已锁定")
	case errors.Is(err, auth.ErrAuthUnavailable):
		response.Error(c, http.StatusServiceUnavailable, "鉴权依赖不可用")
	default:
		response.Error(c, http.StatusInternalServerError, "登录失败")
	}
}
