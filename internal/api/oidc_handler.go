package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/oidc"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type OIDCService interface {
	Discovery() (*oidc.DiscoveryDocument, error)
	JWKS() (*oidc.JWKS, error)
}

type OIDCHandler struct {
	service OIDCService
}

func NewOIDCHandler(service OIDCService) *OIDCHandler {
	return &OIDCHandler{service: service}
}

func (h *OIDCHandler) RegisterRoutes(router *gin.Engine) {
	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/oauth2/jwks", h.JWKS)
}

func (h *OIDCHandler) Discovery(c *gin.Context) {
	document, err := h.service.Discovery()
	if err != nil {
		writeOIDCError(c, err)
		return
	}
	c.JSON(http.StatusOK, document)
}

func (h *OIDCHandler) JWKS(c *gin.Context) {
	keys, err := h.service.JWKS()
	if err != nil {
		writeOIDCError(c, err)
		return
	}
	c.JSON(http.StatusOK, keys)
}

func writeOIDCError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, oidc.ErrOIDCDisabled):
		response.Error(c, http.StatusNotFound, "OIDC 未启用")
	default:
		response.Error(c, http.StatusInternalServerError, "OIDC 服务异常")
	}
}
