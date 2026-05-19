package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/oidc"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type OIDCService interface {
	Authorize(ctx context.Context, input oidc.AuthorizeInput) (*oidc.AuthorizeResult, error)
	Discovery() (*oidc.DiscoveryDocument, error)
	JWKS() (*oidc.JWKS, error)
	Token(ctx context.Context, input oidc.TokenInput) (*oidc.TokenResult, error)
	UserInfo(ctx context.Context, accessToken string) (*oidc.UserInfo, error)
}

type OIDCHandler struct {
	service OIDCService
}

func NewOIDCHandler(service OIDCService) *OIDCHandler {
	return &OIDCHandler{service: service}
}

func (h *OIDCHandler) RegisterRoutes(router *gin.Engine) {
	router.GET("/.well-known/openid-configuration", h.Discovery)
	router.GET("/oauth2/authorize", h.Authorize)
	router.POST("/oauth2/token", h.Token)
	router.GET("/oauth2/jwks", h.JWKS)
	router.GET("/oauth2/userinfo", h.UserInfo)
}

func (h *OIDCHandler) Authorize(c *gin.Context) {
	token, ok := bearerToken(c.GetHeader("Authorization"))
	if !ok {
		writeOAuthError(c, http.StatusUnauthorized, "login_required")
		return
	}
	result, err := h.service.Authorize(c.Request.Context(), oidc.AuthorizeInput{
		ResponseType: c.Query("response_type"),
		ClientID:     c.Query("client_id"),
		RedirectURI:  c.Query("redirect_uri"),
		Scope:        c.Query("scope"),
		State:        c.Query("state"),
		AccessToken:  token,
	})
	if err != nil {
		writeOAuthServiceError(c, err)
		return
	}
	c.Redirect(http.StatusFound, result.RedirectURI)
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

type oidcTokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
	Code         string `json:"code" form:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
}

func (h *OIDCHandler) Token(c *gin.Context) {
	req, ok := bindOIDCTokenRequest(c)
	if !ok {
		writeOAuthError(c, http.StatusBadRequest, "invalid_request")
		return
	}
	if req.ClientID == "" {
		req.ClientID, req.ClientSecret, _ = c.Request.BasicAuth()
	}
	result, err := h.service.Token(c.Request.Context(), oidc.TokenInput{
		GrantType:    req.GrantType,
		RefreshToken: req.RefreshToken,
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
	})
	if err != nil {
		writeOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *OIDCHandler) UserInfo(c *gin.Context) {
	token, ok := bearerToken(c.GetHeader("Authorization"))
	if !ok {
		writeOAuthError(c, http.StatusUnauthorized, "invalid_token")
		return
	}
	result, err := h.service.UserInfo(c.Request.Context(), token)
	if err != nil {
		writeOAuthServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func bindOIDCTokenRequest(c *gin.Context) (oidcTokenRequest, bool) {
	var req oidcTokenRequest
	contentType := c.GetHeader("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		if err := c.ShouldBindJSON(&req); err != nil {
			return req, false
		}
		return req, true
	}
	req.GrantType = c.PostForm("grant_type")
	req.RefreshToken = c.PostForm("refresh_token")
	req.Code = c.PostForm("code")
	req.RedirectURI = c.PostForm("redirect_uri")
	req.ClientID = c.PostForm("client_id")
	req.ClientSecret = c.PostForm("client_secret")
	return req, true
}

func writeOIDCError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, oidc.ErrOIDCDisabled):
		response.Error(c, http.StatusNotFound, "OIDC 未启用")
	default:
		response.Error(c, http.StatusInternalServerError, "OIDC 服务异常")
	}
}

func writeOAuthServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, oidc.ErrOIDCDisabled):
		writeOAuthError(c, http.StatusNotFound, "server_error")
	case errors.Is(err, oidc.ErrUnsupportedGrant):
		writeOAuthError(c, http.StatusBadRequest, "unsupported_grant_type")
	case errors.Is(err, oidc.ErrInvalidAuthorizeRequest):
		writeOAuthError(c, http.StatusBadRequest, "invalid_request")
	case errors.Is(err, oidc.ErrInvalidClient), errors.Is(err, oidc.ErrClientNotFound):
		writeOAuthError(c, http.StatusUnauthorized, "invalid_client")
	case errors.Is(err, oidc.ErrInvalidAuthCode):
		writeOAuthError(c, http.StatusBadRequest, "invalid_grant")
	case errors.Is(err, oidc.ErrInvalidToken):
		writeOAuthError(c, http.StatusUnauthorized, "invalid_token")
	case errors.Is(err, oidc.ErrTokenServiceUnavailable), errors.Is(err, oidc.ErrOIDCStoreUnavailable):
		writeOAuthError(c, http.StatusServiceUnavailable, "temporarily_unavailable")
	default:
		writeOAuthError(c, http.StatusInternalServerError, "server_error")
	}
}

func writeOAuthError(c *gin.Context, status int, code string) {
	c.JSON(status, gin.H{"error": code})
}
