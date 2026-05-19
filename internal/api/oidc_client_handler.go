package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	oidcclientsvc "github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/oidcclient"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type OIDCClientService interface {
	Create(ctx context.Context, actor oidcclientsvc.Actor, input oidcclientsvc.CreateInput) (*oidcclientsvc.Result, error)
	List(ctx context.Context, actor oidcclientsvc.Actor) ([]model.OIDCClient, error)
	Get(ctx context.Context, actor oidcclientsvc.Actor, id string) (*model.OIDCClient, error)
}

type OIDCClientHandler struct {
	service OIDCClientService
}

type oidcClientCreateRequest struct {
	Name        string `json:"name" binding:"required"`
	RedirectURI string `json:"redirectUri" binding:"required"`
}

type oidcClientResponse struct {
	ID           string `json:"id"`
	ClientID     string `json:"clientId"`
	Name         string `json:"name"`
	RedirectURI  string `json:"redirectUri"`
	OwnerUserID  string `json:"ownerUserId"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
	UpdatedAt    string `json:"updatedAt"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

func NewOIDCClientHandler(service OIDCClientService) *OIDCClientHandler {
	return &OIDCClientHandler{service: service}
}

func (h *OIDCClientHandler) RegisterRoutes(group *gin.RouterGroup) {
	clients := group.Group("/oidc-clients")
	clients.POST("", h.Create)
	clients.GET("", h.List)
	clients.GET("/:id", h.Get)
}

func (h *OIDCClientHandler) Create(c *gin.Context) {
	var req oidcClientCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "请求参数无效")
		return
	}
	result, err := h.service.Create(c.Request.Context(), oidcClientActorFromContext(c), oidcclientsvc.CreateInput{
		Name:        req.Name,
		RedirectURI: req.RedirectURI,
	})
	if err != nil {
		writeOIDCClientError(c, err)
		return
	}
	response.OK(c, oidcClientResultResponse(result))
}

func (h *OIDCClientHandler) List(c *gin.Context) {
	clients, err := h.service.List(c.Request.Context(), oidcClientActorFromContext(c))
	if err != nil {
		writeOIDCClientError(c, err)
		return
	}
	items := make([]oidcClientResponse, 0, len(clients))
	for _, item := range clients {
		items = append(items, oidcClientModelResponse(item, ""))
	}
	response.OK(c, items)
}

func (h *OIDCClientHandler) Get(c *gin.Context) {
	result, err := h.service.Get(c.Request.Context(), oidcClientActorFromContext(c), c.Param("id"))
	if err != nil {
		writeOIDCClientError(c, err)
		return
	}
	response.OK(c, oidcClientModelResponse(*result, ""))
}

func oidcClientActorFromContext(c *gin.Context) oidcclientsvc.Actor {
	return oidcclientsvc.Actor{
		UserID:  c.GetString(ContextUserID),
		IsAdmin: contextHasRole(c, model.RoleAdminCode),
	}
}

func oidcClientResultResponse(result *oidcclientsvc.Result) oidcClientResponse {
	if result == nil {
		return oidcClientResponse{}
	}
	return oidcClientModelResponse(result.Client, result.ClientSecret)
}

func oidcClientModelResponse(client model.OIDCClient, secret string) oidcClientResponse {
	return oidcClientResponse{
		ID:           client.ID,
		ClientID:     client.ClientID,
		Name:         client.Name,
		RedirectURI:  client.RedirectURI,
		OwnerUserID:  client.OwnerUserID,
		Status:       client.Status,
		CreatedAt:    client.CreatedAt.Format(timeFormatRFC3339),
		UpdatedAt:    client.UpdatedAt.Format(timeFormatRFC3339),
		ClientSecret: secret,
	}
}

func writeOIDCClientError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, oidcclientsvc.ErrInvalidInput):
		response.Error(c, http.StatusBadRequest, "OIDC Client 参数无效")
	case errors.Is(err, oidcclientsvc.ErrConflict):
		response.Error(c, http.StatusConflict, "OIDC Client 已存在")
	case errors.Is(err, oidcclientsvc.ErrForbidden):
		response.Error(c, http.StatusForbidden, "无权访问 OIDC Client")
	case errors.Is(err, oidcclientsvc.ErrNotFound):
		response.Error(c, http.StatusNotFound, "OIDC Client 不存在")
	case errors.Is(err, oidcclientsvc.ErrUnavailable):
		response.Error(c, http.StatusServiceUnavailable, "OIDC Client 依赖不可用")
	default:
		response.Error(c, http.StatusInternalServerError, "OIDC Client 操作失败")
	}
}
