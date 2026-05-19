package server

import (
	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

type healthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

type RouteRegistrar interface {
	RegisterRoutes(group *gin.RouterGroup)
}

type EngineRouteRegistrar interface {
	RegisterRoutes(router *gin.Engine)
}

type routerOptions struct {
	auth RouteRegistrar
	oidc EngineRouteRegistrar
}

type Option func(*routerOptions)

func WithAuthRoutes(registrar RouteRegistrar) Option {
	return func(opts *routerOptions) {
		opts.auth = registrar
	}
}

func WithOIDCRoutes(registrar EngineRouteRegistrar) Option {
	return func(opts *routerOptions) {
		opts.oidc = registrar
	}
}

func NewRouter(cfg *config.Config, options ...Option) *gin.Engine {
	if cfg.Server.RunMode == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}
	opts := routerOptions{}
	for _, option := range options {
		option(&opts)
	}

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), requestIDMiddleware())

	router.GET("/health", func(c *gin.Context) {
		response.OK(c, healthResponse{
			Status:  "ok",
			Service: cfg.Service.Code,
			Version: cfg.Service.Version,
		})
	})
	if opts.oidc != nil {
		opts.oidc.RegisterRoutes(router)
	}

	api := router.Group("/api")
	if opts.auth != nil {
		opts.auth.RegisterRoutes(api.Group("/auth"))
	}

	return router
}
