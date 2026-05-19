package server

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/config"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/metrics"
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
	auth      RouteRegistrar
	oidc      EngineRouteRegistrar
	limit     EngineRouteRegistrar
	ui        EngineRouteRegistrar
	apiRoutes []apiRouteRegistration
}

type Option func(*routerOptions)

type apiRouteRegistration struct {
	registrar   RouteRegistrar
	middlewares []gin.HandlerFunc
}

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

func WithLimitRoutes(registrar EngineRouteRegistrar) Option {
	return func(opts *routerOptions) {
		opts.limit = registrar
	}
}

func WithUIRoutes(registrar EngineRouteRegistrar) Option {
	return func(opts *routerOptions) {
		opts.ui = registrar
	}
}

func WithAPIRoutes(registrar RouteRegistrar, middlewares ...gin.HandlerFunc) Option {
	return func(opts *routerOptions) {
		opts.apiRoutes = append(opts.apiRoutes, apiRouteRegistration{
			registrar:   registrar,
			middlewares: middlewares,
		})
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
	router.Use(gin.Logger(), gin.Recovery(), requestIDMiddleware(), metrics.Middleware())

	router.GET("/health", func(c *gin.Context) {
		response.OK(c, healthResponse{
			Status:  "ok",
			Service: cfg.Service.Code,
			Version: cfg.Service.Version,
		})
	})
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
	if opts.oidc != nil {
		opts.oidc.RegisterRoutes(router)
	}
	if opts.limit != nil {
		opts.limit.RegisterRoutes(router)
	}
	if opts.ui != nil && cfg.UI.Enable {
		opts.ui.RegisterRoutes(router)
	}

	api := router.Group("/api")
	if opts.auth != nil {
		opts.auth.RegisterRoutes(api.Group("/auth"))
	}
	for _, route := range opts.apiRoutes {
		group := api.Group("")
		if len(route.middlewares) > 0 {
			group.Use(route.middlewares...)
		}
		route.registrar.RegisterRoutes(group)
	}

	return router
}
