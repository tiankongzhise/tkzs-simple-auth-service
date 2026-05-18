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

func NewRouter(cfg *config.Config) *gin.Engine {
	if cfg.Server.RunMode == "prod" {
		gin.SetMode(gin.ReleaseMode)
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

	return router
}
