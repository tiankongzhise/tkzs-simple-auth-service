package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

//go:embed static/*
var files embed.FS

type Handler struct {
	prefix string
	fs     http.FileSystem
}

func NewHandler(prefix string) (*Handler, error) {
	static, err := fs.Sub(files, "static")
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "/ui/"
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &Handler{prefix: prefix, fs: http.FS(static)}, nil
}

func (h *Handler) RegisterRoutes(router *gin.Engine) {
	handler := http.StripPrefix(strings.TrimRight(h.prefix, "/"), http.FileServer(h.fs))
	router.GET(strings.TrimRight(h.prefix, "/"), func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, h.prefix)
	})
	router.GET(h.prefix+"*filepath", gin.WrapH(handler))
}
