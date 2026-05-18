package response

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	CodeOK    = 0
	CodeError = 1
)

type Body struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	Data      any    `json:"data,omitempty"`
	RequestID string `json:"requestId,omitempty"`
}

func OK(c *gin.Context, data any) {
	JSON(c, http.StatusOK, CodeOK, "ok", data)
}

func Error(c *gin.Context, status int, message string) {
	JSON(c, status, CodeError, message, nil)
}

func JSON(c *gin.Context, status int, code int, message string, data any) {
	c.JSON(status, Body{
		Code:      code,
		Message:   message,
		Data:      data,
		RequestID: c.GetString("request_id"),
	})
}
