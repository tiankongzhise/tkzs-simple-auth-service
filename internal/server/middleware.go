package server

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
)

const requestIDHeader = "X-Request-ID"

func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(requestIDHeader)
		if requestID == "" {
			requestID = uuid.NewString()
		}
		c.Set("request_id", requestID)
		c.Header(requestIDHeader, requestID)
		c.Next()
	}
}

type OperationAuditRecorder interface {
	RecordOperation(ctx context.Context, log model.OperationLog) error
}

func OperationAuditMiddleware(recorder OperationAuditRecorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		if recorder == nil || !isMutationMethod(c.Request.Method) {
			c.Next()
			return
		}
		c.Next()
		result := "success"
		if c.Writer.Status() >= 400 {
			result = "failure"
		}
		_ = recorder.RecordOperation(c.Request.Context(), model.OperationLog{
			ActorID:    c.GetString("auth_user_id"),
			ActorType:  "user",
			Action:     c.Request.Method,
			Resource:   routeResource(c.FullPath(), c.Request.URL.Path),
			ResourceID: c.Param("id"),
			IP:         c.ClientIP(),
			Result:     result,
			Detail:     c.Request.URL.RawQuery,
		})
	}
}

func isMutationMethod(method string) bool {
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func routeResource(fullPath string, fallback string) string {
	if fullPath == "" {
		fullPath = fallback
	}
	fullPath = strings.TrimPrefix(fullPath, "/api/")
	fullPath = strings.TrimPrefix(fullPath, "/")
	if fullPath == "" {
		return "api"
	}
	parts := strings.Split(fullPath, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "api"
	}
	return parts[0]
}
