package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/model"
	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if contextHasRole(c, model.RoleAdminCode) || contextHasPermission(c, permission) {
			c.Next()
			return
		}
		response.Error(c, http.StatusForbidden, "权限不足")
		c.Abort()
	}
}

func contextHasPermission(c *gin.Context, permission string) bool {
	value, ok := c.Get(ContextPermissions)
	if !ok {
		return false
	}
	permissions, ok := value.([]string)
	if !ok {
		return false
	}
	for _, item := range permissions {
		if item == permission {
			return true
		}
	}
	return false
}
