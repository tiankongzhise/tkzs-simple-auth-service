package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/pkg/response"
)

const (
	ContextUserID      = "auth_user_id"
	ContextRoles       = "auth_roles"
	ContextPermissions = "auth_permissions"
)

func AuthMiddleware(service AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, ok := bearerToken(c.GetHeader("Authorization"))
		if !ok {
			response.Error(c, http.StatusUnauthorized, "缺少访问令牌")
			c.Abort()
			return
		}
		result, err := service.Verify(c.Request.Context(), token)
		if err != nil {
			writeTokenError(c, err)
			c.Abort()
			return
		}
		c.Set(ContextUserID, result.UserID)
		c.Set(ContextRoles, result.Roles)
		c.Set(ContextPermissions, result.Permissions)
		writeRenewedAccessToken(c, result)
		c.Next()
	}
}
