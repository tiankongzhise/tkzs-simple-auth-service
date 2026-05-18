package api

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/hbc-thinkbook/tkzs-simple-auth-service/internal/auth"
)

const (
	HeaderAccessToken         = "X-Access-Token"
	HeaderAccessTokenExpireAt = "X-Access-Token-Expire-At"
)

func bearerToken(header string) (string, bool) {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func writeRenewedAccessToken(c *gin.Context, result *auth.VerifyResult) {
	if result == nil || result.RenewedAccessToken == "" {
		return
	}
	c.Header(HeaderAccessToken, result.RenewedAccessToken)
	c.Header(HeaderAccessTokenExpireAt, result.RenewedAccessTokenExpiry.Format(timeFormatRFC3339))
}

const timeFormatRFC3339 = "2006-01-02T15:04:05Z07:00"
