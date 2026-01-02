// Package middleware 提供 HTTP 中间件实现
package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
)

// ExternalAuthMiddleware 外部端口认证中间件
// 仅允许 sk-lic-* 前缀的 License Key，拒绝普通 api-keys
func ExternalAuthMiddleware(manager *sdkaccess.Manager, licenseEnabled bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 设置端口模式为外部
		SetPortMode(c, PortModeExternal)

		if manager == nil {
			c.Next()
			return
		}

		result, err := manager.Authenticate(c.Request.Context(), c.Request)
		if err != nil {
			handleExternalAuthError(c, err)
			return
		}

		if result != nil {
			apiKey := result.Principal

			// 如果启用了 License 系统，外部端口只接受 License Key
			if licenseEnabled && !strings.HasPrefix(apiKey, "sk-lic-") {
				SetAuthResult(c, AuthResultRejected, "EXTERNAL_PORT_LICENSE_ONLY")
				LogAuthRejection(c, "外部端口仅接受 License Key", apiKey)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "外部端口仅接受 License Key (sk-lic-*)",
					"code":  "EXTERNAL_PORT_LICENSE_ONLY",
				})
				return
			}

			// 认证成功
			SetAuthResult(c, AuthResultSuccess, "")
			c.Set("apiKey", apiKey)
			c.Set("accessProvider", result.Provider)
			if len(result.Metadata) > 0 {
				c.Set("accessMetadata", result.Metadata)
			}
		}

		c.Next()
	}
}

// handleExternalAuthError 处理外部端口认证错误
func handleExternalAuthError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, sdkaccess.ErrNoCredentials):
		SetAuthResult(c, AuthResultFailed, "MISSING_API_KEY")
		LogAuthFailure(c, "缺少 API Key", "unknown")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "缺少 API Key",
			"code":  "MISSING_API_KEY",
		})
	case errors.Is(err, sdkaccess.ErrInvalidCredential):
		SetAuthResult(c, AuthResultFailed, "INVALID_API_KEY")
		LogAuthFailure(c, "无效的 API Key", "unknown")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "无效的 API Key",
			"code":  "INVALID_API_KEY",
		})
	default:
		SetAuthResult(c, AuthResultFailed, "AUTH_SERVICE_ERROR")
		LogAuthFailure(c, "认证服务错误: "+err.Error(), "unknown")
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "认证服务错误",
			"code":  "AUTH_SERVICE_ERROR",
		})
	}
}
