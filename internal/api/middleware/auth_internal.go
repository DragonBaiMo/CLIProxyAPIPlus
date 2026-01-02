// Package middleware 提供 HTTP 中间件实现
package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v6/sdk/access"
)

// InternalAuthMiddleware 内部端口认证中间件
// 仅允许普通 api-keys，拒绝 sk-lic-* 前缀的 License Key
func InternalAuthMiddleware(manager *sdkaccess.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 设置端口模式为内部
		SetPortMode(c, PortModeInternal)

		if manager == nil {
			c.Next()
			return
		}

		result, err := manager.Authenticate(c.Request.Context(), c.Request)
		if err != nil {
			handleInternalAuthError(c, err)
			return
		}

		if result != nil {
			apiKey := result.Principal

			// 内部端口拒绝 License Key
			if strings.HasPrefix(apiKey, "sk-lic-") {
				SetAuthResult(c, AuthResultRejected, "INTERNAL_PORT_NO_LICENSE")
				LogAuthRejection(c, "内部端口不接受 License Key", apiKey)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "内部端口不接受 License Key，请使用普通 API Key",
					"code":  "INTERNAL_PORT_NO_LICENSE",
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

// handleInternalAuthError 处理内部端口认证错误
func handleInternalAuthError(c *gin.Context, err error) {
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
