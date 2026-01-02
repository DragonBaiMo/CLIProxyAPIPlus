// Package middleware 提供 HTTP 中间件实现
package middleware

import "github.com/gin-gonic/gin"

// PortMode 端口模式类型
type PortMode string

const (
	// PortModeExternal 外部端口模式（主端口，仅接受 License Key）
	PortModeExternal PortMode = "external"

	// PortModeInternal 内部端口模式（开发者端口，仅接受普通 api-keys）
	PortModeInternal PortMode = "internal"
)

// ContextKeyPortMode Context 中存储端口模式的 Key
const ContextKeyPortMode = "portMode"

// ContextKeyAuthResult Context 中存储认证结果的 Key
const ContextKeyAuthResult = "authResult"

// ContextKeyRejectReason Context 中存储拒绝原因的 Key
const ContextKeyRejectReason = "rejectReason"

// AuthResult 认证结果类型
type AuthResult string

const (
	// AuthResultSuccess 认证成功
	AuthResultSuccess AuthResult = "success"
	// AuthResultFailed 认证失败（Key 无效）
	AuthResultFailed AuthResult = "failed"
	// AuthResultRejected 认证被拒绝（Key 类型不匹配端口）
	AuthResultRejected AuthResult = "rejected"
)

// SetPortMode 设置端口模式到 Gin Context
func SetPortMode(c *gin.Context, mode PortMode) {
	c.Set(ContextKeyPortMode, mode)
}

// GetPortMode 从 Gin Context 获取端口模式
func GetPortMode(c *gin.Context) PortMode {
	if mode, exists := c.Get(ContextKeyPortMode); exists {
		if pm, ok := mode.(PortMode); ok {
			return pm
		}
	}
	return PortModeExternal // 默认外部模式
}

// SetAuthResult 设置认证结果到 Gin Context
func SetAuthResult(c *gin.Context, result AuthResult, reason string) {
	c.Set(ContextKeyAuthResult, result)
	if reason != "" {
		c.Set(ContextKeyRejectReason, reason)
	}
}

// GetAuthResult 从 Gin Context 获取认证结果
func GetAuthResult(c *gin.Context) (AuthResult, string) {
	result := AuthResultSuccess
	reason := ""

	if r, exists := c.Get(ContextKeyAuthResult); exists {
		if ar, ok := r.(AuthResult); ok {
			result = ar
		}
	}

	if r, exists := c.Get(ContextKeyRejectReason); exists {
		if s, ok := r.(string); ok {
			reason = s
		}
	}

	return result, reason
}

// IsInternalPort 检查当前请求是否来自内部端口
func IsInternalPort(c *gin.Context) bool {
	return GetPortMode(c) == PortModeInternal
}

// IsExternalPort 检查当前请求是否来自外部端口
func IsExternalPort(c *gin.Context) bool {
	return GetPortMode(c) == PortModeExternal
}
