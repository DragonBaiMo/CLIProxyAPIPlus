// Package middleware 提供 HTTP 中间件实现
package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// FingerprintHeader 机器指纹 Header 名称
const FingerprintHeader = "X-Machine-Fingerprint"

// LicenseMiddleware 验证 API Key 是否为有效的已激活 License Key
// 该中间件应在 AuthMiddleware 之后使用
type LicenseMiddleware struct {
	store                    *LicenseStore
	enabled                  bool
	requireFingerprint       bool // 是否强制要求机器指纹验证
	allowMissingFingerprint  bool // 是否允许缺少指纹（宽松模式，仅记录警告）
	mu                       sync.RWMutex
}

// LicenseMiddlewareConfig 中间件配置
type LicenseMiddlewareConfig struct {
	Enabled                 bool
	RequireFingerprint      bool // 强制要求指纹验证（防止 Key 分享）
	AllowMissingFingerprint bool // 宽松模式：缺少指纹时仅警告不拒绝
}

// NewLicenseMiddleware 创建一个新的 LicenseMiddleware 实例
func NewLicenseMiddleware(store *LicenseStore, enabled bool) *LicenseMiddleware {
	return &LicenseMiddleware{
		store:                   store,
		enabled:                 enabled,
		requireFingerprint:      false,
		allowMissingFingerprint: true,
	}
}

// NewLicenseMiddlewareWithConfig 使用配置创建 LicenseMiddleware
func NewLicenseMiddlewareWithConfig(store *LicenseStore, cfg LicenseMiddlewareConfig) *LicenseMiddleware {
	return &LicenseMiddleware{
		store:                   store,
		enabled:                 cfg.Enabled,
		requireFingerprint:      cfg.RequireFingerprint,
		allowMissingFingerprint: cfg.AllowMissingFingerprint,
	}
}

// SetRequireFingerprint 设置是否强制要求指纹验证
func (m *LicenseMiddleware) SetRequireFingerprint(require bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requireFingerprint = require
}

// IsRequireFingerprint 返回是否强制要求指纹验证
func (m *LicenseMiddleware) IsRequireFingerprint() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.requireFingerprint
}

// SetEnabled 动态启用或禁用 License 验证
func (m *LicenseMiddleware) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// IsEnabled 返回当前是否启用 License 验证
func (m *LicenseMiddleware) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// Handler 返回 Gin 中间件处理函数
func (m *LicenseMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查是否启用
		if !m.IsEnabled() {
			c.Next()
			return
		}

		// 检查端口模式：内部端口直接放行（不进行 License 验证）
		if IsInternalPort(c) {
			c.Next()
			return
		}

		// 从 Context 获取 API Key（由 AuthMiddleware 注入）
		apiKeyRaw, exists := c.Get("apiKey")
		if !exists {
			c.Next()
			return
		}

		apiKey, ok := apiKeyRaw.(string)
		if !ok || apiKey == "" {
			c.Next()
			return
		}

		// 只验证以 "sk-lic-" 开头的 Key（License Key）
		if !strings.HasPrefix(apiKey, "sk-lic-") {
			c.Next()
			return
		}

		// 获取请求中的机器指纹
		fingerprint := c.GetHeader(FingerprintHeader)

		// 外部端口强制要求指纹验证
		if m.IsRequireFingerprint() {
			if fingerprint == "" {
				m.mu.RLock()
				allowMissing := m.allowMissingFingerprint
				m.mu.RUnlock()

				if allowMissing {
					log.Warnf("License Key %s 请求缺少机器指纹，IP: %s", MaskKey(apiKey), c.ClientIP())
				} else {
					SetAuthResult(c, AuthResultFailed, "FINGERPRINT_REQUIRED")
					LogLicenseValidationFailure(c, "缺少机器指纹", apiKey, "")
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"error": "请求缺少机器指纹验证，请使用许可证代理客户端",
						"code":  "FINGERPRINT_REQUIRED",
					})
					return
				}
			}
		}

		// 使用加密验证：解密 Key 并验证指纹
		var payload *KeyPayload
		var errCode string

		if fingerprint != "" {
			// 有指纹时：解密 Key 并验证指纹匹配
			payload, errCode = m.store.crypto.ValidateKeyWithFingerprint(apiKey, fingerprint)
		} else {
			// 无指纹时：仅解密 Key 验证格式和过期时间
			var err error
			payload, err = m.store.crypto.DecryptKey(apiKey)
			if err != nil {
				errCode = "INVALID_KEY"
			} else if payload.ExpiresAt < time.Now().Unix() {
				errCode = "KEY_EXPIRED"
			}
		}

		// 处理验证错误
		if errCode != "" {
			switch errCode {
			case "KEY_EXPIRED":
				SetAuthResult(c, AuthResultFailed, "KEY_EXPIRED")
				LogLicenseValidationFailure(c, "Key 已过期", apiKey, fingerprint)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "API Key 已过期",
					"code":  "KEY_EXPIRED",
				})
			case "FINGERPRINT_MISMATCH":
				SetAuthResult(c, AuthResultFailed, "FINGERPRINT_MISMATCH")
				LogLicenseValidationFailure(c, "机器指纹不匹配", apiKey, fingerprint)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
					"error": "机器指纹验证失败，此 Key 已绑定其他设备",
					"code":  "FINGERPRINT_MISMATCH",
				})
			default:
				SetAuthResult(c, AuthResultFailed, "INVALID_API_KEY")
				LogLicenseValidationFailure(c, "无效的 License Key", apiKey, fingerprint)
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "无效的 API Key",
					"code":  "INVALID_API_KEY",
				})
			}
			return
		}

		// 检查 Key 是否被吊销（使用缓存，O(1) 查找）
		if m.store.IsKeyRevoked(payload.KeyID) {
			SetAuthResult(c, AuthResultFailed, "KEY_REVOKED")
			LogLicenseValidationFailure(c, "Key 已被撤销", apiKey, fingerprint)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "API Key 已被撤销",
				"code":  "KEY_REVOKED",
			})
			return
		}

		// 将 License 信息存入 Context
		c.Set("licenseKeyID", payload.KeyID)
		c.Set("licenseExpiresAt", time.Unix(payload.ExpiresAt, 0))
		c.Set("licenseAllowedModels", payload.AllowedModels) // 存储模型权限

		// 异步更新使用统计
		clientIP := c.ClientIP()
		keyID := payload.KeyID
		go func() {
			if err := m.store.UpdateKeyUsageByID(keyID, clientIP); err != nil {
				log.Warnf("更新 License Key 使用统计失败: %v", err)
			}
		}()

		c.Next()
	}
}

// GetStore 返回底层的 LicenseStore
func (m *LicenseMiddleware) GetStore() *LicenseStore {
	return m.store
}

// LicenseModelFilterMiddleware 验证请求的模型是否在 License Key 的允许列表中
// 该中间件应在 LicenseMiddleware 之后使用
func LicenseModelFilterMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 内部端口不受模型过滤限制
		if IsInternalPort(c) {
			c.Next()
			return
		}

		// 获取 License 允许的模型列表
		allowedModelsRaw, exists := c.Get("licenseAllowedModels")
		if !exists {
			// 没有 License 信息，可能是普通 Key 或未启用 License
			c.Next()
			return
		}

		allowedModels, ok := allowedModelsRaw.([]string)
		if !ok || len(allowedModels) == 0 {
			// 空列表表示不限制
			c.Next()
			return
		}

		// 从请求中提取模型名称
		model := extractModelFromRequest(c)
		if model == "" {
			// 无法提取模型名称，放行（由后续 handler 处理）
			c.Next()
			return
		}

		// 检查模型是否被允许
		if !isModelAllowedByLicense(model, allowedModels) {
			keyID, _ := c.Get("licenseKeyID")
			log.WithFields(log.Fields{
				"audit":          true,
				"port_mode":      string(GetPortMode(c)),
				"client_ip":      c.ClientIP(),
				"model":          model,
				"license_key_id": keyID,
				"reason":         "MODEL_NOT_ALLOWED",
			}).Warn("访问审计 - 模型权限不足")

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "您的授权不包含此模型的使用权限",
				"code":  "MODEL_NOT_ALLOWED",
				"model": model,
			})
			return
		}

		c.Next()
	}
}

// isModelAllowedByLicense 检查模型是否在允许列表中（支持通配符）
func isModelAllowedByLicense(model string, allowedModels []string) bool {
	modelLower := strings.ToLower(model)
	for _, pattern := range allowedModels {
		if matchModelPattern(modelLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// matchModelPattern 支持通配符的模式匹配
// 支持: "gemini-*", "*-preview", "*flash*", "gemini-*-preview"
func matchModelPattern(model, pattern string) bool {
	// 精确匹配
	if model == pattern {
		return true
	}

	// 通配符匹配
	if strings.Contains(pattern, "*") {
		// 前缀匹配: "gemini-*"
		if strings.HasSuffix(pattern, "*") && !strings.HasPrefix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			return strings.HasPrefix(model, prefix)
		}
		// 后缀匹配: "*-preview"
		if strings.HasPrefix(pattern, "*") && !strings.HasSuffix(pattern, "*") {
			suffix := strings.TrimPrefix(pattern, "*")
			return strings.HasSuffix(model, suffix)
		}
		// 包含匹配: "*flash*"
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			middle := strings.Trim(pattern, "*")
			return strings.Contains(model, middle)
		}
		// 复杂通配符: "gemini-*-preview"
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(model, parts[0]) && strings.HasSuffix(model, parts[1])
		}
	}

	return false
}

// extractModelFromRequest 从请求中提取模型名称
func extractModelFromRequest(c *gin.Context) string {
	// 1. 从 URL 路径提取（Gemini API: /v1beta/models/gemini-pro:generateContent）
	path := c.Request.URL.Path
	if strings.Contains(path, "/models/") {
		parts := strings.Split(path, "/models/")
		if len(parts) > 1 {
			modelPart := parts[1]
			// 移除操作后缀（如 :generateContent）
			if idx := strings.Index(modelPart, ":"); idx > 0 {
				return modelPart[:idx]
			}
			// 移除路径后缀
			if idx := strings.Index(modelPart, "/"); idx > 0 {
				return modelPart[:idx]
			}
			return modelPart
		}
	}

	// 2. 从查询参数提取
	if model := c.Query("model"); model != "" {
		return model
	}

	// 3. 从 Context 提取（可能由其他中间件设置）
	if modelRaw, exists := c.Get("requestModel"); exists {
		if model, ok := modelRaw.(string); ok {
			return model
		}
	}

	return ""
}
