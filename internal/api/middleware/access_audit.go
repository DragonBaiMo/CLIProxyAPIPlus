// Package middleware 提供 HTTP 中间件实现
package middleware

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// AccessAuditLog 访问审计日志结构
type AccessAuditLog struct {
	Timestamp       string `json:"timestamp"`
	PortMode        string `json:"port_mode"`
	ClientIP        string `json:"client_ip"`
	ForwardedFor    string `json:"forwarded_for,omitempty"`
	RealIP          string `json:"real_ip,omitempty"`
	KeyType         string `json:"key_type"`
	KeyID           string `json:"key_id"`
	LicenseKeyID    string `json:"license_key_id,omitempty"`
	FingerprintHash string `json:"fingerprint_hash,omitempty"`
	UserAgent       string `json:"user_agent"`
	RequestPath     string `json:"request_path"`
	RequestMethod   string `json:"request_method"`
	ResponseStatus  int    `json:"response_status"`
	AuthResult      string `json:"auth_result"`
	RejectReason    string `json:"reject_reason,omitempty"`
}

// AccessAuditMiddleware 访问审计中间件
// 记录所有 API 请求的访问日志，用于安全审计和异常检测
func AccessAuditMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 先执行后续处理
		c.Next()

		// 请求处理完成后记录审计日志
		auditLog := buildAuditLog(c)
		logAuditEntry(auditLog)
	}
}

// buildAuditLog 构建审计日志条目
func buildAuditLog(c *gin.Context) *AccessAuditLog {
	auditLog := &AccessAuditLog{
		Timestamp:     time.Now().Format(time.RFC3339),
		PortMode:      string(GetPortMode(c)),
		ClientIP:      c.ClientIP(),
		ForwardedFor:  c.GetHeader("X-Forwarded-For"),
		RealIP:        c.GetHeader("X-Real-IP"),
		UserAgent:     c.GetHeader("User-Agent"),
		RequestPath:   c.Request.URL.Path,
		RequestMethod: c.Request.Method,
		ResponseStatus: c.Writer.Status(),
	}

	// 获取 API Key 信息
	if apiKey, exists := c.Get("apiKey"); exists {
		if key, ok := apiKey.(string); ok {
			auditLog.KeyID = maskAPIKey(key)
			auditLog.KeyType = detectKeyType(key)
		}
	}

	// 获取 License Key ID（如果是 License Key）
	if licenseKeyID, exists := c.Get("licenseKeyID"); exists {
		if keyID, ok := licenseKeyID.(string); ok {
			auditLog.LicenseKeyID = keyID
		}
	}

	// 获取机器指纹哈希
	fingerprint := c.GetHeader(FingerprintHeader)
	if fingerprint != "" {
		// 只记录指纹的前16个字符（已经是哈希值）
		if len(fingerprint) > 16 {
			auditLog.FingerprintHash = fingerprint[:16] + "..."
		} else {
			auditLog.FingerprintHash = fingerprint
		}
	}

	// 获取认证结果
	authResult, rejectReason := GetAuthResult(c)
	auditLog.AuthResult = string(authResult)
	auditLog.RejectReason = rejectReason

	return auditLog
}

// logAuditEntry 记录审计日志条目
func logAuditEntry(auditLog *AccessAuditLog) {
	fields := log.Fields{
		"audit":          true,
		"port_mode":      auditLog.PortMode,
		"client_ip":      auditLog.ClientIP,
		"key_type":       auditLog.KeyType,
		"key_id":         auditLog.KeyID,
		"request_path":   auditLog.RequestPath,
		"request_method": auditLog.RequestMethod,
		"response_status": auditLog.ResponseStatus,
		"auth_result":    auditLog.AuthResult,
	}

	// 添加可选字段
	if auditLog.ForwardedFor != "" {
		fields["forwarded_for"] = auditLog.ForwardedFor
	}
	if auditLog.RealIP != "" {
		fields["real_ip"] = auditLog.RealIP
	}
	if auditLog.LicenseKeyID != "" {
		fields["license_key_id"] = auditLog.LicenseKeyID
	}
	if auditLog.FingerprintHash != "" {
		fields["fingerprint_hash"] = auditLog.FingerprintHash
	}
	if auditLog.RejectReason != "" {
		fields["reject_reason"] = auditLog.RejectReason
	}
	if auditLog.UserAgent != "" {
		// 截断过长的 User-Agent
		ua := auditLog.UserAgent
		if len(ua) > 100 {
			ua = ua[:100] + "..."
		}
		fields["user_agent"] = ua
	}

	// 根据认证结果选择日志级别
	switch AuthResult(auditLog.AuthResult) {
	case AuthResultSuccess:
		log.WithFields(fields).Info("访问审计")
	case AuthResultFailed, AuthResultRejected:
		log.WithFields(fields).Warn("访问审计 - 认证失败/拒绝")
	default:
		log.WithFields(fields).Info("访问审计")
	}
}

// maskAPIKey 对 API Key 进行脱敏处理
func maskAPIKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:8] + "****" + key[len(key)-4:]
}

// detectKeyType 检测 Key 类型
func detectKeyType(key string) string {
	if strings.HasPrefix(key, "sk-lic-") {
		return "license-key"
	}
	return "api-key"
}

// LogAuthFailure 记录认证失败日志（供认证中间件调用）
func LogAuthFailure(c *gin.Context, reason string, keyType string) {
	fields := log.Fields{
		"audit":          true,
		"port_mode":      string(GetPortMode(c)),
		"client_ip":      c.ClientIP(),
		"key_type":       keyType,
		"request_path":   c.Request.URL.Path,
		"request_method": c.Request.Method,
		"auth_result":    string(AuthResultFailed),
		"reject_reason":  reason,
	}

	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		fields["forwarded_for"] = xff
	}
	if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		fields["real_ip"] = realIP
	}

	log.WithFields(fields).Warn("访问审计 - 认证失败")
}

// LogAuthRejection 记录认证拒绝日志（Key 类型不匹配端口）
func LogAuthRejection(c *gin.Context, reason string, key string) {
	fields := log.Fields{
		"audit":          true,
		"port_mode":      string(GetPortMode(c)),
		"client_ip":      c.ClientIP(),
		"key_type":       detectKeyType(key),
		"key_id":         maskAPIKey(key),
		"request_path":   c.Request.URL.Path,
		"request_method": c.Request.Method,
		"auth_result":    string(AuthResultRejected),
		"reject_reason":  reason,
	}

	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		fields["forwarded_for"] = xff
	}
	if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		fields["real_ip"] = realIP
	}

	log.WithFields(fields).Warn("访问审计 - Key 类型不匹配端口")
}

// LogLicenseValidationFailure 记录 License 验证失败日志
func LogLicenseValidationFailure(c *gin.Context, reason string, key string, fingerprint string) {
	fields := log.Fields{
		"audit":          true,
		"port_mode":      string(GetPortMode(c)),
		"client_ip":      c.ClientIP(),
		"key_type":       "license-key",
		"key_id":         maskAPIKey(key),
		"request_path":   c.Request.URL.Path,
		"request_method": c.Request.Method,
		"auth_result":    string(AuthResultFailed),
		"reject_reason":  reason,
	}

	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		fields["forwarded_for"] = xff
	}
	if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
		fields["real_ip"] = realIP
	}
	if fingerprint != "" {
		if len(fingerprint) > 16 {
			fields["fingerprint_hash"] = fingerprint[:16] + "..."
		} else {
			fields["fingerprint_hash"] = fingerprint
		}
	}

	log.WithFields(fields).Warn("访问审计 - License 验证失败")
}
