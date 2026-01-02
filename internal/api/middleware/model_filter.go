// Package middleware 提供 HTTP 中间件实现
package middleware

import (
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// ModelFilterMode 模型过滤模式
type ModelFilterMode string

const (
	// ModelFilterModeBlacklist 黑名单模式（默认）
	ModelFilterModeBlacklist ModelFilterMode = "blacklist"
	// ModelFilterModeWhitelist 白名单模式
	ModelFilterModeWhitelist ModelFilterMode = "whitelist"
)

// ModelFilterConfig 模型过滤配置
type ModelFilterConfig struct {
	Mode   ModelFilterMode
	Models []string
}

// ModelFilter 模型过滤器
type ModelFilter struct {
	mu      sync.RWMutex
	enabled bool
	mode    ModelFilterMode
	models  []string
}

// NewModelFilter 创建模型过滤器
func NewModelFilter(enabled bool, mode string, models []string) *ModelFilter {
	filterMode := ModelFilterModeBlacklist
	if strings.ToLower(mode) == "whitelist" {
		filterMode = ModelFilterModeWhitelist
	}

	return &ModelFilter{
		enabled: enabled,
		mode:    filterMode,
		models:  models,
	}
}

// SetEnabled 设置是否启用过滤
func (f *ModelFilter) SetEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = enabled
}

// IsEnabled 返回是否启用过滤
func (f *ModelFilter) IsEnabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.enabled
}

// SetMode 设置过滤模式
func (f *ModelFilter) SetMode(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.ToLower(mode) == "whitelist" {
		f.mode = ModelFilterModeWhitelist
	} else {
		f.mode = ModelFilterModeBlacklist
	}
}

// GetMode 获取过滤模式
func (f *ModelFilter) GetMode() ModelFilterMode {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.mode
}

// SetModels 设置模型列表
func (f *ModelFilter) SetModels(models []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.models = models
}

// GetModels 获取模型列表
func (f *ModelFilter) GetModels() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	result := make([]string, len(f.models))
	copy(result, f.models)
	return result
}

// IsModelAllowed 检查模型是否被允许
func (f *ModelFilter) IsModelAllowed(model string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled || len(f.models) == 0 {
		return true
	}

	matched := f.matchModel(model)

	if f.mode == ModelFilterModeWhitelist {
		// 白名单模式：只有匹配的模型才允许
		return matched
	}
	// 黑名单模式：匹配的模型被禁止
	return !matched
}

// matchModel 检查模型是否匹配列表中的任一模式
func (f *ModelFilter) matchModel(model string) bool {
	modelLower := strings.ToLower(model)
	for _, pattern := range f.models {
		if matchPattern(modelLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// matchPattern 支持通配符的模式匹配
// 支持: "gemini-*", "*-preview", "*flash*"
func matchPattern(model, pattern string) bool {
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

// ModelFilterMiddleware 模型过滤中间件
// 仅对外部端口生效，内部端口不受限制
func ModelFilterMiddleware(filter *ModelFilter) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 内部端口不受模型过滤限制
		if IsInternalPort(c) {
			c.Next()
			return
		}

		// 检查是否启用过滤
		if filter == nil || !filter.IsEnabled() {
			c.Next()
			return
		}

		// 从请求中提取模型名称
		model := extractModelFromRequest(c)
		if model == "" {
			c.Next()
			return
		}

		// 检查模型是否被允许
		if !filter.IsModelAllowed(model) {
			mode := filter.GetMode()
			var reason string
			if mode == ModelFilterModeWhitelist {
				reason = "MODEL_NOT_IN_WHITELIST"
			} else {
				reason = "MODEL_IN_BLACKLIST"
			}

			log.WithFields(log.Fields{
				"audit":       true,
				"port_mode":   string(GetPortMode(c)),
				"client_ip":   c.ClientIP(),
				"model":       model,
				"filter_mode": string(mode),
				"reason":      reason,
			}).Warn("访问审计 - 模型被过滤")

			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "该模型不可用",
				"code":  reason,
				"model": model,
			})
			return
		}

		c.Next()
	}
}
