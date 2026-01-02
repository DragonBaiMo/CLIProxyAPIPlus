// Package management 提供管理 API 处理器
package management

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/api/middleware"
)

// LicenseHandler 处理 License 相关的管理 API
type LicenseHandler struct {
	store                  *middleware.LicenseStore
	defaultKeyDuration     string
	activationCodeValidity time.Duration
}

// NewLicenseHandler 创建一个新的 LicenseHandler 实例
func NewLicenseHandler(store *middleware.LicenseStore, defaultKeyDuration string, activationCodeValidity time.Duration) *LicenseHandler {
	return &LicenseHandler{
		store:                  store,
		defaultKeyDuration:     defaultKeyDuration,
		activationCodeValidity: activationCodeValidity,
	}
}

// CreateActivationCodeRequest 创建激活码的请求体
type CreateActivationCodeRequest struct {
	Duration      string   `json:"duration"`                 // Key 有效期，如 "30d"
	MaxUses       int      `json:"max_uses"`                 // 最大激活次数，默认 1
	Memo          string   `json:"memo"`                     // 备注
	AllowedModels []string `json:"allowed_models,omitempty"` // 允许使用的模型列表（支持通配符，空表示不限制）
}

// CreateActivationCodeResponse 创建激活码的响应体
type CreateActivationCodeResponse struct {
	Code          string    `json:"code"`
	ExpiresAt     time.Time `json:"expires_at"`
	Duration      string    `json:"duration"`
	MaxUses       int       `json:"max_uses"`
	AllowedModels []string  `json:"allowed_models,omitempty"`
}

// CreateActivationCode POST /v0/management/license/codes
// 生成新的激活码
func (h *LicenseHandler) CreateActivationCode(c *gin.Context) {
	var req CreateActivationCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	// 设置默认值
	if req.Duration == "" {
		req.Duration = h.defaultKeyDuration
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}

	ac, err := h.store.GenerateActivationCode(req.Duration, h.activationCodeValidity, req.MaxUses, req.Memo, req.AllowedModels)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, CreateActivationCodeResponse{
		Code:          ac.Code,
		ExpiresAt:     ac.ExpiresAt,
		Duration:      ac.Duration,
		MaxUses:       ac.MaxUses,
		AllowedModels: ac.AllowedModels,
	})
}

// ListActivationCodes GET /v0/management/license/codes
// 列出所有激活码
func (h *LicenseHandler) ListActivationCodes(c *gin.Context) {
	codes := h.store.GetAllActivationCodes()
	c.JSON(http.StatusOK, gin.H{"codes": codes})
}

// DeleteActivationCode DELETE /v0/management/license/codes/:code
// 删除激活码
func (h *LicenseHandler) DeleteActivationCode(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少激活码参数"})
		return
	}

	if err := h.store.DeleteActivationCode(code); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "激活码已删除"})
}

// ActivateRequest 激活请求体
// 安全性说明：不再使用客户端签名（因为密钥会被反编译提取）
// 真正的安全性来自：1) 加密 Key 中嵌入指纹哈希 2) 每次请求验证指纹
type ActivateRequest struct {
	ActivationCode     string `json:"activation_code"`
	MachineFingerprint string `json:"machine_fingerprint"`
}

// ActivateResponse 激活响应体
type ActivateResponse struct {
	APIKey        string    `json:"api_key"`
	ExpiresAt     time.Time `json:"expires_at"`
	AllowedModels []string  `json:"allowed_models,omitempty"` // 允许使用的模型列表
}

// Activate POST /v0/management/license/activate
// 使用激活码激活，生成 API Key（由激活程序调用）
// 生成的 Key 中加密嵌入了机器指纹，使用时需要本地代理附加指纹进行验证
func (h *LicenseHandler) Activate(c *gin.Context) {
	var req ActivateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	if req.ActivationCode == "" || req.MachineFingerprint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "激活码和机器指纹不能为空"})
		return
	}

	// 直接调用激活逻辑，Key 中会加密嵌入指纹哈希
	lk, err := h.store.Activate(req.ActivationCode, req.MachineFingerprint)
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ActivateResponse{
		APIKey:        lk.Key,
		ExpiresAt:     lk.ExpiresAt,
		AllowedModels: lk.AllowedModels,
	})
}

// LicensedKeyResponse 已激活 Key 的响应（脱敏）
type LicensedKeyResponse struct {
	Key                string    `json:"key"`
	KeyID              string    `json:"key_id"`
	ActivationCode     string    `json:"activation_code"`
	MachineFingerprint string    `json:"machine_fingerprint"`
	ActivatedAt        time.Time `json:"activated_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	Revoked            bool      `json:"revoked"`
	Memo               string    `json:"memo"`
	LastUsedAt         time.Time `json:"last_used_at"`
	LastUsedIP         string    `json:"last_used_ip"`
	UseCount           int       `json:"use_count"`
	AllowedModels      []string  `json:"allowed_models,omitempty"`
}

// ListLicensedKeys GET /v0/management/license/keys
// 列出所有已激活的 Key
func (h *LicenseHandler) ListLicensedKeys(c *gin.Context) {
	keys := h.store.GetAllLicensedKeys()

	// 对 Key 进行脱敏处理
	response := make([]LicensedKeyResponse, len(keys))
	for i, k := range keys {
		maskedFingerprint := k.MachineFingerprint
		if len(maskedFingerprint) > 8 {
			maskedFingerprint = maskedFingerprint[:8] + "****"
		}
		response[i] = LicensedKeyResponse{
			Key:                middleware.MaskKey(k.Key),
			KeyID:              k.KeyID,
			ActivationCode:     k.ActivationCode,
			MachineFingerprint: maskedFingerprint,
			ActivatedAt:        k.ActivatedAt,
			ExpiresAt:          k.ExpiresAt,
			Revoked:            k.Revoked,
			Memo:               k.Memo,
			LastUsedAt:         k.LastUsedAt,
			LastUsedIP:         k.LastUsedIP,
			UseCount:           k.UseCount,
			AllowedModels:      k.AllowedModels,
		}
	}

	c.JSON(http.StatusOK, gin.H{"keys": response})
}

// RevokeKey DELETE /v0/management/license/keys/:key
// 撤销 API Key（临时禁用，可恢复）
func (h *LicenseHandler) RevokeKey(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 Key 参数"})
		return
	}

	if err := h.store.RevokeKey(key); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Key 已撤销"})
}

// ========== 激活码扩展 API ==========

// BatchCreateActivationCodeRequest 批量创建激活码的请求体
type BatchCreateActivationCodeRequest struct {
	Duration      string   `json:"duration"`                 // Key 有效期
	MaxUses       int      `json:"max_uses"`                 // 每个激活码的最大激活次数
	Count         int      `json:"count"`                    // 生成数量
	Memo          string   `json:"memo"`                     // 备注
	AllowedModels []string `json:"allowed_models,omitempty"` // 允许使用的模型列表（支持通配符，空表示不限制）
}

// BatchCreateActivationCodes POST /v0/management/license/codes/batch
// 批量生成激活码
func (h *LicenseHandler) BatchCreateActivationCodes(c *gin.Context) {
	var req BatchCreateActivationCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	if req.Duration == "" {
		req.Duration = h.defaultKeyDuration
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 1
	}
	if req.Count <= 0 || req.Count > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "生成数量必须在 1-100 之间"})
		return
	}

	codes, err := h.store.BatchGenerateActivationCodes(req.Duration, h.activationCodeValidity, req.MaxUses, req.Count, req.Memo, req.AllowedModels)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"codes": codes, "count": len(codes)})
}

// GetActivationCode GET /v0/management/license/codes/:code
// 获取单个激活码详情
func (h *LicenseHandler) GetActivationCode(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少激活码参数"})
		return
	}

	ac, err := h.store.GetActivationCode(code)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ac)
}

// UpdateActivationCodeMemoRequest 更新激活码备注的请求体
type UpdateActivationCodeMemoRequest struct {
	Memo string `json:"memo"`
}

// UpdateActivationCodeMemo PATCH /v0/management/license/codes/:code
// 更新激活码备注
func (h *LicenseHandler) UpdateActivationCodeMemo(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少激活码参数"})
		return
	}

	var req UpdateActivationCodeMemoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	if err := h.store.UpdateActivationCodeMemo(code, req.Memo); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "备注已更新"})
}

// DisableActivationCode PATCH /v0/management/license/codes/:code/disable
// 禁用激活码
func (h *LicenseHandler) DisableActivationCode(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少激活码参数"})
		return
	}

	if err := h.store.DisableActivationCode(code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "激活码已禁用"})
}

// EnableActivationCode PATCH /v0/management/license/codes/:code/enable
// 启用激活码
func (h *LicenseHandler) EnableActivationCode(c *gin.Context) {
	code := c.Param("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少激活码参数"})
		return
	}

	if err := h.store.EnableActivationCode(code); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "激活码已启用"})
}

// ========== License Key 扩展 API ==========

// GetLicensedKey GET /v0/management/license/keys/:key
// 获取单个 Key 详情
func (h *LicenseHandler) GetLicensedKey(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 Key 参数"})
		return
	}

	lk, err := h.store.GetLicensedKey(key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 脱敏处理
	maskedFingerprint := lk.MachineFingerprint
	if len(maskedFingerprint) > 8 {
		maskedFingerprint = maskedFingerprint[:8] + "****"
	}

	c.JSON(http.StatusOK, LicensedKeyResponse{
		Key:                middleware.MaskKey(lk.Key),
		KeyID:              lk.KeyID,
		ActivationCode:     lk.ActivationCode,
		MachineFingerprint: maskedFingerprint,
		ActivatedAt:        lk.ActivatedAt,
		ExpiresAt:          lk.ExpiresAt,
		Revoked:            lk.Revoked,
		Memo:               lk.Memo,
		LastUsedAt:         lk.LastUsedAt,
		LastUsedIP:         lk.LastUsedIP,
		UseCount:           lk.UseCount,
		AllowedModels:      lk.AllowedModels,
	})
}

// RestoreKey PATCH /v0/management/license/keys/:key/restore
// 恢复已吊销的 Key
func (h *LicenseHandler) RestoreKey(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 Key 参数"})
		return
	}

	if err := h.store.RestoreKey(key); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Key 已恢复"})
}

// BanKey DELETE /v0/management/license/keys/:key/ban
// 封禁 Key（永久删除，不可恢复）
func (h *LicenseHandler) BanKey(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 Key 参数"})
		return
	}

	if err := h.store.DeleteKey(key); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Key 已封禁（永久删除）"})
}

// UnbindKey DELETE /v0/management/license/keys/:key/unbind
// 解绑机器（删除 Key + 恢复激活码使用次数）
func (h *LicenseHandler) UnbindKey(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 Key 参数"})
		return
	}

	if err := h.store.UnbindKey(key); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "已解绑，用户可使用原激活码重新激活"})
}

// ExtendKeyRequest 续期请求体
type ExtendKeyRequest struct {
	Duration string `json:"duration"` // 延长时间，如 "30d"
}

// ExtendKey PATCH /v0/management/license/keys/:key/extend
// 延长 Key 有效期
func (h *LicenseHandler) ExtendKey(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 Key 参数"})
		return
	}

	var req ExtendKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	if req.Duration == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "延长时间不能为空"})
		return
	}

	if err := h.store.ExtendKey(key, req.Duration); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Key 有效期已延长"})
}

// UpdateKeyMemoRequest 更新 Key 备注的请求体
type UpdateKeyMemoRequest struct {
	Memo string `json:"memo"`
}

// UpdateKeyMemo PATCH /v0/management/license/keys/:key
// 更新 Key 备注
func (h *LicenseHandler) UpdateKeyMemo(c *gin.Context) {
	key := c.Param("key")
	if key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 Key 参数"})
		return
	}

	var req UpdateKeyMemoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	if err := h.store.UpdateKeyMemo(key, req.Memo); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "备注已更新"})
}

// ========== 在线验证 API ==========

// HeartbeatRequest 心跳验证请求体
// 安全性说明：不再使用客户端签名（因为密钥会被反编译提取）
// 真正的安全性来自：加密 Key 中嵌入指纹哈希，每次请求验证指纹
type HeartbeatRequest struct {
	APIKey             string `json:"api_key"`
	MachineFingerprint string `json:"machine_fingerprint"`
}

// HeartbeatResponse 心跳验证响应体
type HeartbeatResponse struct {
	Valid       bool      `json:"valid"`
	ExpiresAt   time.Time `json:"expires_at"`
	ServerTime  int64     `json:"server_time"`
	NextCheckIn int64     `json:"next_check_in"` // 下次检查间隔（秒）
}

// Heartbeat POST /v0/license/heartbeat
// 客户端定期调用验证 Key 有效性（公开端点，无需管理密钥）
// 通过解密 Key 验证指纹是否匹配
func (h *LicenseHandler) Heartbeat(c *gin.Context) {
	var req HeartbeatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	if req.APIKey == "" || req.MachineFingerprint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key 和机器指纹不能为空"})
		return
	}

	now := time.Now().Unix()

	// 使用加密验证：解密 Key 并验证指纹
	payload, errCode := h.store.GetCrypto().ValidateKeyWithFingerprint(req.APIKey, req.MachineFingerprint)
	if errCode != "" {
		c.JSON(http.StatusOK, HeartbeatResponse{
			Valid:       false,
			ServerTime:  now,
			NextCheckIn: 3600, // 1 小时后重试
		})
		return
	}

	// 检查 Key 是否被吊销
	if lk, _ := h.store.GetLicensedKeyByID(payload.KeyID); lk != nil && lk.Revoked {
		c.JSON(http.StatusOK, HeartbeatResponse{
			Valid:       false,
			ServerTime:  now,
			NextCheckIn: 3600,
		})
		return
	}

	// 计算下次检查间隔（根据剩余有效期动态调整）
	expiresAt := time.Unix(payload.ExpiresAt, 0)
	remaining := expiresAt.Sub(time.Now())
	var nextCheckIn int64 = 86400 // 默认 24 小时
	if remaining < 7*24*time.Hour {
		nextCheckIn = 3600 // 剩余不足 7 天，每小时检查
	} else if remaining < 30*24*time.Hour {
		nextCheckIn = 21600 // 剩余不足 30 天，每 6 小时检查
	}

	c.JSON(http.StatusOK, HeartbeatResponse{
		Valid:       true,
		ExpiresAt:   expiresAt,
		ServerTime:  now,
		NextCheckIn: nextCheckIn,
	})
}
