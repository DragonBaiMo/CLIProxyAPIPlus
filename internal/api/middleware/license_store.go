// Package middleware 提供 HTTP 中间件实现
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ActivationCode 表示一个激活码
type ActivationCode struct {
	Code          string    `json:"code"`                     // ACT-xxxx-yyyy-zzzz
	CreatedAt     time.Time `json:"created_at"`               // 创建时间
	ExpiresAt     time.Time `json:"expires_at"`               // 激活码过期时间（必须在此之前激活）
	Duration      string    `json:"duration"`                 // 激活后 Key 的有效期（如 "30d"）
	MaxUses       int       `json:"max_uses"`                 // 最大激活次数（通常 = 1）
	UsedCount     int       `json:"used_count"`               // 已使用次数
	UsedBy        string    `json:"used_by"`                  // 激活后绑定的机器指纹（仅单次激活时有效）
	Memo          string    `json:"memo"`                     // 备注信息
	Disabled      bool      `json:"disabled"`                 // 是否禁用
	DisabledAt    time.Time `json:"disabled_at"`              // 禁用时间
	AllowedModels []string  `json:"allowed_models,omitempty"` // 允许使用的模型列表（支持通配符，空表示不限制）
}

// LicensedKey 表示一个已激活的 API Key
type LicensedKey struct {
	Key                string    `json:"key"`                      // sk-lic-{加密数据}
	KeyID              string    `json:"key_id"`                   // Key 唯一标识（用于管理）
	ActivationCode     string    `json:"activation_code"`          // 来源激活码
	MachineFingerprint string    `json:"machine_fingerprint"`      // 绑定的机器指纹（哈希）
	ActivatedAt        time.Time `json:"activated_at"`             // 激活时间
	ExpiresAt          time.Time `json:"expires_at"`               // 过期时间
	Revoked            bool      `json:"revoked"`                  // 是否已吊销（可恢复）
	Memo               string    `json:"memo"`                     // 备注信息
	LastUsedAt         time.Time `json:"last_used_at"`             // 最后使用时间
	LastUsedIP         string    `json:"last_used_ip"`             // 最后使用 IP
	UseCount           int       `json:"use_count"`                // 使用次数
	AllowedModels      []string  `json:"allowed_models,omitempty"` // 允许使用的模型列表（继承自激活码）
}

// LicenseData 存储所有激活码和已激活 Key 的数据
type LicenseData struct {
	ActivationCodes []ActivationCode `json:"activation_codes"`
	LicensedKeys    []LicensedKey    `json:"licensed_keys"`
}

// LicenseStore 管理激活码和 API Key 的持久化存储
type LicenseStore struct {
	mu        sync.RWMutex
	filePath  string
	data      LicenseData
	crypto    *LicenseCrypto
	encrypted bool // 是否启用加密存储

	// === 性能优化：内存索引 ===
	keyIDIndex     map[string]int  // KeyID -> LicensedKeys 数组索引
	revokedCache   map[string]bool // KeyID -> 是否被吊销（缓存）
	indexMu        sync.RWMutex    // 索引专用锁（避免与主锁竞争）

	// === 性能优化：批量写入 ===
	pendingUsage   map[string]*usageUpdate // KeyID -> 待写入的使用统计
	usageMu        sync.Mutex              // 使用统计专用锁
	flushInterval  time.Duration           // 批量写入间隔
	flushTicker    *time.Ticker            // 定时器
	stopFlush      chan struct{}           // 停止信号

	// === 性能优化：过期清理 ===
	cleanupInterval time.Duration // 清理间隔
	cleanupTicker   *time.Ticker  // 清理定时器
	stopCleanup     chan struct{} // 停止信号
}

// usageUpdate 待写入的使用统计
type usageUpdate struct {
	LastUsedAt time.Time
	LastUsedIP string
	UseCount   int // 增量计数
}

// NewLicenseStore 创建一个新的 LicenseStore 实例
func NewLicenseStore(filePath string) (*LicenseStore, error) {
	return NewLicenseStoreWithCrypto(filePath, nil, nil, true)
}

// NewLicenseStoreWithCrypto 创建带自定义加密密钥的 LicenseStore
func NewLicenseStoreWithCrypto(filePath string, encKey, signKey []byte, encrypted bool) (*LicenseStore, error) {
	store := &LicenseStore{
		filePath:  filePath,
		encrypted: encrypted,
		crypto:    NewLicenseCrypto(encKey, signKey),
		data: LicenseData{
			ActivationCodes: []ActivationCode{},
			LicensedKeys:    []LicensedKey{},
		},
		// 初始化索引
		keyIDIndex:   make(map[string]int),
		revokedCache: make(map[string]bool),
		// 初始化批量写入
		pendingUsage:  make(map[string]*usageUpdate),
		flushInterval: 30 * time.Second, // 默认 30 秒批量写入一次
		stopFlush:     make(chan struct{}),
		// 初始化过期清理
		cleanupInterval: 1 * time.Hour, // 默认 1 小时清理一次
		stopCleanup:     make(chan struct{}),
	}

	// 尝试加载现有数据
	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("加载 license 数据失败: %w", err)
	}

	// 构建内存索引
	store.rebuildIndex()

	// 启动后台任务
	store.startBackgroundTasks()

	return store, nil
}

// rebuildIndex 重建内存索引（加载数据后调用）
func (s *LicenseStore) rebuildIndex() {
	s.indexMu.Lock()
	defer s.indexMu.Unlock()

	// 清空旧索引
	s.keyIDIndex = make(map[string]int)
	s.revokedCache = make(map[string]bool)

	// 构建 KeyID 索引和吊销缓存
	for i := range s.data.LicensedKeys {
		lk := &s.data.LicensedKeys[i]
		s.keyIDIndex[lk.KeyID] = i
		if lk.Revoked {
			s.revokedCache[lk.KeyID] = true
		}
	}
}

// startBackgroundTasks 启动后台任务（批量写入、过期清理）
func (s *LicenseStore) startBackgroundTasks() {
	// 启动批量写入定时器
	s.flushTicker = time.NewTicker(s.flushInterval)
	go s.flushLoop()

	// 启动过期清理定时器
	s.cleanupTicker = time.NewTicker(s.cleanupInterval)
	go s.cleanupLoop()
}

// flushLoop 批量写入循环
func (s *LicenseStore) flushLoop() {
	for {
		select {
		case <-s.flushTicker.C:
			s.flushPendingUsage()
		case <-s.stopFlush:
			s.flushTicker.Stop()
			// 退出前刷新剩余数据
			s.flushPendingUsage()
			return
		}
	}
}

// flushPendingUsage 将待写入的使用统计批量写入
func (s *LicenseStore) flushPendingUsage() {
	s.usageMu.Lock()
	if len(s.pendingUsage) == 0 {
		s.usageMu.Unlock()
		return
	}
	// 复制待写入数据并清空
	pending := s.pendingUsage
	s.pendingUsage = make(map[string]*usageUpdate)
	s.usageMu.Unlock()

	// 批量更新到内存数据
	s.mu.Lock()
	defer s.mu.Unlock()

	s.indexMu.RLock()
	for keyID, update := range pending {
		if idx, ok := s.keyIDIndex[keyID]; ok && idx < len(s.data.LicensedKeys) {
			s.data.LicensedKeys[idx].LastUsedAt = update.LastUsedAt
			s.data.LicensedKeys[idx].LastUsedIP = update.LastUsedIP
			s.data.LicensedKeys[idx].UseCount += update.UseCount
		}
	}
	s.indexMu.RUnlock()

	// 一次性写入文件
	_ = s.save()
}

// cleanupLoop 过期清理循环
func (s *LicenseStore) cleanupLoop() {
	for {
		select {
		case <-s.cleanupTicker.C:
			s.cleanupExpiredKeys()
		case <-s.stopCleanup:
			s.cleanupTicker.Stop()
			return
		}
	}
}

// cleanupExpiredKeys 清理过期的 Key（惰性删除）
func (s *LicenseStore) cleanupExpiredKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	// 保留 7 天的过期 Key（便于审计）
	cutoff := now.Add(-7 * 24 * time.Hour)

	var cleaned int
	newKeys := make([]LicensedKey, 0, len(s.data.LicensedKeys))
	for i := range s.data.LicensedKeys {
		lk := &s.data.LicensedKeys[i]
		// 只清理过期超过 7 天的 Key
		if lk.ExpiresAt.Before(cutoff) {
			cleaned++
			continue
		}
		newKeys = append(newKeys, *lk)
	}

	if cleaned > 0 {
		s.data.LicensedKeys = newKeys
		_ = s.save()
		// 重建索引
		s.rebuildIndex()
	}
}

// Close 关闭 LicenseStore，停止后台任务并刷新数据
func (s *LicenseStore) Close() {
	// 停止后台任务
	close(s.stopFlush)
	close(s.stopCleanup)
}

// load 从文件加载数据
func (s *LicenseStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	// 如果启用加密，先解密
	if s.encrypted && len(data) > 0 {
		// 检查是否是加密数据（Base64 格式）
		if !isJSONData(data) {
			decrypted, err := s.crypto.DecryptFromBase64(string(data))
			if err != nil {
				// 尝试作为明文 JSON 加载（兼容旧数据）
				if jsonErr := json.Unmarshal(data, &s.data); jsonErr == nil {
					// 成功加载明文数据，下次保存时会自动加密
					return nil
				}
				return fmt.Errorf("解密数据失败: %w", err)
			}
			data = decrypted
		}
	}

	return json.Unmarshal(data, &s.data)
}

// isJSONData 检查数据是否是 JSON 格式
func isJSONData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// JSON 数据以 { 或 [ 开头
	firstChar := data[0]
	return firstChar == '{' || firstChar == '['
}

// save 保存数据到文件
func (s *LicenseStore) save() error {
	// 确保目录存在
	dir := filepath.Dir(s.filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}

	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}

	// 如果启用加密，加密数据
	if s.encrypted {
		encrypted, err := s.crypto.EncryptToBase64(data)
		if err != nil {
			return fmt.Errorf("加密数据失败: %w", err)
		}
		data = []byte(encrypted)
	}

	return os.WriteFile(s.filePath, data, 0600)
}

// GenerateActivationCode 生成新的激活码
// allowedModels: 允许使用的模型列表（支持通配符，空表示不限制）
func (s *LicenseStore) GenerateActivationCode(duration string, validity time.Duration, maxUses int, memo string, allowedModels []string) (*ActivationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 生成随机激活码
	codeBytes := make([]byte, 12)
	if _, err := rand.Read(codeBytes); err != nil {
		return nil, fmt.Errorf("生成随机码失败: %w", err)
	}
	code := fmt.Sprintf("ACT-%s-%s-%s",
		hex.EncodeToString(codeBytes[0:4]),
		hex.EncodeToString(codeBytes[4:8]),
		hex.EncodeToString(codeBytes[8:12]))

	now := time.Now()
	ac := ActivationCode{
		Code:          code,
		CreatedAt:     now,
		ExpiresAt:     now.Add(validity),
		Duration:      duration,
		MaxUses:       maxUses,
		UsedCount:     0,
		Memo:          memo,
		AllowedModels: allowedModels,
	}

	s.data.ActivationCodes = append(s.data.ActivationCodes, ac)

	if err := s.save(); err != nil {
		// 回滚
		s.data.ActivationCodes = s.data.ActivationCodes[:len(s.data.ActivationCodes)-1]
		return nil, err
	}

	return &ac, nil
}

// Activate 使用激活码激活，生成 API Key
func (s *LicenseStore) Activate(activationCode, machineFingerprint string) (*LicensedKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 对机器指纹进行哈希处理
	hashedFingerprint := s.crypto.HashFingerprint(machineFingerprint)

	// 查找激活码
	var ac *ActivationCode
	var acIndex int
	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].Code == activationCode {
			ac = &s.data.ActivationCodes[i]
			acIndex = i
			break
		}
	}

	if ac == nil {
		return nil, fmt.Errorf("激活码不存在")
	}

	// 检查激活码是否过期
	if time.Now().After(ac.ExpiresAt) {
		return nil, fmt.Errorf("激活码已过期")
	}

	// 检查激活码是否被禁用
	if ac.Disabled {
		return nil, fmt.Errorf("激活码已被禁用")
	}

	// 检查使用次数
	if ac.UsedCount >= ac.MaxUses {
		return nil, fmt.Errorf("激活码已达到最大使用次数")
	}

	// 解析有效期
	keyDuration, err := parseDuration(ac.Duration)
	if err != nil {
		return nil, fmt.Errorf("解析有效期失败: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(keyDuration)

	// 生成加密的 API Key（指纹哈希和模型权限嵌入 Key 中）
	apiKey, keyID, err := s.crypto.GenerateEncryptedKey(hashedFingerprint, expiresAt, ac.AllowedModels)
	if err != nil {
		return nil, fmt.Errorf("生成 API Key 失败: %w", err)
	}

	lk := LicensedKey{
		Key:                apiKey,
		ActivationCode:     activationCode,
		MachineFingerprint: hashedFingerprint, // 存储哈希后的指纹（用于管理查询）
		ActivatedAt:        now,
		ExpiresAt:          expiresAt,
		Revoked:            false,
		KeyID:              keyID,             // 存储 Key ID 用于管理
		AllowedModels:      ac.AllowedModels,  // 继承激活码的模型权限
	}

	// 更新激活码使用状态
	s.data.ActivationCodes[acIndex].UsedCount++
	if ac.MaxUses == 1 {
		s.data.ActivationCodes[acIndex].UsedBy = hashedFingerprint
	}

	s.data.LicensedKeys = append(s.data.LicensedKeys, lk)

	// 更新索引
	s.indexMu.Lock()
	s.keyIDIndex[keyID] = len(s.data.LicensedKeys) - 1
	s.indexMu.Unlock()

	if err := s.save(); err != nil {
		// 回滚
		s.data.ActivationCodes[acIndex].UsedCount--
		s.data.ActivationCodes[acIndex].UsedBy = ""
		s.data.LicensedKeys = s.data.LicensedKeys[:len(s.data.LicensedKeys)-1]
		return nil, err
	}

	return &lk, nil
}

// ValidateKey 验证 API Key 是否有效（仅检查是否存在和状态）
// 注意：指纹验证在中间件层通过解密 Key 完成
func (s *LicenseStore) ValidateKey(apiKey string) (*LicensedKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			lk := &s.data.LicensedKeys[i]

			if lk.Revoked {
				return nil, fmt.Errorf("KEY_REVOKED")
			}

			if time.Now().After(lk.ExpiresAt) {
				return nil, fmt.Errorf("KEY_EXPIRED")
			}

			return lk, nil
		}
	}

	return nil, fmt.Errorf("INVALID_KEY")
}

// GetAllActivationCodes 获取所有激活码
func (s *LicenseStore) GetAllActivationCodes() []ActivationCode {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ActivationCode, len(s.data.ActivationCodes))
	copy(result, s.data.ActivationCodes)
	return result
}

// GetAllLicensedKeys 获取所有已激活的 Key
func (s *LicenseStore) GetAllLicensedKeys() []LicensedKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]LicensedKey, len(s.data.LicensedKeys))
	copy(result, s.data.LicensedKeys)
	return result
}

// RevokeKey 撤销指定的 API Key
func (s *LicenseStore) RevokeKey(apiKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			s.data.LicensedKeys[i].Revoked = true
			// 更新吊销缓存
			s.indexMu.Lock()
			s.revokedCache[s.data.LicensedKeys[i].KeyID] = true
			s.indexMu.Unlock()
			return s.save()
		}
	}

	return fmt.Errorf("Key 不存在")
}

// DeleteActivationCode 删除激活码
func (s *LicenseStore) DeleteActivationCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].Code == code {
			s.data.ActivationCodes = append(s.data.ActivationCodes[:i], s.data.ActivationCodes[i+1:]...)
			return s.save()
		}
	}

	return fmt.Errorf("激活码不存在")
}

// DisableActivationCode 禁用激活码
func (s *LicenseStore) DisableActivationCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].Code == code {
			if s.data.ActivationCodes[i].Disabled {
				return fmt.Errorf("激活码已被禁用")
			}
			s.data.ActivationCodes[i].Disabled = true
			s.data.ActivationCodes[i].DisabledAt = time.Now()
			return s.save()
		}
	}

	return fmt.Errorf("激活码不存在")
}

// EnableActivationCode 启用激活码
func (s *LicenseStore) EnableActivationCode(code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].Code == code {
			if !s.data.ActivationCodes[i].Disabled {
				return fmt.Errorf("激活码未被禁用")
			}
			s.data.ActivationCodes[i].Disabled = false
			s.data.ActivationCodes[i].DisabledAt = time.Time{}
			return s.save()
		}
	}

	return fmt.Errorf("激活码不存在")
}

// UpdateActivationCodeMemo 更新激活码备注
func (s *LicenseStore) UpdateActivationCodeMemo(code, memo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].Code == code {
			s.data.ActivationCodes[i].Memo = memo
			return s.save()
		}
	}

	return fmt.Errorf("激活码不存在")
}

// GetActivationCode 获取单个激活码
func (s *LicenseStore) GetActivationCode(code string) (*ActivationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].Code == code {
			ac := s.data.ActivationCodes[i]
			return &ac, nil
		}
	}

	return nil, fmt.Errorf("激活码不存在")
}

// BatchGenerateActivationCodes 批量生成激活码
// allowedModels: 允许使用的模型列表（支持通配符，空表示不限制）
func (s *LicenseStore) BatchGenerateActivationCodes(duration string, validity time.Duration, maxUses, count int, memo string, allowedModels []string) ([]ActivationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var codes []ActivationCode
	now := time.Now()

	for i := 0; i < count; i++ {
		codeBytes := make([]byte, 12)
		if _, err := rand.Read(codeBytes); err != nil {
			return nil, fmt.Errorf("生成随机码失败: %w", err)
		}
		code := fmt.Sprintf("ACT-%s-%s-%s",
			hex.EncodeToString(codeBytes[0:4]),
			hex.EncodeToString(codeBytes[4:8]),
			hex.EncodeToString(codeBytes[8:12]))

		ac := ActivationCode{
			Code:          code,
			CreatedAt:     now,
			ExpiresAt:     now.Add(validity),
			Duration:      duration,
			MaxUses:       maxUses,
			UsedCount:     0,
			Memo:          memo,
			AllowedModels: allowedModels,
		}
		codes = append(codes, ac)
		s.data.ActivationCodes = append(s.data.ActivationCodes, ac)
	}

	if err := s.save(); err != nil {
		// 回滚
		s.data.ActivationCodes = s.data.ActivationCodes[:len(s.data.ActivationCodes)-count]
		return nil, err
	}

	return codes, nil
}

// RestoreKey 恢复已吊销的 Key
func (s *LicenseStore) RestoreKey(apiKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			if !s.data.LicensedKeys[i].Revoked {
				return fmt.Errorf("Key 未被吊销")
			}
			s.data.LicensedKeys[i].Revoked = false
			// 更新吊销缓存
			s.indexMu.Lock()
			delete(s.revokedCache, s.data.LicensedKeys[i].KeyID)
			s.indexMu.Unlock()
			return s.save()
		}
	}

	return fmt.Errorf("Key 不存在")
}

// DeleteKey 永久删除 Key（封禁）
func (s *LicenseStore) DeleteKey(apiKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			s.data.LicensedKeys = append(s.data.LicensedKeys[:i], s.data.LicensedKeys[i+1:]...)
			return s.save()
		}
	}

	return fmt.Errorf("Key 不存在")
}

// UnbindKey 解绑机器（删除 Key 并恢复激活码使用次数）
func (s *LicenseStore) UnbindKey(apiKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var keyIndex = -1
	var activationCode string

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			keyIndex = i
			activationCode = s.data.LicensedKeys[i].ActivationCode
			break
		}
	}

	if keyIndex == -1 {
		return fmt.Errorf("Key 不存在")
	}

	// 恢复激活码使用次数
	for i := range s.data.ActivationCodes {
		if s.data.ActivationCodes[i].Code == activationCode {
			if s.data.ActivationCodes[i].UsedCount > 0 {
				s.data.ActivationCodes[i].UsedCount--
			}
			if s.data.ActivationCodes[i].UsedBy != "" {
				s.data.ActivationCodes[i].UsedBy = ""
			}
			break
		}
	}

	// 删除 Key
	s.data.LicensedKeys = append(s.data.LicensedKeys[:keyIndex], s.data.LicensedKeys[keyIndex+1:]...)

	return s.save()
}

// ExtendKey 延长 Key 有效期
func (s *LicenseStore) ExtendKey(apiKey, duration string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, err := parseDuration(duration)
	if err != nil {
		return fmt.Errorf("解析有效期失败: %w", err)
	}

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			s.data.LicensedKeys[i].ExpiresAt = s.data.LicensedKeys[i].ExpiresAt.Add(d)
			return s.save()
		}
	}

	return fmt.Errorf("Key 不存在")
}

// UpdateKeyMemo 更新 Key 备注
func (s *LicenseStore) UpdateKeyMemo(apiKey, memo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			s.data.LicensedKeys[i].Memo = memo
			return s.save()
		}
	}

	return fmt.Errorf("Key 不存在")
}

// GetLicensedKey 获取单个 Key
func (s *LicenseStore) GetLicensedKey(apiKey string) (*LicensedKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			lk := s.data.LicensedKeys[i]
			return &lk, nil
		}
	}

	return nil, fmt.Errorf("Key 不存在")
}

// GetLicensedKeyByID 通过 KeyID 获取 Key（使用索引优化，O(1) 查找）
func (s *LicenseStore) GetLicensedKeyByID(keyID string) (*LicensedKey, error) {
	s.indexMu.RLock()
	idx, ok := s.keyIDIndex[keyID]
	s.indexMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("Key 不存在")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if idx >= len(s.data.LicensedKeys) {
		return nil, fmt.Errorf("Key 不存在")
	}

	lk := s.data.LicensedKeys[idx]
	return &lk, nil
}

// IsKeyRevoked 快速检查 Key 是否被吊销（使用缓存，O(1) 查找）
func (s *LicenseStore) IsKeyRevoked(keyID string) bool {
	s.indexMu.RLock()
	defer s.indexMu.RUnlock()
	return s.revokedCache[keyID]
}

// UpdateKeyUsage 更新 Key 使用统计
func (s *LicenseStore) UpdateKeyUsage(apiKey, clientIP string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.LicensedKeys {
		if s.data.LicensedKeys[i].Key == apiKey {
			s.data.LicensedKeys[i].LastUsedAt = time.Now()
			s.data.LicensedKeys[i].LastUsedIP = clientIP
			s.data.LicensedKeys[i].UseCount++
			return s.save()
		}
	}

	return fmt.Errorf("Key 不存在")
}

// UpdateKeyUsageByID 通过 KeyID 更新使用统计（批量写入优化，不立即写文件）
func (s *LicenseStore) UpdateKeyUsageByID(keyID, clientIP string) error {
	// 检查 KeyID 是否存在
	s.indexMu.RLock()
	_, exists := s.keyIDIndex[keyID]
	s.indexMu.RUnlock()

	if !exists {
		return fmt.Errorf("Key 不存在")
	}

	// 添加到待写入队列（批量写入）
	s.usageMu.Lock()
	if s.pendingUsage[keyID] == nil {
		s.pendingUsage[keyID] = &usageUpdate{
			LastUsedAt: time.Now(),
			LastUsedIP: clientIP,
			UseCount:   1,
		}
	} else {
		s.pendingUsage[keyID].LastUsedAt = time.Now()
		s.pendingUsage[keyID].LastUsedIP = clientIP
		s.pendingUsage[keyID].UseCount++
	}
	s.usageMu.Unlock()

	return nil
}

// HashFingerprint 对机器指纹进行哈希（公开方法，供外部调用）
func (s *LicenseStore) HashFingerprint(rawFingerprint string) string {
	return s.crypto.HashFingerprint(rawFingerprint)
}

// GetCrypto 返回加密工具实例（供外部验证使用）
func (s *LicenseStore) GetCrypto() *LicenseCrypto {
	return s.crypto
}

// parseDuration 解析持续时间字符串（支持 "30d", "7d", "1h" 等格式）
func parseDuration(s string) (time.Duration, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("空的持续时间字符串")
	}

	// 处理天数格式
	if s[len(s)-1] == 'd' {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	// 使用标准库解析
	return time.ParseDuration(s)
}

// MaskKey 对 Key 进行脱敏处理
func MaskKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:8] + "****" + key[len(key)-4:]
}
