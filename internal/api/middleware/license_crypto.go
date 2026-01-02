// Package middleware 提供 HTTP 中间件实现
package middleware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// 内嵌的加密密钥（编译时混淆）
// 实际部署时应通过环境变量或安全配置注入
var (
	// 32字节 AES-256 密钥（生产环境应替换）
	defaultEncryptionKey = []byte{
		0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x4b,
		0x65, 0x79, 0x32, 0x30, 0x32, 0x35, 0x53, 0x65,
		0x63, 0x75, 0x72, 0x65, 0x50, 0x72, 0x6f, 0x78,
		0x79, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x21,
	}
	// HMAC 签名密钥
	defaultSigningKey = []byte{
		0x48, 0x4d, 0x41, 0x43, 0x53, 0x69, 0x67, 0x6e,
		0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x32, 0x30,
		0x32, 0x35, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x41,
		0x50, 0x49, 0x53, 0x65, 0x63, 0x75, 0x72, 0x65,
	}
)

// LicenseCrypto 提供加密和签名功能
type LicenseCrypto struct {
	encryptionKey []byte
	signingKey    []byte
}

// NewLicenseCrypto 创建加密工具实例
func NewLicenseCrypto(encKey, signKey []byte) *LicenseCrypto {
	if len(encKey) == 0 {
		encKey = defaultEncryptionKey
	}
	if len(signKey) == 0 {
		signKey = defaultSigningKey
	}
	return &LicenseCrypto{
		encryptionKey: encKey,
		signingKey:    signKey,
	}
}

// Encrypt 使用 AES-256-GCM 加密数据
func (c *LicenseCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	// nonce + ciphertext + tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt 使用 AES-256-GCM 解密数据
func (c *LicenseCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	return plaintext, nil
}

// KeyPayload Key 中加密的数据结构
type KeyPayload struct {
	FingerprintHash string   `json:"fp"`            // 机器指纹哈希
	ExpiresAt       int64    `json:"exp"`           // 过期时间戳
	KeyID           string   `json:"kid"`           // Key 唯一标识
	Salt            string   `json:"s"`             // 随机盐（防止相同指纹生成相同密文）
	AllowedModels   []string `json:"am,omitempty"`  // 允许使用的模型列表（支持通配符，空表示不限制）
}

// GenerateEncryptedKey 生成加密的 API Key
// 格式: sk-lic-{base64url(AES-GCM加密(KeyPayload))}
// 安全性: 加密密钥只在服务端，客户端无法伪造
func (c *LicenseCrypto) GenerateEncryptedKey(fingerprintHash string, expiresAt time.Time, allowedModels []string) (string, string, error) {
	// 生成随机 Key ID
	keyIDBytes := make([]byte, 8)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return "", "", fmt.Errorf("生成 Key ID 失败: %w", err)
	}
	keyID := hex.EncodeToString(keyIDBytes)

	// 生成随机盐
	saltBytes := make([]byte, 8)
	if _, err := rand.Read(saltBytes); err != nil {
		return "", "", fmt.Errorf("生成盐失败: %w", err)
	}

	// 构造 payload
	payload := KeyPayload{
		FingerprintHash: fingerprintHash,
		ExpiresAt:       expiresAt.Unix(),
		KeyID:           keyID,
		Salt:            hex.EncodeToString(saltBytes),
		AllowedModels:   allowedModels,
	}

	// JSON 序列化
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", "", fmt.Errorf("序列化 payload 失败: %w", err)
	}

	// AES-GCM 加密
	encrypted, err := c.Encrypt(payloadJSON)
	if err != nil {
		return "", "", fmt.Errorf("加密失败: %w", err)
	}

	// Base64URL 编码（URL 安全）
	encoded := base64.RawURLEncoding.EncodeToString(encrypted)

	// 组装最终 Key
	apiKey := fmt.Sprintf("sk-lic-%s", encoded)

	return apiKey, keyID, nil
}

// DecryptKey 解密 API Key，提取 payload
// 返回: payload, error
func (c *LicenseCrypto) DecryptKey(apiKey string) (*KeyPayload, error) {
	// 检查前缀
	if !strings.HasPrefix(apiKey, "sk-lic-") {
		return nil, fmt.Errorf("无效的 Key 格式")
	}

	// 提取加密部分
	encoded := strings.TrimPrefix(apiKey, "sk-lic-")

	// Base64URL 解码
	encrypted, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %w", err)
	}

	// AES-GCM 解密
	decrypted, err := c.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	// JSON 反序列化
	var payload KeyPayload
	if err := json.Unmarshal(decrypted, &payload); err != nil {
		return nil, fmt.Errorf("解析 payload 失败: %w", err)
	}

	return &payload, nil
}

// ValidateKeyWithFingerprint 验证 Key 并检查指纹是否匹配
// rawFingerprint: 请求中携带的原始机器指纹
// 返回: payload（如果验证成功）, 错误码
func (c *LicenseCrypto) ValidateKeyWithFingerprint(apiKey, rawFingerprint string) (*KeyPayload, string) {
	// 解密 Key
	payload, err := c.DecryptKey(apiKey)
	if err != nil {
		return nil, "INVALID_KEY"
	}

	// 检查过期
	if time.Now().Unix() > payload.ExpiresAt {
		return nil, "KEY_EXPIRED"
	}

	// 验证指纹
	requestFpHash := c.HashFingerprint(rawFingerprint)
	if !hmac.Equal([]byte(payload.FingerprintHash), []byte(requestFpHash)) {
		return nil, "FINGERPRINT_MISMATCH"
	}

	return payload, ""
}

// GenerateNonce 生成防重放 nonce
func (c *LicenseCrypto) GenerateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidateTimestamp 验证时间戳是否在有效范围内（防重放）
func (c *LicenseCrypto) ValidateTimestamp(timestamp int64, maxAgeSeconds int64) bool {
	now := time.Now().Unix()
	diff := now - timestamp
	if diff < 0 {
		diff = -diff
	}
	return diff <= maxAgeSeconds
}

// HashFingerprint 对机器指纹进行安全哈希
func (c *LicenseCrypto) HashFingerprint(rawFingerprint string) string {
	// 加盐哈希
	salt := "LicenseFingerprint2025Salt"
	data := rawFingerprint + salt

	h := sha256.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// EncryptToBase64 加密并转为 Base64 字符串
func (c *LicenseCrypto) EncryptToBase64(plaintext []byte) (string, error) {
	encrypted, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptFromBase64 从 Base64 解密
func (c *LicenseCrypto) DecryptFromBase64(encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %w", err)
	}
	return c.Decrypt(ciphertext)
}

// GenerateSecureRandom 生成安全随机字节
func GenerateSecureRandom(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// DeriveKey 从密码派生密钥（PBKDF2 简化版）
func DeriveKey(password string, salt []byte, iterations int) []byte {
	key := []byte(password)
	for i := 0; i < iterations; i++ {
		h := sha256.New()
		h.Write(key)
		h.Write(salt)
		key = h.Sum(nil)
	}
	return key
}
