// Package management 提供管理 API 处理器和中间件
package management

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	log "github.com/sirupsen/logrus"
)

// PanelState 前端面板持久化状态
type PanelState struct {
	Version     int                        `json:"version"`
	UpdatedAt   time.Time                  `json:"updated_at"`
	ModelPrices map[string]ModelPriceEntry `json:"model_prices,omitempty"`
	// 未来可扩展其他前端需要持久化的状态
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// ModelPriceEntry 模型价格条目
type ModelPriceEntry struct {
	Prompt     float64 `json:"prompt"`
	Completion float64 `json:"completion"`
	Cache      float64 `json:"cache"`
}

// PanelStateStore 面板状态存储
type PanelStateStore struct {
	mu             sync.RWMutex
	filePath       string
	state          *PanelState
	autoSaveCtx    context.Context
	autoSaveCancel context.CancelFunc
	dirty          bool // 标记是否有未保存的更改
}

// panelStateStoreInstance 全局单例
var (
	panelStateStoreInstance *PanelStateStore
	panelStateStoreMu       sync.Mutex
)

// GetPanelStateStore 获取面板状态存储单例
func GetPanelStateStore(configFilePath string) *PanelStateStore {
	panelStateStoreMu.Lock()
	defer panelStateStoreMu.Unlock()

	if panelStateStoreInstance != nil {
		return panelStateStoreInstance
	}

	panelStateStoreInstance = newPanelStateStore(configFilePath)
	return panelStateStoreInstance
}

// GetPanelStateStoreIfExists 获取面板状态存储（如果存在）
func GetPanelStateStoreIfExists() *PanelStateStore {
	panelStateStoreMu.Lock()
	defer panelStateStoreMu.Unlock()
	return panelStateStoreInstance
}

// InitPanelStateStore 初始化面板状态存储
func InitPanelStateStore(configFilePath string, autoSaveInterval time.Duration) *PanelStateStore {
	panelStateStoreMu.Lock()
	defer panelStateStoreMu.Unlock()

	// 如果已存在，先停止自动保存
	if panelStateStoreInstance != nil {
		panelStateStoreInstance.StopAutoSave()
	}

	panelStateStoreInstance = newPanelStateStore(configFilePath)

	// 启动自动保存
	if autoSaveInterval > 0 {
		panelStateStoreInstance.StartAutoSave(autoSaveInterval)
	}

	return panelStateStoreInstance
}

func newPanelStateStore(configFilePath string) *PanelStateStore {
	// 计算存储路径：优先使用配置文件目录，其次是 WRITABLE_PATH，最后是当前工作目录
	var dir string

	// 1. 尝试使用配置文件目录
	if configFilePath != "" {
		dir = filepath.Dir(configFilePath)
		if dir != "" && dir != "." {
			// 配置文件路径有效
			log.Debugf("面板状态存储：使用配置文件目录: %s", dir)
		} else {
			dir = ""
		}
	}

	// 2. 如果配置文件目录无效，尝试使用 WRITABLE_PATH
	if dir == "" {
		if writablePath := util.WritablePath(); writablePath != "" {
			dir = writablePath
			log.Debugf("面板状态存储：使用 WRITABLE_PATH: %s", dir)
		}
	}

	// 3. 最后使用当前工作目录
	if dir == "" {
		if wd, err := os.Getwd(); err == nil {
			dir = wd
			log.Debugf("面板状态存储：使用当前工作目录: %s", dir)
		} else {
			dir = "."
			log.Warnf("面板状态存储：无法获取工作目录，使用相对路径: %s", dir)
		}
	}

	filePath := filepath.Join(dir, "panel-state.json")
	log.Infof("面板状态存储文件路径: %s", filePath)

	store := &PanelStateStore{
		filePath: filePath,
		state: &PanelState{
			Version:     1,
			UpdatedAt:   time.Now().UTC(),
			ModelPrices: make(map[string]ModelPriceEntry),
			Extra:       make(map[string]interface{}),
		},
		dirty: false,
	}

	// 尝试从文件加载
	if err := store.load(); err != nil {
		if os.IsNotExist(err) {
			log.Infof("面板状态文件不存在，将创建: %s", filePath)
			// 立即创建空文件
			if saveErr := store.Save(); saveErr != nil {
				log.WithError(saveErr).Warn("创建面板状态文件失败")
			}
		} else {
			log.WithError(err).Warn("加载面板状态失败，使用默认值")
		}
	} else {
		log.Infof("已加载面板状态: %s (模型价格数量: %d)", filePath, len(store.state.ModelPrices))
	}

	return store
}

// load 从文件加载状态
func (s *PanelStateStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var state PanelState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	// 确保 map 不为 nil
	if state.ModelPrices == nil {
		state.ModelPrices = make(map[string]ModelPriceEntry)
	}
	if state.Extra == nil {
		state.Extra = make(map[string]interface{})
	}

	s.state = &state
	s.dirty = false
	return nil
}

// Save 保存状态到文件
func (s *PanelStateStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.saveUnlocked()
}

// saveUnlocked 不加锁保存（内部使用）
func (s *PanelStateStore) saveUnlocked() error {
	s.state.UpdatedAt = time.Now().UTC()

	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}

	// 确保目录存在
	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(s.filePath, data, 0644); err != nil {
		return err
	}

	s.dirty = false
	return nil
}

// SaveIfDirty 如果有未保存的更改则保存
func (s *PanelStateStore) SaveIfDirty() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.dirty {
		return nil
	}

	return s.saveUnlocked()
}

// GetState 获取当前状态（只读副本）
func (s *PanelStateStore) GetState() PanelState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 返回副本
	prices := make(map[string]ModelPriceEntry, len(s.state.ModelPrices))
	for k, v := range s.state.ModelPrices {
		prices[k] = v
	}

	extra := make(map[string]interface{}, len(s.state.Extra))
	for k, v := range s.state.Extra {
		extra[k] = v
	}

	return PanelState{
		Version:     s.state.Version,
		UpdatedAt:   s.state.UpdatedAt,
		ModelPrices: prices,
		Extra:       extra,
	}
}

// UpdateState 更新状态
func (s *PanelStateStore) UpdateState(state PanelState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if state.ModelPrices != nil {
		s.state.ModelPrices = state.ModelPrices
	}
	if state.Extra != nil {
		s.state.Extra = state.Extra
	}
	s.state.UpdatedAt = time.Now().UTC()
	s.dirty = true
}

// FilePath 返回存储文件路径
func (s *PanelStateStore) FilePath() string {
	return s.filePath
}

// StartAutoSave 启动自动保存
func (s *PanelStateStore) StartAutoSave(interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 如果已有自动保存，先停止
	if s.autoSaveCancel != nil {
		s.autoSaveCancel()
	}

	s.autoSaveCtx, s.autoSaveCancel = context.WithCancel(context.Background())

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-s.autoSaveCtx.Done():
				return
			case <-ticker.C:
				if err := s.SaveIfDirty(); err != nil {
					log.WithError(err).Warn("自动保存面板状态失败")
				} else if s.dirty {
					log.Debug("已自动保存面板状态")
				}
			}
		}
	}()

	log.Infof("面板状态自动保存已启动，间隔: %v", interval)
}

// StopAutoSave 停止自动保存
func (s *PanelStateStore) StopAutoSave() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.autoSaveCancel != nil {
		s.autoSaveCancel()
		s.autoSaveCancel = nil
	}
}

// Handler 方法：获取面板状态
func (h *Handler) GetPanelState(c *gin.Context) {
	store := GetPanelStateStore(h.configFilePath)
	state := store.GetState()
	log.Debugf("GetPanelState: 返回状态，模型价格数量=%d, 文件路径=%s", len(state.ModelPrices), store.FilePath())
	c.JSON(http.StatusOK, state)
}

// Handler 方法：更新面板状态
func (h *Handler) UpdatePanelState(c *gin.Context) {
	var payload PanelState
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求体"})
		return
	}

	store := GetPanelStateStore(h.configFilePath)
	store.UpdateState(payload)

	// 立即保存
	if err := store.Save(); err != nil {
		log.WithError(err).Error("保存面板状态失败")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存失败"})
		return
	}

	log.Infof("面板状态已更新: 模型价格数量=%d", len(payload.ModelPrices))
	c.JSON(http.StatusOK, gin.H{"status": "ok", "updated_at": time.Now().UTC()})
}

// SavePanelStateOnShutdown 在关闭时保存面板状态（供 Server.Shutdown 调用）
func SavePanelStateOnShutdown() {
	panelStateStoreMu.Lock()
	store := panelStateStoreInstance
	panelStateStoreMu.Unlock()

	if store == nil {
		log.Debug("面板状态存储未初始化，跳过保存")
		return
	}

	// 停止自动保存
	store.StopAutoSave()

	// 保存最终状态
	if err := store.Save(); err != nil {
		log.WithError(err).Warn("关闭时保存面板状态失败")
	} else {
		log.Infof("已保存面板状态到: %s", store.FilePath())
	}
}
