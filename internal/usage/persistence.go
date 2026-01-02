// Package usage provides usage tracking and logging functionality for the CLI Proxy API server.
package usage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	log "github.com/sirupsen/logrus"
)

// UsagePersistence 使用统计持久化管理
type UsagePersistence struct {
	mu             sync.RWMutex
	filePath       string
	stats          *RequestStatistics
	autoSaveCtx    context.Context
	autoSaveCancel context.CancelFunc
	dirty          bool
	lastSaveTime   time.Time
}

// usagePersistenceInstance 全局单例
var (
	usagePersistenceInstance *UsagePersistence
	usagePersistenceMu       sync.Mutex
)

// persistedUsageData 持久化的使用数据结构
type persistedUsageData struct {
	Version   int                `json:"version"`
	UpdatedAt time.Time          `json:"updated_at"`
	Usage     StatisticsSnapshot `json:"usage"`
}

// InitUsagePersistence 初始化使用统计持久化
func InitUsagePersistence(configFilePath string, autoSaveInterval time.Duration) *UsagePersistence {
	usagePersistenceMu.Lock()
	defer usagePersistenceMu.Unlock()

	// 如果已存在，先停止自动保存
	if usagePersistenceInstance != nil {
		usagePersistenceInstance.StopAutoSave()
	}

	usagePersistenceInstance = newUsagePersistence(configFilePath)

	// 启动自动保存
	if autoSaveInterval > 0 {
		usagePersistenceInstance.StartAutoSave(autoSaveInterval)
	}

	return usagePersistenceInstance
}

// GetUsagePersistence 获取使用统计持久化单例
func GetUsagePersistence() *UsagePersistence {
	usagePersistenceMu.Lock()
	defer usagePersistenceMu.Unlock()
	return usagePersistenceInstance
}

func newUsagePersistence(configFilePath string) *UsagePersistence {
	// 计算存储路径：优先使用配置文件目录，其次是 WRITABLE_PATH，最后是当前工作目录
	var dir string

	// 1. 尝试使用配置文件目录
	if configFilePath != "" {
		dir = filepath.Dir(configFilePath)
		if dir != "" && dir != "." {
			log.Debugf("使用统计持久化：使用配置文件目录: %s", dir)
		} else {
			dir = ""
		}
	}

	// 2. 如果配置文件目录无效，尝试使用 WRITABLE_PATH
	if dir == "" {
		if writablePath := util.WritablePath(); writablePath != "" {
			dir = writablePath
			log.Debugf("使用统计持久化：使用 WRITABLE_PATH: %s", dir)
		}
	}

	// 3. 最后使用当前工作目录
	if dir == "" {
		if wd, err := os.Getwd(); err == nil {
			dir = wd
			log.Debugf("使用统计持久化：使用当前工作目录: %s", dir)
		} else {
			dir = "."
			log.Warnf("使用统计持久化：无法获取工作目录，使用相对路径: %s", dir)
		}
	}

	filePath := filepath.Join(dir, "usage-stats.json")
	log.Infof("使用统计持久化文件路径: %s", filePath)

	persistence := &UsagePersistence{
		filePath:     filePath,
		stats:        defaultRequestStatistics,
		dirty:        false,
		lastSaveTime: time.Now(),
	}

	// 尝试从文件加载
	if err := persistence.Load(); err != nil {
		if os.IsNotExist(err) {
			log.Infof("使用统计文件不存在，将在有数据时创建: %s", filePath)
		} else {
			log.WithError(err).Warn("加载使用统计失败，使用空数据")
		}
	}

	return persistence
}

// Load 从文件加载使用统计
func (p *UsagePersistence) Load() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return err
	}

	var persisted persistedUsageData
	if err := json.Unmarshal(data, &persisted); err != nil {
		return err
	}

	// 合并加载的数据到统计中
	if p.stats != nil {
		result := p.stats.MergeSnapshot(persisted.Usage)
		log.Infof("已加载使用统计: %s (添加 %d 条记录，跳过 %d 条重复)", p.filePath, result.Added, result.Skipped)
	}

	p.dirty = false
	return nil
}

// Save 保存使用统计到文件
func (p *UsagePersistence) Save() error {
	if p == nil || p.stats == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	return p.saveUnlocked()
}

// saveUnlocked 不加锁保存（内部使用）
func (p *UsagePersistence) saveUnlocked() error {
	snapshot := p.stats.Snapshot()

	// 如果没有数据，不保存
	if snapshot.TotalRequests == 0 {
		return nil
	}

	persisted := persistedUsageData{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Usage:     snapshot,
	}

	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}

	// 确保目录存在
	dir := filepath.Dir(p.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if err := os.WriteFile(p.filePath, data, 0644); err != nil {
		return err
	}

	p.dirty = false
	p.lastSaveTime = time.Now()
	return nil
}

// MarkDirty 标记数据已修改
func (p *UsagePersistence) MarkDirty() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.dirty = true
	p.mu.Unlock()
}

// SaveIfDirty 如果有未保存的更改则保存
func (p *UsagePersistence) SaveIfDirty() error {
	if p == nil {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.dirty {
		return nil
	}

	return p.saveUnlocked()
}

// FilePath 返回存储文件路径
func (p *UsagePersistence) FilePath() string {
	if p == nil {
		return ""
	}
	return p.filePath
}

// StartAutoSave 启动自动保存
func (p *UsagePersistence) StartAutoSave(interval time.Duration) {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// 如果已有自动保存，先停止
	if p.autoSaveCancel != nil {
		p.autoSaveCancel()
	}

	p.autoSaveCtx, p.autoSaveCancel = context.WithCancel(context.Background())

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-p.autoSaveCtx.Done():
				return
			case <-ticker.C:
				// 每次都保存（因为使用统计会不断变化）
				if err := p.Save(); err != nil {
					log.WithError(err).Warn("自动保存使用统计失败")
				} else {
					snapshot := p.stats.Snapshot()
					if snapshot.TotalRequests > 0 {
						log.Debugf("已自动保存使用统计: %d 请求, %d tokens", snapshot.TotalRequests, snapshot.TotalTokens)
					}
				}
			}
		}
	}()

	log.Infof("使用统计自动保存已启动，间隔: %v", interval)
}

// StopAutoSave 停止自动保存
func (p *UsagePersistence) StopAutoSave() {
	if p == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.autoSaveCancel != nil {
		p.autoSaveCancel()
		p.autoSaveCancel = nil
	}
}

// SaveUsageOnShutdown 在关闭时保存使用统计（供 Server.Shutdown 调用）
func SaveUsageOnShutdown() {
	usagePersistenceMu.Lock()
	persistence := usagePersistenceInstance
	usagePersistenceMu.Unlock()

	if persistence == nil {
		log.Debug("使用统计持久化未初始化，跳过保存")
		return
	}

	// 停止自动保存
	persistence.StopAutoSave()

	// 保存最终状态
	if err := persistence.Save(); err != nil {
		log.WithError(err).Warn("关闭时保存使用统计失败")
	} else {
		log.Infof("已保存使用统计到: %s", persistence.FilePath())
	}
}

// StartDefault 启动默认的持久化（在 service.Run 中调用）
// 这个函数会在没有显式初始化时使用默认配置
func StartDefault(ctx context.Context) {
	usagePersistenceMu.Lock()
	defer usagePersistenceMu.Unlock()

	// 如果已经初始化，跳过
	if usagePersistenceInstance != nil {
		return
	}

	// 使用默认配置初始化
	usagePersistenceInstance = newUsagePersistence("")

	// 启动自动保存（默认 5 分钟）
	usagePersistenceInstance.StartAutoSave(5 * time.Minute)
}
