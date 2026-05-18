package autofix

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
	"github.com/cbuntingde/wp-guard/internal/scanner"
)

type Manager struct {
	cfg     *config.Config
	scanner *scanner.Scanner
	backups string
}

func NewManager(cfg *config.Config, sc *scanner.Scanner) (*Manager, error) {
	m := &Manager{
		cfg:     cfg,
		scanner: sc,
	}

	// Create backup directory
	if cfg.AutoFix.CreateBackup {
		backups := filepath.Join(filepath.Dir(cfg.BaselinePath), "backups")
		if err := os.MkdirAll(backups, 0755); err != nil {
			return nil, err
		}
		m.backups = backups
	}

	return m, nil
}

// IsPluginsDir checks if the file is in the plugins directory
func (m *Manager) IsPluginsDir(path string) bool {
	if !m.cfg.AutoFix.PluginsOnly {
		return true // auto-fix any path if not limited to plugins
	}

	pluginsDir := m.cfg.WordPress.PluginsDir
	if pluginsDir == "" {
		pluginsDir = "wp-content/plugins"
	}

	// Check if path contains plugins dir
	absWatch, _ := filepath.Abs(m.cfg.WatchPath)
	absPath, _ := filepath.Abs(path)

	relPath, err := filepath.Rel(absWatch, absPath)
	if err != nil {
		return false
	}

	return len(relPath) > len(pluginsDir) &&
		relPath[:len(pluginsDir)] == pluginsDir
}

// HealthCheck verifies WordPress is responding
func (m *Manager) HealthCheck(ctx context.Context) error {
	if m.cfg.AutoFix.HealthCheckURL == "" {
		// No health check configured, assume healthy
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", m.cfg.AutoFix.HealthCheckURL, nil)
	if err != nil {
		return fmt.Errorf("health check request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("WP returned %d", resp.StatusCode)
	}

	return nil
}

// CreateBackup saves a backup before modification
func (m *Manager) CreateBackup(path string) (string, error) {
	if m.backups == "" {
		return "", nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	ts := time.Now().Format("20060102-150405")
	orig := filepath.Base(path)
	backupName := fmt.Sprintf("%s_%s", ts, orig)
	backupPath := filepath.Join(m.backups, backupName)

	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return "", err
	}

	log.Printf("[autofix] backup created: %s", backupPath)
	return backupPath, nil
}

// ApplyFix applies AI-generated fix with rollback on failure
func (m *Manager) ApplyFix(ctx context.Context, path string, fixedCode string) error {
	// 1. Pre-health check
	log.Printf("[autofix] pre-health check for %s", path)
	if err := m.HealthCheck(ctx); err != nil {
		log.Printf("[autofix] pre-health check failed: %v - proceeding anyway", err)
	}

	// 2. Create backup
	backupPath, err := m.CreateBackup(path)
	if err != nil {
		log.Printf("[autofix] backup failed: %v", err)
	}
	_ = backupPath

	// 3. Apply fix (write new code)
	log.Printf("[autofix] applying fix to %s", path)
	if err := os.WriteFile(path, []byte(fixedCode), 0644); err != nil {
		return fmt.Errorf("write fix: %w", err)
	}

	// 4. Post-health check
	log.Printf("[autofix] post-health check")
	if err := m.HealthCheck(ctx); err != nil {
		if m.cfg.AutoFix.RollbackOnFail && backupPath != "" {
			log.Printf("[autofix] health check failed, rolling back: %v", err)
			return m.Rollback(path, backupPath)
		}
		return fmt.Errorf("health check failed after fix: %w", err)
	}

	log.Printf("[autofix] fix applied successfully: %s", path)
	return nil
}

// Rollback restores from backup
func (m *Manager) Rollback(path string, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write rollback: %w", err)
	}

	log.Printf("[autofix] rolled back: %s", path)

	// Verify health after rollback
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := m.HealthCheck(ctx); err != nil {
		log.Printf("[autofix] CRITICAL: health check failed after rollback!")
		return fmt.Errorf("health check failed after rollback: %w", err)
	}

	return nil
}

// IsAutofixEnabled checks if auto-fix is enabled and applies to this file
func (m *Manager) IsAutofixEnabled(path string) bool {
	if !m.cfg.AutoFix.Enabled {
		return false
	}
	return m.IsPluginsDir(path)
}