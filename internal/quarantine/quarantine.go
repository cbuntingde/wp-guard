package quarantine

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
)

type Manager struct {
	cfg        *config.Config
	quarantine string
}

func NewManager(cfg *config.Config) (*Manager, error) {
	q := cfg.QuarantinePath
	if q == "" {
		q = filepath.Join(filepath.Dir(cfg.BaselinePath), "quarantine")
	}

	if err := os.MkdirAll(q, 0755); err != nil {
		return nil, err
	}

	return &Manager{
		cfg:        cfg,
		quarantine: q,
	}, nil
}

func (m *Manager) QuarantineFile(path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	// Read file
	data, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	// Build quarantine filename with timestamp
	ts := time.Now().Format("20060102-150405")
	orig := filepath.Base(absPath)
	quarName := fmt.Sprintf("%s_%s", ts, orig)
	quarPath := filepath.Join(m.quarantine, quarName)

	// Write to quarantine
	if err := os.WriteFile(quarPath, data, 0600); err != nil {
		return fmt.Errorf("writing quarantine: %w", err)
	}

	log.Printf("[quarantine] moved %s -> %s", path, quarPath)
	return nil
}

func (m *Manager) RestoreFile(relPath string, backupHash string) error {
	// Find the quarantined version
	quarFiles, err := os.ReadDir(m.quarantine)
	if err != nil {
		return err
	}

	originalPath := filepath.Join(m.cfg.WatchPath, relPath)

	for _, f := range quarFiles {
		if f.Name() == "" {
			continue
		}
		// Check if this quarantine entry matches our file
		quarPath := filepath.Join(m.quarantine, f.Name())

		data, err := os.ReadFile(quarPath)
		if err != nil {
			continue
		}

		// Simple heuristic: first part of quarantine filename contains original name
		if len(f.Name()) > 20 && f.Name()[20:] == filepath.Base(originalPath) {
			return os.WriteFile(originalPath, data, 0644)
		}
	}

	return fmt.Errorf("quarantined backup not found for %s", relPath)
}

func (m *Manager) ListQuarantined() ([]string, error) {
	entries, err := os.ReadDir(m.quarantine)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, filepath.Join(m.quarantine, e.Name()))
		}
	}
	return files, nil
}

func CopyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}