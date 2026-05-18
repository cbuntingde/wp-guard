package store

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FileRecord struct {
	Path       string    `json:"path"`
	Hash       string    `json:"hash"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"mod_time"`
	Mode       string    `json:"mode"`
	IsNew      bool      `json:"is_new"`
	IsDeleted  bool      `json:"is_deleted"`
	WasQuarantined bool  `json:"was_quarantined"`
}

type Baseline struct {
	Root     string                 `json:"root"`
	Scanned  time.Time             `json:"scanned"`
	Files    map[string]FileRecord `json:"files"`
	Version  int                   `json:"version"`
}

func NewBaseline(root string) *Baseline {
	return &Baseline{
		Root:    root,
		Scanned: time.Now(),
		Files:   make(map[string]FileRecord),
		Version: 1,
	}
}

func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

func ScanDirectory(root string, excludeExts, excludePaths []string) (*Baseline, error) {
	base := NewBaseline(root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}

		if rel == "." {
			return nil
		}

		// check exclusions
		for _, ex := range excludePaths {
			if strings.HasPrefix(rel, ex) {
				return nil
			}
		}
		ext := filepath.Ext(path)
		for _, ex := range excludeExts {
			if ext == ex {
				return nil
			}
		}

		if info.IsDir() {
			return nil
		}

		hash, err := HashFile(path)
		if err != nil {
			return nil
		}

		base.Files[rel] = FileRecord{
			Path:    rel,
			Hash:    hash,
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Mode:    info.Mode().String(),
			IsNew:   false,
		}

		return nil
	})

	return base, err
}

func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (b *Baseline) CheckFile(relPath, newHash string, newSize int64) ChangeType {
	record, exists := b.Files[relPath]
	if !exists {
		return ChangeNew
	}

	if record.Hash != newHash {
		return ChangeModified
	}

	_ = record // suppress unused warning
	return ChangeClean
}

type ChangeType int

const (
	ChangeClean ChangeType = iota
	ChangeNew
	ChangeModified
	ChangeDeleted
)