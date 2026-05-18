package watcher

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
	"github.com/cbuntingde/wp-guard/internal/scanner"
	"github.com/cbuntingde/wp-guard/internal/store"
)

type EventType int

const (
	EventCreate EventType = iota
	EventModify
	EventDelete
	EventMove
)

type FileEvent struct {
	Type      EventType
	Path      string
	RelPath   string
	Timestamp time.Time
}

type Watcher struct {
	cfg      *config.Config
	scanner  *scanner.Scanner
	baseline *store.Baseline

	root       string
	excludeExt []string
	excludePath []string

	events chan FileEvent
	quit   chan struct{}
	wg     sync.WaitGroup
}

func NewWatcher(cfg *config.Config, baseline *store.Baseline) *Watcher {
	return &Watcher{
		cfg:        cfg,
		scanner:    scanner.NewScanner(cfg.Scanner, cfg.AI),
		baseline:   baseline,
		root:       cfg.WatchPath,
		excludeExt: cfg.Scanner.ExcludeExtensions,
		excludePath: cfg.Scanner.ExcludePaths,
		events:     make(chan FileEvent, 100),
		quit:       make(chan struct{}),
	}
}

func (w *Watcher) Start(ctx context.Context) {
	w.wg.Add(2)
	go w.fsnotifyLoop(ctx)
	go w.pollLoop(ctx)
}

func (w *Watcher) Stop() {
	close(w.quit)
	w.wg.Wait()
}

func (w *Watcher) Events() <-chan FileEvent {
	return w.events
}

func (w *Watcher) fsnotifyLoop(ctx context.Context) {
	defer w.wg.Done()

	// Use polling fallback if fsnotify isn't available
	ticker := time.NewTicker(time.Duration(w.cfg.PollIntervalSec) * time.Second)
	defer ticker.Stop()

	log.Printf("[watcher] starting poll loop every %ds", w.cfg.PollIntervalSec)

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.quit:
			return
		case <-ticker.C:
			w.checkForChanges(ctx)
		}
	}
}

func (w *Watcher) pollLoop(ctx context.Context) {
	defer w.wg.Done()
	// Currently not used - fsnotifyLoop handles polling
	// Reserved for future fsnotify integration if needed
}

func (w *Watcher) checkForChanges(ctx context.Context) {
	_ = ctx
	currentFiles := make(map[string]store.FileRecord)

	err := filepath.Walk(w.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		rel, err := filepath.Rel(w.root, path)
		if err != nil || rel == "." {
			return nil
		}

		// check exclusions
		for _, ex := range w.excludePath {
			if strings.HasPrefix(rel, ex) {
				return filepath.SkipDir
			}
		}
		ext := filepath.Ext(path)
		for _, ex := range w.excludeExt {
			if ext == ex {
				return nil
			}
		}

		if info.IsDir() {
			return nil
		}

		hash, err := store.HashFile(path)
		if err != nil {
			return nil
		}

		currentFiles[rel] = store.FileRecord{
			Path: rel,
			Hash: hash,
			Size: info.Size(),
			ModTime: info.ModTime(),
		}

		return nil
	})

	if err != nil {
		log.Printf("[watcher] error walking directory: %v", err)
		return
	}

	// Check for changes vs baseline
	for rel, current := range currentFiles {
		baselineRecord, exists := w.baseline.Files[rel]

		if !exists {
			// New file
			select {
			case w.events <- FileEvent{
				Type:      EventCreate,
				Path:      filepath.Join(w.root, rel),
				RelPath:   rel,
				Timestamp: time.Now(),
			}:
			default:
			}
		} else if baselineRecord.Hash != current.Hash {
			// Modified
			select {
			case w.events <- FileEvent{
				Type:      EventModify,
				Path:      filepath.Join(w.root, rel),
				RelPath:   rel,
				Timestamp: time.Now(),
			}:
			default:
			}
		}
	}

	// Check for deletions
	for rel, baselineRecord := range w.baseline.Files {
		if _, exists := currentFiles[rel]; !exists {
			select {
			case w.events <- FileEvent{
				Type:      EventDelete,
				Path:      filepath.Join(w.root, rel),
				RelPath:   rel,
				Timestamp: time.Now(),
			}:
			default:
			}
		}
		_ = baselineRecord // suppress unused
	}
}