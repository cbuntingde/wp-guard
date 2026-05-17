package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
	"github.com/cbuntingde/wp-guard/internal/notifier"
	"github.com/cbuntingde/wp-guard/internal/quarantine"
	"github.com/cbuntingde/wp-guard/internal/scanner"
	"github.com/cbuntingde/wp-guard/internal/store"
	"github.com/cbuntingde/wp-guard/internal/watcher"
)

var (
	flagConfig   = flag.String("config", "wp-guard.yaml", "Config file path")
	flagBaseline = flag.String("baseline", "", "Baseline file path (overrides config)")
	flagWatch    = flag.String("watch", "", "Watch path (overrides config)")
	flagReinit   = flag.Bool("reinit", false, "Reinitialize baseline and exit")
	flagVersion  = flag.Bool("version", false, "Print version")
)

const version = "0.1.0"

func main() {
	flag.Parse()

	if *flagVersion {
		fmt.Printf("wp-guard %s\n", version)
		return
	}

	// Load config
	cfgPath := *flagConfig
	if !filepath.IsAbs(cfgPath) {
		cwd, _ := os.Getwd()
		cfgPath = filepath.Join(cwd, cfgPath)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	// Override config with CLI flags
	if *flagWatch != "" {
		cfg.WatchPath = *flagWatch
	}

	// Resolve paths
	if !filepath.IsAbs(cfg.WatchPath) {
		cfg.WatchPath, _ = filepath.Abs(cfg.WatchPath)
	}

	baselinePath := cfg.BaselinePath
	if *flagBaseline != "" {
		baselinePath = *flagBaseline
	}
	if baselinePath == "" {
		baselinePath = filepath.Join(filepath.Dir(cfgPath), "baseline.json")
	}
	cfg.BaselinePath = baselinePath

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load or create baseline
	var baseline *store.Baseline
	if *flagReinit {
		baseline = initBaseline(cfg)
		return
	}

	if _, err := os.Stat(cfg.BaselinePath); os.IsNotExist(err) {
		log.Println("No baseline found, creating initial baseline...")
		baseline = initBaseline(cfg)
	} else {
		baseline, err = store.LoadBaseline(cfg.BaselinePath)
		if err != nil {
			log.Fatalf("loading baseline: %v", err)
		}
		log.Printf("Loaded baseline: %d files", len(baseline.Files))
	}

	// Setup notifier
	// Setup notifier
		notif, err := notifier.NewNotifier(cfg.Telegram, cfg.Email, cfg.LogPath)
		if err != nil {
			log.Printf("notifier warning: %v", err)
		}
		defer notif.Close()
	if err != nil {
		log.Printf("notifier warning: %v", err)
	}
	defer notif.Close()

	// Notify startup
	notifier.NotifyStartup(cfg.Telegram)

	// Setup quarantine manager
	quarMgr, err := quarantine.NewManager(cfg)
	if err != nil {
		log.Fatalf("quarantine init: %v", err)
	}

	// Setup scanner
	scan := scanner.NewScanner(cfg.Scanner, cfg.AI)

	// Setup watcher
	w := watcher.NewWatcher(cfg, baseline)
	w.Start(ctx)

	// Handle events
	go handleEvents(ctx, w, notif, quarMgr, scan, cfg)

	// Wait for interrupt
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	cancel()
	w.Stop()
	notifier.NotifyShutdown(cfg.Telegram)
}

func initBaseline(cfg *config.Config) *store.Baseline {
	base, err := store.ScanDirectory(
		cfg.WatchPath,
		cfg.Scanner.ExcludeExtensions,
		cfg.Scanner.ExcludePaths,
	)
	if err != nil {
		log.Fatalf("scanning directory: %v", err)
	}

	if err := base.Save(cfg.BaselinePath); err != nil {
		log.Fatalf("saving baseline: %v", err)
	}

	log.Printf("Baseline saved: %d files", len(base.Files))
	return base
}

func handleEvents(
	ctx context.Context,
	w *watcher.Watcher,
	notif *notifier.Notifier,
	quar *quarantine.Manager,
	scan *scanner.Scanner,
	cfg *config.Config,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-w.Events():
			handleEvent(ctx, ev, notif, quar, scan, cfg)
		}
	}
}

func handleEvent(
	ctx context.Context,
	ev watcher.FileEvent,
	notif *notifier.Notifier,
	quar *quarantine.Manager,
	scan *scanner.Scanner,
	cfg *config.Config,
) {
	log.Printf("[event] %s: %s", eventTypeName(ev.Type), ev.RelPath)

	alert := notifier.Alert{
		Timestamp: ev.Timestamp,
		File:      ev.RelPath,
		EventType: eventTypeName(ev.Type),
	}

	eventCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	_ = eventCtx // TODO: pass to AI triage when implemented

	switch ev.Type {
	case watcher.EventCreate, watcher.EventModify:
		// Scan the file
		results, err := scan.ScanFile(ev.Path)
		if err != nil {
			log.Printf("[scanner] error: %v", err)
			return
		}

		for _, r := range results {
			alert.Severity = r.Severity.String()
			alert.Pattern = r.Pattern
			alert.Message = r.Message

			if r.Severity == scanner.CRITICAL {
				alert.Action = "QUARANTINED"
				quar.QuarantineFile(ev.Path)
				notif.SendAlert(alert)
			} else if r.Severity == scanner.WARN {
				alert.Action = "REVIEW"
				notif.SendAlert(alert)
			}
		}

		// If scan found nothing but it's a modify, still alert if notify_on_clean
		if len(results) == 0 && cfg.NotifyOnClean {
			alert.Severity = "INFO"
			alert.Message = "File changed"
			alert.Action = "BASELINE_UPDATED"
			notif.SendAlert(alert)
		}

		// Update baseline with new hash
		hash, _ := store.HashFile(ev.Path)
		baseline, _ := store.LoadBaseline(cfg.BaselinePath)
		if baseline != nil {
			baseline.Files[ev.RelPath] = store.FileRecord{
				Path:  ev.RelPath,
				Hash:  hash,
				IsNew: ev.Type == watcher.EventCreate,
			}
			baseline.Save(cfg.BaselinePath)
		}

	case watcher.EventDelete:
		alert.Severity = "WARN"
		alert.Message = "File deleted"
		alert.Action = "REVIEW"
		notif.SendAlert(alert)
	}
}

func eventTypeName(t watcher.EventType) string {
	switch t {
	case watcher.EventCreate:
		return "CREATE"
	case watcher.EventModify:
		return "MODIFY"
	case watcher.EventDelete:
		return "DELETE"
	case watcher.EventMove:
		return "MOVE"
	default:
		return "UNKNOWN"
	}
}