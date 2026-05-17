package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cbuntingde/wp-guard/internal/config"
	"github.com/cbuntingde/wp-guard/internal/store"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "scan":
		runScan()
	case "baseline":
		runBaseline()
	case "status":
		runStatus()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`wp-guard CLI

Usage:
  wp-guard baseline    Initialize or refresh baseline
  wp-guard scan        Scan for changes vs baseline
  wp-guard status      Show monitoring status
  wp-guard version     Show version

Run 'wp-guard <command> -h' for more info`)
}

func runScan() {
	cfg, err := config.Load("wp-guard.yaml")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	base, err := store.LoadBaseline(cfg.BaselinePath)
	if err != nil {
		log.Fatalf("baseline: %v", err)
	}

	fmt.Printf("Baseline: %d files tracked\n", len(base.Files))
	fmt.Printf("Watch path: %s\n", cfg.WatchPath)
}

func runBaseline() {
	cfg, err := config.Load("wp-guard.yaml")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	base, err := store.ScanDirectory(
		cfg.WatchPath,
		cfg.Scanner.ExcludeExtensions,
		cfg.Scanner.ExcludePaths,
	)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}

	if err := base.Save(cfg.BaselinePath); err != nil {
		log.Fatalf("save: %v", err)
	}

	fmt.Printf("Baseline saved: %d files\n", len(base.Files))
}

func runStatus() {
	cfg, err := config.Load("wp-guard.yaml")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	base, err := store.LoadBaseline(cfg.BaselinePath)
	if err != nil {
		log.Fatalf("baseline: %v", err)
	}

	fmt.Printf("Watch path: %s\n", cfg.WatchPath)
	fmt.Printf("Baseline: %d files\n", len(base.Files))
	fmt.Printf("Baseline path: %s\n", cfg.BaselinePath)
	fmt.Printf("Poll interval: %ds\n", cfg.PollIntervalSec)
	fmt.Printf("AI enabled: %v\n", cfg.AI.Enabled)
	fmt.Printf("Telegram: %v\n", cfg.Telegram.Enabled)
}