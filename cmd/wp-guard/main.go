package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cbuntingde/wp-guard/internal/config"
	"github.com/cbuntingde/wp-guard/internal/scanner"
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
	case "scan-plugin":
		runScanPlugin()
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
  wp-guard baseline       Initialize or refresh baseline
  wp-guard scan          Scan all PHP files for malicious code
  wp-guard scan-plugin   Scan plugin(s) for malicious code
  wp-guard status       Show monitoring status

Run 'wp-guard <command> -h' for more info`)
}

func runScan() {
	aiEnable := false
	aiEnabled := false

	args := os.Args[2:]
	for _, a := range args {
		if a == "--ai" || a == "-ai" {
			aiEnable = true
		}
	}

	cfg, err := config.Load("wp-guard.yaml")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	scan := scanner.NewScanner(cfg.Scanner, cfg.AI)

	aiEnabled = cfg.AI.Enabled || aiEnable
	if aiEnabled && cfg.AI.APIKey == "" {
		log.Fatal("AI enabled but api_key not set in config")
	}

	var (
		results    []scanner.Result
		filesScanned int
	)

	err = filepath.Walk(cfg.WatchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".php" {
			return nil
		}

		rel, _ := filepath.Rel(cfg.WatchPath, path)
		for _, ex := range cfg.Scanner.ExcludePaths {
			if strings.HasPrefix(rel, ex) {
				return nil
			}
		}

		// Check skip patterns
		for _, skip := range cfg.Scanner.SkipPatterns {
			if strings.Contains(rel, skip) {
				return nil
			}
		}

		res, err := scan.ScanFile(path)
		if err != nil {
			log.Printf("scan %s: %v", path, err)
			return nil
		}
		filesScanned++
		results = append(results, res...)
		return nil
	})

	if err != nil {
		log.Fatalf("walk: %v", err)
	}

	groupBySeverity(results)

	if aiEnabled && len(results) > 0 {
		fmt.Println("\n--- AI Triage ---")
		ctx := context.Background()
		for _, r := range results {
			if r.Severity == scanner.WARN || r.Severity == scanner.CRITICAL {
				code := extractCodeSnippet(r.File, r.Line)
				triage, err := scan.AITriage(ctx, r.File, code)
				if err != nil {
					log.Printf("triage %s: %v", r.File, err)
					continue
				}
				fmt.Printf("\n%s:%d:\n  %s\n  AI: malicious=%v confidence=%.2f\n  %s\n",
					r.File, r.Line, r.Message, triage.Malicious, triage.Confidence, triage.Recommendation)
			}
		}
	}

	fmt.Printf("\nScanned %d PHP files in %s\n", filesScanned, cfg.WatchPath)
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

func runScanPlugin() {
	pluginName := ""
	aiEnable := false
	aiEnabled := false

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-plugin", "--plugin":
			if i+1 < len(args) {
				pluginName = args[i+1]
				i++
			}
		case "-ai", "--ai":
			aiEnable = true
		}
	}

	cfg, err := config.Load("wp-guard.yaml")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Validate plugin name to prevent path traversal
	if pluginName != "" {
		if strings.Contains(pluginName, "..") || strings.HasPrefix(pluginName, "/") {
			log.Fatal("invalid plugin name: path traversal not allowed")
		}
	}

	// Resolve plugins directory
	pluginsDir := filepath.Join(cfg.WatchPath, cfg.WordPress.PluginsDir)
	if pluginName != "" {
		pluginsDir = filepath.Join(pluginsDir, pluginName)
		// Verify resolved path is within plugins directory (prevent traversal)
		absWatch, _ := filepath.Abs(cfg.WatchPath)
		absPlugin, _ := filepath.Abs(pluginsDir)
		if !strings.HasPrefix(absPlugin, absWatch) {
			log.Fatal("invalid plugin path: must be within watch directory")
		}
	}

	if _, err := os.Stat(pluginsDir); err != nil {
		log.Fatalf("plugins dir: %v", err)
	}

	// Build scanner
	scan := scanner.NewScanner(cfg.Scanner, cfg.AI)

	// If AI requested but not enabled in config, need API key
	aiEnabled = cfg.AI.Enabled || aiEnable
	if aiEnabled && cfg.AI.APIKey == "" {
		log.Fatal("AI enabled but api_key not set in config")
	}

	var results []scanner.Result
	var filesScanned int

	err = filepath.Walk(pluginsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".php" {
			return nil
		}

		// Skip excluded paths
		rel, _ := filepath.Rel(cfg.WatchPath, path)
		for _, ex := range cfg.Scanner.ExcludePaths {
			if strings.HasPrefix(rel, ex) {
				return nil
			}
		}

		res, err := scan.ScanFile(path)
		if err != nil {
			log.Printf("scan %s: %v", path, err)
			return nil
		}
		filesScanned++
		results = append(results, res...)
		return nil
	})

	if err != nil {
		log.Fatalf("walk: %v", err)
	}

	// Print results
	groupBySeverity(results)

	// AI triage on suspicious findings if enabled
	if aiEnabled && len(results) > 0 {
		fmt.Println("\n--- AI Triage ---")
		ctx := context.Background()
		for _, r := range results {
			if r.Severity == scanner.WARN || r.Severity == scanner.CRITICAL {
				code := extractCodeSnippet(r.File, r.Line)
				triage, err := scan.AITriage(ctx, r.File, code)
				if err != nil {
					log.Printf("triage %s: %v", r.File, err)
					continue
				}
				fmt.Printf("\n%s:%d:\n  %s\n  AI: malicious=%v confidence=%.2f\n  %s\n",
					r.File, r.Line, r.Message, triage.Malicious, triage.Confidence, triage.Recommendation)
			}
		}
	}

	fmt.Printf("\nScanned %d PHP files in plugins\n", filesScanned)
}

func groupBySeverity(results []scanner.Result) {
	var critical, warn, info []scanner.Result
	for _, r := range results {
		switch r.Severity {
		case scanner.CRITICAL:
			critical = append(critical, r)
		case scanner.WARN:
			warn = append(warn, r)
		case scanner.INFO:
			info = append(info, r)
		}
	}

	if len(critical) > 0 {
		fmt.Println("\n=== CRITICAL ===")
		for _, r := range critical {
			fmt.Printf("%s:%d: %s\n", r.File, r.Line, r.Message)
		}
	}
	if len(warn) > 0 {
		fmt.Println("\n=== WARN ===")
		for _, r := range warn {
			fmt.Printf("%s:%d: %s\n", r.File, r.Line, r.Message)
		}
	}
	if len(info) > 0 {
		fmt.Println("\n=== INFO ===")
		for _, r := range info {
			fmt.Printf("%s:%d: %s\n", r.File, r.Line, r.Message)
		}
	}
	if len(results) == 0 {
		fmt.Println("\nNo suspicious patterns found.")
	}
}

func extractCodeSnippet(path string, line int) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	start := line - 2
	if start < 1 {
		start = 1
	}
	end := line + 2

	var code strings.Builder
	fileScanner := bufio.NewScanner(file)
	current := 0
	for fileScanner.Scan() {
		current++
		if current >= start && current <= end {
			code.WriteString(fileScanner.Text())
			code.WriteString("\n")
		}
		if current > end {
			break
		}
	}
	return code.String()
}