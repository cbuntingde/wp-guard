package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WatchPath       string         `yaml:"watch_path"`
	BaselinePath    string         `yaml:"baseline_path"`
	QuarantinePath  string         `yaml:"quarantine_path"`
	LogPath         string         `yaml:"log_path"`
	PollIntervalSec int            `yaml:"poll_interval_sec"`
	AI              AIConfig       `yaml:"ai"`
	Telegram        TelegramConfig `yaml:"telegram"`
	WordPress       WPConfig       `yaml:"wordpress"`
	Scanner         ScannerConfig  `yaml:"scanner"`
	AutoFix         bool           `yaml:"auto_fix"`
	NotifyOnClean   bool           `yaml:"notify_on_clean"`
}

type AIConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Provider     string `yaml:"provider"` // "openrouter", "claude", "mock"
	Model        string `yaml:"model"`
	APIKey       string `yaml:"api_key"`
	APIURL       string `yaml:"api_url"`
	SystemPrompt string `yaml:"system_prompt"`
}

type TelegramConfig struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
	ChatID  string `yaml:"chat_id"`
}

type WPConfig struct {
	CoreFiles []string `yaml:"core_files"` // files that should NOT change
	ThemesDir string   `yaml:"themes_dir"`
	PluginsDir string  `yaml:"plugins_dir"`
}

type ScannerConfig struct {
	SuspiciousPatterns []string           `yaml:"suspicious_patterns"`
	MaxFileSizeMB      int                `yaml:"max_file_size_mb"`
	ExcludeExtensions  []string           `yaml:"exclude_extensions"`
	ExcludePaths       []string           `yaml:"exclude_paths"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// defaults
	if cfg.PollIntervalSec == 0 {
		cfg.PollIntervalSec = 30
	}
	if cfg.Scanner.MaxFileSizeMB == 0 {
		cfg.Scanner.MaxFileSizeMB = 10
	}

	return &cfg, nil
}