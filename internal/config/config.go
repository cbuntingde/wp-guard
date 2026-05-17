package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WatchPath      string         `yaml:"watch_path"`
	BaselinePath  string        `yaml:"baseline_path"`
	QuarantinePath string       `yaml:"quarantine_path"`
	LogPath      string        `yaml:"log_path"`
	PollIntervalSec int        `yaml:"poll_interval_sec"`
	AI           AIConfig      `yaml:"ai"`
	Telegram     TelegramConfig `yaml:"telegram"`
	Email        EmailConfig  `yaml:"email"`
	Slack       SlackConfig  `yaml:"slack"`
	Discord     DiscordConfig `yaml:"discord"`
	Syslog      SyslogConfig `yaml:"syslog"`
	Hooks       HooksConfig `yaml:"hooks"`
	WordPress    WPConfig   `yaml:"wordpress"`
	Scanner     ScannerConfig `yaml:"scanner"`
	AutoFix     bool       `yaml:"auto_fix"`
	NotifyOnClean bool      `yaml:"notify_on_clean"`
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

type EmailConfig struct {
	Enabled     bool   `yaml:"enabled"`
	SMTPHost    string `yaml:"smtp_host"`
	SMTPPort    int    `yaml:"smtp_port"`
	SMTPUser    string `yaml:"smtp_user"`
	SMTPPass    string `yaml:"smtp_pass"`
	From       string `yaml:"from"`
	To         string `yaml:"to"`
	UseTLS     bool   `yaml:"use_tls"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	Channel   string `yaml:"channel"`
	Username  string `yaml:"username"`
}

type DiscordConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
}

type SyslogConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	AppName string `yaml:"app_name"`
}

type HooksConfig struct {
	Enabled       bool     `yaml:"enabled"`
	OnCritical   string   `yaml:"on_critical"`   // script path to run on critical alerts
	OnWarn       string   `yaml:"on_warn"`     // script path to run on warnings
	OnClean      string   `yaml:"on_clean"`    // script path to run on clean baseline update
	TimeoutSec   int      `yaml:"timeout_sec"`
}

type WPConfig struct {
	CoreFiles []string `yaml:"core_files"` // files that should NOT change
	ThemesDir string   `yaml:"themes_dir"`
	PluginsDir string  `yaml:"plugins_dir"`
}

type ScannerConfig struct {
	SuspiciousPatterns []string `yaml:"suspicious_patterns"`
	MaxFileSizeMB     int     `yaml:"max_file_size_mb"`
	ExcludeExtensions []string `yaml:"exclude_extensions"`
	ExcludePaths      []string `yaml:"exclude_paths"`
	SkipPatterns      []string `yaml:"skip_patterns"` // patterns to ignore in full scan (e.g., "-plugin-slug")
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
	if cfg.Email.SMTPPort == 0 {
		cfg.Email.SMTPPort = 587
	}
	if cfg.Syslog.Port == 0 {
		cfg.Syslog.Port = 514
	}

	return &cfg, nil
}