package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configData := `
watch_path: /var/www/html
baseline_path: ./baseline.json
quarantine_path: ./quarantine
log_path: ./wp-guard.log
poll_interval_sec: 30
http:
  enabled: true
  addr: "127.0.0.1"
  port: 8080
scanner:
  max_file_size_mb: 10
email:
  enabled: false
  smtp_host: "localhost"
  smtp_port: 587
`

	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Verify basic config values
	if cfg.WatchPath != "/var/www/html" {
		t.Errorf("expected watch_path=/var/www/html, got %s", cfg.WatchPath)
	}
	if cfg.PollIntervalSec != 30 {
		t.Errorf("expected poll_interval_sec=30, got %d", cfg.PollIntervalSec)
	}
	if cfg.HTTP.Port != 8080 {
		t.Errorf("expected HTTP port=8080, got %d", cfg.HTTP.Port)
	}
}

func TestConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-defaults.yaml")

	// Minimal config
	configData := `
watch_path: /var/www/html
`

	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Check defaults are applied
	if cfg.PollIntervalSec != 30 {
		t.Errorf("expected default poll_interval_sec=30, got %d", cfg.PollIntervalSec)
	}
	if cfg.Scanner.MaxFileSizeMB != 10 {
		t.Errorf("expected default max_file_size_mb=10, got %d", cfg.Scanner.MaxFileSizeMB)
	}
	if cfg.Email.SMTPPort != 587 {
		t.Errorf("expected default SMTP port=587, got %d", cfg.Email.SMTPPort)
	}
	if cfg.HTTP.Port != 8080 {
		t.Errorf("expected default HTTP port=8080, got %d", cfg.HTTP.Port)
	}
	if cfg.RateLimit.WindowSec != 300 {
		t.Errorf("expected default rate_limit.window_sec=300, got %d", cfg.RateLimit.WindowSec)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: &Config{
				WatchPath:       "/var/www/html",
				PollIntervalSec: 30,
				HTTP:            HTTPConfig{Port: 8080},
				Scanner:         ScannerConfig{MaxFileSizeMB: 10},
				RateLimit:       RateLimitConfig{WindowSec: 300, MaxAlerts: 5},
			},
			wantErr: false,
		},
		{
			name: "missing watch_path",
			cfg: &Config{
				PollIntervalSec: 30,
				HTTP:            HTTPConfig{Port: 8080},
			},
			wantErr: true,
		},
		{
			name: "invalid HTTP port",
			cfg: &Config{
				WatchPath:       "/var/www/html",
				PollIntervalSec: 30,
				HTTP:            HTTPConfig{Port: 99999},
			},
			wantErr: true,
		},
		{
			name: "invalid poll interval",
			cfg: &Config{
				WatchPath:       "/var/www/html",
				PollIntervalSec: 0,
				HTTP:            HTTPConfig{Port: 8080},
			},
			wantErr: true,
		},
		{
			name: "invalid max file size",
			cfg: &Config{
				WatchPath:       "/var/www/html",
				PollIntervalSec: 30,
				HTTP:            HTTPConfig{Port: 8080},
				Scanner:         ScannerConfig{MaxFileSizeMB: 0},
			},
			wantErr: true,
		},
		{
			name: "AI enabled without API key",
			cfg: &Config{
				WatchPath:       "/var/www/html",
				PollIntervalSec: 30,
				HTTP:            HTTPConfig{Port: 8080},
				Scanner:         ScannerConfig{MaxFileSizeMB: 10},
				AI: AIConfig{
					Enabled:  true,
					Provider: "openrouter",
					Model:    "test-model",
					APIKey:   "",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestContainsNullByte(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"normal/path", false},
		{"/var/www\x00html", true},
		{"", false},
		{"test\x00", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := containsNullByte(tt.input)
			if got != tt.want {
				t.Errorf("containsNullByte(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
