> [!WARNING]
> **TEST PROJECT - NEEDS THOROUGH TESTING!** This is not meant for production use. /CB

# wp-guard

[![Version](https://img.shields.io/github/v/tag/cbuntingde/wp-guard)](https://github.com/cbuntingde/wp-guard/tags)
[![License](https://img.shields.io/github/license/cbuntingde/wp-guard)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.18+-00ADD8?style=flat&logo=go)](https://go.dev/doc/install)

wp-guard is a standalone WordPress file integrity monitor and malware scanner. It runs as a separate daemon — if WordPress goes down, wp-guard keeps watching and alerts you.

## Why wp-guard?

- **Defense in Depth** — Monitors WordPress even when the site is compromised
- **Zero Dependencies** — No WordPress plugins required
- **Enterprise Ready** — Multiple notification channels, Prometheus metrics, rate limiting
- **Privacy First** — All data stays on your infrastructure

## Features

### Security Monitoring

- **File Integrity Monitoring** — Detects new, modified, and deleted files
- **Malware Scanning** — Pattern-matches for known backdoor signatures (`base64_decode`, `eval` with user input, `shell_exec`, etc.)
- **AI Triage** — Optional LLM-powered code analysis via OpenRouter or Anthropic API
- **AI Auto-Fix** — Auto-remediate exploits with rollback protection
- **Quarantine** — Auto-isolate suspicious files for review
- **Baseline Tracking** — JSON baseline stores every file hash, mode, and timestamp
- **Plugin Guardrails** — Enhanced monitoring for `wp-content/plugins/`

### Notifications (Choose Your Channel)

- **Telegram** — Instant bot notifications
- **Slack** — Color-coded attachments
- **Discord** — Rich embeds
- **Email** — SMTP with TLS
- **Syslog** — Enterprise logging (UDP)
- **Webhooks** — Run custom scripts on alerts

### Operations

- **HTTP API** — Remote monitoring endpoint
- **Prometheus Metrics** — `/metrics` endpoint for Prometheus
- **Rate Limiting** — Prevent alert storms during plugin updates

### CLI Commands

- `scan` — Scan all PHP files for malicious code
- `scan-plugin` — Scan specific plugin or all plugins
- `baseline` — Initialize or refresh baseline
- `status` — Show monitoring status

## Quick Start

### 1. Build

```bash
go build -o wp-guard ./cmd/server      # Daemon
go build -o wp-guard ./cmd/wp-guard   # CLI tool
```

### 2. Configure

Copy `wp-guard.yaml.example` to `wp-guard.yaml` and customize:

```yaml
# Required: Path to WordPress installation
watch_path: /var/www/html
baseline_path: /etc/wp-guard/baseline.json
quarantine_path: /var/www/wp-guard-quarantine
log_path: /var/log/wp-guard/events.log

# Polling interval (seconds)
poll_interval_sec: 30

# HTTP API (optional)
http:
  enabled: false
  addr: "0.0.0.0"
  port: 8080
  auth_token: "CHANGE_ME"

# Rate limiting (optional)
rate_limit:
  enabled: false
  window_sec: 300  # 5 minutes
  max_alerts: 5

# Notification channels (enable one or more)

# Telegram
telegram:
  enabled: false
  token: "BOT_TOKEN"
  chat_id: "CHAT_ID"

# Slack
slack:
  enabled: false
  webhook_url: "https://hooks.slack.com/services/XXX"
  channel: "#security"
  username: "wp-guard"

# Discord
discord:
  enabled: false
  webhook_url: "https://discord.com/api/webhooks/XXX"

# Email
email:
  enabled: false
  smtp_host: "smtp.gmail.com"
  smtp_port: 587
  smtp_user: "user@gmail.com"
  smtp_pass: "APP_PASSWORD"
  from: "user@gmail.com"
  to: "alert@example.com"
  use_tls: true

# Syslog
syslog:
  enabled: false
  host: "localhost"
  port: 514
  app_name: "wp-guard"

# AI Triage (optional)
ai:
  enabled: false
  provider: openrouter  # "openrouter" or "anthropic"
  model: anthropic/claude-3-haiku
  api_key: "API_KEY"

# Auto-fix (AI-powered remediation)
auto_fix:
  enabled: false
  plugins_only: true   # only auto-fix plugins dir (safer)
  create_backup: true # keep backups before fix
  rollback_on_fail: true  # auto-rollback if WP fails
  health_check_url: "https://yoursite.com/wp-admin/admin-ajax.php?action=health_check"

# Hooks (run scripts on alerts)
hooks:
  enabled: false
  on_critical: "/etc/wp-guard/scripts/alert.sh"
  timeout_sec: 30

# Scanner settings
scanner:
  max_file_size_mb: 10
  exclude_extensions:
    - .jpg
    - .png
    - .zip
  exclude_paths:
    - wp-content/uploads
    - wp-content/cache
  skip_patterns:
    - auto-updating-plugin
```

### 3. Initialize Baseline

```bash
./wp-guard baseline --config wp-guard.yaml
```

### 4. Run

```bash
# As daemon
./wp-guard run --config wp-guard.yaml

# Or install as systemd service
sudo cp wp-guard /usr/local/bin/
sudo cp wp-guard.yaml /etc/wp-guard/
sudo cp scripts/wp-guard.service /etc/systemd/system/
sudo systemctl enable wp-guard
sudo systemctl start wp-guard
```

### 5. Scan On Demand

```bash
# Scan all PHP files
./wp-guard scan

# Scan all plugins
./wp-guard scan-plugin

# Scan specific plugin
./wp-guard scan-plugin -plugin akismet

# Scan with AI triage
./wp-guard scan --ai
```

## HTTP API

When `http.enabled: true`:

| Endpoint | Description | Auth |
|----------|-------------|------|
| `GET /health` | Health check | No |
| `GET /status` | Files tracked, alerts 24h | Yes |
| `GET /events` | Recent alerts | Yes |
| `GET /metrics` | Prometheus metrics | Yes |
| `POST /reload` | Reload config | Yes |

```bash
# Health check
curl http://localhost:8080/health

# With auth
curl -H "Authorization: Bearer TOKEN" http://localhost:8080/status

# Prometheus scrape
curl -H "Authorization: Bearer TOKEN" http://localhost:8080/metrics
```

## Security Notes

- Run wp-guard as a dedicated service account (not root)
- Protect config file: `chmod 600 wp-guard.yaml`
- Don't commit config files with secrets
- Use App Passwords for Gmail (not your regular password)

## Hook Scripts

Hook scripts receive environment variables:

```bash
#!/bin/bash
echo "ALERT: $WP_ALERT_SEVERITY on $WP_ALERT_FILE"
echo "$WP_ALERT_MESSAGE"
```

Available variables:

- `WP_ALERT_SEVERITY` — CRITICAL, WARN, INFO
- `WP_ALERT_FILE` — File path
- `WP_ALERT_EVENT` — create, modify, delete
- `WP_ALERT_MESSAGE` — Alert description

## Prometheus Metrics

```yaml
# Example Prometheus config
scrape_configs:
  - job_name: 'wp-guard'
    static_configs:
      - targets: ['localhost:8080']
    scheme: http
    authorization:
      credentials: 'TOKEN'
```

Metrics:

- `wp_guard_files_tracked` — Gauge
- `wp_guard_alerts_total` — Counter
- `wp_guard_alerts_24h` — Gauge
- `wp_guard_critical_24h` — Gauge
- `wp_guard_last_scan_timestamp` — Gauge

## Architecture

```
wp-guard/
├── cmd/
│   ├── server/          # Daemon
│   └── wp-guard/        # CLI
├── internal/
│   ├── config/          # YAML config
│   ├── scanner/         # Malware patterns + AI triage
│   ├── watcher/        # File monitoring
│   ├── store/          # Baseline management
│   ├── quarantine/     # File isolation
│   ├── autofix/        # AI auto-fix with rollback
│   ├── notifier/       # All notification channels
│   ├── server/        # HTTP API
│   └── logger/        # JSON logging
├── scripts/
│   └── install.sh      # systemd installer
└── wp-guard.yaml.example
```

## Requirements

- Go 1.21+
- Linux (uses inotify-compatible polling)

## License

MIT License - See [LICENSE](LICENSE)

## Credits

- Malware patterns inspired by Wordfence, Sucuri
- Built with Go standard library