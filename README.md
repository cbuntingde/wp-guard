# wp-guard

Standalone WordPress file integrity monitor and exploit scanner.

Runs as a separate daemon — if WordPress goes down, wp-guard keeps watching and alerts you.

## Features

- **File integrity monitoring** — Detects new, modified, and deleted files in your WordPress install
- **Static malware scanning** — Pattern-matches for known backdoor signatures (base64_decode, eval w/ user input, shell_exec, etc.)
- **AI triage** — Optional LLM-powered code analysis via OpenRouter
- **Quarantine** — Auto-isolate suspicious files
- **Telegram alerts** — Instant notifications on security events
- **Baseline diff** — JSON baseline tracks every file hash, mode, and timestamp

## Quick Start

```bash
# Build
go build -o wp-guard ./cmd/server

# Initialize baseline (first run)
./wp-guard baseline --config wp-guard.yaml

# Start daemon
./wp-guard run --config wp-guard.yaml

# Or install as systemd service
sudo ./scripts/install.sh
```

## Configuration

Copy `wp-guard.yaml.example` to `wp-guard.yaml` and configure:

```yaml
watch_path: /var/www/html
baseline_path: /etc/wp-guard/baseline.json
quarantine_path: /var/www/wp-guard-quarantine
poll_interval_sec: 30

telegram:
  enabled: true
  token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

ai:
  enabled: true
  provider: openrouter
  model: anthropic/claude-3-haiku
  api_key: "YOUR_API_KEY"
  api_url: https://openrouter.ai/api/v1/chat/completions

scanner:
  exclude_extensions:
    - .jpg
    - .png
    - .zip
  exclude_paths:
    - wp-content/uploads
    - wp-content/cache
```

## Architecture

```
wp-guard/
├── cmd/
│   ├── server/        # Main daemon
│   └── wp-guard/       # CLI tool
├── internal/
│   ├── config/         # YAML config loader
│   ├── scanner/       # Static analysis + AI triage
│   ├── watcher/       # File system monitor
│   ├── store/         # Baseline management
│   ├── quarantine/    # Suspicious file isolation
│   └── notifier/      # Telegram alerts
├── scripts/
│   └── install.sh     # systemd installer
└── wp-guard.yaml.example
```

## How it works

1. On first run, creates a baseline snapshot (hash + size + mode of every file)
2. Polls the watched directory every N seconds (configurable)
3. Detects new/modified/deleted files
4. Scans modified files against known malicious patterns
5. Optionally sends code to LLM for AI-powered triage
6. Quarantines CRITICAL findings, alerts via Telegram
7. Updates baseline for clean changes

## Alert severity levels

| Level | Action |
|-------|--------|
| CRITICAL | Quarantine file + immediate alert |
| WARN | Alert for review |
| INFO | Log only (or silent baseline update) |

## Requirements

- Go 1.21+
- Linux (uses inotify-compatible polling)
- Telegram bot (optional, for alerts)

## Security notes

- Run on a separate host/VM from the WordPress server if possible
- wp-guard process should have read-only access to WordPress files and write access only to quarantine/ and log directories
- Never run wp-guard as root in production (use dedicated service account)