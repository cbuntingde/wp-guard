# wp-guard Roadmap

## Phase 1: Notifications (Quick Wins)

### 1.1 Slack Webhook
- Add Slack notification support
- Config: `slack.enabled`, `slack.webhook_url`, `slack.channel`
- Use slack incoming webhook API

### 1.2 Discord Webhook
- Add Discord notification support
- Config: `discord.enabled`, `discord.webhook_url`
- Use Discord embed format for alerts

### 1.3 Syslog
- Add syslog support for enterprise environments
- Config: `syslog.enabled`, `syslog.host`, `syslog.port`, `syslog.app_name`
- Use standard syslog protocol

---

## Phase 2: Operational Features

### 2.1 Web Dashboard/API
- HTTP server for remote monitoring
- Endpoints:
  - `GET /health` - health check
  - `GET /status` - current monitoring status
  - `GET /events` - recent alerts
  - `GET /files` - tracked files count
- Config: `http.enabled`, `http.port`, `http.addr`, `http.auth_token`

### 2.2 Config Hot-Reload
- Reload config on SIGHUP signal
- Avoid restart for config changes
- Track which settings require restart vs hot-reload

### 2.3 Rate Limiting
- Don't spam alerts on bulk file changes (e.g., plugin update)
- Config: `rate_limit.enabled`, `rate_limit.window_sec`, `rate_limit.max_alerts`
- Alert grouping for multiple issues

---

## Phase 3: Multi-Server Support

### 3.1 Watch Multiple WordPress Installs
- Support multiple watch paths
- Config: `watch_paths: []` as array
- Per-path baseline storage

### 3.2 Central Reporting
- Aggregated dashboard across hosts
- Per-site alerting
- Config inheritance with overrides

---

## Phase 4: Polish

### 4.1 Prometheus Metrics
- Exportprometheus metrics
- `wp_guard_files_tracked_total`
- `wp_guard_alerts_total`
- `wp_guard_last_scan_timestamp`

### 4.2 Prometheus Alerting Rules
- alertmanager integration
- Critical/warn/clean alert rules

### 4.3 Structured Logging (JSON)
- JSON log output option
- Easier log aggregation
- Config: `log.format: json`

---

## Priority Order

| Priority | Feature | Effort |
|----------|---------|--------|
| 1 | Slack webhook | Low |
| 2 | Discord webhook | Low |
| 3 | Syslog | Low |
| 4 | Web API | Medium |
| 5 | Health endpoint | Low |
| 6 | Config hot-reload | Low |
| 7 | Rate limiting | Medium |
| 8 | Multi-server | High |
| 9 | Prometheus metrics | Medium |
| 10 | JSON logging | Low |

---

## Completed Features (Phase 0)

- File integrity monitoring
- Static malware scanning
- AI triage (OpenRouter)
- Quarantine
- Telegram alerts
- Email (SMTP) alerts
- Baseline diff
- `scan-plugin` command
- `scan` command
- Skip patterns
- Hook execution
- Path traversal protection