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

## Completed Phase 2: Operational Features

- [x] Web API / HTTP server
- [x] Health endpoint
- [x] Config hot-reload (SIGHUP)
- [x] Rate limiting

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

## Completed Phase 4: Polish

- [x] Prometheus metrics endpoint
- [x] JSON logging support

---

ALL PHASES COMPLETE! 🎉

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

## Completed Phase 1: Notifications

- [x] Slack webhook
- [x] Discord webhook
- [x] Syslog