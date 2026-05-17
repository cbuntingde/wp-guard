package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
)

type Notifier struct {
	cfg     config.TelegramConfig
	logPath string
	logFile *os.File
}

func NewNotifier(cfg config.TelegramConfig, logPath string) (*Notifier, error) {
	n := &Notifier{
		cfg:     cfg,
		logPath: logPath,
	}

	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		n.logFile = f
	}

	return n, nil
}

func (n *Notifier) Close() error {
	if n.logFile != nil {
		return n.logFile.Close()
	}
	return nil
}

type Alert struct {
	Timestamp  time.Time
	EventType  string
	File       string
	Severity   string
	Pattern    string
	Message    string
	Action     string
}

func (n *Notifier) SendAlert(a Alert) error {
	msg := n.formatAlert(a)

	// Log it
	n.log(a)

	// Send Telegram if configured
	if n.cfg.Enabled {
		return n.sendTelegram(msg)
	}

	return nil
}

func (n *Notifier) formatAlert(a Alert) string {
	emoji := "ℹ️"
	switch a.Severity {
	case "CRITICAL":
		emoji = "🚨"
	case "WARN":
		emoji = "⚠️"
	}

	return fmt.Sprintf(`%s *WordPress Security Alert*

*File:* %s
*Event:* %s
*Severity:* %s
*Pattern:* %s
*Message:* %s
*Action:* %s
*Time:* %s`,
		emoji,
		a.File,
		a.EventType,
		a.Severity,
		a.Pattern,
		a.Message,
		a.Action,
		a.Timestamp.Format("2006-01-02 15:04:05 MST"),
	)
}

func (n *Notifier) sendTelegram(text string) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", n.cfg.Token)

	payload := map[string]interface{}{
		"chat_id":    n.cfg.ChatID,
		"text":       text,
		"parse_mode": "Markdown",
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("telegram API error: %s", resp.Status)
	}

	return nil
}

func (n *Notifier) log(a Alert) {
	if n.logFile == nil {
		return
	}
	entry, _ := json.Marshal(a)
	n.logFile.Write(append(entry, '\n'))
}

func SendSimpleMessage(cfg config.TelegramConfig, msg string) error {
	if !cfg.Enabled {
		return nil
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.Token)
	payload := map[string]interface{}{
		"chat_id": cfg.ChatID,
		"text":    msg,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func NotifyStartup(cfg config.TelegramConfig) {
	SendSimpleMessage(cfg, "🟢 *wp-guard started*\nWatching WordPress installation.")
}

func NotifyShutdown(cfg config.TelegramConfig) {
	SendSimpleMessage(cfg, "🔴 *wp-guard stopped*")
}

func NotifyError(cfg config.TelegramConfig, err error) {
	SendSimpleMessage(cfg, fmt.Sprintf("⚠️ *wp-guard error:*\n`%v`", err))
}