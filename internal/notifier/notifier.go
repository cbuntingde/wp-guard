package notifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
)

type Notifier struct {
	cfg       config.TelegramConfig
	emailCfg  config.EmailConfig
	slackCfg  config.SlackConfig
	discordCfg config.DiscordConfig
	syslogCfg config.SyslogConfig
	hooksCfg  config.HooksConfig
	logPath  string
	logFile  *os.File
}

func NewNotifier(cfg config.TelegramConfig, emailCfg config.EmailConfig, slackCfg config.SlackConfig, discordCfg config.DiscordConfig, syslogCfg config.SyslogConfig, hooksCfg config.HooksConfig, logPath string) (*Notifier, error) {
	n := &Notifier{
		cfg:        cfg,
		emailCfg:   emailCfg,
		slackCfg:   slackCfg,
		discordCfg: discordCfg,
		syslogCfg: syslogCfg,
		hooksCfg:  hooksCfg,
		logPath:   logPath,
	}

	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
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
		if err := n.sendTelegram(msg); err != nil {
			return err
		}
	}

	// Send Email if configured
	if n.emailCfg.Enabled {
		if err := n.sendEmail(msg, a.Severity); err != nil {
			return err
		}
	}

	// Send Slack if configured
	if n.slackCfg.Enabled {
		if err := n.sendSlack(msg, a.Severity); err != nil {
			return err
		}
	}

	// Send Discord if configured
	if n.discordCfg.Enabled {
		if err := n.sendDiscord(msg, a.Severity); err != nil {
			return err
		}
	}

	// Send Syslog if configured
	if n.syslogCfg.Enabled {
		if err := n.sendSyslog(a); err != nil {
			return err
		}
	}

	// Run hooks if configured
	if n.hooksCfg.Enabled {
		n.runHook(a, msg)
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

func (n *Notifier) sendEmail(text string, severity string) error {
	from := n.emailCfg.From
	if from == "" {
		from = n.emailCfg.SMTPUser
	}
	to := n.emailCfg.To

	subject := fmt.Sprintf("[wp-guard] Security Alert: %s", severity)
	header := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n", from, to, subject)
	if n.emailCfg.UseTLS {
		header += "MIME-version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n"
	}
	header += "\r\n"

	msg := []byte(header + text)

	addr := fmt.Sprintf("%s:%d", n.emailCfg.SMTPHost, n.emailCfg.SMTPPort)

	var auth smtp.Auth
	if n.emailCfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", n.emailCfg.SMTPUser, n.emailCfg.SMTPPass, n.emailCfg.SMTPHost)
	}

	var conn net.Conn
	var err error
	if n.emailCfg.UseTLS {
		conn, err = tlsDial("tcp", addr, n.emailCfg.SMTPHost)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial: %v", err)
	}
	defer conn.Close()

	c, err := smtp.NewClient(conn, n.emailCfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp client: %v", err)
	}

	if auth != nil {
		if err = c.Auth(auth); err != nil {
			return fmt.Errorf("auth: %v", err)
		}
	}

	if err = c.Mail(from); err != nil {
		return fmt.Errorf("mail: %v", err)
	}
	if err = c.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt: %v", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %v", err)
	}
	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("write: %v", err)
	}
	err = w.Close()
	if err != nil {
		return fmt.Errorf("close: %v", err)
	}

	return c.Quit()
}

func (n *Notifier) sendSlack(text string, severity string) error {
	color := "#36a64f" // green
	if severity == "CRITICAL" {
		color = "#ff0000" // red
	} else if severity == "WARN" {
		color = "#ff9900" // orange
	}

	payload := map[string]interface{}{
		"channel": n.slackCfg.Channel,
		"username": n.slackCfg.Username,
		"attachments": []map[string]interface{}{
			{
				"color":     color,
				"text":     text,
				"mrkdwn_in": []string{"text"},
			},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(n.slackCfg.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack error: %s", resp.Status)
	}
	return nil
}

func (n *Notifier) sendDiscord(text string, severity string) error {
	color := 0x36a64f // green
	if severity == "CRITICAL" {
		color = 0xff0000 // red
	} else if severity == "WARN" {
		color = 0xff9900 // orange
	}

	// Discord username
	username := "wp-guard"
	if n.cfg.Enabled {
		username = "wp-guard"
	}

	payload := map[string]interface{}{
		"username": username,
		"embeds": []map[string]interface{}{
			{
				"color":       color,
				"description": text,
			},
		},
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(n.discordCfg.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord error: %s", resp.Status)
	}
	return nil
}

func (n *Notifier) sendSyslog(a Alert) error {
	priority := 14 // LOG_INFO | LOG_USER
	switch a.Severity {
	case "CRITICAL":
		priority = 2 // LOG_CRIT | LOG_USER
	case "WARN":
		priority = 10 // LOG_WARNING | LOG_USER
	}

	syslogMsg := fmt.Sprintf("<%d>%s: [%s] %s - %s: %s",
		priority,
		n.syslogCfg.AppName,
		a.Severity,
		a.EventType,
		a.File,
		a.Message,
	)

	addr := fmt.Sprintf("%s:%d", n.syslogCfg.Host, n.syslogCfg.Port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(syslogMsg))
	return err
}

func tlsDial(network, addr, hostname string) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,
	}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (n *Notifier) runHook(a Alert, msg string) {
	var script string
	switch a.Severity {
	case "CRITICAL":
		script = n.hooksCfg.OnCritical
	case "WARN":
		script = n.hooksCfg.OnWarn
	default:
		script = n.hooksCfg.OnClean
	}

	if script == "" {
		return
	}

	if _, err := os.Stat(script); err != nil {
		log.Printf("[hooks] script not found: %s", script)
		return
	}

	env := []string{
		fmt.Sprintf("WP_ALERT_SEVERITY=%s", a.Severity),
		fmt.Sprintf("WP_ALERT_FILE=%s", a.File),
		fmt.Sprintf("WP_ALERT_EVENT=%s", a.EventType),
		fmt.Sprintf("WP_ALERT_MESSAGE=%s", a.Message),
	}
	env = append(env, os.Environ()...)

	timeout := n.hooksCfg.TimeoutSec
	if timeout == 0 {
		timeout = 30
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, script)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Printf("[hooks] error running %s: %v", script, err)
	}
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