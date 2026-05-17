package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
)

type Result struct {
	File        string
	Severity    Severity // INFO, WARN, CRITICAL
	Pattern     string
	Message     string
	Line        int
	AutoFixable bool
}

type Severity int

const (
	INFO Severity = iota
	WARN
	CRITICAL
)

func (s Severity) String() string {
	switch s {
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case CRITICAL:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type Scanner struct {
	cfg      config.ScannerConfig
	patterns []*pattern
	aiCfg    config.AIConfig
}

type pattern struct {
	regex   *regexp.Regexp
	severity Severity
	message string
}

func NewScanner(cfg config.ScannerConfig, aiCfg config.AIConfig) *Scanner {
	s := &Scanner{
		cfg:   cfg,
		aiCfg: aiCfg,
	}
	s.compilePatterns()
	return s
}

func (s *Scanner) compilePatterns() {
	defaults := []struct {
		regex    string
		severity Severity
		msg      string
	}{
		// Backdoors & obfuscation
		{`base64_decode\s*\(`, CRITICAL, "base64_decode found - common malware obfuscation"},
		{`eval\s*\(\s*base64_decode`, CRITICAL, "eval(base64_decode(...)) - classic backdoor pattern"},
		{`eval\s*\(.*\$_(?:POST|GET|REQUEST|COOKIE)`, CRITICAL, "eval() with user input - code injection risk"},
		{`\$_(?:POST|GET|REQUEST|COOKIE)\s*\[.*\]\s*\(\s*`, WARN, "Dynamic function call with user input"},
		{`create_function\s*\(`, WARN, "create_function is deprecated and risky"},
		{`\$[a-zA-Z_]+\s*=\s*['"]eval`, CRITICAL, "Variable assigned eval - possible backdoor"},
		{`call_user_func(?:_array)?\s*\(\s*\$_(?:POST|GET|REQUEST)`, CRITICAL, "call_user_func with user input"},
		{`\$_(?:POST|GET|REQUEST)\[.*\]\s*\(\)`, CRITICAL, "User input used as function call"},
		{`passthru|shell_exec|system\(|exec\s*\(`, WARN, "Shell execution function - validate usage"},

		// Suspicious patterns
		{`@ini_set\s*\(\s*['"]display_errors`, WARN, "Disabling error display - possible stealth attempt"},
		{`error_reporting\s*\(\s*0\s*\)`, WARN, "Error reporting disabled"},
		{`fopen\s*\(\s*\$_(?:POST|GET|REQUEST)`, WARN, "fopen with user input"},
		{`file_put_contents\s*\(.*\$_(?:POST|GET|REQUEST)`, WARN, "file_put_contents with user input"},
		{`file_get_contents\s*\(\s*\$_(?:POST|GET|REQUEST)`, WARN, "file_get_contents with user input"},
		{`curl_exec\s*\(\s*\$`, WARN, "curl_exec with variable - inspect source"},
		{`wp_load_(?:prefix| constants)`, WARN, "Direct WP core loading attempt"},
		{`goto\s+[a-zA-Z_]`, WARN, "goto statement - uncommon in legitimate plugins"},
		{`\$GLOBALS\s*\[`, CRITICAL, "Manipulating $GLOBALS - possible exploit"},
		{`unserialize\s*\(\s*\$_(?:POST|GET|REQUEST)`, CRITICAL, "unserialize with user input - PHP object injection risk"},
		{`str_rot13\s*\(\s*base64_decode`, CRITICAL, "str_rot13 + base64_decode - encoding obfuscation"},
		{`assert\s*\(.*\$`, WARN, "assert with variable - can execute code in some PHP versions"},
	}

	// Add custom patterns from config
	for _, p := range s.cfg.SuspiciousPatterns {
		defaults = append(defaults, struct {
			regex    string
			severity Severity
			msg      string
		}{regex: p, severity: WARN, msg: fmt.Sprintf("Custom pattern: %s", p)})
	}

	for _, d := range defaults {
		re, err := regexp.Compile(d.regex)
		if err != nil {
			continue
		}
		s.patterns = append(s.patterns, &pattern{
			regex:    re,
			severity: d.severity,
			message:  d.msg,
		})
	}
}

func (s *Scanner) ScanFile(path string) ([]Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	maxSize := int64(s.cfg.MaxFileSizeMB) * 1024 * 1024
	if info.Size() > maxSize {
		return nil, nil // skip large files
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var results []Result
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		content := scanner.Bytes()

		for _, p := range s.patterns {
			if p.regex.Match(content) {
				results = append(results, Result{
					File:        path,
					Severity:    p.severity,
					Pattern:     p.regex.String(),
					Message:     p.message,
					Line:        lineNum,
					AutoFixable: false,
				})
			}
		}
	}

	return results, nil
}

type AITriageResult struct {
	Malicious   bool
	Confidence  float64
	Reason      string
	Recommendation string
}

func (s *Scanner)AITriage(ctx context.Context, path string, codeSnippet string) (*AITriageResult, error) {
	if !s.aiCfg.Enabled {
		return &AITriageResult{Malicious: false, Confidence: 0}, nil
	}

	switch s.aiCfg.Provider {
	case "openrouter":
		return s.openrouterTriage(ctx, codeSnippet)
	case "claude":
		return s.openrouterTriage(ctx, codeSnippet) // same API shape
	default:
		return &AITriageResult{Malicious: false, Confidence: 0}, nil
	}
}

func (s *Scanner) openrouterTriage(ctx context.Context, code string) (*AITriageResult, error) {
	systemPrompt := s.aiCfg.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = "You are a WordPress security analyzer. Given PHP code, respond with JSON: {\"malicious\": bool, \"confidence\": 0.0-1.0, \"reason\": \"...\", \"recommendation\": \"...\"}"
	}

	payload := map[string]interface{}{
		"model": s.aiCfg.Model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": fmt.Sprintf("Analyze this PHP code for WordPress security issues:\n\n%s", code)},
		},
		"temperature": 0.1,
	}

	reqBody, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", s.aiCfg.APIURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.aiCfg.APIKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Choices) == 0 {
		return &AITriageResult{}, nil
	}

	raw := result.Choices[0].Message.Content
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var triage AITriageResult
	if err := json.Unmarshal([]byte(raw), &triage); err != nil {
		return nil, err
	}

	return &triage, nil
}