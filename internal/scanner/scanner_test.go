package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cbuntingde/wp-guard/internal/config"
)

func TestScannerPatternCompilation(t *testing.T) {
	cfg := config.ScannerConfig{
		MaxFileSizeMB:     10,
		SuspiciousPatterns: []string{`eval\s*\(`},
	}
	aiCfg := config.AIConfig{}

	s := NewScanner(cfg, aiCfg)

	if s == nil {
		t.Fatal("NewScanner returned nil")
	}

	if len(s.patterns) == 0 {
		t.Error("expected patterns to be compiled")
	}
}

func TestScanFileBasic(t *testing.T) {
	cfg := config.ScannerConfig{
		MaxFileSizeMB: 10,
	}
	aiCfg := config.AIConfig{}
	s := NewScanner(cfg, aiCfg)

	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.php")

	phpCode := `<?php
// Legitimate code
function hello() {
	echo "Hello World";
}
`

	if err := os.WriteFile(testFile, []byte(phpCode), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	results, err := s.ScanFile(testFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("expected no malicious patterns in legitimate code, got %d results", len(results))
	}
}

func TestScanFileWithMaliciousCode(t *testing.T) {
	cfg := config.ScannerConfig{
		MaxFileSizeMB: 10,
	}
	aiCfg := config.AIConfig{}
	s := NewScanner(cfg, aiCfg)

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "malware.php")

	// Code with base64_decode - classic backdoor pattern
	phpCode := `<?php
$code = base64_decode($_POST['cmd']);
eval($code);
?>`

	if err := os.WriteFile(testFile, []byte(phpCode), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	results, err := s.ScanFile(testFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("expected to detect malicious patterns")
	}

	// Verify at least one is CRITICAL
	foundCritical := false
	for _, r := range results {
		if r.Severity == CRITICAL {
			foundCritical = true
			break
		}
	}

	if !foundCritical {
		t.Error("expected at least one CRITICAL severity finding")
	}
}

func TestScanFileExceedsMaxSize(t *testing.T) {
	cfg := config.ScannerConfig{
		MaxFileSizeMB: 1, // 1 MB
	}
	aiCfg := config.AIConfig{}
	s := NewScanner(cfg, aiCfg)

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "large.php")

	// Create a file larger than 1 MB
	largeData := make([]byte, 2*1024*1024) // 2 MB
	if err := os.WriteFile(testFile, largeData, 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	results, err := s.ScanFile(testFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Should skip file and return no results
	if len(results) != 0 {
		t.Errorf("expected to skip large file, got %d results", len(results))
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev Severity
		str string
	}{
		{INFO, "INFO"},
		{WARN, "WARN"},
		{CRITICAL, "CRITICAL"},
		{Severity(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.str {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.str)
		}
	}
}

func TestScanFileNotFound(t *testing.T) {
	cfg := config.ScannerConfig{
		MaxFileSizeMB: 10,
	}
	aiCfg := config.AIConfig{}
	s := NewScanner(cfg, aiCfg)

	results, err := s.ScanFile("/nonexistent/file.php")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	if len(results) != 0 {
		t.Errorf("expected no results for error, got %d", len(results))
	}
}

func TestAITriageDisabled(t *testing.T) {
	cfg := config.ScannerConfig{
		MaxFileSizeMB: 10,
	}
	aiCfg := config.AIConfig{
		Enabled: false,
	}
	s := NewScanner(cfg, aiCfg)

	ctx := context.Background()
	result, err := s.AITriage(ctx, "test.php", "<?php echo 'test'; ?>")

	if err != nil {
		t.Errorf("AITriage with disabled AI should not error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
	if result.Malicious {
		t.Error("disabled AI should return non-malicious")
	}
	if result.Confidence != 0 {
		t.Errorf("disabled AI should return 0 confidence, got %f", result.Confidence)
	}
}

func TestPatternEdgeCases(t *testing.T) {
	cfg := config.ScannerConfig{
		MaxFileSizeMB: 10,
	}
	aiCfg := config.AIConfig{}
	s := NewScanner(cfg, aiCfg)

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "edge.php")

	// Test code with spaces and variations
	phpCode := `<?php
	eval   (  $code  );
	base64_decode($x);
	shell_exec("ls");
?>`

	if err := os.WriteFile(testFile, []byte(phpCode), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	results, err := s.ScanFile(testFile)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	if len(results) < 2 {
		t.Errorf("expected multiple pattern matches, got %d", len(results))
	}
}
