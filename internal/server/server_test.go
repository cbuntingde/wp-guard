package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
	"github.com/cbuntingde/wp-guard/internal/store"
)

func TestRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(1, 3) // 3 alerts per 1 second window

	// First 3 should be allowed
	if !limiter.Allow() {
		t.Error("first alert should be allowed")
	}
	if !limiter.Allow() {
		t.Error("second alert should be allowed")
	}
	if !limiter.Allow() {
		t.Error("third alert should be allowed")
	}

	// Fourth should be blocked
	if limiter.Allow() {
		t.Error("fourth alert should be blocked")
	}

	// After window passes, should be allowed again
	time.Sleep(1100 * time.Millisecond)
	if !limiter.Allow() {
		t.Error("alert after window should be allowed")
	}
}

func TestRateLimiterEdgeCases(t *testing.T) {
	limiter := NewRateLimiter(1, 1) // 1 alert per 1 second window

	// First should be allowed
	if !limiter.Allow() {
		t.Error("first alert should be allowed")
	}

	// Second should be blocked
	if limiter.Allow() {
		t.Error("second alert should be blocked")
	}

	// After window passes, should be allowed again
	time.Sleep(1100 * time.Millisecond)
	if !limiter.Allow() {
		t.Error("alert after window should be allowed")
	}
}

func TestServerHandleHealth(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{Enabled: true},
	}
	baseline := store.NewBaseline("/test")
	srv := New(cfg, baseline, nil)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	srv.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result["status"] != "ok" {
		t.Errorf("expected status=ok, got %s", result["status"])
	}

	// Check security headers
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("missing X-Frame-Options header")
	}
}

func TestServerHandleStatus(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{Enabled: true},
	}
	baseline := store.NewBaseline("/test")
	baseline.Files["file1.php"] = store.FileRecord{Path: "file1.php", Hash: "abc"}
	baseline.Files["file2.php"] = store.FileRecord{Path: "file2.php", Hash: "def"}

	srv := New(cfg, baseline, nil)

	// Add some alerts
	srv.alerts = append(srv.alerts, Alert{
		Timestamp: time.Now().Format(time.RFC3339),
		Severity:  "CRITICAL",
	})

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()

	srv.handleStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var result Status
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if result.FilesTracked != 2 {
		t.Errorf("expected FilesTracked=2, got %d", result.FilesTracked)
	}
}

func TestServerRecordAlert(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{Enabled: true},
		RateLimit: config.RateLimitConfig{
			Enabled:   false,
			WindowSec: 300,
			MaxAlerts: 5,
		},
	}
	baseline := store.NewBaseline("/test")
	srv := New(cfg, baseline, nil)

	srv.RecordAlert("modify", "test.php", "CRITICAL", "suspicious pattern found")

	if len(srv.alerts) != 1 {
		t.Errorf("expected 1 alert, got %d", len(srv.alerts))
	}

	alert := srv.alerts[0]
	if alert.File != "test.php" {
		t.Errorf("expected file=test.php, got %s", alert.File)
	}
	if alert.Severity != "CRITICAL" {
		t.Errorf("expected severity=CRITICAL, got %s", alert.Severity)
	}
}

func TestServerRecordAlertBounded(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{Enabled: true},
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
	}
	baseline := store.NewBaseline("/test")
	srv := New(cfg, baseline, nil)

	// Record more alerts than MaxAlertsInMemory
	for i := 0; i < MaxAlertsInMemory+100; i++ {
		srv.RecordAlert("test", "file.php", "INFO", "test alert")
	}

	if len(srv.alerts) > MaxAlertsInMemory {
		t.Errorf("expected max %d alerts, got %d", MaxAlertsInMemory, len(srv.alerts))
	}

	// Most recent alerts should be kept
	if srv.alerts[len(srv.alerts)-1].Message != "test alert" {
		t.Error("expected most recent alert to be kept")
	}
}

func TestServerAuthMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Test with auth token required
	authHandler := authMiddleware("secret-token", handler)

	// Request without auth should be rejected
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	// Request with correct token should succeed
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	w = httptest.NewRecorder()
	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Request with wrong token should fail
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w = httptest.NewRecorder()
	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestServerAuthMiddlewareNoToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No auth token required (empty string)
	authHandler := authMiddleware("", handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when no auth required, got %d", w.Code)
	}
}

func TestServerStop(t *testing.T) {
	cfg := &config.Config{
		HTTP: config.HTTPConfig{Enabled: false},
	}
	baseline := store.NewBaseline("/test")
	srv := New(cfg, baseline, nil)

	err := srv.Stop()
	if err != nil {
		t.Errorf("Stop() should not error when HTTP disabled: %v", err)
	}
}
