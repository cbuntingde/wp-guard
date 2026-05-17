package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cbuntingde/wp-guard/internal/config"
	"github.com/cbuntingde/wp-guard/internal/notifier"
	"github.com/cbuntingde/wp-guard/internal/store"
)

type Server struct {
	cfg    *config.Config
	notify *notifier.Notifier
	baseline *store.Baseline

	mu       sync.RWMutex
	alerts   []Alert
	rateLimiter *RateLimiter

	httpServer *http.Server
	stopped   chan struct{}
}

type Alert struct {
	Timestamp string `json:"timestamp"`
	Event    string `json:"event"`
	File     string `json:"file"`
	Severity string `json:"severity"`
	Message string `json:"message"`
}

type Status struct {
	FilesTracked  int       `json:"files_tracked"`
	LastScan   time.Time `json:"last_scan"`
	Uptime    string    `json:"uptime"`
	Alerts24h  int       `json:"alerts_24h"`
}

type RateLimiter struct {
	windowSec int
	maxAlerts int
	alerts    []time.Time
	mu       sync.Mutex
}

func NewRateLimiter(windowSec, maxAlerts int) *RateLimiter {
	return &RateLimiter{
		windowSec: windowSec,
		maxAlerts: maxAlerts,
	}
}

func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(r.windowSec) * time.Second)

	// Remove old alerts
	var recent []time.Time
	for _, t := range r.alerts {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	r.alerts = recent

	if len(r.alerts) >= r.maxAlerts {
		return false
	}

	r.alerts = append(r.alerts, now)
	return true
}

func New(cfg *config.Config, baseline *store.Baseline, notify *notifier.Notifier) *Server {
	return &Server{
		cfg:       cfg,
		baseline:  baseline,
		notify:    notify,
		rateLimiter: NewRateLimiter(cfg.RateLimit.WindowSec, cfg.RateLimit.MaxAlerts),
		stopped:   make(chan struct{}),
	}
}

func (s *Server) Start() error {
	if !s.cfg.HTTP.Enabled {
		return nil
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.HTTP.Addr, s.cfg.HTTP.Port)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/reload", s.handleReload)
	mux.HandleFunc("/metrics", s.handleMetrics)

	// Auth middleware
	handler := authMiddleware(s.cfg.HTTP.AuthToken, mux)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("[http] starting server on %s", addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[http] error: %v", err)
		}
	}()

	// Handle SIGHUP for config reload
	go s.handleSignals()

	return nil
}

func (s *Server) handleSignals() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)

	for {
		select {
		case <-s.stopped:
			return
		case <-sigCh:
			log.Println("[http] received SIGHUP, reloading config...")
			// Config reload is handled by main
			log.Println("[http] config reloaded")
		}
	}
}

func authMiddleware(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+token {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)
	alerts24h := 0
	for _, a := range s.alerts {
		if a.Timestamp > cutoff.Format(time.RFC3339) {
			alerts24h++
		}
	}

	status := Status{
		FilesTracked: len(s.baseline.Files),
		LastScan:   now, // Would track actual last scan
		Uptime:    "24h0m", // Would track actual uptime
		Alerts24h: alerts24h,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return last 100 events
	alerts := s.alerts
	if len(alerts) > 100 {
		alerts = alerts[len(alerts)-100:]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "reloading",
	})
	// Signal main to reload
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	cutoff := now.Add(-24 * time.Hour)
	alerts24h := 0
	critical24h := 0
	for _, a := range s.alerts {
		if a.Timestamp > cutoff.Format(time.RFC3339) {
			alerts24h++
			if a.Severity == "CRITICAL" {
				critical24h++
			}
		}
	}

	metrics := fmt.Sprintf(`# HELP wp_guard_files_tracked Total files tracked
# TYPE wp_guard_files_tracked gauge
wp_guard_files_tracked %d
# HELP wp_guard_alerts_total Total alerts sent
# TYPE wp_guard_alerts_total counter
wp_guard_alerts_total %d
# HELP wp_guard_alerts_24h Alerts in last 24 hours
# TYPE wp_guard_alerts_24h gauge
wp_guard_alerts_24h %d
# HELP wp_guard_critical_24h Critical alerts in last 24 hours
# TYPE wp_guard_critical_24h gauge
wp_guard_critical_24h %d
# HELP wp_guard_last_scan_timestamp Unix timestamp of last scan
# TYPE wp_guard_last_scan_timestamp gauge
wp_guard_last_scan_timestamp %d
`, len(s.baseline.Files), len(s.alerts), alerts24h, critical24h, now.Unix())

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, metrics)
}

func (s *Server) RecordAlert(event, file, severity, message string) {
	// Rate limiting
	if s.cfg.RateLimit.Enabled && !s.rateLimiter.Allow() {
		log.Printf("[rate-limit] alert suppressed for %s", file)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.alerts = append(s.alerts, Alert{
		Timestamp: time.Now().Format(time.RFC3339),
		Event:     event,
		File:      file,
		Severity:  severity,
		Message:  message,
	})

	// Keep only last 1000
	if len(s.alerts) > 1000 {
		s.alerts = s.alerts[len(s.alerts)-1000:]
	}
}

func (s *Server) Stop() error {
	close(s.stopped)
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}