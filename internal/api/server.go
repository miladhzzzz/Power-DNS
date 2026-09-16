// Package api implements the HTTP surface: health/readiness, Prometheus
// metrics, the records-management REST API, and (in relay/both mode) the
// RFC 8484 relay endpoint.
//
// v1 (internal/api) pulled in Gin plus its entire dependency tree for two
// endpoints, guessed at its own container IP via a hand-rolled network
// interface scan (getContainerIP in server.go) instead of just binding an
// address from config, and wrote every request log line to a file handle
// that was never closed or rotated. v2 uses the standard library's
// net/http.ServeMux (pattern-matching routing has been built in since Go
// 1.22), binds whatever address config says, and logs through slog.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/records"
	"github.com/miladhzzzz/power-dns/internal/relay"
)

// Config controls what the API server exposes.
type Config struct {
	Addr              string
	RelayPath         string // mount point for the RFC 8484 relay handler; empty disables it
	RecordsPathPrefix string // mount point for the records CRUD API; empty disables it
	AdminAuthToken    string // if set, required as a Bearer token on the records API
}

// Server is the HTTP API server.
type Server struct {
	cfgMu   sync.RWMutex
	cfg     Config
	logger  *slog.Logger
	metrics *metrics.Registry
	records *records.Store // nil if records management is disabled
	relay   http.Handler   // nil if relay mode isn't active

	httpServer *http.Server
}

// New builds a Server. recordsStore and relayHandler may be nil to disable
// those features.
func New(cfg Config, logger *slog.Logger, reg *metrics.Registry, recordsStore *records.Store, relayHandler *relay.Server) *Server {
	s := &Server{cfg: cfg, logger: logger, metrics: reg, records: recordsStore}
	if relayHandler != nil {
		s.relay = relayHandler
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	if s.relay != nil && cfg.RelayPath != "" {
		mux.Handle(cfg.RelayPath, s.relay)
	}

	if s.records != nil && cfg.RecordsPathPrefix != "" {
		prefix := cfg.RecordsPathPrefix
		mux.HandleFunc("GET "+prefix, s.withAuth(s.handleListRecords))
		mux.HandleFunc("POST "+prefix, s.withAuth(s.handleAddRecord))
		mux.HandleFunc("DELETE "+prefix, s.withAuth(s.handleDeleteRecord))
	}

	s.httpServer = &http.Server{
		Addr:              cfg.Addr,
		Handler:           withRequestLog(logger, mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// Run starts the HTTP server and blocks until ctx is canceled, at which
// point it shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.httpServer.ListenAndServe() }()

	s.logger.Info("api server listening", "addr", s.cfg.Addr)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("api server failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		s.logger.Info("api server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		http.Error(w, "metrics disabled", http.StatusNotFound)
		return
	}
	var b strings.Builder
	s.metrics.WriteProm(&b)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) handleListRecords(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.records.List())
}

func (s *Server) handleAddRecord(w http.ResponseWriter, r *http.Request) {
	var rec records.Record
	if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
		http.Error(w, "invalid json body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if rec.Name == "" || rec.Type == "" || rec.Value == "" {
		http.Error(w, "name, type, and value are required", http.StatusBadRequest)
		return
	}
	if err := s.records.Add(rec); err != nil {
		http.Error(w, "failed to save record: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, rec)
}

func (s *Server) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	typ := r.URL.Query().Get("type")
	value := r.URL.Query().Get("value") // optional; empty deletes all values for name+type
	if name == "" || typ == "" {
		http.Error(w, "name and type query parameters are required", http.StatusBadRequest)
		return
	}
	if err := s.records.Delete(name, typ, value); err != nil {
		http.Error(w, "failed to delete record: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read token on each request so admin_auth_token can hot-reload.
		s.cfgMu.RLock()
		token := s.cfg.AdminAuthToken
		s.cfgMu.RUnlock()
		if token == "" {
			next(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ApplyAdminAuth updates the records-API bearer token without restarting the
// HTTP server (hot-reload).
func (s *Server) ApplyAdminAuth(token string) {
	s.cfgMu.Lock()
	s.cfg.AdminAuthToken = token
	s.cfgMu.Unlock()
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func withRequestLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		logger.Debug("http request", "method", r.Method, "path", r.URL.Path, "duration_ms", time.Since(start).Milliseconds())
	})
}
