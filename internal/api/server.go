// Package api implements the HTTP surface: health/readiness, Prometheus
// metrics, the records-management REST API, management endpoints (cache
// flush/refresh, status), and (in relay/both mode) the RFC 8484 relay
// endpoint.
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

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/cache"
	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/records"
	"github.com/miladhzzzz/power-dns/internal/relay"
	"github.com/miladhzzzz/power-dns/internal/resolver"
)

// Config controls what the API server exposes.
type Config struct {
	Addr              string
	RelayPath         string // mount point for the RFC 8484 relay handler; empty disables it
	RecordsPathPrefix string // mount point for the records CRUD API; empty disables it
	AdminPathPrefix   string // mount point for management endpoints; empty disables them
	AdminAuthToken    string // if set, required as a Bearer token on records + admin APIs
}

// Server is the HTTP API server.
type Server struct {
	cfgMu   sync.RWMutex
	cfg     Config
	logger  *slog.Logger
	metrics *metrics.Registry
	records *records.Store // nil if records management is disabled
	cache   *cache.Cache   // nil if cache is disabled
	res     *resolver.Resolver // nil outside client/both mode
	relay   http.Handler   // nil if relay mode isn't active

	upstreamHealthFunc func() []UpstreamEndpointHealth
	incidentsFunc      func() []HealthIncident
	// statusFunc builds GET /admin/status. Kept as a callback so this
	// package does not import config or hold a full Config copy; main
	// closes over live state and fills a small StatusSnapshot.
	statusFunc func() StatusSnapshot

	httpServer *http.Server
}

// StatusSnapshot is the JSON body for GET .../admin/status. Fields are
// scalars, bools, and shared slice headers (server lists) — no deep copies
// of large structures on each request beyond what encoding/json allocates
// while writing the response.
type StatusSnapshot struct {
	Status string `json:"status"`
	Mode   string `json:"mode"`

	Features StatusFeatures `json:"features"`
	Log      StatusLog      `json:"log"`
	Listen   StatusListen   `json:"listen"`
	Resolution StatusResolution `json:"resolution"`
	Cache    *StatusCache   `json:"cache,omitempty"`
	Records  *StatusRecords `json:"records,omitempty"`
	Relay    StatusRelay    `json:"relay"`
	Upstream StatusUpstream `json:"upstream"`
	Security StatusSecurity `json:"security"`
	Health   StatusHealth   `json:"health"`
}

type StatusFeatures struct {
	Metrics   bool `json:"metrics"`
	Records   bool `json:"records"`
	Cache     bool `json:"cache"`
	Resolver  bool `json:"resolver"`   // client/both mode with a resolver
	Relay     bool `json:"relay"`      // process is serving DoH relay
	RelayDoT  bool `json:"relay_dot"`  // process is serving DoT relay
	DNSServer bool `json:"dns_server"` // process is answering local DNS
	Adaptive  bool `json:"adaptive"`
	AdminAPI  bool `json:"admin_api"`
	AdminAuth bool `json:"admin_auth"` // bearer required on admin/records
}

type StatusLog struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

type StatusListen struct {
	API        string `json:"api"`
	DNS        string `json:"dns,omitempty"`
	DNSDoT     string `json:"dns_dot,omitempty"`
	RelayDoT   string `json:"relay_dot,omitempty"`
	RelayPath  string `json:"relay_path,omitempty"`
}

type StatusResolution struct {
	Order    []string `json:"order"`
	Adaptive bool     `json:"adaptive"`
}

type StatusCache struct {
	Entries                     int    `json:"entries"`
	Capacity                    int    `json:"capacity"`
	MinTTLSeconds               int    `json:"min_ttl_seconds"`
	MaxTTLSeconds               int    `json:"max_ttl_seconds"`
	NegativeTTLSeconds          int    `json:"negative_ttl_seconds"`
	StaleWhileRevalidateSeconds int    `json:"stale_while_revalidate_seconds"`
	PersistPath                 string `json:"persist_path,omitempty"`
	PrefetchEnabled             bool   `json:"prefetch_enabled"`
	PrefetchThresholdSeconds    int    `json:"prefetch_threshold_seconds,omitempty"`
	PrefetchMinHits             uint64 `json:"prefetch_min_hits,omitempty"`
}

type StatusRecords struct {
	Path    string `json:"path,omitempty"`
	Count   int    `json:"count,omitempty"`
}

type StatusRelay struct {
	Configured bool   `json:"configured"` // client has relay url and/or dot
	URL        string `json:"url,omitempty"`
	DoTAddr    string `json:"dot_addr,omitempty"`
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	AuthConfigured bool `json:"auth_configured"`
}

type StatusUpstream struct {
	TimeoutSeconds int      `json:"timeout_seconds"`
	DoHServers     []string `json:"doh_servers"`
	DoTServers     []string `json:"dot_servers"`
	PlainServers   []string `json:"plain_servers"`
	DoHCount       int      `json:"doh_count"`
	DoTCount       int      `json:"dot_count"`
	PlainCount     int      `json:"plain_count"`
}

type StatusSecurity struct {
	RelayAuthConfigured  bool     `json:"relay_auth_configured"`
	AdminAuthConfigured  bool     `json:"admin_auth_configured"`
	AllowedDomains       []string `json:"allowed_domains,omitempty"`
	AllowedDomainsCount  int      `json:"allowed_domains_count"`
	RelayRateLimitPerMin int      `json:"relay_rate_limit_per_minute"`
	BannedAnswerCIDRs    []string `json:"banned_answer_cidrs"`
	BanListActive        bool     `json:"ban_list_active"`
}

type StatusHealth struct {
	EndpointsObserved int `json:"endpoints_observed"`
	ActiveIncidents   int `json:"active_incidents"`
}

// UpstreamEndpointHealth is the JSON shape for GET /api/v1/health/upstreams.
type UpstreamEndpointHealth struct {
	Path     string  `json:"path"`
	Endpoint string  `json:"endpoint"`
	State    string  `json:"state"`
	Score    float64 `json:"score"`

	EWMALatencyMs float64 `json:"ewma_latency_ms"`

	Requests  uint64 `json:"requests"`
	Successes uint64 `json:"successes"`
	Failures  uint64 `json:"failures"`

	ConsecutiveFailures  uint64 `json:"consecutive_failures"`
	ConsecutiveSuccesses uint64 `json:"consecutive_successes"`
}

// HealthIncident is the JSON shape for GET /api/v1/health/incidents.
type HealthIncident struct {
	Kind     string `json:"kind"`
	Path     string `json:"path,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	Message  string `json:"message"`
	Since    string `json:"since"`
	Severity string `json:"severity"`
}

// New builds a Server. recordsStore, answerCache, res, and relayHandler may
// be nil to disable those features.
func New(cfg Config, logger *slog.Logger, reg *metrics.Registry, recordsStore *records.Store, answerCache *cache.Cache, res *resolver.Resolver, relayHandler *relay.Server) *Server {
	s := &Server{
		cfg:     cfg,
		logger:  logger,
		metrics: reg,
		records: recordsStore,
		cache:   answerCache,
		res:     res,
	}
	if relayHandler != nil {
		s.relay = relayHandler
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/v1/health/upstreams", s.handleUpstreamHealth)
	mux.HandleFunc("GET /api/v1/health/incidents", s.handleHealthIncidents)

	if s.relay != nil && cfg.RelayPath != "" {
		mux.Handle(cfg.RelayPath, s.relay)
	}

	if s.records != nil && cfg.RecordsPathPrefix != "" {
		prefix := cfg.RecordsPathPrefix
		mux.HandleFunc("GET "+prefix, s.withAuth(s.handleListRecords))
		mux.HandleFunc("POST "+prefix, s.withAuth(s.handleAddRecord))
		mux.HandleFunc("DELETE "+prefix, s.withAuth(s.handleDeleteRecord))
	}

	if cfg.AdminPathPrefix != "" {
		prefix := strings.TrimRight(cfg.AdminPathPrefix, "/")
		mux.HandleFunc("GET "+prefix+"/status", s.withAuth(s.handleStatus))
		mux.HandleFunc("GET "+prefix+"/cache", s.withAuth(s.handleCacheStats))
		mux.HandleFunc("POST "+prefix+"/cache/flush", s.withAuth(s.handleCacheFlush))
		mux.HandleFunc("POST "+prefix+"/cache/refresh", s.withAuth(s.handleCacheRefresh))
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

// handleStatus returns feature flags and the runtime settings currently in
// force. Prefer statusFunc (wired from main) so flags match real wiring,
// not just non-nil pointers on this Server.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if s.statusFunc != nil {
		writeJSON(w, http.StatusOK, s.statusFunc())
		return
	}
	// Minimal fallback if main never wired a builder.
	out := StatusSnapshot{
		Status: "ok",
		Features: StatusFeatures{
			Metrics:  s.metrics != nil,
			Records:  s.records != nil,
			Cache:    s.cache != nil,
			Resolver: s.res != nil,
			Relay:    s.relay != nil,
			AdminAPI: s.cfg.AdminPathPrefix != "",
			AdminAuth: s.cfg.AdminAuthToken != "",
		},
		Listen: StatusListen{API: s.cfg.Addr, RelayPath: s.cfg.RelayPath},
	}
	if s.cache != nil {
		out.Cache = &StatusCache{Entries: s.cache.Len(), Capacity: s.cache.Cap()}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCacheStats returns current cache occupancy.
func (s *Server) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if s.cache == nil {
		http.Error(w, "cache disabled", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries":  s.cache.Len(),
		"capacity": s.cache.Cap(),
	})
}

// handleCacheFlush clears the answer cache, optionally limited to a single
// name (any type) or a specific (name, type).
//
//	POST /api/v1/admin/cache/flush
//	POST /api/v1/admin/cache/flush?name=example.com
//	POST /api/v1/admin/cache/flush?name=example.com&type=A
func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if s.cache == nil {
		http.Error(w, "cache disabled", http.StatusNotFound)
		return
	}
	name := r.URL.Query().Get("name")
	typStr := r.URL.Query().Get("type")

	var removed int
	switch {
	case name != "" && typStr != "":
		qtype, ok := dns.StringToType[strings.ToUpper(typStr)]
		if !ok {
			http.Error(w, "unknown type: "+typStr, http.StatusBadRequest)
			return
		}
		before := s.cache.Len()
		s.cache.Delete(name, qtype)
		removed = before - s.cache.Len()
	case name != "":
		removed = s.cache.FlushName(name)
	default:
		removed = s.cache.Flush()
	}

	s.logger.Info("cache flush", "name", name, "type", typStr, "removed", removed)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"removed": removed,
	})
}

// handleCacheRefresh forces a background upstream re-resolve for (name, type)
// and stores the result in the cache (if caching is enabled). Useful after
// you know an upstream answer changed and you don't want to wait for TTL.
//
//	POST /api/v1/admin/cache/refresh?name=example.com&type=A
func (s *Server) handleCacheRefresh(w http.ResponseWriter, r *http.Request) {
	if s.res == nil {
		http.Error(w, "resolver not available (client/both mode only)", http.StatusNotFound)
		return
	}
	name := r.URL.Query().Get("name")
	typStr := r.URL.Query().Get("type")
	if name == "" || typStr == "" {
		http.Error(w, "name and type query parameters are required", http.StatusBadRequest)
		return
	}
	qtype, ok := dns.StringToType[strings.ToUpper(typStr)]
	if !ok {
		http.Error(w, "unknown type: "+typStr, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	msg, err := s.res.ResolveUpstreamOnly(ctx, name, qtype)
	if err != nil {
		http.Error(w, "refresh failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if s.cache != nil && msg != nil {
		s.cache.Set(name, qtype, msg)
	}

	rcode := -1
	answers := 0
	if msg != nil {
		rcode = msg.Rcode
		answers = len(msg.Answer)
	}
	s.logger.Info("cache refresh", "name", name, "type", typStr, "rcode", rcode, "answers", answers)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":    name,
		"type":    strings.ToUpper(typStr),
		"rcode":   rcode,
		"answers": answers,
		"cached":  s.cache != nil,
	})
}


// SetUpstreamHealthFunc wires upstream health snapshots into the API.
func (s *Server) SetUpstreamHealthFunc(f func() []UpstreamEndpointHealth) {
	s.upstreamHealthFunc = f
}

// SetIncidentsFunc wires the incident detector into the API.
func (s *Server) SetIncidentsFunc(f func() []HealthIncident) {
	s.incidentsFunc = f
}

// SetStatusFunc wires the status snapshot builder used by GET .../admin/status.
func (s *Server) SetStatusFunc(f func() StatusSnapshot) {
	s.statusFunc = f
}

func (s *Server) handleUpstreamHealth(w http.ResponseWriter, r *http.Request) {
	f := s.upstreamHealthFunc
	if f == nil {
		writeJSON(w, http.StatusOK, []UpstreamEndpointHealth{})
		return
	}
	writeJSON(w, http.StatusOK, f())
}

func (s *Server) handleHealthIncidents(w http.ResponseWriter, r *http.Request) {
	f := s.incidentsFunc
	if f == nil {
		writeJSON(w, http.StatusOK, []HealthIncident{})
		return
	}
	writeJSON(w, http.StatusOK, f())
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

// ApplyAdminAuth updates the records-API / admin-API bearer token without
// restarting the HTTP server (hot-reload).
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
