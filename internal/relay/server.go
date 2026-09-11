// Package relay implements both sides of the client<->relay connection,
// over two transports: RFC 8484 DNS-over-HTTPS (Server.ServeHTTP) and
// RFC 7858 DNS-over-TLS (DoTServer). Running both means a network that
// blocks one transport doesn't necessarily block the other.
//
// v1's relay was a Gin controller that only handled GET requests over
// plain HTTP, decoded answers into a hand-rolled JSON shape carrying
// nothing but A records, had no DoT support at all, and had no way to
// restrict who could use it or how fast. v2's Server is a plain
// net/http.Handler that speaks RFC 8484 directly: any standard DoH client
// can point at it, not just Power-DNS's own client, and full wire-format
// messages mean every record type round-trips intact.
package relay

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/upstream"
	"github.com/miladhzzzz/power-dns/internal/wire"
)

// Upstream is anything that can resolve a DNS message against the real
// internet. *upstream.DoHClient and a plain-DNS wrapper both satisfy this.
type Upstream interface {
	Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

// Server is an RFC 8484 DoH endpoint. It resolves queries against Upstream
// and optionally enforces an auth token, an allow-list of domains, and a
// per-source rate limit -- none of which v1's open relay had.
type Server struct {
	Upstream        Upstream
	Logger          *slog.Logger
	Metrics         *metrics.Registry
	AuthToken       string   // if set, require "Authorization: Bearer <token>"
	AllowedSuffixes []string // if non-empty, only resolve names under these suffixes

	limiter *rateLimiter
}

// NewServer builds a relay Server. ratePerMinute of 0 disables rate limiting.
func NewServer(up Upstream, logger *slog.Logger, reg *metrics.Registry, authToken string, allowedSuffixes []string, ratePerMinute int) *Server {
	return &Server{
		Upstream:        up,
		Logger:          logger,
		Metrics:         reg,
		AuthToken:       authToken,
		AllowedSuffixes: allowedSuffixes,
		limiter:         newRateLimiter(ratePerMinute, time.Minute),
	}
}

// ServeHTTP implements RFC 8484: a GET with a base64url "dns" query
// parameter, or a POST with an application/dns-message body.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.AuthToken != "" && !validBearer(r, s.AuthToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if s.limiter != nil && !s.limiter.Allow(clientIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	reqBytes, err := readQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	reqMsg, err := wire.Unpack(reqBytes)
	if err != nil {
		http.Error(w, "malformed dns message", http.StatusBadRequest)
		return
	}

	respMsg, err := s.resolve(r.Context(), reqMsg, "doh")
	if err != nil {
		if err == errDomainNotAllowed {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if err == errNoQuestion {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "resolution failed", http.StatusBadGateway)
		return
	}

	respBytes, err := wire.Pack(respMsg)
	if err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", wire.ContentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

var (
	errDomainNotAllowed = fmt.Errorf("domain not allowed")
	errNoQuestion       = fmt.Errorf("no question in dns message")
)

// resolve is the transport-agnostic core shared by the DoH (ServeHTTP) and
// DoT (DoTServer) endpoints: check the allow-list, resolve via Upstream,
// record metrics and logs, and stamp the reply's ID to match the request.
// transport is just a log label ("doh" or "dot").
func (s *Server) resolve(ctx context.Context, reqMsg *dns.Msg, transport string) (*dns.Msg, error) {
	if len(reqMsg.Question) == 0 {
		return nil, errNoQuestion
	}
	qname := reqMsg.Question[0].Name
	if !s.allowed(qname) {
		return nil, errDomainNotAllowed
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	respMsg, err := s.Upstream.Resolve(ctx, reqMsg)
	if s.Metrics != nil {
		s.Metrics.ObserveRelayLatency(time.Since(start))
	}
	if err != nil {
		s.log().Warn("relay resolution failed", "transport", transport, "qname", qname, "error", err)
		return nil, err
	}
	respMsg.Id = reqMsg.Id

	s.log().Info("relay query", "transport", transport, "qname", qname, "qtype", dns.TypeToString[reqMsg.Question[0].Qtype], "duration_ms", time.Since(start).Milliseconds())
	return respMsg, nil
}

func (s *Server) allowed(qname string) bool {
	if len(s.AllowedSuffixes) == 0 {
		return true
	}
	qname = strings.ToLower(qname)
	for _, suffix := range s.AllowedSuffixes {
		if strings.HasSuffix(qname, strings.ToLower(dns.Fqdn(suffix))) {
			return true
		}
	}
	return false
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func readQuery(r *http.Request) ([]byte, error) {
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			return nil, fmt.Errorf("missing dns query parameter")
		}
		return wire.B64URLDecode(q)
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && ct != wire.ContentType {
			return nil, fmt.Errorf("unsupported content-type %q, want %q", ct, wire.ContentType)
		}
		return io.ReadAll(io.LimitReader(r.Body, 64*1024))
	default:
		return nil, fmt.Errorf("method %s not allowed", r.Method)
	}
}

func validBearer(r *http.Request, token string) bool {
	got := r.Header.Get("Authorization")
	return got == "Bearer "+token
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// rateLimiter is a simple per-key fixed-window limiter: good enough to blunt
// abuse of a relay endpoint without pulling in an external dependency.
type rateLimiter struct {
	limit  int
	window time.Duration

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count      int
	windowFrom time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	if limit <= 0 {
		return nil
	}
	return &rateLimiter{limit: limit, window: window, buckets: make(map[string]*bucket)}
}

func (rl *rateLimiter) Allow(key string) bool {
	if rl == nil {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok || now.Sub(b.windowFrom) > rl.window {
		b = &bucket{count: 0, windowFrom: now}
		rl.buckets[key] = b
	}
	b.count++
	return b.count <= rl.limit
}

var _ Upstream = (*upstream.Chain)(nil)
