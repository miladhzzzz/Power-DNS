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
// per-source rate limit -- none of which v1's open relay had. Concurrent
// queries for the same (qname, qtype) -- whether they arrive over DoH, DoT,
// or a mix of both -- are coalesced into a single upstream resolution: this
// is exactly the "50 clients ask for the same freshly-expired domain at
// once" scenario a public relay is most likely to actually see.
type Server struct {
	Upstream Upstream
	Logger   *slog.Logger
	Metrics  *metrics.Registry

	// secMu protects AuthToken, AllowedSuffixes, and limiter for hot-reload.
	secMu           sync.RWMutex
	AuthToken       string   // if set, require "Authorization: Bearer <token>"
	AllowedSuffixes []string // if non-empty, only resolve names under these suffixes
	limiter         *rateLimiter

	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
}

// ApplySecurity updates auth token, domain allow-list, and rate limit without
// restarting the listener (used on SIGHUP config reload).
func (s *Server) ApplySecurity(authToken string, allowedSuffixes []string, ratePerMinute int) {
	s.secMu.Lock()
	defer s.secMu.Unlock()
	s.AuthToken = authToken
	s.AllowedSuffixes = append([]string(nil), allowedSuffixes...)
	s.limiter = newRateLimiter(ratePerMinute, time.Minute)
}

// ApplyUpstream swaps the upstream resolver used for relay queries (hot-reload).
func (s *Server) ApplyUpstream(up Upstream) {
	s.secMu.Lock()
	defer s.secMu.Unlock()
	s.Upstream = up
}

// inflightCall represents one real, currently-running (or just-finished)
// upstream resolution that other concurrent queries for the same key are
// waiting on. Deliberately not golang.org/x/sync/singleflight -- see the
// identical note on internal/resolver.Resolver.inflight, which applies here
// for the same reason: telling "I executed" from "I piggybacked" apart is
// what makes powerdns_relay_calls_total and powerdns_relay_coalesced_total
// a clean, non-overlapping partition instead of an approximation.
type inflightCall struct {
	wg   sync.WaitGroup
	resp *dns.Msg
	err  error
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
	s.secMu.RLock()
	token := s.AuthToken
	limiter := s.limiter
	s.secMu.RUnlock()

	if token != "" && !validBearer(r, token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if limiter != nil && !limiter.Allow(clientIP(r)) {
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

	respMsg, err := s.resolve(r.Context(), reqMsg, "doh", clientIP(r))
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
// DoT (DoTServer) endpoints: check the allow-list, resolve via Upstream
// (coalescing concurrent identical queries -- see inflightCall), record
// metrics and logs, and stamp the reply's ID to match the request. transport
// is just a log label ("doh" or "dot"); origin is the connecting client's
// address, used only for debug-level logging (see the package-level note on
// log levels below).
//
// With log.level = "debug", every query logs its origin, transport, and
// (via Upstream, if it's an *upstream.Chain with a Logger set) which
// upstream protocol actually answered -- so you can trace the full path a
// query took through the relay. At info level and above, only genuine
// failures are logged, so normal operation stays quiet.
func (s *Server) resolve(ctx context.Context, reqMsg *dns.Msg, transport, origin string) (*dns.Msg, error) {
	if len(reqMsg.Question) == 0 {
		return nil, errNoQuestion
	}
	q := reqMsg.Question[0]
	qname := q.Name
	if !s.allowed(qname) {
		s.log().Debug("relay query rejected", "reason", "domain not allowed", "origin", origin, "transport", transport, "qname", qname)
		return nil, errDomainNotAllowed
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	start := time.Now()
	respMsg, shared, err := s.resolveCoalesced(ctx, reqMsg, q)
	if err != nil {
		s.log().Warn("relay resolution failed", "origin", origin, "transport", transport, "qname", qname, "error", err)
		return nil, err
	}

	s.log().Debug("resolved query",
		"origin", origin,
		"transport", transport,
		"qname", qname,
		"qtype", dns.TypeToString[q.Qtype],
		"coalesced", shared,
		"duration_ms", time.Since(start).Milliseconds(),
	)
	return respMsg, nil
}

// resolveCoalesced runs s.Upstream.Resolve for (qname, qtype), coalescing
// concurrent callers into a single in-flight attempt. Every caller gets
// back its own independent, correctly-ID-stamped *dns.Msg regardless of
// whether it triggered the call or piggybacked on someone else's -- sharing
// the response object itself, Id included, would break the DNS protocol for
// every caller but the one that actually issued the request.
func (s *Server) resolveCoalesced(ctx context.Context, reqMsg *dns.Msg, q dns.Question) (resp *dns.Msg, shared bool, err error) {
	key := dns.Fqdn(q.Name) + "|" + dns.TypeToString[q.Qtype]

	s.inflightMu.Lock()
	if s.inflight == nil {
		s.inflight = make(map[string]*inflightCall)
	}
	if call, ok := s.inflight[key]; ok {
		s.inflightMu.Unlock()
		call.wg.Wait()
		if s.Metrics != nil {
			s.Metrics.IncRelayCoalesced()
		}
		if call.err != nil {
			return nil, true, call.err
		}
		return restampReply(call.resp, reqMsg), true, nil
	}

	call := &inflightCall{}
	call.wg.Add(1)
	s.inflight[key] = call
	s.inflightMu.Unlock()

	func() {
		defer func() {
			s.inflightMu.Lock()
			delete(s.inflight, key)
			s.inflightMu.Unlock()
			call.wg.Done()
		}()

		start := time.Now()
		s.secMu.RLock()
		up := s.Upstream
		s.secMu.RUnlock()
		if up == nil {
			call.err = fmt.Errorf("no upstream configured")
		} else {
			call.resp, call.err = up.Resolve(ctx, reqMsg)
		}
		if s.Metrics != nil {
			s.Metrics.ObserveRelayServerLatency(time.Since(start))
			s.Metrics.IncRelayCall()
		}
	}()

	if call.err != nil {
		return nil, false, call.err
	}
	return restampReply(call.resp, reqMsg), false, nil
}

// restampReply deep-copies shared (the response the coalescer handed back,
// possibly to several concurrent callers) and re-stamps it as a reply to
// req, so each caller's Id and Question match what it actually asked, while
// the underlying Answer/Ns/Extra content -- the expensive part to obtain --
// stays shared.
func restampReply(shared *dns.Msg, req *dns.Msg) *dns.Msg {
	resp := shared.Copy()
	answer, ns, extra := resp.Answer, resp.Ns, resp.Extra
	resp.SetReply(req)
	resp.Answer, resp.Ns, resp.Extra = answer, ns, extra
	resp.Id = req.Id
	return resp
}

func (s *Server) allowed(qname string) bool {
	s.secMu.RLock()
	suffixes := s.AllowedSuffixes
	s.secMu.RUnlock()
	if len(suffixes) == 0 {
		return true
	}
	qname = strings.ToLower(qname)
	for _, suffix := range suffixes {
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
