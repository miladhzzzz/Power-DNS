// Package resolver ties together every resolution strategy Power-DNS knows
// about: local records, cache, relay, direct DoH, direct DoT, and plain DNS.
//
// v1's equivalent (DnsHandler.ServeDNS in internal/dns/main.go) hardcoded a
// two-step chain (relay, then plain-DNS-on-failure) directly inside the DNS
// server's request handler, with no cache-first check despite a cache
// existing, no way to reorder or disable a strategy, and no per-call
// timeout anywhere in the chain -- a hung relay meant a hung client query.
// v2 makes the chain configurable (config.ResolutionConfig.Order) and each
// strategy self-contained, timeout-bounded, and independently testable. On
// top of that, every network-bound strategy (relay/doh/dot/plain) records
// its own latency histogram, and concurrent identical queries for the same
// (name, type, strategy) are coalesced into a single in-flight upstream
// attempt (see inflightCall) so N clients asking for the same
// freshly-expired record in the same instant cost one upstream round trip,
// not N.
package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/cache"
	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/records"
	"github.com/miladhzzzz/power-dns/internal/relay"
	"github.com/miladhzzzz/power-dns/internal/upstream"
)

// Strategy names, matching config.ResolutionConfig.Order entries.
const (
	StrategyRecords = "records"
	StrategyCache   = "cache"
	StrategyRelay   = "relay"
	StrategyDoH     = "doh"
	StrategyDoT     = "dot"
	StrategyPlain   = "plain"
)

// isUpstream reports whether a strategy is network-bound (as opposed to
// records/cache, which are local lookups) -- these are the ones that get
// latency histograms and in-flight coalescing.
func isUpstream(strategy string) bool {
	switch strategy {
	case StrategyRelay, StrategyDoH, StrategyDoT, StrategyPlain:
		return true
	default:
		return false
	}
}

// Resolver answers DNS queries by trying each configured strategy in order.
type Resolver struct {
	Order []string

	Records     *records.Store // may be nil if disabled
	Cache       *cache.Cache   // may be nil if disabled
	RelayClient *relay.Client  // may be nil if no relay configured
	DoH         *upstream.DoHClient
	DoT         *upstream.DoTClient
	Plain       *upstream.PlainClient

	Timeout time.Duration // per relay/doh/dot/plain attempt
	Logger  *slog.Logger
	Metrics *metrics.Registry

	// inflight coalesces concurrent calls to the same (qname, qtype,
	// strategy) into a single in-flight upstream attempt; see
	// attemptUpstream. Deliberately not golang.org/x/sync/singleflight:
	// that package reports the same "shared" flag to every caller in a
	// coalesced group, including whichever one actually executed the
	// call, which would make it impossible to count "real calls" and
	// "coalesced callers" as a clean partition for metrics. This
	// hand-rolled version tracks that distinction directly, since getting
	// powerdns_upstream_calls_total and powerdns_upstream_coalesced_total
	// right depends on it.
	inflightMu sync.Mutex
	inflight   map[string]*inflightCall
}

// inflightCall represents one real, currently-running (or just-finished)
// upstream attempt that other callers for the same key are waiting on.
type inflightCall struct {
	wg   sync.WaitGroup
	resp *dns.Msg
	err  error
}

// Resolve answers req, trying strategies in r.Order and returning the first
// success. It always returns a message suitable for writing back to the
// original client (Id and Question populated), even on total failure
// (SERVFAIL) so callers never have to synthesize an error reply themselves.
//
// origin identifies who asked (typically the querying client's IP:port, as
// seen by the local DNS listener) and is included in every debug log line
// below, alongside which strategy was tried and whether it answered -- so
// with log.level = "debug" you can trace exactly which route (records,
// cache, relay, doh, dot, or plain) answered each query, and for whom.
// These lines are debug-only by design: at info level and above, only
// service lifecycle and genuine failures are logged, so normal operation
// doesn't spam the log with a line per query.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg, origin string) *dns.Msg {
	if len(req.Question) == 0 {
		return servfail(req)
	}
	q := req.Question[0]
	start := time.Now()

	for _, strategy := range r.Order {
		var (
			resp *dns.Msg
			err  error
		)
		switch {
		case strategy == StrategyRecords:
			resp, err = r.fromRecords(req, q)
		case strategy == StrategyCache:
			resp, err = r.fromCache(req, q, origin)
		case strategy == StrategyRelay && r.RelayClient == nil:
			// Relay is disabled (no relay.url or relay.dot_addr
			// configured) -- this is a normal, expected configuration,
			// not a failure, so skip it without logging anything.
			continue
		case isUpstream(strategy):
			var shared bool
			resp, err, shared = r.attemptUpstream(ctx, req, q, strategy)
			if shared {
				r.log().Debug("coalesced with an in-flight request", "origin", origin, "strategy", strategy, "qname", q.Name)
			}
		default:
			continue
		}
		if err != nil {
			r.log().Debug("resolution strategy failed", "origin", origin, "strategy", strategy, "qname", q.Name, "error", err)
			continue
		}
		if resp == nil {
			r.log().Debug("resolution strategy declined", "origin", origin, "strategy", strategy, "qname", q.Name)
			continue // e.g. a records/cache miss; try the next strategy
		}

		r.recordMetric(strategy)
		if strategy != StrategyCache && strategy != StrategyRecords && r.Cache != nil {
			r.Cache.Set(q.Name, q.Qtype, resp)
		}
		r.log().Debug("resolved query",
			"origin", origin,
			"qname", q.Name,
			"qtype", dns.TypeToString[q.Qtype],
			"route", strategy,
			"duration_ms", time.Since(start).Milliseconds(),
		)
		return resp
	}

	r.recordMetric("failed")
	r.log().Warn("all resolution strategies failed", "origin", origin, "qname", q.Name, "duration_ms", time.Since(start).Milliseconds())
	return servfail(req)
}

// ResolveUpstreamOnly re-resolves (name, qtype) directly against whichever
// of relay/doh/dot/plain appear in r.Order, bypassing records and cache
// entirely. It shares the same per-strategy latency metrics and
// singleflight coalescing as Resolve, so a background prefetch attempt
// coalesces with a concurrent real query for the same record instead of
// racing it. This is the RefreshFunc wired into cache.PrefetchOptions.
func (r *Resolver) ResolveUpstreamOnly(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	q := req.Question[0]

	var lastErr error
	for _, strategy := range r.Order {
		if !isUpstream(strategy) || (strategy == StrategyRelay && r.RelayClient == nil) {
			continue
		}
		resp, err, _ := r.attemptUpstream(ctx, req, q, strategy)
		if err != nil {
			lastErr = err
			continue
		}
		if resp != nil {
			return resp, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream strategy configured")
	}
	return nil, fmt.Errorf("prefetch refresh of %s %s failed: %w", name, dns.TypeToString[qtype], lastErr)
}

// attemptUpstream runs one network-bound strategy for (req, q), coalescing
// concurrent callers for the same (qname, qtype, strategy) into a single
// in-flight attempt, and recording that strategy's latency and call count
// exactly once per real attempt (not once per coalesced waiter) -- every
// caller that instead piggybacks on someone else's in-flight attempt is
// counted separately via powerdns_upstream_coalesced_total. Every caller
// still gets back its own independent *dns.Msg, correctly re-stamped with
// its own request's ID: the in-flight attempt's result is shared, never the
// response object itself, since a shared Id would break the DNS protocol
// for every caller but the one that triggered the request.
func (r *Resolver) attemptUpstream(ctx context.Context, req *dns.Msg, q dns.Question, strategy string) (resp *dns.Msg, err error, shared bool) {
	key := dns.Fqdn(q.Name) + "|" + dns.TypeToString[q.Qtype] + "|" + strategy

	r.inflightMu.Lock()
	if r.inflight == nil {
		r.inflight = make(map[string]*inflightCall)
	}
	if call, ok := r.inflight[key]; ok {
		// Another caller is already resolving this exact query; wait for
		// it instead of starting a redundant one.
		r.inflightMu.Unlock()
		call.wg.Wait()
		if r.Metrics != nil {
			r.Metrics.IncUpstreamCoalesced(strategy)
		}
		if call.err != nil {
			return nil, call.err, true
		}
		if call.resp == nil {
			return nil, fmt.Errorf("upstream strategy %q returned no response and no error", strategy), true
		}
		return restampReply(call.resp, req), nil, true
	}

	call := &inflightCall{}
	call.wg.Add(1)
	r.inflight[key] = call
	r.inflightMu.Unlock()

	func() {
		defer func() {
			r.inflightMu.Lock()
			delete(r.inflight, key)
			r.inflightMu.Unlock()
			call.wg.Done()
		}()
		call.resp, call.err = r.callUpstream(ctx, req, strategy)
	}()

	if call.err != nil {
		return nil, call.err, false
	}
	if call.resp == nil {
		return nil, fmt.Errorf("upstream strategy %q returned no response and no error", strategy), false
	}
	return restampReply(call.resp, req), nil, false
}

// restampReply deep-copies shared (the response singleflight handed back,
// possibly to several waiters at once) and re-stamps it as a reply to req,
// so each caller's Id and Question match what it actually asked, while the
// underlying Answer/Ns/Extra content -- the expensive part to obtain --
// stays shared.
func restampReply(shared *dns.Msg, req *dns.Msg) *dns.Msg {
	resp := shared.Copy()
	answer, ns, extra := resp.Answer, resp.Ns, resp.Extra
	resp.SetReply(req)
	resp.Answer, resp.Ns, resp.Extra = answer, ns, extra
	return resp
}

// callUpstream is the actual per-strategy network call, run at most once
// per singleflight key regardless of how many callers are waiting on it.
func (r *Resolver) callUpstream(ctx context.Context, req *dns.Msg, strategy string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	start := time.Now()
	var (
		resp *dns.Msg
		err  error
	)
	switch strategy {
	case StrategyRelay:
		if r.RelayClient == nil {
			return nil, fmt.Errorf("no relay configured")
		}
		resp, err = r.RelayClient.Resolve(ctx, req)
	case StrategyDoH:
		if r.DoH == nil {
			return nil, fmt.Errorf("no doh upstream configured")
		}
		resp, err = r.DoH.Resolve(ctx, req)
	case StrategyDoT:
		if r.DoT == nil {
			return nil, fmt.Errorf("no dot upstream configured")
		}
		resp, err = r.DoT.Resolve(ctx, req)
	case StrategyPlain:
		if r.Plain == nil {
			return nil, fmt.Errorf("no plain upstream configured")
		}
		resp, err = r.Plain.Resolve(ctx, req)
	default:
		return nil, fmt.Errorf("unknown upstream strategy %q", strategy)
	}

	if r.Metrics != nil {
		r.Metrics.ObserveUpstreamLatency(strategy, time.Since(start))
		r.Metrics.IncUpstreamCall(strategy)
	}
	return resp, err
}

func (r *Resolver) fromRecords(req *dns.Msg, q dns.Question) (*dns.Msg, error) {
	if r.Records == nil {
		return nil, nil
	}
	matches := r.Records.Lookup(q.Name, dns.TypeToString[q.Qtype])
	if len(matches) == 0 {
		return nil, nil
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	for _, rec := range matches {
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", rec.Name, rec.TTL, rec.Type, rec.Value))
		if err != nil {
			return nil, fmt.Errorf("building RR for record %+v: %w", rec, err)
		}
		resp.Answer = append(resp.Answer, rr)
	}
	return resp, nil
}

// fromCache looks up (q.Name, q.Qtype) in the cache and debug-logs the
// outcome. Hit/miss/eviction *metrics* are recorded by the Cache itself
// (see internal/cache), except for the one case the Cache can't see on its
// own: caching being disabled entirely, which is recorded here as a
// metrics.MissDisabled miss so "why did this query miss the cache" always
// has an answer, even when there's no cache to ask.
func (r *Resolver) fromCache(req *dns.Msg, q dns.Question, origin string) (*dns.Msg, error) {
	if r.Cache == nil {
		if r.Metrics != nil {
			r.Metrics.IncCacheMiss(metrics.MissDisabled)
		}
		r.log().Debug("cache disabled", "origin", origin, "qname", q.Name, "qtype", dns.TypeToString[q.Qtype])
		return nil, nil
	}
	resp, ok := r.Cache.Get(req, q.Name, q.Qtype)
	if ok {
		r.log().Debug("cache hit", "origin", origin, "qname", q.Name, "qtype", dns.TypeToString[q.Qtype])
		return resp, nil
	}
	r.log().Debug("cache miss", "origin", origin, "qname", q.Name, "qtype", dns.TypeToString[q.Qtype])
	return nil, nil
}

func (r *Resolver) recordMetric(strategy string) {
	if r.Metrics != nil {
		r.Metrics.IncQuery(strategy)
	}
}

func (r *Resolver) log() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

func servfail(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	return m
}
