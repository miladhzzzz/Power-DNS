// Package resolver ties together every resolution strategy Power-DNS knows
// about: local records, cache, relay, direct DoH, direct DoT, and plain DNS.
//
// v1's equivalent (DnsHandler.ServeDNS in internal/dns/main.go) hardcoded a
// two-step chain (relay, then plain-DNS-on-failure) directly inside the DNS
// server's request handler, with no cache-first check despite a cache
// existing, no way to reorder or disable a strategy, and no per-call
// timeout anywhere in the chain -- a hung relay meant a hung client query.
// v2 makes the chain configurable (config.ResolutionConfig.Order) and each
// strategy self-contained, timeout-bounded, and independently testable.
package resolver

import (
	"context"
	"fmt"
	"log/slog"
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
}

// Resolve answers req, trying strategies in r.Order and returning the first
// success. It always returns a message suitable for writing back to the
// original client (Id and Question populated), even on total failure
// (SERVFAIL) so callers never have to synthesize an error reply themselves.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) *dns.Msg {
	if len(req.Question) == 0 {
		return servfail(req)
	}
	q := req.Question[0]

	for _, strategy := range r.Order {
		var (
			resp *dns.Msg
			err  error
		)
		switch strategy {
		case StrategyRecords:
			resp, err = r.fromRecords(req, q)
		case StrategyCache:
			resp, err = r.fromCache(req, q)
		case StrategyRelay:
			resp, err = r.fromRelay(ctx, req)
		case StrategyDoH:
			resp, err = r.fromDoH(ctx, req)
		case StrategyDoT:
			resp, err = r.fromDoT(ctx, req)
		case StrategyPlain:
			resp, err = r.fromPlain(ctx, req)
		default:
			continue
		}
		if err != nil {
			r.log().Debug("resolution strategy failed", "strategy", strategy, "qname", q.Name, "error", err)
			continue
		}
		if resp == nil {
			continue // strategy declined to answer (e.g. cache miss); try the next one
		}

		r.recordMetric(strategy)
		if strategy != StrategyCache && strategy != StrategyRecords && r.Cache != nil {
			r.Cache.Set(q.Name, q.Qtype, resp)
		}
		return resp
	}

	r.recordMetric("failed")
	r.log().Warn("all resolution strategies failed", "qname", q.Name)
	return servfail(req)
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

func (r *Resolver) fromCache(req *dns.Msg, q dns.Question) (*dns.Msg, error) {
	if r.Cache == nil {
		return nil, nil
	}
	if resp, ok := r.Cache.Get(req, q.Name, q.Qtype); ok {
		return resp, nil
	}
	return nil, nil
}

func (r *Resolver) fromRelay(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if r.RelayClient == nil {
		return nil, fmt.Errorf("no relay configured")
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	return r.RelayClient.Resolve(ctx, req)
}

func (r *Resolver) fromDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if r.DoH == nil {
		return nil, fmt.Errorf("no doh upstream configured")
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	return r.DoH.Resolve(ctx, req)
}

func (r *Resolver) fromDoT(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if r.DoT == nil {
		return nil, fmt.Errorf("no dot upstream configured")
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	return r.DoT.Resolve(ctx, req)
}

func (r *Resolver) fromPlain(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if r.Plain == nil {
		return nil, fmt.Errorf("no plain upstream configured")
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	return r.Plain.Resolve(ctx, req)
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
