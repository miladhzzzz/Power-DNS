// Package upstream implements the fallback resolution paths used when the
// relay is unreachable: direct DoH (RFC 8484), DoT (RFC 7858), and plain
// UDP/TCP DNS.
//
// v1 had a single hardcoded DoH server ("https://dns.google/dns-query") and
// a single hardcoded plain fallback ("8.8.8.8:53"), each tried once with no
// timeout and no retry across servers, and no DoT support at all. v2
// accepts a list for each transport and tries them in order with a bounded
// timeout per attempt, so one slow or blocked resolver -- or one blocked
// transport -- doesn't take the whole fallback chain down with it.
//
// When a health.Tracker is attached, servers within one transport are tried
// in health-preferred order (see internal/upstream/health) and each attempt
// records success/failure + latency. Cross-transport adaptive ordering is
// handled by the resolver when resolution.adaptive is enabled.
package upstream

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/filter"
	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/upstream/health"
	"github.com/miladhzzzz/power-dns/internal/wire"
)

// DoHClient queries a list of RFC 8484 DNS-over-HTTPS servers in order --
// or, if Health is set, in whatever order Health.Order currently prefers.
// Health is optional and nil-safe.
type DoHClient struct {
	Servers []string
	Client  *http.Client
	Health  *health.Tracker
}

// NewDoHClient builds a DoHClient with the given timeout applied per attempt.
//
// The Transport is configured explicitly rather than left as Go's
// zero-value default: http.DefaultTransport caps MaxIdleConnsPerHost at 2,
// which under any real concurrency (multiple domains in flight, or bursts
// coalescing doesn't fully absorb) means connections to the same DoH
// provider get closed and redialed -- a full TLS handshake -- far more
// often than necessary. Raising that limit and enabling HTTP/2 lets
// repeated queries to the same provider actually reuse a warm connection,
// which is the difference between paying TLS-handshake latency on every
// single query versus paying it once per idle-timeout window.
func NewDoHClient(servers []string, timeout time.Duration) *DoHClient {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &DoHClient{
		Servers: servers,
		Client:  &http.Client{Timeout: timeout, Transport: transport},
	}
}

// Resolve sends req to each configured DoH server in turn, returning the
// first successful response.
func (d *DoHClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(d.Servers) == 0 {
		return nil, fmt.Errorf("no doh servers configured")
	}
	reqBytes, err := wire.Pack(req)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, server := range d.Health.Order(metrics.PathDoH, d.Servers) {
		start := time.Now()
		resp, err := d.query(ctx, server, reqBytes)
		if err != nil {
			d.Health.RecordFailure(metrics.PathDoH, server, err)
			lastErr = err
			continue
		}
		d.Health.RecordSuccess(metrics.PathDoH, server, time.Since(start))
		return resp, nil
	}
	return nil, fmt.Errorf("all doh servers failed, last error: %w", lastErr)
}

func (d *DoHClient) query(ctx context.Context, server string, reqBytes []byte) (*dns.Msg, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, server, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("building request to %s: %w", server, err)
	}
	httpReq.Header.Set("Content-Type", wire.ContentType)
	httpReq.Header.Set("Accept", wire.ContentType)

	resp, err := d.Client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("querying %s: %w", server, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned status %d", server, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", server, err)
	}
	return wire.Unpack(body)
}

// Chain tries DoH first, then DoT, then plain DNS. When Adaptive is true
// and Health is set, the order of those three transports is re-ranked by
// aggregate path health (encrypted transports still never fall behind
// plain purely because plain is faster — see OrderTransports).
type Chain struct {
	DoH      *DoHClient
	DoT      *DoTClient
	Plain    *PlainClient
	Metrics  *metrics.Registry // optional
	Health   *health.Tracker   // optional; used when Adaptive is true
	Adaptive bool
}

// Resolve implements the relay.Upstream interface.
func (c *Chain) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	paths := []string{metrics.PathDoH, metrics.PathDoT, metrics.PathPlain}
	if c.Adaptive && c.Health != nil {
		paths = c.Health.OrderTransports(paths)
	}

	var lastErr error
	for _, path := range paths {
		var attempt func() (*dns.Msg, error)
		switch path {
		case metrics.PathDoH:
			if c.DoH == nil {
				continue
			}
			attempt = func() (*dns.Msg, error) { return c.DoH.Resolve(ctx, req) }
		case metrics.PathDoT:
			if c.DoT == nil {
				continue
			}
			attempt = func() (*dns.Msg, error) { return c.DoT.Resolve(ctx, req) }
		case metrics.PathPlain:
			if c.Plain == nil {
				continue
			}
			attempt = func() (*dns.Msg, error) { return c.Plain.Resolve(ctx, req) }
		default:
			continue
		}
		resp, err := c.timed(path, attempt)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no upstream available")
	}
	return nil, lastErr
}

func (c *Chain) timed(path string, attempt func() (*dns.Msg, error)) (*dns.Msg, error) {
	start := time.Now()
	resp, err := attempt()
	if c.Metrics != nil {
		c.Metrics.ObserveUpstreamLatency(path, time.Since(start))
	}
	return resp, err
}

// DoTClient queries a list of RFC 7858 DNS-over-TLS servers.
type DoTClient struct {
	Servers []string
	Client  *dns.Client
	Health  *health.Tracker
}

// NewDoTClient builds a DoTClient with the given timeout applied per attempt.
func NewDoTClient(servers []string, timeout time.Duration) *DoTClient {
	return &DoTClient{
		Servers: servers,
		Client: &dns.Client{
			Net:       "tcp-tls",
			Timeout:   timeout,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// Resolve sends req to each configured DoT server in turn over TLS.
func (d *DoTClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(d.Servers) == 0 {
		return nil, fmt.Errorf("no dot servers configured")
	}
	var lastErr error
	for _, server := range d.Health.Order(metrics.PathDoT, d.Servers) {
		start := time.Now()
		resp, _, err := d.Client.ExchangeContext(ctx, req, server)
		if err != nil {
			d.Health.RecordFailure(metrics.PathDoT, server, err)
			lastErr = err
			continue
		}
		if resp.Truncated {
			err = fmt.Errorf("%s returned a truncated response", server)
			d.Health.RecordFailure(metrics.PathDoT, server, err)
			lastErr = err
			continue
		}
		d.Health.RecordSuccess(metrics.PathDoT, server, time.Since(start))
		return resp, nil
	}
	return nil, fmt.Errorf("all dot servers failed, last error: %w", lastErr)
}

// PlainClient queries classic DNS servers (host:port).
//
// When Ban is set, any response whose Answer/Additional contains an A or
// AAAA in a banned network is rejected. Health tracking records
// success/failure per server when Health is set.
type PlainClient struct {
	Servers []string
	Client  *dns.Client
	Ban     *filter.BanList   // optional
	Metrics *metrics.Registry // optional
	Health  *health.Tracker   // optional
}

// NewPlainClient builds a PlainClient with the given timeout applied per attempt.
func NewPlainClient(servers []string, timeout time.Duration) *PlainClient {
	return &PlainClient{
		Servers: servers,
		Client:  &dns.Client{Timeout: timeout},
	}
}

// Resolve sends req to each configured plain server in turn over UDP.
func (p *PlainClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(p.Servers) == 0 {
		return nil, fmt.Errorf("no plain dns servers configured")
	}
	var lastErr error
	for _, server := range p.Health.Order(metrics.PathPlain, p.Servers) {
		if ctx.Err() != nil {
			lastErr = ctx.Err()
			break
		}
		start := time.Now()
		resp, _, err := p.Client.ExchangeContext(ctx, req, server)
		if err != nil {
			p.Health.RecordFailure(metrics.PathPlain, server, err)
			lastErr = err
			continue
		}
		if resp.Truncated {
			err = fmt.Errorf("%s returned a truncated response", server)
			p.Health.RecordFailure(metrics.PathPlain, server, err)
			lastErr = err
			continue
		}
		if p.Ban != nil {
			if bad := p.Ban.ContainsAnswer(resp); bad != "" {
				if p.Metrics != nil {
					p.Metrics.IncPoisonedAnswer(metrics.PathPlain)
				}
				err = fmt.Errorf("%s returned poisoned answer containing banned address %s", server, bad)
				p.Health.RecordFailure(metrics.PathPlain, server, err)
				lastErr = err
				continue
			}
		}
		p.Health.RecordSuccess(metrics.PathPlain, server, time.Since(start))
		return resp, nil
	}
	return nil, fmt.Errorf("all plain dns servers failed, last error: %w", lastErr)
}
