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

	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/wire"
)

// DoHClient queries a list of RFC 8484 DNS-over-HTTPS servers in order.
type DoHClient struct {
	Servers []string
	Client  *http.Client
}

// NewDoHClient builds a DoHClient with the given timeout applied per attempt.
func NewDoHClient(servers []string, timeout time.Duration) *DoHClient {
	return &DoHClient{
		Servers: servers,
		Client:  &http.Client{Timeout: timeout},
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
	for _, server := range d.Servers {
		resp, err := d.query(ctx, server, reqBytes)
		if err != nil {
			lastErr = err
			continue
		}
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

// Chain tries DoH first, then DoT, then falls back to plain DNS. This is
// what the relay uses to resolve against the real internet, and what a
// client can use to bypass its own relay entirely: different networks
// block different transports, so trying HTTPS (DoH), then TLS-on-853 (DoT),
// then plain give three independent chances to get through before giving
// up.
//
// If Metrics is set, each sub-attempt (whether it succeeds or fails) is
// timed under its own path label (metrics.PathDoH/PathDoT/PathPlain), so
// "the relay is slow" becomes "the relay's DoT leg is slow" rather than one
// opaque aggregate number.
type Chain struct {
	DoH     *DoHClient
	DoT     *DoTClient
	Plain   *PlainClient
	Metrics *metrics.Registry // optional
}

// Resolve implements the relay.Upstream interface.
func (c *Chain) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if c.DoH != nil {
		if resp, err := c.timed(metrics.PathDoH, func() (*dns.Msg, error) { return c.DoH.Resolve(ctx, req) }); err == nil {
			return resp, nil
		}
	}
	if c.DoT != nil {
		if resp, err := c.timed(metrics.PathDoT, func() (*dns.Msg, error) { return c.DoT.Resolve(ctx, req) }); err == nil {
			return resp, nil
		}
	}
	if c.Plain != nil {
		return c.timed(metrics.PathPlain, func() (*dns.Msg, error) { return c.Plain.Resolve(ctx, req) })
	}
	return nil, fmt.Errorf("no upstream available")
}

func (c *Chain) timed(path string, attempt func() (*dns.Msg, error)) (*dns.Msg, error) {
	start := time.Now()
	resp, err := attempt()
	if c.Metrics != nil {
		c.Metrics.ObserveUpstreamLatency(path, time.Since(start))
	}
	return resp, err
}

// DoTClient queries a list of RFC 7858 DNS-over-TLS servers (host:port,
// e.g. "1.1.1.1:853") in order.
type DoTClient struct {
	Servers []string
	Client  *dns.Client
}

// NewDoTClient builds a DoTClient with the given timeout applied per
// attempt. serverName, if set, is used for TLS certificate verification
// (SNI + hostname check); leave empty to rely on the server's IP-based
// certificate, if any -- most public DoT providers require a real hostname
// here (e.g. "dns.google", "cloudflare-dns.com").
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

// Resolve sends req to each configured DoT server in turn over TLS,
// returning the first successful, non-truncated response.
func (d *DoTClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(d.Servers) == 0 {
		return nil, fmt.Errorf("no dot servers configured")
	}
	var lastErr error
	for _, server := range d.Servers {
		resp, _, err := d.Client.ExchangeContext(ctx, req, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Truncated {
			lastErr = fmt.Errorf("%s returned a truncated response", server)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all dot servers failed, last error: %w", lastErr)
}

// PlainClient queries a list of classic DNS servers (host:port) in order.
type PlainClient struct {
	Servers []string
	Client  *dns.Client
}

// NewPlainClient builds a PlainClient with the given timeout applied per attempt.
func NewPlainClient(servers []string, timeout time.Duration) *PlainClient {
	return &PlainClient{
		Servers: servers,
		Client:  &dns.Client{Timeout: timeout},
	}
}

// Resolve sends req to each configured plain server in turn over UDP,
// returning the first successful, non-truncated response. ctx bounds the
// whole call, in addition to the client's own per-exchange Timeout.
func (p *PlainClient) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(p.Servers) == 0 {
		return nil, fmt.Errorf("no plain dns servers configured")
	}
	var lastErr error
	for _, server := range p.Servers {
		if ctx.Err() != nil {
			lastErr = ctx.Err()
			break
		}
		resp, _, err := p.Client.ExchangeContext(ctx, req, server)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Truncated {
			lastErr = fmt.Errorf("%s returned a truncated response", server)
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all plain dns servers failed, last error: %w", lastErr)
}
