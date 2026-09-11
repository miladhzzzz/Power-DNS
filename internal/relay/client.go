package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/wire"
)

// Client talks to a Power-DNS (or any RFC 8484/RFC 7858 compliant) relay
// endpoint over HTTPS (DoH) and/or TLS (DoT). If both DoHURL and DoTAddr
// are set, Resolve tries DoH first and falls back to DoT -- so if a network
// blocks one transport, the other still gets through.
//
// v1's equivalent (httpDNSrelay/localDNSrelay in internal/dns/main.go) used
// http.Get with no timeout and only ever spoke one bespoke JSON-over-HTTP
// protocol, so an unresponsive or blocked relay meant the calling DNS query
// simply hung or failed outright. Client always resolves with a context
// deadline, and can fall back to a second transport before giving up.
type Client struct {
	DoHURL  string // e.g. "https://relay.example.com/dns-query"; empty disables DoH
	DoTAddr string // e.g. "relay.example.com:853"; empty disables DoT

	AuthToken string // sent as a Bearer token on DoH requests only (see DoTServer's auth note)

	HTTPClient *http.Client
	DoTClient  *dns.Client
}

// NewClient builds a relay Client. Either dohURL or dotAddr may be empty to
// disable that transport, but not both.
func NewClient(dohURL, dotAddr, authToken string, timeout time.Duration) *Client {
	return &Client{
		DoHURL:     dohURL,
		DoTAddr:    dotAddr,
		AuthToken:  authToken,
		HTTPClient: &http.Client{Timeout: timeout},
		DoTClient: &dns.Client{
			Net:       "tcp-tls",
			Timeout:   timeout,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}

// Resolve tries DoH, then DoT, returning the first successful answer.
func (c *Client) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if c.DoHURL == "" && c.DoTAddr == "" {
		return nil, fmt.Errorf("relay client has no DoH URL or DoT address configured")
	}

	var lastErr error
	if c.DoHURL != "" {
		resp, err := c.resolveDoH(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if c.DoTAddr != "" {
		resp, err := c.resolveDoT(ctx, req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("relay unreachable over every configured transport: %w", lastErr)
}

func (c *Client) resolveDoH(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	reqBytes, err := wire.Pack(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.DoHURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("building relay request: %w", err)
	}
	httpReq.Header.Set("Content-Type", wire.ContentType)
	httpReq.Header.Set("Accept", wire.ContentType)
	if c.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("reaching relay (doh) %s: %w", c.DoHURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay (doh) %s returned status %d", c.DoHURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading relay (doh) response: %w", err)
	}
	respMsg, err := wire.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("decoding relay (doh) response: %w", err)
	}
	return respMsg, nil
}

func (c *Client) resolveDoT(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp, _, err := c.DoTClient.ExchangeContext(ctx, req, c.DoTAddr)
	if err != nil {
		return nil, fmt.Errorf("reaching relay (dot) %s: %w", c.DoTAddr, err)
	}
	if resp.Truncated {
		return nil, fmt.Errorf("relay (dot) %s returned a truncated response", c.DoTAddr)
	}
	return resp, nil
}
