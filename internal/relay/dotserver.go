package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// DoTServer is an RFC 7858 DNS-over-TLS endpoint: a plain DNS server over a
// TLS-wrapped TCP connection on (conventionally) port 853. It shares the
// same Upstream, allow-list, and metrics as Server (the DoH endpoint) via
// Server.resolve, so both transports enforce identical policy.
//
// Note on auth: DoH's bearer-token auth (Server.AuthToken) has no DoT
// equivalent here, since DoT is raw TCP+TLS with no place to carry an HTTP
// header. If you need authenticated DoT, restrict access at the network
// layer (firewall/allow-list by source IP) or require mutual TLS by setting
// TLSConfig.ClientAuth yourself before calling Run. AllowedSuffixes and the
// rate limiter both still apply, keyed by the connecting IP.
type DoTServer struct {
	*Server
	CertFile string
	KeyFile  string

	dnsServer *dns.Server
}

// NewDoTServer builds a DoTServer sharing policy with an existing DoH
// Server. certFile/keyFile must be a PEM certificate and private key.
func NewDoTServer(base *Server, certFile, keyFile string) *DoTServer {
	return &DoTServer{Server: base, CertFile: certFile, KeyFile: keyFile}
}

// Run starts listening on addr and blocks until ctx is canceled.
func (d *DoTServer) Run(ctx context.Context, addr string) error {
	cert, err := tls.LoadX509KeyPair(d.CertFile, d.KeyFile)
	if err != nil {
		return fmt.Errorf("loading DoT TLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	d.dnsServer = &dns.Server{
		Addr:      addr,
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler:   dns.HandlerFunc(d.handle),
	}

	errCh := make(chan error, 1)
	go func() { errCh <- d.dnsServer.ListenAndServe() }()

	d.log().Info("dot relay listening", "addr", addr)

	select {
	case err := <-errCh:
		return fmt.Errorf("dot server failed: %w", err)
	case <-ctx.Done():
		d.log().Info("dot relay shutting down")
		return d.dnsServer.ShutdownContext(context.Background())
	}
}

func (d *DoTServer) handle(w dns.ResponseWriter, req *dns.Msg) {
	origin := peerIP(w.RemoteAddr())
	if d.limiter != nil && !d.limiter.Allow(origin) {
		_ = w.WriteMsg(refused(req))
		return
	}

	respMsg, err := d.resolve(context.Background(), req, "dot", origin)
	if err != nil {
		_ = w.WriteMsg(refused(req))
		return
	}
	if writeErr := w.WriteMsg(respMsg); writeErr != nil {
		d.log().Warn("failed to write dot response", "origin", origin, "error", writeErr)
	}
}

func refused(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	return m
}

func peerIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
