// Package dnsserver runs the client-facing DNS listener(s): plain UDP/TCP,
// and optionally RFC 7858 DNS-over-TLS for LAN devices that speak it.
//
// v1 (StartDNSserver in internal/dns/main.go) only listened on UDP, blocked
// forever on an empty `select {}` instead of a real shutdown signal, and
// its ServeDNS handler dropped the request on the floor (no response
// written at all) whenever both the relay and the plain-DNS fallback
// failed, leaving clients to time out instead of getting a fast SERVFAIL.
// v2 listens on UDP and TCP, always writes a response (falling back to
// SERVFAIL via Resolver.Resolve), optionally serves DoT too, and shuts down
// cleanly on context cancellation.
package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/resolver"
)

// DoTConfig configures the optional local DNS-over-TLS listener.
type DoTConfig struct {
	Addr     string // empty disables DoT
	CertFile string
	KeyFile  string
}

// Server wraps miekg/dns's UDP, TCP, and (optionally) DoT servers,
// dispatching every query to a Resolver.
type Server struct {
	Addr     string
	DoT      DoTConfig
	Resolver *resolver.Resolver
	Logger   *slog.Logger

	udp *dns.Server
	tcp *dns.Server
	dot *dns.Server
}

// New builds a Server; call Run to start listening. dot.Addr may be empty
// to run UDP/TCP only.
func New(addr string, dot DoTConfig, res *resolver.Resolver, logger *slog.Logger) *Server {
	return &Server{Addr: addr, DoT: dot, Resolver: res, Logger: logger}
}

// Run starts the UDP, TCP, and (if configured) DoT listeners and blocks
// until ctx is canceled, at which point it shuts them all down gracefully
// and returns.
func (s *Server) Run(ctx context.Context) error {
	handler := dns.HandlerFunc(s.handle)

	s.udp = &dns.Server{Addr: s.Addr, Net: "udp", Handler: handler}
	s.tcp = &dns.Server{Addr: s.Addr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 3)
	go func() { errCh <- s.udp.ListenAndServe() }()
	go func() { errCh <- s.tcp.ListenAndServe() }()
	s.log().Info("dns server listening", "addr", s.Addr)

	if s.DoT.Addr != "" {
		cert, err := tls.LoadX509KeyPair(s.DoT.CertFile, s.DoT.KeyFile)
		if err != nil {
			return fmt.Errorf("loading DoT TLS certificate: %w", err)
		}
		s.dot = &dns.Server{
			Addr:      s.DoT.Addr,
			Net:       "tcp-tls",
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			Handler:   handler,
		}
		go func() { errCh <- s.dot.ListenAndServe() }()
		s.log().Info("local dot listener started", "addr", s.DoT.Addr)
	}

	select {
	case err := <-errCh:
		return fmt.Errorf("dns server failed: %w", err)
	case <-ctx.Done():
		s.log().Info("dns server shutting down")
		_ = s.udp.ShutdownContext(context.Background())
		_ = s.tcp.ShutdownContext(context.Background())
		if s.dot != nil {
			_ = s.dot.ShutdownContext(context.Background())
		}
		return nil
	}
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	resp := s.Resolver.Resolve(context.Background(), req)
	if err := w.WriteMsg(resp); err != nil {
		s.log().Warn("failed to write dns response", "error", err)
	}
}

func (s *Server) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
