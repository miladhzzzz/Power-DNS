package upstream

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/wire"
)

// startFakePlainServer runs a local UDP DNS server answering every A query
// with a fixed IP, so tests don't depend on real network access.
func startFakePlainServer(t *testing.T) (addr string, shutdown func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 198.51.100.9")
			resp.Answer = append(resp.Answer, rr)
		}
		_ = w.WriteMsg(resp)
	})}

	readyCh := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(readyCh) }
	go func() { _ = srv.ActivateAndServe() }()
	<-readyCh

	return pc.LocalAddr().String(), func() { _ = srv.Shutdown() }
}

func TestPlainClientResolve(t *testing.T) {
	addr, shutdown := startFakePlainServer(t)
	defer shutdown()

	client := NewPlainClient([]string{addr}, 2*time.Second)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, err := client.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
}

func TestPlainClientResolveNoServers(t *testing.T) {
	client := NewPlainClient(nil, time.Second)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := client.Resolve(context.Background(), req); err == nil {
		t.Fatalf("expected error with no servers configured")
	}
}

func TestPlainClientResolveRespectsCanceledContext(t *testing.T) {
	addr, shutdown := startFakePlainServer(t)
	defer shutdown()

	client := NewPlainClient([]string{addr}, 2*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := client.Resolve(ctx, req); err == nil {
		t.Fatalf("expected error from an already-canceled context")
	}
}

func TestChainFallsBackToPlainWhenDoHFails(t *testing.T) {
	addr, shutdown := startFakePlainServer(t)
	defer shutdown()

	chain := &Chain{
		// Nothing listens on 127.0.0.1:1, so this fails fast (connection
		// refused) without any real network access, exercising the actual
		// Chain.Resolve fallback path: DoH fails -> Plain succeeds.
		DoH:   NewDoHClient([]string{"http://127.0.0.1:1/dns-query"}, time.Second),
		Plain: NewPlainClient([]string{addr}, 2*time.Second),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp, err := chain.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("expected Chain to fall back to Plain, got error: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer from the plain fallback, got %d", len(resp.Answer))
	}
}

func TestChainReturnsErrorWhenNothingConfigured(t *testing.T) {
	chain := &Chain{}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := chain.Resolve(context.Background(), req); err == nil {
		t.Fatalf("expected error from an empty Chain")
	}
}

func TestNewDoHClientConfiguresConnectionReuse(t *testing.T) {
	c := NewDoHClient([]string{"https://example.com/dns-query"}, 2*time.Second)
	transport, ok := c.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected an explicit *http.Transport, got %T (the zero-value default caps MaxIdleConnsPerHost at 2, causing repeated TLS handshakes under any real concurrency)", c.Client.Transport)
	}
	if transport.MaxIdleConnsPerHost <= 2 {
		t.Fatalf("expected MaxIdleConnsPerHost above the http.DefaultTransport default of 2, got %d", transport.MaxIdleConnsPerHost)
	}
	if !transport.ForceAttemptHTTP2 {
		t.Fatalf("expected ForceAttemptHTTP2 to be enabled")
	}
}

func TestDoHClientReusesConnections(t *testing.T) {
	var connCount int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqMsg := new(dns.Msg)
		body, _ := io.ReadAll(r.Body)
		_ = reqMsg.Unpack(body)
		resp := new(dns.Msg)
		resp.SetReply(reqMsg)
		respBytes, _ := resp.Pack()
		w.Header().Set("Content-Type", wire.ContentType)
		_, _ = w.Write(respBytes)
	}))
	srv.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			atomic.AddInt32(&connCount, 1)
		}
	}
	srv.Start()
	defer srv.Close()

	client := NewDoHClient([]string{srv.URL}, 2*time.Second)
	for i := 0; i < 10; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		if _, err := client.Resolve(context.Background(), req); err != nil {
			t.Fatalf("Resolve #%d: %v", i, err)
		}
	}

	// 10 sequential queries against a client with connection reuse enabled
	// should open at most a couple of underlying TCP connections, not 10 --
	// this is the concrete behavior the MaxIdleConnsPerHost change buys.
	if got := atomic.LoadInt32(&connCount); got > 2 {
		t.Fatalf("expected connection reuse across sequential queries, opened %d new connections for 10 queries", got)
	}
}
