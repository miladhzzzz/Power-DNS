package upstream

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
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
