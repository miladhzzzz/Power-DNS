package resolver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/cache"
	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/records"
	"github.com/miladhzzzz/power-dns/internal/upstream"
	"github.com/miladhzzzz/power-dns/internal/wire"
)

func newTestRequest(name string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return req
}

func TestResolveUsesRecordsBeforeCache(t *testing.T) {
	dir := t.TempDir()
	store, err := records.Open(dir + "/records.json")
	if err != nil {
		t.Fatalf("records.Open: %v", err)
	}
	if err := store.Add(records.Record{Name: "example.com", Type: "A", Value: "10.0.0.1", TTL: 60}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	r := &Resolver{
		Order:   []string{StrategyRecords, StrategyCache},
		Records: store,
	}

	resp := r.Resolve(context.Background(), newTestRequest("example.com"), "1.2.3.4:9999")
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer from records, got %d", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || a.A.String() != "10.0.0.1" {
		t.Fatalf("unexpected answer: %v", resp.Answer[0])
	}
}

func TestResolveSkipsDisabledRelayWithoutError(t *testing.T) {
	// RelayClient is nil (disabled) and nothing else is configured, so
	// resolution should fail cleanly with SERVFAIL rather than panicking
	// or hanging on the disabled strategy.
	r := &Resolver{
		Order:   []string{StrategyRelay, StrategyPlain},
		Metrics: metrics.New(),
	}
	resp := r.Resolve(context.Background(), newTestRequest("example.com"), "")
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when every strategy is unavailable, got rcode %d", resp.Rcode)
	}
}

func TestCacheHitAndMissMetrics(t *testing.T) {
	reg := metrics.New()
	c := cache.New(cache.Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second, Metrics: reg})

	r := &Resolver{
		Order:   []string{StrategyRecords, StrategyCache},
		Cache:   c,
		Metrics: reg,
	}

	// First query: nothing in cache yet, no records configured -> total
	// failure, but the cache strategy itself should still register a
	// not_found miss.
	r.Resolve(context.Background(), newTestRequest("miss.example.com"), "")

	// Seed the cache directly, then resolve again -- this time it should
	// be a hit.
	seedReq := newTestRequest("hit.example.com")
	seedResp := new(dns.Msg)
	seedResp.SetReply(seedReq)
	rr, err := dns.NewRR("hit.example.com. 60 IN A 203.0.113.5")
	if err != nil {
		t.Fatalf("building seed RR: %v", err)
	}
	seedResp.Answer = append(seedResp.Answer, rr)
	c.Set("hit.example.com.", dns.TypeA, seedResp)

	resp := r.Resolve(context.Background(), newTestRequest("hit.example.com"), "")
	if len(resp.Answer) != 1 {
		t.Fatalf("expected the cached answer to be returned, got %d answers", len(resp.Answer))
	}

	var b strings.Builder
	reg.WriteProm(&b)
	out := b.String()
	if !containsLine(out, "powerdns_cache_hits_total 1") {
		t.Fatalf("expected exactly 1 cache hit in metrics output, got:\n%s", out)
	}
	if !containsLine(out, `powerdns_cache_misses_total{reason="not_found"} 1`) {
		t.Fatalf("expected exactly 1 not_found cache miss in metrics output, got:\n%s", out)
	}
}

func TestCacheDisabledCountsAsDisabledMiss(t *testing.T) {
	reg := metrics.New()
	// Cache is nil (disabled) on the Resolver, but Metrics is set -- the
	// "disabled" miss reason is recorded by the resolver itself, since
	// there's no Cache object to record it.
	r := &Resolver{
		Order:   []string{StrategyCache},
		Metrics: reg,
	}
	r.Resolve(context.Background(), newTestRequest("nocache.example.com"), "")

	var b strings.Builder
	reg.WriteProm(&b)
	out := b.String()
	if !containsLine(out, `powerdns_cache_misses_total{reason="disabled"} 1`) {
		t.Fatalf("expected a disabled cache miss in metrics output, got:\n%s", out)
	}
}

func TestConcurrentIdenticalQueriesCoalesceIntoOneUpstreamCall(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(50 * time.Millisecond) // hold the request open so concurrent callers actually overlap

		reqMsg := readDoHRequest(t, req)
		resp := new(dns.Msg)
		resp.SetReply(reqMsg)
		rr, _ := dns.NewRR("coalesce.example.com. 60 IN A 198.51.100.42")
		resp.Answer = append(resp.Answer, rr)
		respBytes, err := wire.Pack(resp)
		if err != nil {
			t.Errorf("packing response: %v", err)
			return
		}
		w.Header().Set("Content-Type", wire.ContentType)
		_, _ = w.Write(respBytes)
	}))
	defer srv.Close()

	r := &Resolver{
		Order:   []string{StrategyDoH},
		DoH:     upstream.NewDoHClient([]string{srv.URL}, 2*time.Second),
		Timeout: 2 * time.Second,
		Metrics: metrics.New(),
	}

	const n = 20
	var wg sync.WaitGroup
	results := make([]*dns.Msg, n)
	reqs := make([]*dns.Msg, n)
	for i := 0; i < n; i++ {
		reqs[i] = newTestRequest("coalesce.example.com")
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = r.Resolve(context.Background(), reqs[i], "")
		}(i)
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 real upstream call for %d concurrent identical queries, got %d", n, got)
	}
	for i, resp := range results {
		if len(resp.Answer) != 1 {
			t.Fatalf("caller %d: expected 1 answer, got %d", i, len(resp.Answer))
		}
		if resp.Id != reqs[i].Id {
			t.Fatalf("caller %d: expected response Id %d to match its own request Id %d (coalescing must not leak another caller's Id)", i, resp.Id, reqs[i].Id)
		}
	}

	var b strings.Builder
	r.Metrics.WriteProm(&b)
	out := b.String()
	// Exactly 1 caller actually triggered the network call; the other 19
	// must show up as coalesced -- a clean partition of all 20 callers,
	// not overlapping (see the doc comment on Resolver.inflight for why
	// golang.org/x/sync/singleflight can't give this exact split).
	if !containsLine(out, `powerdns_upstream_calls_total{path="doh"} 1`) {
		t.Fatalf("expected exactly 1 upstream call recorded, got:\n%s", out)
	}
	if !containsLine(out, `powerdns_upstream_coalesced_total{path="doh"} 19`) {
		t.Fatalf("expected exactly 19 coalesced callers recorded, got:\n%s", out)
	}
}

func readDoHRequest(t *testing.T, httpReq *http.Request) *dns.Msg {
	t.Helper()
	body, err := io.ReadAll(httpReq.Body)
	if err != nil {
		t.Fatalf("reading DoH request body: %v", err)
	}
	msg, err := wire.Unpack(body)
	if err != nil {
		t.Fatalf("unpacking DoH request: %v", err)
	}
	return msg
}

func containsLine(haystack, line string) bool {
	for _, l := range strings.Split(haystack, "\n") {
		if l == line {
			return true
		}
	}
	return false
}
