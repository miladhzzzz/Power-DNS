package cache

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/metrics"
)

func makeAnswer(name string, ttl uint32) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, _ := dns.NewRR(dns.Fqdn(name) + " " + itoa(ttl) + " IN A 1.2.3.4")
	resp.Answer = append(resp.Answer, rr)
	return resp
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	digits := []byte{}
	for v > 0 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		v /= 10
	}
	return string(digits)
}

func TestSetGetRoundTrip(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second})
	resp := makeAnswer("example.com", 300)
	c.Set("example.com.", dns.TypeA, resp)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	got, ok := c.Get(req, "example.com.", dns.TypeA)
	if !ok {
		t.Fatalf("expected cache hit")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(got.Answer))
	}
	if got.Id != req.Id {
		t.Fatalf("expected reply Id %d to match request Id %d", got.Id, req.Id)
	}
}

func TestExpiry(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: 0, MaxTTL: time.Hour, NegativeTTL: time.Second})
	resp := makeAnswer("expiring.com", 0) // TTL 0 gets clamped up to MinTTL... but MinTTL is 0 here
	c.opts.MinTTL = 10 * time.Millisecond
	c.Set("expiring.com.", dns.TypeA, resp)

	time.Sleep(30 * time.Millisecond)

	req := new(dns.Msg)
	req.SetQuestion("expiring.com.", dns.TypeA)
	if _, ok := c.Get(req, "expiring.com.", dns.TypeA); ok {
		t.Fatalf("expected entry to have expired")
	}
}

func TestLRUEviction(t *testing.T) {
	c := New(Options{MaxEntries: 2, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second})
	c.Set("a.com.", dns.TypeA, makeAnswer("a.com", 300))
	c.Set("b.com.", dns.TypeA, makeAnswer("b.com", 300))
	c.Set("c.com.", dns.TypeA, makeAnswer("c.com", 300)) // should evict a.com (least recently used)

	req := new(dns.Msg)
	req.SetQuestion("a.com.", dns.TypeA)
	if _, ok := c.Get(req, "a.com.", dns.TypeA); ok {
		t.Fatalf("expected a.com to have been evicted")
	}
	if c.Len() != 2 {
		t.Fatalf("expected 2 entries, got %d", c.Len())
	}
}

func TestNegativeCaching(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Hour})
	req := new(dns.Msg)
	req.SetQuestion("nxdomain.com.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeNameError) // no Answer records

	c.Set("nxdomain.com.", dns.TypeA, resp)

	if _, ok := c.Get(req, "nxdomain.com.", dns.TypeA); !ok {
		t.Fatalf("expected negative response to be cached")
	}
}

func TestDelete(t *testing.T) {
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second})
	c.Set("del.com.", dns.TypeA, makeAnswer("del.com", 300))
	c.Delete("del.com.", dns.TypeA)

	req := new(dns.Msg)
	req.SetQuestion("del.com.", dns.TypeA)
	if _, ok := c.Get(req, "del.com.", dns.TypeA); ok {
		t.Fatalf("expected entry to be deleted")
	}
}

func metricsSnapshot(reg *metrics.Registry) string {
	var b strings.Builder
	reg.WriteProm(&b)
	return b.String()
}

func TestMissReasonNotFound(t *testing.T) {
	reg := metrics.New()
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second, Metrics: reg})

	req := new(dns.Msg)
	req.SetQuestion("neverseen.com.", dns.TypeA)
	if _, ok := c.Get(req, "neverseen.com.", dns.TypeA); ok {
		t.Fatalf("expected a miss for a key that was never set")
	}

	out := metricsSnapshot(reg)
	if !strings.Contains(out, `powerdns_cache_misses_total{reason="not_found"} 1`) {
		t.Fatalf("expected a not_found miss, got:\n%s", out)
	}
}

func TestMissReasonExpired(t *testing.T) {
	reg := metrics.New()
	c := New(Options{MaxEntries: 10, MinTTL: 10 * time.Millisecond, MaxTTL: time.Hour, NegativeTTL: time.Second, Metrics: reg})
	c.Set("expiring2.com.", dns.TypeA, makeAnswer("expiring2.com", 0))

	time.Sleep(30 * time.Millisecond)

	req := new(dns.Msg)
	req.SetQuestion("expiring2.com.", dns.TypeA)
	if _, ok := c.Get(req, "expiring2.com.", dns.TypeA); ok {
		t.Fatalf("expected the entry to have expired")
	}

	out := metricsSnapshot(reg)
	if !strings.Contains(out, `powerdns_cache_misses_total{reason="expired"} 1`) {
		t.Fatalf("expected an expired miss, got:\n%s", out)
	}
}

func TestHitIncrementsMetric(t *testing.T) {
	reg := metrics.New()
	c := New(Options{MaxEntries: 10, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second, Metrics: reg})
	c.Set("hitme.com.", dns.TypeA, makeAnswer("hitme.com", 300))

	req := new(dns.Msg)
	req.SetQuestion("hitme.com.", dns.TypeA)
	if _, ok := c.Get(req, "hitme.com.", dns.TypeA); !ok {
		t.Fatalf("expected a hit")
	}

	out := metricsSnapshot(reg)
	if !strings.Contains(out, "powerdns_cache_hits_total 1") {
		t.Fatalf("expected 1 cache hit, got:\n%s", out)
	}
}

func TestLRUEvictionIncrementsMetric(t *testing.T) {
	reg := metrics.New()
	c := New(Options{MaxEntries: 1, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second, Metrics: reg})
	c.Set("first.com.", dns.TypeA, makeAnswer("first.com", 300))
	c.Set("second.com.", dns.TypeA, makeAnswer("second.com", 300)) // evicts first.com

	out := metricsSnapshot(reg)
	if !strings.Contains(out, `powerdns_cache_evictions_total{reason="lru"} 1`) {
		t.Fatalf("expected 1 lru eviction, got:\n%s", out)
	}
}

func TestCapReportsMaxEntries(t *testing.T) {
	c := New(Options{MaxEntries: 42, MinTTL: time.Second, MaxTTL: time.Hour, NegativeTTL: time.Second})
	if c.Cap() != 42 {
		t.Fatalf("expected Cap() to report 42, got %d", c.Cap())
	}
}

func TestPrefetchRefreshesPopularSoonToExpireEntry(t *testing.T) {
	reg := metrics.New()

	var refreshCalls int32
	refresh := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		atomic.AddInt32(&refreshCalls, 1)
		return makeAnswer(name, 300), nil // a fresh, long-TTL answer
	}

	c := New(Options{
		MaxEntries:     10,
		MinTTL:         10 * time.Millisecond,
		MaxTTL:         time.Hour,
		NegativeTTL:    time.Second,
		Metrics:        reg,
		Refresh:        refresh,
		RefreshTimeout: time.Second,
		Prefetch: PrefetchOptions{
			Enabled:   true,
			Threshold: 50 * time.Millisecond, // "soon to expire" = less than this remaining
			MinHits:   2,                     // needs at least 2 hits to count as popular
		},
	})

	// Store with a TTL already inside the prefetch threshold, so the very
	// next hit is eligible once it's also popular enough.
	c.Set("popular.com.", dns.TypeA, makeAnswer("popular.com", 0))
	c.opts.MinTTL = 30 * time.Millisecond // keep the short TTL from being clamped up further

	req := new(dns.Msg)
	req.SetQuestion("popular.com.", dns.TypeA)

	c.Get(req, "popular.com.", dns.TypeA) // hit 1: not popular enough yet
	if atomic.LoadInt32(&refreshCalls) != 0 {
		t.Fatalf("expected no prefetch after only 1 hit, got %d calls", refreshCalls)
	}

	c.Get(req, "popular.com.", dns.TypeA) // hit 2: now popular enough, and TTL is low -> should prefetch

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&refreshCalls) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&refreshCalls) < 1 {
		t.Fatalf("expected at least 1 prefetch refresh call, got %d", refreshCalls)
	}

	// Metrics recording happens just after c.Set() inside the same
	// goroutine as the refresh call, so give it a moment to land.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(metricsSnapshot(reg), `powerdns_cache_prefetch_total{result="success"} 1`) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected 1 successful prefetch in metrics output, got:\n%s", metricsSnapshot(reg))
}

func TestPrefetchFailureIsRecorded(t *testing.T) {
	reg := metrics.New()
	refresh := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		return nil, fmt.Errorf("upstream is down")
	}

	c := New(Options{
		MaxEntries:     10,
		MinTTL:         10 * time.Millisecond,
		MaxTTL:         time.Hour,
		NegativeTTL:    time.Second,
		Metrics:        reg,
		Refresh:        refresh,
		RefreshTimeout: time.Second,
		Prefetch: PrefetchOptions{
			Enabled:   true,
			Threshold: 50 * time.Millisecond,
			MinHits:   1,
		},
	})
	c.Set("flaky.com.", dns.TypeA, makeAnswer("flaky.com", 0))
	c.opts.MinTTL = 30 * time.Millisecond

	req := new(dns.Msg)
	req.SetQuestion("flaky.com.", dns.TypeA)
	c.Get(req, "flaky.com.", dns.TypeA)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(metricsSnapshot(reg), `powerdns_cache_prefetch_total{result="failure"} 1`) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected 1 failed prefetch in metrics output, got:\n%s", metricsSnapshot(reg))
}

func TestPrefetchSkippedWhileInFlight(t *testing.T) {
	reg := metrics.New()
	started := make(chan struct{})
	release := make(chan struct{})
	refresh := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		close(started)
		<-release // hold the first refresh open so a second Get() finds it still in flight
		return makeAnswer(name, 300), nil
	}

	c := New(Options{
		MaxEntries:     10,
		MinTTL:         10 * time.Millisecond,
		MaxTTL:         time.Hour,
		NegativeTTL:    time.Second,
		Metrics:        reg,
		Refresh:        refresh,
		RefreshTimeout: 5 * time.Second,
		Prefetch: PrefetchOptions{
			Enabled:   true,
			Threshold: 50 * time.Millisecond,
			MinHits:   1,
		},
	})
	c.Set("slow.com.", dns.TypeA, makeAnswer("slow.com", 0))
	c.opts.MinTTL = 30 * time.Millisecond

	req := new(dns.Msg)
	req.SetQuestion("slow.com.", dns.TypeA)

	c.Get(req, "slow.com.", dns.TypeA) // triggers the (now-blocked) refresh goroutine
	<-started                          // make sure it's actually in flight before checking again

	c.Get(req, "slow.com.", dns.TypeA) // should see the in-flight refresh and skip

	close(release)

	out := metricsSnapshot(reg)
	if !strings.Contains(out, `powerdns_cache_prefetch_skipped_total{reason="in_flight"} 1`) {
		t.Fatalf("expected 1 in_flight prefetch skip, got:\n%s", out)
	}
}

func TestPrefetchDisabledByDefault(t *testing.T) {
	var refreshCalls int32
	refresh := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		atomic.AddInt32(&refreshCalls, 1)
		return makeAnswer(name, 300), nil
	}

	// Prefetch.Enabled left false (the zero value) even though a Refresh
	// func is provided -- prefetching must stay off until explicitly
	// turned on.
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      time.Millisecond,
		MaxTTL:      time.Hour,
		NegativeTTL: time.Second,
		Refresh:     refresh,
		Prefetch:    PrefetchOptions{Threshold: time.Hour, MinHits: 1},
	})
	c.Set("quiet.com.", dns.TypeA, makeAnswer("quiet.com", 1))

	req := new(dns.Msg)
	req.SetQuestion("quiet.com.", dns.TypeA)
	c.Get(req, "quiet.com.", dns.TypeA)

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&refreshCalls) != 0 {
		t.Fatalf("expected no prefetch calls while Prefetch.Enabled is false, got %d", refreshCalls)
	}
}

func TestPrefetchDoesNotFireForUnpopularEntry(t *testing.T) {
	var refreshCalls int32
	refresh := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		atomic.AddInt32(&refreshCalls, 1)
		return makeAnswer(name, 300), nil
	}

	c := New(Options{
		MaxEntries:  10,
		MinTTL:      time.Millisecond,
		MaxTTL:      time.Hour,
		NegativeTTL: time.Second,
		Refresh:     refresh,
		Prefetch: PrefetchOptions{
			Enabled:   true,
			Threshold: time.Hour, // always "soon to expire" for this test
			MinHits:   1000,      // effectively unreachable
		},
	})
	c.Set("unpopular.com.", dns.TypeA, makeAnswer("unpopular.com", 1))

	req := new(dns.Msg)
	req.SetQuestion("unpopular.com.", dns.TypeA)
	c.Get(req, "unpopular.com.", dns.TypeA)

	time.Sleep(50 * time.Millisecond)
	if atomic.LoadInt32(&refreshCalls) != 0 {
		t.Fatalf("expected no prefetch calls for an entry below MinHits, got %d", refreshCalls)
	}
}

func TestStaleWhileRevalidateDisabledByDefault(t *testing.T) {
	reg := metrics.New()
	// StaleMaxAge left at zero (the default) even though a Refresh func is
	// provided -- an expired entry must be a genuine miss until this is
	// explicitly turned on.
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      10 * time.Millisecond,
		MaxTTL:      time.Hour,
		NegativeTTL: time.Second,
		Metrics:     reg,
		Refresh: func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			return makeAnswer(name, 300), nil
		},
	})
	c.Set("normal.com.", dns.TypeA, makeAnswer("normal.com", 0))
	c.opts.MinTTL = 10 * time.Millisecond

	time.Sleep(30 * time.Millisecond)

	req := new(dns.Msg)
	req.SetQuestion("normal.com.", dns.TypeA)
	if _, ok := c.Get(req, "normal.com.", dns.TypeA); ok {
		t.Fatalf("expected a genuine miss when stale_while_revalidate is disabled (the default)")
	}
	out := metricsSnapshot(reg)
	if !strings.Contains(out, `powerdns_cache_misses_total{reason="expired"} 1`) {
		t.Fatalf("expected an expired miss, got:\n%s", out)
	}
	if !strings.Contains(out, "powerdns_cache_stale_hits_total 0") {
		t.Fatalf("expected zero stale hits when the feature is disabled, got:\n%s", out)
	}
}

func TestStaleWhileRevalidateServesStaleAndRefreshes(t *testing.T) {
	reg := metrics.New()
	var refreshCalls int32
	refresh := func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
		atomic.AddInt32(&refreshCalls, 1)
		return makeAnswer(name, 300), nil // a fresh, long-TTL answer
	}

	c := New(Options{
		MaxEntries:     10,
		MinTTL:         10 * time.Millisecond,
		MaxTTL:         time.Hour,
		NegativeTTL:    time.Second,
		Metrics:        reg,
		Refresh:        refresh,
		RefreshTimeout: time.Second,
		StaleMaxAge:    200 * time.Millisecond,
	})
	c.Set("stale.com.", dns.TypeA, makeAnswer("stale.com", 0))
	c.opts.MinTTL = 30 * time.Millisecond // let the entry actually expire quickly

	time.Sleep(50 * time.Millisecond) // now expired, but well within the 200ms stale window

	req := new(dns.Msg)
	req.SetQuestion("stale.com.", dns.TypeA)
	resp, ok := c.Get(req, "stale.com.", dns.TypeA)
	if !ok {
		t.Fatalf("expected a stale hit, got a miss")
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected the stale answer to still be returned, got %d answers", len(resp.Answer))
	}
	if resp.Id != req.Id {
		t.Fatalf("expected stale response Id %d to match request Id %d", resp.Id, req.Id)
	}

	// Background revalidation should fire and eventually succeed.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&refreshCalls) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&refreshCalls) < 1 {
		t.Fatalf("expected stale hit to trigger a background revalidation")
	}

	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		out := metricsSnapshot(reg)
		if strings.Contains(out, "powerdns_cache_stale_hits_total 1") &&
			strings.Contains(out, "powerdns_cache_stale_revalidations_total 1") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("expected 1 stale hit and 1 successful revalidation in metrics, got:\n%s", metricsSnapshot(reg))
}

func TestStaleWhileRevalidateBeyondWindowIsAGenuineMiss(t *testing.T) {
	reg := metrics.New()
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      10 * time.Millisecond,
		MaxTTL:      time.Hour,
		NegativeTTL: time.Second,
		Metrics:     reg,
		Refresh: func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			return makeAnswer(name, 300), nil
		},
		StaleMaxAge: 20 * time.Millisecond, // a short stale window
	})
	c.Set("toostale.com.", dns.TypeA, makeAnswer("toostale.com", 0))
	c.opts.MinTTL = 10 * time.Millisecond

	// Wait past both the TTL and the stale window entirely.
	time.Sleep(60 * time.Millisecond)

	req := new(dns.Msg)
	req.SetQuestion("toostale.com.", dns.TypeA)
	if _, ok := c.Get(req, "toostale.com.", dns.TypeA); ok {
		t.Fatalf("expected a genuine miss once the entry is older than the stale window")
	}
	out := metricsSnapshot(reg)
	if !strings.Contains(out, `powerdns_cache_misses_total{reason="expired"} 1`) {
		t.Fatalf("expected an expired miss, got:\n%s", out)
	}
	if !strings.Contains(out, "powerdns_cache_stale_hits_total 0") {
		t.Fatalf("expected zero stale hits once past the stale window, got:\n%s", out)
	}
	if !strings.Contains(out, "powerdns_cache_expired_entry_age_seconds_count 1") {
		t.Fatalf("expected the expired-entry-age histogram to record 1 observation even for a genuine miss, got:\n%s", out)
	}
}

func TestExpiredEntryAgeRecordedOnStaleHitToo(t *testing.T) {
	// The age histogram should fire on every past-expiry lookup, not just
	// genuine misses -- otherwise it can't give an unbiased view of the
	// full distribution (see the doc comment on ObserveExpiredEntryAge).
	reg := metrics.New()
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      10 * time.Millisecond,
		MaxTTL:      time.Hour,
		NegativeTTL: time.Second,
		Metrics:     reg,
		Refresh: func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
			return makeAnswer(name, 300), nil
		},
		StaleMaxAge: time.Hour, // generous window -- this lookup should be a stale hit
	})
	c.Set("agecheck.com.", dns.TypeA, makeAnswer("agecheck.com", 0))
	c.opts.MinTTL = 10 * time.Millisecond

	time.Sleep(30 * time.Millisecond)

	req := new(dns.Msg)
	req.SetQuestion("agecheck.com.", dns.TypeA)
	if _, ok := c.Get(req, "agecheck.com.", dns.TypeA); !ok {
		t.Fatalf("expected a stale hit")
	}
	out := metricsSnapshot(reg)
	if !strings.Contains(out, "powerdns_cache_expired_entry_age_seconds_count 1") {
		t.Fatalf("expected the expired-entry-age histogram to record 1 observation on a stale hit too, got:\n%s", out)
	}
}

func TestStaleWhileRevalidateRequiresRefreshFunc(t *testing.T) {
	reg := metrics.New()
	// StaleMaxAge is set, but no Refresh func is wired -- there would be no
	// way to ever bring the entry up to date, so this must behave as if
	// disabled rather than serving indefinitely-stale data forever.
	c := New(Options{
		MaxEntries:  10,
		MinTTL:      10 * time.Millisecond,
		MaxTTL:      time.Hour,
		NegativeTTL: time.Second,
		Metrics:     reg,
		StaleMaxAge: time.Hour,
	})
	c.Set("norefresh.com.", dns.TypeA, makeAnswer("norefresh.com", 0))
	c.opts.MinTTL = 10 * time.Millisecond

	time.Sleep(30 * time.Millisecond)

	req := new(dns.Msg)
	req.SetQuestion("norefresh.com.", dns.TypeA)
	if _, ok := c.Get(req, "norefresh.com.", dns.TypeA); ok {
		t.Fatalf("expected a miss when StaleMaxAge is set but no Refresh func is configured")
	}
}
