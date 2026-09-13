package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestCacheHitRateComputation(t *testing.T) {
	r := New()
	r.IncCacheHit()
	r.IncCacheHit()
	r.IncCacheHit()
	r.IncCacheMiss(MissNotFound)

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, "powerdns_cache_hits_total 3")
	assertLine(t, out, `powerdns_cache_misses_total{reason="not_found"} 1`)
	assertLine(t, out, "powerdns_cache_hit_rate 0.75")
}

func TestCacheMissReasonsAreLabeledSeparately(t *testing.T) {
	r := New()
	r.IncCacheMiss(MissNotFound)
	r.IncCacheMiss(MissNotFound)
	r.IncCacheMiss(MissExpired)
	r.IncCacheMiss(MissDisabled)

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, `powerdns_cache_misses_total{reason="disabled"} 1`)
	assertLine(t, out, `powerdns_cache_misses_total{reason="expired"} 1`)
	assertLine(t, out, `powerdns_cache_misses_total{reason="not_found"} 2`)
}

func TestCacheEvictions(t *testing.T) {
	r := New()
	r.IncCacheEviction(EvictionLRU)
	r.IncCacheEviction(EvictionLRU)

	var b strings.Builder
	r.WriteProm(&b)
	assertLine(t, b.String(), `powerdns_cache_evictions_total{reason="lru"} 2`)
}

func TestCacheSizeFuncGauges(t *testing.T) {
	r := New()
	r.SetCacheSizeFunc(func() (int, int) { return 847, 10000 })

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, "powerdns_cache_entries 847")
	assertLine(t, out, "powerdns_cache_capacity 10000")
}

func TestCacheSizeGaugesAbsentWithoutCallback(t *testing.T) {
	r := New()
	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()
	if strings.Contains(out, "powerdns_cache_entries") {
		t.Fatalf("expected no powerdns_cache_entries line when SetCacheSizeFunc was never called")
	}
}

func TestUpstreamLatencyPerPath(t *testing.T) {
	r := New()
	r.ObserveUpstreamLatency(PathRelay, 12*time.Millisecond)
	r.ObserveUpstreamLatency(PathDoH, 40*time.Millisecond)
	r.ObserveUpstreamLatency(PathDoT, 40*time.Millisecond)
	r.ObserveUpstreamLatency(PathPlain, 5*time.Millisecond)

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	for _, path := range []string{PathRelay, PathDoH, PathDoT, PathPlain} {
		if !strings.Contains(out, `powerdns_upstream_latency_ms_count{path="`+path+`"} 1`) {
			t.Fatalf("expected a latency count for path %q, got:\n%s", path, out)
		}
	}
}

func TestRelayServerLatencyIsSeparateFromUpstreamLatency(t *testing.T) {
	r := New()
	r.ObserveRelayServerLatency(7 * time.Millisecond)

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	if !strings.Contains(out, "powerdns_relay_server_latency_ms_count 1") {
		t.Fatalf("expected powerdns_relay_server_latency_ms_count 1, got:\n%s", out)
	}
	if strings.Contains(out, `powerdns_upstream_latency_ms_bucket{path=`) {
		t.Fatalf("relay server latency should not appear as a labeled upstream_latency_ms series, got:\n%s", out)
	}
}

func TestUpstreamCallsAndCoalescedAreLabeledPerPath(t *testing.T) {
	r := New()
	r.IncUpstreamCall(PathDoH)
	r.IncUpstreamCall(PathDoH)
	r.IncUpstreamCoalesced(PathDoH)
	r.IncUpstreamCoalesced(PathDoH)
	r.IncUpstreamCoalesced(PathDoH)

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, `powerdns_upstream_calls_total{path="doh"} 2`)
	assertLine(t, out, `powerdns_upstream_coalesced_total{path="doh"} 3`)
	// 3 coalesced out of 5 total (2 calls + 3 coalesced) = 0.6
	assertLine(t, out, `powerdns_upstream_coalesce_rate{path="doh"} 0.6`)
}

func TestUpstreamCoalesceRateZeroWithoutTraffic(t *testing.T) {
	r := New()
	r.IncUpstreamCall(PathPlain) // calls but no coalescing at all

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, `powerdns_upstream_coalesce_rate{path="plain"} 0`)
}

func TestPrefetchOutcomesAreLabeled(t *testing.T) {
	r := New()
	r.IncPrefetch(PrefetchSuccess)
	r.IncPrefetch(PrefetchSuccess)
	r.IncPrefetch(PrefetchFailure)

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, `powerdns_cache_prefetch_total{result="success"} 2`)
	assertLine(t, out, `powerdns_cache_prefetch_total{result="failure"} 1`)
}

func TestPrefetchSkipsAreLabeledByReason(t *testing.T) {
	r := New()
	r.IncPrefetchSkipped(PrefetchSkipInFlight)
	r.IncPrefetchSkipped(PrefetchSkipCooldown)
	r.IncPrefetchSkipped(PrefetchSkipCooldown)

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, `powerdns_cache_prefetch_skipped_total{reason="in_flight"} 1`)
	assertLine(t, out, `powerdns_cache_prefetch_skipped_total{reason="cooldown"} 2`)
}

func TestRelayCoalescing(t *testing.T) {
	r := New()
	r.IncRelayCall()
	r.IncRelayCoalesced()
	r.IncRelayCoalesced()
	r.IncRelayCoalesced()

	var b strings.Builder
	r.WriteProm(&b)
	out := b.String()

	assertLine(t, out, "powerdns_relay_calls_total 1")
	assertLine(t, out, "powerdns_relay_coalesced_total 3")
	// 3 coalesced out of 4 total = 0.75
	assertLine(t, out, "powerdns_relay_coalesce_rate 0.75")
}

func TestRelayCoalesceRateZeroWithoutTraffic(t *testing.T) {
	r := New()
	var b strings.Builder
	r.WriteProm(&b)
	assertLine(t, b.String(), "powerdns_relay_coalesce_rate 0")
}

func assertLine(t *testing.T, haystack, line string) {
	t.Helper()
	for _, l := range strings.Split(haystack, "\n") {
		if l == line {
			return
		}
	}
	t.Fatalf("expected line %q in output:\n%s", line, haystack)
}
