// Package metrics gives Power-DNS operational visibility without the
// complexity v1 chased via eBPF packet-flow monitoring.
//
// v1's README promised "packet flow monitoring with eBPF" and "dynamic
// routing methods using eBPF" for metrics, but no such code ever existed
// (internal/ebpf was an empty package). Kernel-level packet tracing is also
// the wrong tool for a userspace HTTP/DNS relay: it needs elevated
// privileges, is hard to run portably (containers, non-Linux hosts), and
// tells you about packets, not about which resolution strategy answered a
// query or how long each upstream path took. Counters, a couple of gauges,
// and latency histograms, exposed in the standard Prometheus text format,
// give the operationally useful signal directly, with zero extra
// dependencies or privileges.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Cache miss reasons, used as the "reason" label on
// powerdns_cache_misses_total. Kept intentionally small and fixed --
// low-cardinality labels are cheap in Prometheus, an unbounded label set
// (e.g. one per query name) is not.
const (
	// MissNotFound is a lookup for a key the cache has never held (or has
	// since evicted), as opposed to one that expired in place.
	MissNotFound = "not_found"
	// MissExpired is a lookup that found the key but its TTL had already
	// passed.
	MissExpired = "expired"
	// MissDisabled is a lookup made while caching is turned off entirely
	// ([cache].enabled = false), so no lookup was even attempted.
	MissDisabled = "disabled"
)

// EvictionLRU labels an entry removed to make room under max_entries,
// as opposed to removed for expiring or by explicit Delete.
const EvictionLRU = "lru"

// Upstream path labels, used on powerdns_upstream_latency_ms. These match
// the resolution strategy names in internal/resolver (minus "records" and
// "cache", which are local lookups, not "upstream" in any meaningful
// latency sense).
const (
	PathRelay = "relay"
	PathDoH   = "doh"
	PathDoT   = "dot"
	PathPlain = "plain"
)

// Prefetch outcomes, used as the "result" label on
// powerdns_cache_prefetch_total.
const (
	PrefetchSuccess = "success"
	PrefetchFailure = "failure"
)

// Reasons a candidate prefetch was skipped rather than attempted, used as
// the "reason" label on powerdns_cache_prefetch_skipped_total -- this is
// what makes "protection against refreshing every low-TTL record
// continuously" (see cache.prefetchCooldown) observable instead of just
// assumed to be working.
const (
	// PrefetchSkipInFlight means a refresh for this key was already
	// running when another hit became eligible to trigger one.
	PrefetchSkipInFlight = "in_flight"
	// PrefetchSkipCooldown means a refresh for this key was attempted too
	// recently (within prefetchCooldown) to try again yet.
	PrefetchSkipCooldown = "cooldown"
)

// Registry holds every counter/gauge/histogram Power-DNS records.
type Registry struct {
	mu sync.Mutex

	queriesTotal     map[string]*int64 // labeled by resolution strategy: records/cache/relay/doh/dot/plain/failed
	cacheMissesTotal map[string]*int64 // labeled by reason: not_found/expired/disabled
	cacheEvictions   map[string]*int64 // labeled by reason: lru

	upstreamLatencyMs  map[string]*histogram // labeled by path: relay/doh/dot/plain
	relayServerLatency *histogram            // the relay's own upstream-resolution time (server side, not a "path")

	// expiredEntryAge records, for every cache lookup that finds an entry
	// past its TTL (whether stale-while-revalidate ends up serving it or
	// it counts as a genuine miss), how many seconds past expiry it was.
	// This is the distribution to look at when choosing
	// cache.stale_while_revalidate_seconds: it's unbiased by whatever
	// window is currently configured, since it's recorded before that
	// decision is made -- see internal/cache.Cache.Get.
	expiredEntryAge *histogram

	// upstreamCalls counts real network attempts per path -- exactly the
	// attempts singleflight actually let through. upstreamCoalesced counts
	// callers that instead got a shared result from someone else's
	// in-flight attempt. Together these show how much request coalescing
	// is actually saving, per path.
	upstreamCalls     map[string]*int64
	upstreamCoalesced map[string]*int64

	// prefetchTotal counts finished background refreshes by outcome
	// (PrefetchSuccess/PrefetchFailure). prefetchSkipped counts candidates
	// that were eligible but not attempted, by reason
	// (PrefetchSkipInFlight/PrefetchSkipCooldown) -- without this, a
	// prefetch feature that's silently never firing (or firing constantly)
	// looks the same as one working as intended.
	prefetchTotal   map[string]*int64
	prefetchSkipped map[string]*int64

	// relayCalls/relayCoalesced count the relay's own incoming-query
	// coalescing (see internal/relay.Server): concurrent DoH/DoT requests
	// for the same (qname, qtype) arriving at the relay share one upstream
	// resolution. Unlike upstreamCalls/upstreamCoalesced, these aren't
	// labeled by path -- coalescing here spans whichever transport(s) the
	// query arrived over and whichever upstream path eventually answered.
	relayCalls     int64
	relayCoalesced int64

	// staleHits counts Get calls served from an expired-but-still-usable
	// entry (stale-while-revalidate). staleRevalidations/
	// staleRevalidationFailures count the background refreshes those hits
	// trigger, by outcome. A stale hit is not counted in cacheHits -- see
	// the effective-hit-rate gauge in writeCacheMetrics for the combined
	// "served locally" view.
	staleHits                 int64
	staleRevalidations        int64
	staleRevalidationFailures int64

	// prefetchProtectedHits counts fresh cache hits served from an entry
	// whose last fill was a successful background prefetch. This is the
	// prefetch analogue of staleHits: it attributes client-visible hits to
	// prior prefetch work, so you can measure whether prefetch is actually
	// preventing misses rather than only counting refresh attempts.
	prefetchProtectedHits int64

	startedAt time.Time
	cacheHits int64

	// cacheSizeFunc, if set, is polled at scrape time to report the
	// current cache occupancy and its configured capacity. It's a
	// callback rather than a direct field so this package doesn't need to
	// import internal/cache (which itself imports metrics to record hits
	// and misses -- a callback avoids the import cycle that would create).
	cacheSizeFunc func() (entries, capacity int)
}

// New creates an empty, ready-to-use Registry.
func New() *Registry {
	return &Registry{
		queriesTotal:       make(map[string]*int64),
		cacheMissesTotal:   make(map[string]*int64),
		cacheEvictions:     make(map[string]*int64),
		upstreamLatencyMs:  make(map[string]*histogram),
		relayServerLatency: newHistogram(latencyBuckets),
		expiredEntryAge:    newHistogram(expiredAgeBuckets),
		upstreamCalls:      make(map[string]*int64),
		upstreamCoalesced:  make(map[string]*int64),
		prefetchTotal:      make(map[string]*int64),
		prefetchSkipped:    make(map[string]*int64),
		startedAt:          time.Now(),
	}
}

var latencyBuckets = []float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// expiredAgeBuckets are in seconds, not milliseconds like latencyBuckets --
// this histogram measures how long after expiry a repeat query arrives,
// which is a "tens of seconds to tens of minutes" question, not a
// millisecond one.
var expiredAgeBuckets = []float64{1, 5, 15, 30, 60, 120, 180, 300, 600, 1800, 3600}

// IncQuery records one resolved (or failed) query for the given strategy
// label, e.g. "cache", "relay", "doh", "dot", "plain", "records", or
// "failed".
func (r *Registry) IncQuery(strategy string) {
	atomic.AddInt64(r.counter(&r.mu, r.queriesTotal, strategy), 1)
}

// IncCacheHit records one answer that the cache was able to serve directly.
func (r *Registry) IncCacheHit() {
	atomic.AddInt64(&r.cacheHits, 1)
}

// IncCacheMiss records one lookup the cache did not have an answer for,
// labeled with why: MissNotFound, MissExpired, or MissDisabled.
func (r *Registry) IncCacheMiss(reason string) {
	atomic.AddInt64(r.counter(&r.mu, r.cacheMissesTotal, reason), 1)
}

// IncCacheEviction records one entry removed from the cache to make room,
// labeled with why (currently always EvictionLRU).
func (r *Registry) IncCacheEviction(reason string) {
	atomic.AddInt64(r.counter(&r.mu, r.cacheEvictions, reason), 1)
}

// IncStaleHit records one Get call served from an expired-but-still-usable
// entry (stale-while-revalidate), rather than either a fresh hit or a
// miss.
func (r *Registry) IncStaleHit() {
	atomic.AddInt64(&r.staleHits, 1)
}

// IncStaleRevalidation records one successful background refresh triggered
// by a stale hit.
func (r *Registry) IncStaleRevalidation() {
	atomic.AddInt64(&r.staleRevalidations, 1)
}

// IncStaleRevalidationFailure records one failed background refresh
// triggered by a stale hit.
func (r *Registry) IncStaleRevalidationFailure() {
	atomic.AddInt64(&r.staleRevalidationFailures, 1)
}

// SetCacheSizeFunc registers a callback polled at scrape time to report
// current cache occupancy (powerdns_cache_entries) and its configured
// capacity (powerdns_cache_capacity). Pass nil to stop reporting either.
func (r *Registry) SetCacheSizeFunc(f func() (entries, capacity int)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cacheSizeFunc = f
}

// ObserveUpstreamLatency records how long one attempt at the given upstream
// path (PathRelay, PathDoH, PathDoT, or PathPlain) took, success or
// failure -- failed attempts still spent real time (e.g. a timeout), and
// that's useful signal too.
func (r *Registry) ObserveUpstreamLatency(path string, d time.Duration) {
	r.mu.Lock()
	h, ok := r.upstreamLatencyMs[path]
	if !ok {
		h = newHistogram(latencyBuckets)
		r.upstreamLatencyMs[path] = h
	}
	r.mu.Unlock()
	h.observe(float64(d.Milliseconds()))
}

// ObserveRelayServerLatency records how long the relay itself took to
// resolve a query against its own upstreams (DoH/DoT/plain), when running
// in relay/both mode. This is distinct from ObserveUpstreamLatency's
// PathRelay, which times a client's round trip *to* a relay -- this times
// the relay's own work once a query arrives.
func (r *Registry) ObserveRelayServerLatency(d time.Duration) {
	r.relayServerLatency.observe(float64(d.Milliseconds()))
}

// ObserveExpiredEntryAge records how many seconds past its expiry time a
// cache entry was when looked up again, for every such lookup -- whether
// stale-while-revalidate ends up serving it or it counts as a genuine
// miss. Use this to size cache.stale_while_revalidate_seconds: it shows
// what fraction of repeat queries for an already-expired entry arrive
// within any given number of seconds after expiry.
func (r *Registry) ObserveExpiredEntryAge(d time.Duration) {
	r.expiredEntryAge.observe(d.Seconds())
}

// IncUpstreamCall records one real network attempt at the given upstream
// path -- exactly the attempts that singleflight actually let through to
// the network, once per coalesced group rather than once per caller.
func (r *Registry) IncUpstreamCall(path string) {
	atomic.AddInt64(r.counter(&r.mu, r.upstreamCalls, path), 1)
}

// IncUpstreamCoalesced records one caller that was served by another
// caller's already-in-flight attempt at the given upstream path, instead of
// making its own network call.
func (r *Registry) IncUpstreamCoalesced(path string) {
	atomic.AddInt64(r.counter(&r.mu, r.upstreamCoalesced, path), 1)
}

// IncPrefetch records one finished background prefetch refresh, labeled
// PrefetchSuccess or PrefetchFailure.
func (r *Registry) IncPrefetch(result string) {
	atomic.AddInt64(r.counter(&r.mu, r.prefetchTotal, result), 1)
}

// IncPrefetchSkipped records one prefetch candidate that was eligible
// (popular enough, low enough on TTL) but not attempted, labeled
// PrefetchSkipInFlight or PrefetchSkipCooldown.
func (r *Registry) IncPrefetchSkipped(reason string) {
	atomic.AddInt64(r.counter(&r.mu, r.prefetchSkipped, reason), 1)
}

// IncPrefetchProtectedHit records one fresh cache hit served from an entry
// that was last filled by a successful background prefetch (not by a
// client-driven resolve or a stale-while-revalidate refresh). Together with
// powerdns_cache_hits_total this answers "what fraction of fresh hits did
// prefetch actually protect."
func (r *Registry) IncPrefetchProtectedHit() {
	atomic.AddInt64(&r.prefetchProtectedHits, 1)
}

// IncRelayCall records one real upstream resolution the relay performed for
// an incoming query -- exactly the attempts that survived the relay's own
// request coalescing (see internal/relay.Server).
func (r *Registry) IncRelayCall() {
	atomic.AddInt64(&r.relayCalls, 1)
}

// IncRelayCoalesced records one incoming relay query that was served by
// another concurrent request's in-flight resolution instead of triggering
// its own.
func (r *Registry) IncRelayCoalesced() {
	atomic.AddInt64(&r.relayCoalesced, 1)
}

// counter fetches-or-creates the *int64 for a label in a label->counter
// map, under mu. Shared by every labeled-counter metric in this package.
func (r *Registry) counter(mu *sync.Mutex, m map[string]*int64, label string) *int64 {
	mu.Lock()
	defer mu.Unlock()
	ctr, ok := m[label]
	if !ok {
		var v int64
		ctr = &v
		m[label] = ctr
	}
	return ctr
}

// WriteProm writes every metric in Prometheus text exposition format.
func (r *Registry) WriteProm(w *strings.Builder) {
	fmt.Fprintf(w, "# HELP powerdns_uptime_seconds Seconds since the process started.\n")
	fmt.Fprintf(w, "# TYPE powerdns_uptime_seconds gauge\n")
	fmt.Fprintf(w, "powerdns_uptime_seconds %.0f\n", time.Since(r.startedAt).Seconds())

	r.writeQueriesTotal(w)
	r.writeCacheMetrics(w)
	r.writeUpstreamLatency(w)
	r.writeUpstreamCoalescing(w)
	r.writeRelayCoalescing(w)
	r.writePrefetchMetrics(w)

	fmt.Fprintf(w, "# HELP powerdns_relay_server_latency_ms Time the relay itself spent resolving a query against its own upstreams (relay/both mode only).\n")
	fmt.Fprintf(w, "# TYPE powerdns_relay_server_latency_ms histogram\n")
	r.relayServerLatency.writeProm(w, "powerdns_relay_server_latency_ms", "")

	fmt.Fprintf(w, "# HELP powerdns_cache_expired_entry_age_seconds Seconds past expiry a cache entry was when looked up again, for every such lookup regardless of outcome. Use this to size cache.stale_while_revalidate_seconds.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_expired_entry_age_seconds histogram\n")
	r.expiredEntryAge.writeProm(w, "powerdns_cache_expired_entry_age_seconds", "")
}

func (r *Registry) writeQueriesTotal(w *strings.Builder) {
	r.mu.Lock()
	strategies := sortedKeys(r.queriesTotal)
	r.mu.Unlock()

	fmt.Fprintf(w, "# HELP powerdns_queries_total DNS queries resolved, by resolution strategy.\n")
	fmt.Fprintf(w, "# TYPE powerdns_queries_total counter\n")
	for _, s := range strategies {
		fmt.Fprintf(w, "powerdns_queries_total{strategy=%q} %d\n", s, atomic.LoadInt64(r.queriesTotal[s]))
	}
}

func (r *Registry) writeCacheMetrics(w *strings.Builder) {
	hits := atomic.LoadInt64(&r.cacheHits)
	staleHits := atomic.LoadInt64(&r.staleHits)
	staleRevalidations := atomic.LoadInt64(&r.staleRevalidations)
	staleRevalidationFailures := atomic.LoadInt64(&r.staleRevalidationFailures)

	r.mu.Lock()
	missReasons := sortedKeys(r.cacheMissesTotal)
	var totalMisses int64
	for _, reason := range missReasons {
		totalMisses += atomic.LoadInt64(r.cacheMissesTotal[reason])
	}
	evictionReasons := sortedKeys(r.cacheEvictions)
	sizeFunc := r.cacheSizeFunc
	r.mu.Unlock()

	fmt.Fprintf(w, "# HELP powerdns_cache_hits_total Answer cache lookups that found a fresh (non-expired) entry.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_hits_total counter\n")
	fmt.Fprintf(w, "powerdns_cache_hits_total %d\n", hits)

	fmt.Fprintf(w, "# HELP powerdns_cache_stale_hits_total Answer cache lookups served from an expired-but-still-usable entry (stale-while-revalidate). Always zero unless cache.stale_while_revalidate_seconds is set.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_stale_hits_total counter\n")
	fmt.Fprintf(w, "powerdns_cache_stale_hits_total %d\n", staleHits)

	fmt.Fprintf(w, "# HELP powerdns_cache_stale_revalidations_total Background refreshes triggered by a stale hit that completed successfully.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_stale_revalidations_total counter\n")
	fmt.Fprintf(w, "powerdns_cache_stale_revalidations_total %d\n", staleRevalidations)

	fmt.Fprintf(w, "# HELP powerdns_cache_stale_revalidation_failures_total Background refreshes triggered by a stale hit that failed.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_stale_revalidation_failures_total counter\n")
	fmt.Fprintf(w, "powerdns_cache_stale_revalidation_failures_total %d\n", staleRevalidationFailures)

	fmt.Fprintf(w, "# HELP powerdns_cache_misses_total Answer cache lookups that found no valid entry, by reason.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_misses_total counter\n")
	for _, reason := range missReasons {
		fmt.Fprintf(w, "powerdns_cache_misses_total{reason=%q} %d\n", reason, atomic.LoadInt64(r.cacheMissesTotal[reason]))
	}

	fmt.Fprintf(w, "# HELP powerdns_cache_evictions_total Cache entries removed to make room, by reason.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_evictions_total counter\n")
	for _, reason := range evictionReasons {
		fmt.Fprintf(w, "powerdns_cache_evictions_total{reason=%q} %d\n", reason, atomic.LoadInt64(r.cacheEvictions[reason]))
	}

	// A simple cumulative hit rate (hits / (hits + misses) since process
	// start), as a quick-glance gauge. For a time-windowed rate, compute
	// rate(powerdns_cache_hits_total[5m]) / (rate(...hits...) +
	// rate(...misses...)) in Prometheus instead -- this gauge is a
	// convenience, not a substitute for that. Deliberately excludes stale
	// hits -- see powerdns_cache_effective_hit_rate for the combined view.
	fmt.Fprintf(w, "# HELP powerdns_cache_hit_rate Cumulative fresh-hit rate (hits / (hits + misses)) since process start. Excludes stale hits -- see powerdns_cache_effective_hit_rate for hits+stale combined.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_hit_rate gauge\n")
	total := hits + totalMisses
	rate := 0.0
	if total > 0 {
		rate = float64(hits) / float64(total)
	}
	fmt.Fprintf(w, "powerdns_cache_hit_rate %g\n", rate)

	// The more meaningful number for "what fraction of queries did the
	// caller experience as instant, locally-served answers": a stale hit
	// is, from the caller's point of view, indistinguishable from a fresh
	// one -- both return immediately with no upstream round trip.
	fmt.Fprintf(w, "# HELP powerdns_cache_effective_hit_rate Cumulative locally-served rate ((hits + stale hits) / (hits + stale hits + misses)) since process start -- what fraction of queries the caller experienced as instant, whether or not the answer happened to be fresh.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_effective_hit_rate gauge\n")
	effectiveTotal := hits + staleHits + totalMisses
	effectiveRate := 0.0
	if effectiveTotal > 0 {
		effectiveRate = float64(hits+staleHits) / float64(effectiveTotal)
	}
	fmt.Fprintf(w, "powerdns_cache_effective_hit_rate %g\n", effectiveRate)

	if sizeFunc != nil {
		entries, capacity := sizeFunc()
		fmt.Fprintf(w, "# HELP powerdns_cache_entries Current number of cached DNS answers.\n")
		fmt.Fprintf(w, "# TYPE powerdns_cache_entries gauge\n")
		fmt.Fprintf(w, "powerdns_cache_entries %d\n", entries)

		fmt.Fprintf(w, "# HELP powerdns_cache_capacity Configured maximum number of cached DNS answers.\n")
		fmt.Fprintf(w, "# TYPE powerdns_cache_capacity gauge\n")
		fmt.Fprintf(w, "powerdns_cache_capacity %d\n", capacity)
	}
}

func (r *Registry) writeUpstreamLatency(w *strings.Builder) {
	r.mu.Lock()
	paths := sortedKeys(r.upstreamLatencyMs)
	histograms := make(map[string]*histogram, len(paths))
	for _, p := range paths {
		histograms[p] = r.upstreamLatencyMs[p]
	}
	r.mu.Unlock()

	fmt.Fprintf(w, "# HELP powerdns_upstream_latency_ms Time to get an answer via a given upstream path, success or failure.\n")
	fmt.Fprintf(w, "# TYPE powerdns_upstream_latency_ms histogram\n")
	for _, p := range paths {
		histograms[p].writeProm(w, "powerdns_upstream_latency_ms", p)
	}
}

// writeUpstreamCoalescing reports how effective request coalescing is,
// per upstream path: how many real network calls were made versus how many
// callers were served by someone else's in-flight call instead, plus a
// computed coalesce rate. A path that's always 0 coalesced simply never had
// concurrent identical queries land in the same instant -- that's normal
// for a lightly-loaded client resolver, and expected to climb on a busier
// relay serving many clients.
func (r *Registry) writeUpstreamCoalescing(w *strings.Builder) {
	r.mu.Lock()
	paths := sortedKeys(unionKeys(r.upstreamCalls, r.upstreamCoalesced))
	calls := make(map[string]int64, len(paths))
	coalesced := make(map[string]int64, len(paths))
	for _, p := range paths {
		if ctr, ok := r.upstreamCalls[p]; ok {
			calls[p] = atomic.LoadInt64(ctr)
		}
		if ctr, ok := r.upstreamCoalesced[p]; ok {
			coalesced[p] = atomic.LoadInt64(ctr)
		}
	}
	r.mu.Unlock()

	fmt.Fprintf(w, "# HELP powerdns_upstream_calls_total Real network attempts made per upstream path (after request coalescing).\n")
	fmt.Fprintf(w, "# TYPE powerdns_upstream_calls_total counter\n")
	for _, p := range paths {
		fmt.Fprintf(w, "powerdns_upstream_calls_total{path=%q} %d\n", p, calls[p])
	}

	fmt.Fprintf(w, "# HELP powerdns_upstream_coalesced_total Queries served by another caller's in-flight upstream request instead of making their own, per path.\n")
	fmt.Fprintf(w, "# TYPE powerdns_upstream_coalesced_total counter\n")
	for _, p := range paths {
		fmt.Fprintf(w, "powerdns_upstream_coalesced_total{path=%q} %d\n", p, coalesced[p])
	}

	fmt.Fprintf(w, "# HELP powerdns_upstream_coalesce_rate Cumulative fraction of queries for a path that were coalesced rather than making their own network call (coalesced / (coalesced + calls)).\n")
	fmt.Fprintf(w, "# TYPE powerdns_upstream_coalesce_rate gauge\n")
	for _, p := range paths {
		total := calls[p] + coalesced[p]
		rate := 0.0
		if total > 0 {
			rate = float64(coalesced[p]) / float64(total)
		}
		fmt.Fprintf(w, "powerdns_upstream_coalesce_rate{path=%q} %g\n", p, rate)
	}
}

// writeRelayCoalescing reports the relay's own incoming-query coalescing:
// how many queries triggered a real upstream resolution versus rode along
// on another concurrent request for the same (qname, qtype). Only
// meaningful in relay/both mode -- a client-only process never populates
// these.
func (r *Registry) writeRelayCoalescing(w *strings.Builder) {
	calls := atomic.LoadInt64(&r.relayCalls)
	coalesced := atomic.LoadInt64(&r.relayCoalesced)

	fmt.Fprintf(w, "# HELP powerdns_relay_calls_total Real upstream resolutions the relay performed for incoming queries (after the relay's own request coalescing).\n")
	fmt.Fprintf(w, "# TYPE powerdns_relay_calls_total counter\n")
	fmt.Fprintf(w, "powerdns_relay_calls_total %d\n", calls)

	fmt.Fprintf(w, "# HELP powerdns_relay_coalesced_total Incoming relay queries served by another concurrent request's in-flight resolution instead of triggering their own.\n")
	fmt.Fprintf(w, "# TYPE powerdns_relay_coalesced_total counter\n")
	fmt.Fprintf(w, "powerdns_relay_coalesced_total %d\n", coalesced)

	fmt.Fprintf(w, "# HELP powerdns_relay_coalesce_rate Cumulative fraction of incoming relay queries that were coalesced rather than triggering their own upstream resolution.\n")
	fmt.Fprintf(w, "# TYPE powerdns_relay_coalesce_rate gauge\n")
	total := calls + coalesced
	rate := 0.0
	if total > 0 {
		rate = float64(coalesced) / float64(total)
	}
	fmt.Fprintf(w, "powerdns_relay_coalesce_rate %g\n", rate)
}

// writePrefetchMetrics reports background-prefetch outcomes and skips. An
// all-zero block here just means prefetching is disabled or nothing has
// crossed the popularity/TTL threshold yet, not an error.
func (r *Registry) writePrefetchMetrics(w *strings.Builder) {
	r.mu.Lock()
	results := sortedKeys(r.prefetchTotal)
	skipReasons := sortedKeys(r.prefetchSkipped)
	resultCounts := make(map[string]int64, len(results))
	skipCounts := make(map[string]int64, len(skipReasons))
	for _, res := range results {
		resultCounts[res] = atomic.LoadInt64(r.prefetchTotal[res])
	}
	for _, reason := range skipReasons {
		skipCounts[reason] = atomic.LoadInt64(r.prefetchSkipped[reason])
	}
	r.mu.Unlock()

	fmt.Fprintf(w, "# HELP powerdns_cache_prefetch_total Background cache-refresh attempts for soon-to-expire, popular entries, by outcome.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_prefetch_total counter\n")
	for _, res := range results {
		fmt.Fprintf(w, "powerdns_cache_prefetch_total{result=%q} %d\n", res, resultCounts[res])
	}

	fmt.Fprintf(w, "# HELP powerdns_cache_prefetch_skipped_total Prefetch candidates that were eligible but not attempted, by reason.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_prefetch_skipped_total counter\n")
	for _, reason := range skipReasons {
		fmt.Fprintf(w, "powerdns_cache_prefetch_skipped_total{reason=%q} %d\n", reason, skipCounts[reason])
	}

	protected := atomic.LoadInt64(&r.prefetchProtectedHits)
	fmt.Fprintf(w, "# HELP powerdns_cache_prefetch_protected_hits_total Fresh cache hits served from an entry last filled by a successful background prefetch. The prefetch analogue of powerdns_cache_stale_hits_total: attributes client-visible hits to prior prefetch work.\n")
	fmt.Fprintf(w, "# TYPE powerdns_cache_prefetch_protected_hits_total counter\n")
	fmt.Fprintf(w, "powerdns_cache_prefetch_protected_hits_total %d\n", protected)
}

func unionKeys(maps ...map[string]*int64) map[string]struct{} {
	out := make(map[string]struct{})
	for _, m := range maps {
		for k := range m {
			out[k] = struct{}{}
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// histogram is a minimal fixed-bucket cumulative histogram, sufficient for
// the handful of latency metrics Power-DNS exposes.
type histogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []int64
	sum     float64
	count   int64
}

func newHistogram(buckets []float64) *histogram {
	return &histogram{buckets: buckets, counts: make([]int64, len(buckets)+1)}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.count++
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
			return
		}
	}
	h.counts[len(h.counts)-1]++
}

// writeProm writes this histogram's series. If pathLabel is non-empty, every
// line carries an additional path="<pathLabel>" label (used for
// powerdns_upstream_latency_ms, which is one histogram per upstream path).
func (h *histogram) writeProm(w *strings.Builder, name, pathLabel string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	labelPrefix := ""
	baseLabel := ""
	if pathLabel != "" {
		labelPrefix = fmt.Sprintf("path=%q,", pathLabel)
		baseLabel = fmt.Sprintf("{path=%q}", pathLabel)
	}

	cumulative := int64(0)
	for i, b := range h.buckets {
		cumulative += h.counts[i]
		fmt.Fprintf(w, "%s_bucket{%sle=%q} %d\n", name, labelPrefix, fmt.Sprintf("%g", b), cumulative)
	}
	cumulative += h.counts[len(h.counts)-1]
	fmt.Fprintf(w, "%s_bucket{%sle=\"+Inf\"} %d\n", name, labelPrefix, cumulative)
	fmt.Fprintf(w, "%s_sum%s %g\n", name, baseLabel, h.sum)
	fmt.Fprintf(w, "%s_count%s %d\n", name, baseLabel, h.count)
}
