// Package metrics gives Power-DNS operational visibility without the
// complexity v1 chased via eBPF packet-flow monitoring.
//
// v1's README promised "packet flow monitoring with eBPF" and "dynamic
// routing methods using eBPF" for metrics, but no such code ever existed
// (internal/ebpf was an empty package). Kernel-level packet tracing is also
// the wrong tool for a userspace HTTP/DNS relay: it needs elevated
// privileges, is hard to run portably (containers, non-Linux hosts), and
// tells you about packets, not about which resolution strategy answered a
// query or how long the relay took. A handful of counters and a latency
// histogram, exposed in the standard Prometheus text format, gives the
// operationally useful signal directly, with zero extra dependencies or
// privileges.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds every counter/histogram Power-DNS records.
type Registry struct {
	mu sync.Mutex

	queriesTotal   map[string]*int64 // labeled by resolution strategy: records/cache/relay/doh/plain/failed
	relayLatencyMs *histogram
	startedAt      time.Time
}

// New creates an empty, ready-to-use Registry.
func New() *Registry {
	return &Registry{
		queriesTotal:   make(map[string]*int64),
		relayLatencyMs: newHistogram([]float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}),
		startedAt:      time.Now(),
	}
}

// IncQuery records one resolved (or failed) query for the given strategy
// label, e.g. "cache", "relay", "doh", "plain", "records", or "failed".
func (r *Registry) IncQuery(strategy string) {
	r.mu.Lock()
	ctr, ok := r.queriesTotal[strategy]
	if !ok {
		var v int64
		ctr = &v
		r.queriesTotal[strategy] = ctr
	}
	r.mu.Unlock()
	atomic.AddInt64(ctr, 1)
}

// ObserveRelayLatency records how long a relay round-trip took.
func (r *Registry) ObserveRelayLatency(d time.Duration) {
	r.relayLatencyMs.observe(float64(d.Milliseconds()))
}

// WriteProm writes every metric in Prometheus text exposition format.
func (r *Registry) WriteProm(w *strings.Builder) {
	r.mu.Lock()
	strategies := make([]string, 0, len(r.queriesTotal))
	for s := range r.queriesTotal {
		strategies = append(strategies, s)
	}
	sort.Strings(strategies)

	fmt.Fprintf(w, "# HELP powerdns_uptime_seconds Seconds since the process started.\n")
	fmt.Fprintf(w, "# TYPE powerdns_uptime_seconds gauge\n")
	fmt.Fprintf(w, "powerdns_uptime_seconds %.0f\n", time.Since(r.startedAt).Seconds())

	fmt.Fprintf(w, "# HELP powerdns_queries_total DNS queries resolved, by resolution strategy.\n")
	fmt.Fprintf(w, "# TYPE powerdns_queries_total counter\n")
	for _, s := range strategies {
		fmt.Fprintf(w, "powerdns_queries_total{strategy=%q} %d\n", s, atomic.LoadInt64(r.queriesTotal[s]))
	}
	r.mu.Unlock()

	fmt.Fprintf(w, "# HELP powerdns_relay_latency_ms Relay HTTP round-trip latency in milliseconds.\n")
	fmt.Fprintf(w, "# TYPE powerdns_relay_latency_ms histogram\n")
	r.relayLatencyMs.writeProm(w, "powerdns_relay_latency_ms")
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

func (h *histogram) writeProm(w *strings.Builder, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cumulative := int64(0)
	for i, b := range h.buckets {
		cumulative += h.counts[i]
		fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, fmt.Sprintf("%g", b), cumulative)
	}
	cumulative += h.counts[len(h.counts)-1]
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, cumulative)
	fmt.Fprintf(w, "%s_sum %g\n", name, h.sum)
	fmt.Fprintf(w, "%s_count %d\n", name, h.count)
}
