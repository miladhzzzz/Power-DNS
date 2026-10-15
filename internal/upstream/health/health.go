// Package health gives Power-DNS's upstream clients (DoH/DoT/plain) a
// notion of "endpoint", distinct from "transport": each configured server
// address is tracked independently, so adaptive behavior can eventually
// say "Google DoH" instead of just "doh".
//
// This is deliberately the boring version described in
// Design-improvements.md: no synthetic probe traffic, no machine learning,
// just an EWMA latency and a four-state health machine (healthy, degraded,
// unhealthy, probing) driven entirely by real query outcomes that the
// upstream clients were already generating. A Tracker never removes an
// endpoint from consideration -- see Order -- it only reorders within a
// transport's configured server list, so a network with only one working
// resolver still works exactly as before even if that resolver is
// currently scored "unhealthy".
package health

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// State is one of the four health states an endpoint can be in.
type State int

const (
	// Healthy is the default state: recent attempts have been succeeding.
	Healthy State = iota
	// Degraded means recent attempts have started failing, but not
	// consistently enough to call the endpoint unhealthy yet.
	Degraded
	// Unhealthy means the endpoint has failed enough consecutive times
	// that it should be considered down.
	Unhealthy
	// Probing means the cooldown after becoming Unhealthy has elapsed and
	// the next attempt(s) will decide whether the endpoint recovers to
	// Healthy or falls back to Unhealthy. There is no synthetic probe
	// query -- the next real query for this endpoint *is* the probe.
	Probing
)

func (s State) String() string {
	switch s {
	case Healthy:
		return "healthy"
	case Degraded:
		return "degraded"
	case Unhealthy:
		return "unhealthy"
	case Probing:
		return "probing"
	default:
		return "unknown"
	}
}

// MarshalJSON renders State as its string name, so the health API and any
// future JSON consumers see "healthy" rather than an opaque integer.
func (s State) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// Tuning constants. Kept fixed and unexported rather than configurable:
// Design-improvements.md is explicit that this should stay "very fucking
// boring" -- these are the values it suggests, and they only affect
// observation and same-transport ordering, never whether an endpoint is
// used at all.
const (
	// ewmaAlpha weights how quickly the latency estimate reacts to a new
	// observation: new = alpha*observed + (1-alpha)*old.
	ewmaAlpha = 0.2
	// degradeThreshold is the number of consecutive failures that moves
	// an endpoint from Healthy to Degraded.
	degradeThreshold = 2
	// unhealthyThreshold is the number of consecutive failures that moves
	// an endpoint from Degraded to Unhealthy.
	unhealthyThreshold = 5
	// recoverThreshold is the number of consecutive successes needed to
	// move an endpoint back to Healthy from Degraded or Probing.
	recoverThreshold = 3
	// cooldown is how long an Unhealthy endpoint is left alone before the
	// next attempt against it is treated as a probe rather than just
	// another failure to count.
	cooldown = 30 * time.Second
)

// endpointStats holds everything tracked for one (path, endpoint) pair,
// e.g. ("doh", "https://dns.google/dns-query").
type endpointStats struct {
	mu sync.Mutex

	path, endpoint string
	state          State

	hasEWMA bool
	ewmaMs  float64

	requests, successes, failures             uint64
	consecutiveFailures, consecutiveSuccesses uint64

	lastSuccess, lastFailure time.Time
	unhealthySince           time.Time
}

// refreshState promotes an Unhealthy endpoint to Probing once cooldown has
// elapsed. Must be called with s.mu held.
func (s *endpointStats) refreshState() {
	if s.state == Unhealthy && !s.unhealthySince.IsZero() && time.Since(s.unhealthySince) >= cooldown {
		s.state = Probing
	}
}

// onSuccess applies a successful observation's effect on the state
// machine. Must be called with s.mu held, after the counters above are
// already updated.
func (s *endpointStats) onSuccess() {
	switch s.state {
	case Probing:
		// The real query that served as our "probe" succeeded.
		s.state = Healthy
		s.consecutiveSuccesses = 0
	case Degraded, Unhealthy:
		if s.consecutiveSuccesses >= recoverThreshold {
			s.state = Healthy
			s.consecutiveSuccesses = 0
		}
	}
}

// onFailure applies a failed observation's effect on the state machine.
// Must be called with s.mu held, after the counters above are already
// updated.
func (s *endpointStats) onFailure() {
	switch s.state {
	case Healthy:
		if s.consecutiveFailures >= degradeThreshold {
			s.state = Degraded
		}
	case Degraded:
		if s.consecutiveFailures >= unhealthyThreshold {
			s.state = Unhealthy
			s.unhealthySince = time.Now()
		}
	case Probing:
		// The probe failed -- back to serving out the cooldown.
		s.state = Unhealthy
		s.unhealthySince = time.Now()
	case Unhealthy:
		s.unhealthySince = time.Now()
	}
}

// score ranks an endpoint for same-transport ordering: state first
// (Healthy/Probing beat Degraded beat Unhealthy), latency second (lower
// EWMA wins within the same state). An endpoint with no observations yet
// scores as a healthy, zero-latency endpoint, so an unmeasured server gets
// tried (and thereby measured) rather than being starved by one that
// merely happens to have data already. Must be called with s.mu held.
func (s *endpointStats) score() float64 {
	var base float64
	switch s.state {
	case Healthy, Probing:
		base = 3000
	case Degraded:
		base = 1000
	case Unhealthy:
		base = 0
	}
	penalty := 0.0
	if s.hasEWMA {
		penalty = s.ewmaMs
	}
	return base - penalty
}

// Snapshot is a point-in-time, read-only view of one endpoint's tracked
// health, used for the /api/v1/health/upstreams endpoint and for
// Prometheus export.
type Snapshot struct {
	Path     string  `json:"path"`
	Endpoint string  `json:"endpoint"`
	State    State   `json:"state"`
	Score    float64 `json:"score"`

	EWMALatencyMs float64 `json:"ewma_latency_ms"`

	Requests  uint64 `json:"requests"`
	Successes uint64 `json:"successes"`
	Failures  uint64 `json:"failures"`

	ConsecutiveFailures  uint64 `json:"consecutive_failures"`
	ConsecutiveSuccesses uint64 `json:"consecutive_successes"`

	LastSuccess time.Time `json:"last_success,omitempty"`
	LastFailure time.Time `json:"last_failure,omitempty"`
}

// Tracker holds health state for every (path, endpoint) pair it has been
// told about. The zero value is not usable -- use NewTracker. A nil
// *Tracker is safe to call every method on (all become no-ops / identity
// operations), so callers that don't want health tracking can simply leave
// a Health field nil instead of branching on it everywhere.
type Tracker struct {
	mu    sync.Mutex
	stats map[string]*endpointStats
}

// NewTracker returns an empty, ready-to-use Tracker.
func NewTracker() *Tracker {
	return &Tracker{stats: make(map[string]*endpointStats)}
}

func statsKey(path, endpoint string) string { return path + "|" + endpoint }

func (t *Tracker) get(path, endpoint string) *endpointStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := statsKey(path, endpoint)
	s, ok := t.stats[k]
	if !ok {
		s = &endpointStats{path: path, endpoint: endpoint, state: Healthy}
		t.stats[k] = s
	}
	return s
}

// RecordSuccess records one successful attempt against (path, endpoint)
// that took latency. path is a transport label such as "doh"/"dot"/"plain";
// endpoint is the server address as configured (e.g. a DoH URL or a
// host:port).
func (t *Tracker) RecordSuccess(path, endpoint string, latency time.Duration) {
	if t == nil {
		return
	}
	s := t.get(path, endpoint)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshState()

	s.requests++
	s.successes++
	s.consecutiveFailures = 0
	s.consecutiveSuccesses++
	s.lastSuccess = time.Now()

	ms := float64(latency.Milliseconds())
	if !s.hasEWMA {
		s.ewmaMs = ms
		s.hasEWMA = true
	} else {
		s.ewmaMs = ewmaAlpha*ms + (1-ewmaAlpha)*s.ewmaMs
	}

	s.onSuccess()
}

// RecordFailure records one failed attempt against (path, endpoint). The
// error itself isn't inspected yet -- Design-improvements.md's error-class
// breakdown (timeout vs. connection vs. protocol vs. rcode) is future work
// (its incident-detection milestone), not needed for the health state
// machine or endpoint ordering.
func (t *Tracker) RecordFailure(path, endpoint string, err error) {
	if t == nil {
		return
	}
	s := t.get(path, endpoint)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshState()

	s.requests++
	s.failures++
	s.consecutiveSuccesses = 0
	s.consecutiveFailures++
	s.lastFailure = time.Now()

	s.onFailure()
}

// Order returns endpoints (a transport's configured server list)
// reordered best-first according to tracked health: Healthy/Probing
// endpoints before Degraded before Unhealthy, and lower EWMA latency
// before higher within the same state. Ties (including "no data for
// either yet") keep their original relative order, so a freshly started
// process behaves exactly like the unordered configuration until it has
// something to learn from.
//
// This never drops an endpoint -- a caller that exhausts every entry in
// the returned slice has tried every configured server, same as before
// this package existed. Reordering only changes *which one is tried
// first*, not the fallback guarantee.
func (t *Tracker) Order(path string, endpoints []string) []string {
	if t == nil || len(endpoints) <= 1 {
		return endpoints
	}
	type scored struct {
		endpoint string
		score    float64
	}
	items := make([]scored, len(endpoints))
	for i, e := range endpoints {
		s := t.get(path, e)
		s.mu.Lock()
		s.refreshState()
		sc := s.score()
		s.mu.Unlock()
		items[i] = scored{endpoint: e, score: sc}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].score > items[j].score })

	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.endpoint
	}
	return out
}

// State reports the current health state of (path, endpoint), applying any
// pending cooldown-driven transition to Probing first. Endpoints never
// seen before report Healthy.
func (t *Tracker) State(path, endpoint string) State {
	if t == nil {
		return Healthy
	}
	s := t.get(path, endpoint)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshState()
	return s.state
}


// EndpointCount returns how many (path, endpoint) pairs have been observed.
// Cheaper than Snapshot when only a count is needed (e.g. admin status).
func (t *Tracker) EndpointCount() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	n := len(t.stats)
	t.mu.Unlock()
	return n
}

// PathState returns the aggregate health of a transport path (e.g. "doh"):
// the best state among endpoints observed for that path. Paths with no
// observations report Healthy so an unmeasured transport is not demoted.
func (t *Tracker) PathState(path string) State {
	if t == nil {
		return Healthy
	}
	t.mu.Lock()
	var matched []*endpointStats
	for _, s := range t.stats {
		if s.path == path {
			matched = append(matched, s)
		}
	}
	t.mu.Unlock()
	if len(matched) == 0 {
		return Healthy
	}
	best := Unhealthy
	for _, s := range matched {
		s.mu.Lock()
		s.refreshState()
		st := s.state
		s.mu.Unlock()
		if stateRank(st) > stateRank(best) {
			best = st
		}
	}
	return best
}

// PathEWMA returns the minimum EWMA latency among observed endpoints for
// path, or 0 if none have latency data yet.
func (t *Tracker) PathEWMA(path string) float64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	var matched []*endpointStats
	for _, s := range t.stats {
		if s.path == path {
			matched = append(matched, s)
		}
	}
	t.mu.Unlock()
	best := 0.0
	found := false
	for _, s := range matched {
		s.mu.Lock()
		if s.hasEWMA {
			if !found || s.ewmaMs < best {
				best = s.ewmaMs
				found = true
			}
		}
		s.mu.Unlock()
	}
	return best
}

func stateRank(s State) int {
	switch s {
	case Healthy:
		return 4
	case Probing:
		return 3
	case Degraded:
		return 2
	case Unhealthy:
		return 1
	default:
		return 0
	}
}

// OrderTransports reorders transport path labels by aggregate path health.
// Encrypted transports (doh, dot, relay) never rank below plain solely
// because plain is faster — plain only rises when every encrypted path in
// the list is Unhealthy. Within a tier, healthier / lower-EWMA paths come
// first. Stable for ties so a cold start matches configuration.
//
// Milestone 5 adaptive transport failover: "DoH degraded → DoT preferred"
// with hysteresis already in the per-endpoint state machine.
func (t *Tracker) OrderTransports(paths []string) []string {
	if t == nil || len(paths) <= 1 {
		return paths
	}
	type scored struct {
		path  string
		score float64
		idx   int
	}
	items := make([]scored, len(paths))
	for i, p := range paths {
		st := t.PathState(p)
		ewma := t.PathEWMA(p)
		var base float64
		switch st {
		case Healthy, Probing:
			base = 3000
		case Degraded:
			base = 1000
		case Unhealthy:
			base = 0
		}
		if p == "doh" || p == "dot" || p == "relay" {
			if st != Unhealthy {
				base += 5000
			}
		}
		items[i] = scored{path: p, score: base - ewma, idx: i}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].idx < items[j].idx
	})
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.path
	}
	return out
}

// Snapshot returns a point-in-time view of every endpoint this Tracker has
// ever recorded an observation for, sorted by (path, endpoint) for stable
// output.
func (t *Tracker) Snapshot() []Snapshot {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	all := make([]*endpointStats, 0, len(t.stats))
	for _, s := range t.stats {
		all = append(all, s)
	}
	t.mu.Unlock()

	out := make([]Snapshot, 0, len(all))
	for _, s := range all {
		s.mu.Lock()
		s.refreshState()
		out = append(out, Snapshot{
			Path:                 s.path,
			Endpoint:             s.endpoint,
			State:                s.state,
			Score:                s.score(),
			EWMALatencyMs:        s.ewmaMs,
			Requests:             s.requests,
			Successes:            s.successes,
			Failures:             s.failures,
			ConsecutiveFailures:  s.consecutiveFailures,
			ConsecutiveSuccesses: s.consecutiveSuccesses,
			LastSuccess:          s.lastSuccess,
			LastFailure:          s.lastFailure,
		})
		s.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out
}
