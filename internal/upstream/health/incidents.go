package health

import (
	"sort"
	"sync"
	"time"
)

// IncidentKind classifies a network/upstream condition detected from the
// Tracker's passive observations (Design-improvements.md Milestone 6).
type IncidentKind string

const (
	// IncidentProviderDegradation: one specific endpoint is unhealthy while
	// peers on the same transport remain healthy.
	IncidentProviderDegradation IncidentKind = "provider_degradation"
	// IncidentTransportDegradation: every observed endpoint on a transport
	// is degraded or worse.
	IncidentTransportDegradation IncidentKind = "transport_degradation"
	// IncidentUpstreamUnavailable: every observed endpoint on a transport
	// is unhealthy.
	IncidentUpstreamUnavailable IncidentKind = "upstream_unavailable"
	// IncidentLatencyDegradation: an endpoint's EWMA is a large multiple of
	// the best peer on the same path (or above a hard floor).
	IncidentLatencyDegradation IncidentKind = "latency_degradation"
	// IncidentDNSErrorSpike: recent failure ratio on an endpoint is high
	// (failures dominate requests in the tracked counters).
	IncidentDNSErrorSpike IncidentKind = "dns_error_spike"
)

// Incident is one active condition the detector currently reports.
type Incident struct {
	Kind      IncidentKind `json:"kind"`
	Path      string       `json:"path,omitempty"`
	Endpoint  string       `json:"endpoint,omitempty"`
	Message   string       `json:"message"`
	Since     time.Time    `json:"since"`
	Severity  string       `json:"severity"` // info | warn | critical
}

// Detector derives incidents from a Tracker snapshot. It is intentionally
// passive: no probes, no side effects on routing — observation only so
// operators (and Grafana) can see *why* the network feels broken.
type Detector struct {
	mu       sync.Mutex
	tracker  *Tracker
	active   map[string]Incident // key = kind|path|endpoint
	latencyX float64             // EWMA multiple vs best peer to flag latency
	failRate float64             // failures/requests threshold for error spike
}

// NewDetector binds a Detector to a Tracker. latencyMultiple defaults to 5x;
// failRatio defaults to 0.3 (30% of attempts failed).
func NewDetector(t *Tracker) *Detector {
	return &Detector{
		tracker:  t,
		active:   make(map[string]Incident),
		latencyX: 5,
		failRate: 0.3,
	}
}

func incidentKey(kind IncidentKind, path, endpoint string) string {
	return string(kind) + "|" + path + "|" + endpoint
}


// ActiveCount returns the number of incidents from the last Evaluate call
// without re-scanning the tracker. Call Evaluate first (or periodically)
// for an up-to-date value.
func (d *Detector) ActiveCount() int {
	if d == nil {
		return 0
	}
	d.mu.Lock()
	n := len(d.active)
	d.mu.Unlock()
	return n
}

// Evaluate refreshes the active incident set from the Tracker's current
// snapshot and returns the list (stable-sorted). Safe to call on every
// scrape or admin request.
func (d *Detector) Evaluate() []Incident {
	if d == nil || d.tracker == nil {
		return nil
	}
	snaps := d.tracker.Snapshot()
	now := time.Now()
	next := make(map[string]Incident)

	// Group by path for transport-level judgments.
	byPath := map[string][]Snapshot{}
	for _, s := range snaps {
		byPath[s.Path] = append(byPath[s.Path], s)
	}

	for path, list := range byPath {
		if len(list) == 0 {
			continue
		}
		allUnhealthy := true
		allDegradedOrWorse := true
		var bestEWMA float64
		hasEWMA := false
		for _, s := range list {
			if s.State != Unhealthy {
				allUnhealthy = false
			}
			if s.State == Healthy || s.State == Probing {
				allDegradedOrWorse = false
			}
			if s.EWMALatencyMs > 0 {
				if !hasEWMA || s.EWMALatencyMs < bestEWMA {
					bestEWMA = s.EWMALatencyMs
					hasEWMA = true
				}
			}
		}

		if allUnhealthy {
			k := incidentKey(IncidentUpstreamUnavailable, path, "")
			next[k] = Incident{
				Kind:     IncidentUpstreamUnavailable,
				Path:     path,
				Message:  "all endpoints on transport " + path + " are unhealthy",
				Since:    now,
				Severity: "critical",
			}
		} else if allDegradedOrWorse {
			k := incidentKey(IncidentTransportDegradation, path, "")
			next[k] = Incident{
				Kind:     IncidentTransportDegradation,
				Path:     path,
				Message:  "all endpoints on transport " + path + " are degraded or worse",
				Since:    now,
				Severity: "warn",
			}
		}

		healthyPeers := 0
		for _, s := range list {
			if s.State == Healthy || s.State == Probing {
				healthyPeers++
			}
		}
		for _, s := range list {
			if (s.State == Unhealthy || s.State == Degraded) && healthyPeers > 0 {
				k := incidentKey(IncidentProviderDegradation, path, s.Endpoint)
				next[k] = Incident{
					Kind:     IncidentProviderDegradation,
					Path:     path,
					Endpoint: s.Endpoint,
					Message:  "endpoint " + s.Endpoint + " on " + path + " is " + s.State.String() + " while peers remain healthy",
					Since:    now,
					Severity: "warn",
				}
			}
			if s.Requests >= 10 {
				rate := float64(s.Failures) / float64(s.Requests)
				if rate >= d.failRate {
					k := incidentKey(IncidentDNSErrorSpike, path, s.Endpoint)
					next[k] = Incident{
						Kind:     IncidentDNSErrorSpike,
						Path:     path,
						Endpoint: s.Endpoint,
						Message:  "high failure ratio on " + s.Endpoint,
						Since:    now,
						Severity: "warn",
					}
				}
			}
			if hasEWMA && s.EWMALatencyMs > 0 && bestEWMA > 0 &&
				s.EWMALatencyMs >= d.latencyX*bestEWMA && s.EWMALatencyMs >= 200 {
				k := incidentKey(IncidentLatencyDegradation, path, s.Endpoint)
				next[k] = Incident{
					Kind:     IncidentLatencyDegradation,
					Path:     path,
					Endpoint: s.Endpoint,
					Message:  "EWMA latency on " + s.Endpoint + " is elevated vs peers",
					Since:    now,
					Severity: "info",
				}
			}
		}
	}

	d.mu.Lock()
	// Preserve Since for incidents that remain active.
	for k, inc := range next {
		if prev, ok := d.active[k]; ok {
			inc.Since = prev.Since
			next[k] = inc
		}
	}
	d.active = next
	out := make([]Incident, 0, len(next))
	for _, inc := range next {
		out = append(out, inc)
	}
	d.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out
}
