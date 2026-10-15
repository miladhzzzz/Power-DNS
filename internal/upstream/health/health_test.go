package health

import (
	"errors"
	"testing"
	"time"
)

func TestNilTrackerIsSafe(t *testing.T) {
	var tr *Tracker
	tr.RecordSuccess("doh", "a", 10*time.Millisecond) // must not panic
	tr.RecordFailure("doh", "a", errors.New("boom"))  // must not panic
	if got := tr.State("doh", "a"); got != Healthy {
		t.Fatalf("nil tracker State = %v, want Healthy", got)
	}
	if snap := tr.Snapshot(); snap != nil {
		t.Fatalf("nil tracker Snapshot = %v, want nil", snap)
	}
	in := []string{"a", "b"}
	if out := tr.Order("doh", in); &out[0] != &in[0] {
		// Order should return the input slice unchanged (same backing
		// array) when the tracker is nil.
		t.Fatalf("nil tracker Order should return input unchanged")
	}
}

func TestStateMachineDegradeAndUnhealthy(t *testing.T) {
	tr := NewTracker()
	err := errors.New("timeout")

	if got := tr.State("doh", "x"); got != Healthy {
		t.Fatalf("fresh endpoint State = %v, want Healthy", got)
	}

	// One failure isn't enough to degrade.
	tr.RecordFailure("doh", "x", err)
	if got := tr.State("doh", "x"); got != Healthy {
		t.Fatalf("after 1 failure State = %v, want Healthy", got)
	}

	// Second consecutive failure crosses degradeThreshold (2).
	tr.RecordFailure("doh", "x", err)
	if got := tr.State("doh", "x"); got != Degraded {
		t.Fatalf("after 2 failures State = %v, want Degraded", got)
	}

	// A success in between resets the failure streak.
	tr.RecordSuccess("doh", "x", 50*time.Millisecond)
	// One success isn't enough to recover from Degraded (needs recoverThreshold).
	if got := tr.State("doh", "x"); got != Degraded {
		t.Fatalf("after 1 success from Degraded State = %v, want still Degraded", got)
	}

	// Enough consecutive failures from Degraded crosses unhealthyThreshold (5).
	for i := 0; i < unhealthyThreshold; i++ {
		tr.RecordFailure("doh", "x", err)
	}
	if got := tr.State("doh", "x"); got != Unhealthy {
		t.Fatalf("after %d failures State = %v, want Unhealthy", unhealthyThreshold, got)
	}
}

func TestStateMachineRecovery(t *testing.T) {
	tr := NewTracker()
	err := errors.New("timeout")

	for i := 0; i < degradeThreshold+unhealthyThreshold; i++ {
		tr.RecordFailure("doh", "x", err)
	}
	if got := tr.State("doh", "x"); got != Unhealthy {
		t.Fatalf("State = %v, want Unhealthy", got)
	}

	for i := 0; i < recoverThreshold; i++ {
		tr.RecordSuccess("doh", "x", 10*time.Millisecond)
	}
	if got := tr.State("doh", "x"); got != Healthy {
		t.Fatalf("after %d consecutive successes from Unhealthy, State = %v, want Healthy", recoverThreshold, got)
	}
}

func TestCooldownPromotesToProbing(t *testing.T) {
	tr := NewTracker()
	err := errors.New("timeout")
	for i := 0; i < degradeThreshold+unhealthyThreshold; i++ {
		tr.RecordFailure("doh", "x", err)
	}
	if got := tr.State("doh", "x"); got != Unhealthy {
		t.Fatalf("State = %v, want Unhealthy", got)
	}

	// Force the unhealthy timestamp into the past instead of sleeping in
	// the test.
	tr.mu.Lock()
	s := tr.stats[statsKey("doh", "x")]
	tr.mu.Unlock()
	s.mu.Lock()
	s.unhealthySince = time.Now().Add(-cooldown - time.Second)
	s.mu.Unlock()

	if got := tr.State("doh", "x"); got != Probing {
		t.Fatalf("after cooldown elapses, State = %v, want Probing", got)
	}

	// A failed probe goes back to Unhealthy.
	tr.RecordFailure("doh", "x", err)
	if got := tr.State("doh", "x"); got != Unhealthy {
		t.Fatalf("after failed probe, State = %v, want Unhealthy", got)
	}
}

func TestOrderPrefersHealthyThenLowerLatency(t *testing.T) {
	tr := NewTracker()

	// "slow" is healthy but slower than "fast".
	tr.RecordSuccess("doh", "slow", 500*time.Millisecond)
	tr.RecordSuccess("doh", "fast", 20*time.Millisecond)

	// "bad" fails enough to become degraded.
	for i := 0; i < degradeThreshold; i++ {
		tr.RecordFailure("doh", "bad", errors.New("x"))
	}

	order := tr.Order("doh", []string{"slow", "bad", "fast"})
	want := []string{"fast", "slow", "bad"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("Order = %v, want %v", order, want)
		}
	}
}

func TestOrderPreservesConfiguredOrderWhenUnmeasured(t *testing.T) {
	tr := NewTracker()
	in := []string{"a", "b", "c"}
	order := tr.Order("doh", in)
	for i := range in {
		if order[i] != in[i] {
			t.Fatalf("Order of never-seen endpoints = %v, want unchanged %v", order, in)
		}
	}
}

func TestSnapshotReportsObservedEndpoints(t *testing.T) {
	tr := NewTracker()
	tr.RecordSuccess("doh", "a", 100*time.Millisecond)
	tr.RecordFailure("dot", "b", errors.New("x"))

	snap := tr.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot len = %d, want 2", len(snap))
	}
	// Sorted by path then endpoint: doh|a before dot|b.
	if snap[0].Path != "doh" || snap[0].Endpoint != "a" || snap[0].Successes != 1 {
		t.Fatalf("unexpected first snapshot entry: %+v", snap[0])
	}
	if snap[1].Path != "dot" || snap[1].Endpoint != "b" || snap[1].Failures != 1 {
		t.Fatalf("unexpected second snapshot entry: %+v", snap[1])
	}
}

func TestOrderTransportsPrefersHealthyEncrypted(t *testing.T) {
	tr := NewTracker()
	// DoH unhealthy, DoT healthy
	tr.RecordFailure("doh", "https://bad.example/dns-query", errors.New("x"))
	tr.RecordFailure("doh", "https://bad.example/dns-query", errors.New("x"))
	tr.RecordFailure("doh", "https://bad.example/dns-query", errors.New("x"))
	tr.RecordFailure("doh", "https://bad.example/dns-query", errors.New("x"))
	tr.RecordFailure("doh", "https://bad.example/dns-query", errors.New("x"))
	tr.RecordSuccess("dot", "1.1.1.1:853", 50*time.Millisecond)
	tr.RecordSuccess("plain", "8.8.8.8:53", 10*time.Millisecond)

	got := tr.OrderTransports([]string{"doh", "dot", "plain"})
	if got[0] != "dot" {
		t.Fatalf("expected dot first (healthy encrypted), got %v", got)
	}
	// plain should not beat healthy/degraded encrypted solely on latency
	if got[len(got)-1] != "doh" && got[0] == "plain" {
		t.Fatalf("plain should not rank first while encrypted exists: %v", got)
	}
}

func TestDetectorTransportUnavailable(t *testing.T) {
	tr := NewTracker()
	for i := 0; i < 6; i++ {
		tr.RecordFailure("doh", "https://a.example/dns-query", errors.New("x"))
	}
	d := NewDetector(tr)
	incs := d.Evaluate()
	found := false
	for _, inc := range incs {
		if inc.Kind == IncidentUpstreamUnavailable && inc.Path == "doh" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected upstream_unavailable for doh, got %+v", incs)
	}
}
