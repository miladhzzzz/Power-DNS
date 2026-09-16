Yeah. I went through the actual repo rather than treating Power-DNS like a generic resolver, and **these ideas fit the architecture unusually well**.

The important thing is that you already built most of the primitives we need.

The current architecture has:

* `internal/upstream` — DoH, DoT, plain DNS clients
* `internal/resolver` — configurable resolution chain
* per-path upstream latency histograms
* upstream call/coalescing metrics
* bounded timeouts
* cache + prefetch + SWR
* Prometheus metrics
* Grafana dashboard

The resolver already explicitly models `relay → doh → dot → plain` as independent strategies, and every network-bound strategy is timed/coalesced independently.  The upstream package already tries configured servers sequentially and records latency for each transport.  And the metrics registry already has low-cardinality per-path latency/call metrics.

So I **would not redesign the resolver**.

I'd evolve it.

# The architecture I would build

I'd split this into **three related features**:

```text
                    Power-DNS
                       │
          ┌────────────┼────────────┐
          │            │            │
       Resolver     Upstream      Observer
          │            │            │
       routing      probing      diagnosis
          │            │            │
          └────────────┼────────────┘
                       │
                  Prometheus
                       │
                    Grafana
```

And I'd build them in this order:

### Phase 1 — Upstream health tracking

### Phase 2 — Adaptive upstream selection

### Phase 3 — Network incident detection

Then **per-network profiles** can sit on top of all three.

---

# 1. First: distinguish "transport" from "upstream endpoint"

This is the biggest architectural change I'd make.

Right now you have:

```toml
doh_servers = [
    "https://dns.google/dns-query",
    "https://cloudflare-dns.com/dns-query"
]

dot_servers = [
    "1.1.1.1:853",
    "8.8.8.8:853"
]
```

and the clients iterate through those lists.

That's fine for fallback.

But adaptive routing needs to know that:

```text
Google DoH
Cloudflare DoH
Google DoT
Cloudflare DoT
Google plain
Cloudflare plain
```

are **six distinct upstream endpoints**.

So I'd introduce an internal concept like:

```go
type UpstreamEndpoint struct {
    ID        string
    Path      string
    Address   string

    // Runtime health
    Healthy   bool
    Score     float64

    // Statistics
    Requests  uint64
    Successes uint64
    Failures  uint64

    Latency   EWMA
}
```

Don't expose this configuration yet.

This is an internal abstraction.

The existing `DoHClient`, `DoTClient`, etc. can still own the actual protocol implementation.

---

# 2. Build an `upstream/health` package

Something like:

```text
internal/
    upstream/
        upstream.go
        health.go
        selector.go
```

I'd keep it **very fucking boring**.

No ML.

No giant adaptive algorithm.

Just measurements.

For every endpoint maintain:

```text
success count
failure count
consecutive failures
last success
last failure
EWMA latency
recent timeout count
recent error count
```

The key metric is probably an EWMA rather than an average.

For example:

```text
new_latency = α * observed + (1-α) * old_latency
```

With something like:

```text
α = 0.2
```

That means the resolver reacts to changing conditions without freaking out because one request took 4 seconds.

---

# 3. Don't immediately make health affect routing

This is important.

First release should be **observation only**.

Power-DNS should run exactly as it does today, but start learning:

```text
Google DoH
  requests: 1204
  success: 1198
  failures: 6
  p50: 112ms
  p95: 241ms
  EWMA: 128ms
  health: 0.997

Cloudflare DoH
  requests: 1201
  success: 1160
  failures: 41
  p50: 141ms
  p95: 2.4s
  EWMA: 391ms
  health: 0.966
```

Then you can look at Grafana and say:

> Holy shit, the resolver already knows which upstream sucks.

**Only after this works do we let it influence routing.**

That gives you a safe progression.

---

# 4. Health states

I'd use four states:

```text
HEALTHY
DEGRADED
UNHEALTHY
PROBING
```

Something like:

```text
HEALTHY
   │
   │ failures/latency
   ▼
DEGRADED
   │
   │ repeated failures
   ▼
UNHEALTHY
   │
   │ cooldown
   ▼
PROBING
   │
   ├── success ──► HEALTHY
   │
   └── failure ──► UNHEALTHY
```

This is much better than simply:

```go
if error {
    server.dead = true
}
```

because networks are messy as fuck.

---

# 5. The really important part: passive health checks

**Don't initially create synthetic DNS traffic.**

Every real query already gives you a measurement.

You currently have:

```go
ObserveUpstreamLatency(...)
IncUpstreamCall(...)
```

Extend that measurement to:

```text
attempt started
attempt succeeded
attempt failed
duration
error category
```

So one real request produces:

```text
Google DoH
    ↓
request
    ↓
130ms
    ↓
SUCCESS
    ↓
health.update(130ms, success)
```

Zero extra traffic.

That's perfect for Power-DNS.

---

# 6. Then adaptive ordering

Once health data exists, change:

```go
for _, strategy := range r.Order {
```

from literally following the configured order to something closer to:

```text
configured policy
        +
learned endpoint ranking
        ↓
actual route
```

But here's where I'd be careful.

**Don't allow the resolver to completely ignore configuration.**

Configuration should define the policy boundary.

For example:

```toml
[resolution]
order = ["records", "cache", "doh", "dot", "plain"]
adaptive = true
```

Means:

> You may optimize **within these strategies**, but you cannot suddenly decide to use plain DNS before DoH because it happens to be faster.

That's an important security/privacy property.

---

# 7. So the algorithm becomes

Suppose configuration says:

```text
records
cache
doh
dot
plain
```

Power-DNS sees:

```text
DoH Google       130ms
DoH Cloudflare   2.1s
DoT Cloudflare   80ms
DoT Google       90ms
Plain Google     20ms
```

It should **not** do:

```text
plain → dot → doh
```

Instead:

```text
DoH:
    Google       130ms
    Cloudflare   2100ms

DoT:
    Cloudflare    80ms
    Google        90ms

Plain:
    Google        20ms
```

And therefore:

```text
configured strategy priority:

DoH > DoT > Plain

but endpoint selection within DoH:
Google > Cloudflare
```

That is a much safer first implementation.

---

# 8. Then introduce adaptive strategy selection

Later, you can add:

```toml
adaptive = true
adaptive_strategy = "conservative"
```

and allow the resolver to say:

> DoH has degraded badly enough that DoT is currently the better strategy.

But I'd make this **opt-in initially**.

And when it happens, expose it:

```text
Resolution policy override

configured:
    DoH → DoT → Plain

current:
    DoT → DoH → Plain

reason:
    DoH degraded

confidence:
    94%
```

That is fucking cool.

---

# 9. Now the incident detector

This should be a separate component.

Not part of the resolver.

Something like:

```text
internal/
    health/
        monitor.go
        state.go
        incident.go
```

The monitor consumes upstream observations.

Then it detects things like:

### Latency degradation

```text
baseline: 130ms
current:  620ms

+377%
```

### Failure spike

```text
baseline: 0.4%
current: 17.2%
```

### Timeout storm

```text
last 60s:
Google DoH
  41 attempts
  12 timeouts
```

### Transport-specific failure

```text
DoH    DEGRADED
DoT    HEALTHY
Plain  HEALTHY
```

This distinction is incredibly useful.

---

# 10. And then the killer feature: classify the failure

Don't just say:

> Internet broken.

That's too dumb.

Power-DNS can say:

```text
DNS INCIDENT

DoH:
  DEGRADED

DoT:
  HEALTHY

Plain:
  HEALTHY

Likely issue:
  HTTPS DNS transport

Action:
  using DoT fallback
```

Versus:

```text
DNS INCIDENT

DoH:
  DOWN

DoT:
  DOWN

Plain:
  DOWN

Likely issue:
  upstream connectivity failure
```

Versus:

```text
DNS INCIDENT

Google:
  DEGRADED

Cloudflare:
  HEALTHY

Likely issue:
  provider-specific degradation
```

That is genuinely useful network intelligence.

---

# 11. But we need to be careful with NXDOMAIN

This one is subtle.

A huge NXDOMAIN spike doesn't necessarily mean upstream failure.

It could mean:

```text
someone mistyped a bunch of domains
```

or:

```text
an application is broken
```

or:

```text
a domain really disappeared
```

So I'd classify responses separately:

```text
transport failure
timeout
connection failure
HTTP failure
DNS protocol failure
SERVFAIL
REFUSED
NXDOMAIN
NOERROR
```

Then incident detection can reason over **different classes**.

For example:

```text
SERVFAIL ↑ 900%
NXDOMAIN → normal
transport errors ↑ 800%
```

is much stronger evidence of infrastructure trouble than:

```text
NXDOMAIN ↑ 900%
```

---

# 12. This leads directly into network diagnosis

Imagine Grafana eventually showing:

```text
┌─────────────────────────────────────────────┐
│             NETWORK HEALTH                  │
│                                             │
│              DEGRADED                      │
│                                             │
│  DNS availability       99.1%              │
│  Median latency         143ms               │
│  Upstream failures      4.8%                │
│                                             │
│  Google DoH             ● DEGRADED          │
│  Cloudflare DoH         ● DOWN              │
│  Google DoT             ● HEALTHY          │
│  Cloudflare DoT         ● HEALTHY          │
│  Plain DNS              ● HEALTHY          │
│                                             │
│  Active strategy:                           │
│      DoT → DoH → Plain                     │
└─────────────────────────────────────────────┘
```

That's not just a DNS dashboard anymore.

It's a **network health dashboard**.

---

# 13. And only then: per-network profiles

This should come **after** the health engine.

Because now the data already exists.

You can persist something like:

```text
network profile
    ↓
upstream observations
    ↓
learned ranking
```

But don't identify networks using SSID alone.

SSID is not necessarily unique.

I'd use a local network fingerprint such as:

```text
interface
gateway
DNS environment
network characteristics
```

without sending any of this anywhere.

Then:

```text
profile-home
profile-university
profile-cafe
```

could each have independent learned state.

---

# 14. The beautiful part: no new external dependencies

This is why I like this direction for **your** codebase.

You've already deliberately moved away from the old eBPF idea and toward userspace operational metrics; the metrics package explicitly describes Prometheus counters, gauges and latency histograms as the intended observability mechanism.

So we're not bolting some giant monitoring system onto Power-DNS.

We're extending what is already there:

```text
                 existing
                    │
        ┌───────────┼───────────┐
        ↓           ↓           ↓
      cache      upstream     resolver
        │           │           │
        └───────────┼───────────┘
                    ↓
                 metrics
                    │
                    ↓
              health engine
                    │
             ┌──────┴──────┐
             ↓             ↓
        adaptive        incidents
        routing         detection
```

---

# 15. I'd make the implementation roadmap very concrete

### Milestone 1 — Upstream observation

Modify `internal/upstream` / resolver metrics.

Add:

```text
success
failure
timeout
error type
```

per endpoint.

No behavior change.

**Goal:** prove the measurements.

---

### Milestone 2 — Health state

Add:

```text
internal/upstream/health/
```

with:

```go
RecordSuccess(endpoint, latency)
RecordFailure(endpoint, error)
State(endpoint)
Score(endpoint)
```

States:

```text
healthy
degraded
unhealthy
probing
```

Unit-test the state machine heavily.

---

### Milestone 3 — Endpoint selection

Change:

```text
configured list
```

into:

```text
configured list
       ↓
health-aware selector
       ↓
best endpoint
```

Still preserve configured transport ordering.

Example:

```text
DoH:
  Google      ← selected
  Cloudflare

DoT:
  Cloudflare
  Google
```

---

### Milestone 4 — Grafana

Add panels:

```text
Upstream Health
Upstream Latency
Upstream Failure Rate
Endpoint Availability
Current Endpoint
Health State
```

And especially:

```text
configured route
        vs
actual route
```

That will be fucking satisfying to watch.

---

### Milestone 5 — Adaptive transport failover

Now permit:

```text
DoH degraded
      ↓
DoT becomes preferred
```

with hysteresis so it doesn't flap.

Something like:

```text
degrade threshold: 3 consecutive failures
recovery threshold: 5 successes
cooldown: 30s
```

The exact values should ultimately come from testing.

---

### Milestone 6 — Incident engine

Add:

```text
internal/health/incidents.go
```

producing classifications such as:

```text
provider_degradation
transport_degradation
upstream_unavailable
dns_error_spike
latency_degradation
```

---

### Milestone 7 — Network profiles

Persist the learned state.

Then:

```text
Home
  Google DoH → excellent

University
  Cloudflare DoH → excellent

Network C
  DoH → terrible
  DoT → excellent
```

and Power-DNS automatically starts with the learned ranking.

---

# One architectural thing I would **not** do

I would **not** turn this into a giant autonomous AI DNS daemon.

No:

> "AI predicts DNS outages."

😂

Fuck that.

The beauty is that the data is deterministic and explainable.

Power-DNS should be able to tell you exactly:

```text
Cloudflare DoH:
  27 requests
  8 failures
  EWMA latency 2.1s

Google DoH:
  31 requests
  0 failures
  EWMA latency 137ms

Decision:
  Google DoH preferred
```

That's **much more powerful** than some black-box "network score: 0.73."

---

## And there's a deeper idea here

The original Power-DNS architecture was basically:

> **Don't assume the network behaves correctly. Build fallbacks.**

The next evolution is:

> **Don't assume the configured fallback is optimal. Measure reality and adapt.**

And then:

> **Don't just adapt silently. Explain what the network is doing.**

That's a really coherent evolution of the project.

You're effectively turning:

```text
DNS resolver
```

into:

```text
DNS resolver
      +
adaptive routing
      +
network health monitor
      +
network diagnostic instrument
```

**without changing the fundamental character of Power-DNS.**

And the repo is already unusually well positioned for it because the resolver has explicit strategy boundaries, the upstream transports are isolated, and the metrics system already distinguishes the paths.

I'd build **Milestone 1 first and resist touching routing until we have a few days of real measurements**. That's also the fun part: once the telemetry exists, you can sit there watching Power-DNS discover that the network you're actually on behaves completely differently from what your static config assumed.
