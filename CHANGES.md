# What changed in v2, and why

v1's [README](https://github.com/miladhzzzz/power-dns) promised a lot:
DoH relaying, caching, custom-record management with hosts-file integration,
Kubernetes/CoreDNS integration, eBPF packet monitoring and dynamic routing,
and failover. Reading the actual code, most of that was either partially
built, silently broken, or not implemented at all (`internal/k8s` and
`internal/ebpf` were empty packages). v2 is a rewrite that keeps the goal --
give people on DoH-restricted networks a working relay -- and either
properly implements or deliberately drops each promise, explained below.

## Config hot-reload (edit the file, no restart)

Tuning SWR, prefetch, upstreams, or log level used to require killing the
process and losing in-memory cache state (unless persistence was enabled).
That made the new age histogram and SWR window experiments painful.

- `cmd/power-dns` watches `config.toml` (mtime + size, every second) and
  reloads automatically when the file changes. SIGHUP still triggers a
  reload as a manual fallback.
- `config.PlanReload` classifies each diff as **hot-applicable** or
  **restart-required**. Safe fields are applied live; listen addresses,
  `mode`, enabling/disabling the cache, and similar structural settings are
  logged as warnings and left alone until the next process start.
- Hot-applicable today:
  - `log.level` (via `slog.LevelVar`)
  - `cache.min_ttl_seconds` / `max_ttl_seconds` / `negative_ttl_seconds`
  - `cache.stale_while_revalidate_seconds`
  - `cache.prefetch.*`
  - `upstream.*` (servers + timeout)
  - `relay.url` / `dot_addr` / `auth_token` / timeout
  - `resolution.order`
  - `security.*` (tokens, allow-list, rate limit)
- Cache entries are **not** dropped on reload; only runtime options change
  (`cache.UpdateRuntime`). Resolver upstream clients and relay security
  settings swap under locks so in-flight queries finish on the old config.

## Prefetch effectiveness: `powerdns_cache_prefetch_protected_hits_total`

SWR has always been easy to measure (`stale_hits_total`). Prefetch was not:
a successful background refresh only helps a *later* client lookup, which
looked like an ordinary fresh hit.

- Cache entries remember whether their current payload was last filled by a
  successful prefetch (`entry.fromPrefetch`).
- Each **fresh** hit on such an entry increments
  `powerdns_cache_prefetch_protected_hits_total` (in addition to
  `powerdns_cache_hits_total`).
- Client-driven `Set` and stale-while-revalidate refreshes clear the flag,
  so only prefetch-sourced fills attribute hits.
- PromQL parallels SWR:

  ```promql
  # Share of fresh hits that rode on a prior prefetch
  100 * powerdns_cache_prefetch_protected_hits_total
    / clamp_min(powerdns_cache_hits_total, 1)

  # Hits gained per successful prefetch
  powerdns_cache_prefetch_protected_hits_total
    / clamp_min(sum(powerdns_cache_prefetch_total{result="success"}), 1)
  ```

## Data-driven stale-window tuning, and DoH connection reuse

- New `powerdns_cache_expired_entry_age_seconds` histogram: every time a
  cache lookup finds an entry already past its TTL -- whether
  stale-while-revalidate ends up serving it or it's a genuine miss --
  `internal/cache.Cache.Get` records how many seconds past expiry it was.
  It's recorded before the stale/miss decision is made, so the
  distribution is unbiased by whatever `stale_while_revalidate_seconds` is
  currently set to: it directly answers "what fraction of repeat queries
  for an expired entry would a given window actually catch," turning
  window tuning into reading a histogram instead of guessing.
- `internal/upstream.NewDoHClient` now configures its `http.Transport`
  explicitly (`MaxIdleConnsPerHost: 16`, `ForceAttemptHTTP2: true`) instead
  of relying on Go's zero-value default, which caps
  `MaxIdleConnsPerHost` at 2. Under any real concurrency, that default
  meant connections to the same DoH provider were closed and redialed --
  a full TLS handshake -- far more often than necessary. Verified with a
  test asserting 10 sequential queries open at most 2 underlying TCP
  connections, not 10.

## DoT (DNS-over-TLS) sits alongside DoH

v1 had no transport but its own bespoke JSON-over-HTTP protocol, and the
initial v2 rewrite added a spec-compliant DoH relay but still only one
transport for the client<->relay link. Since different networks block
different things -- some block HTTPS-based DoH, some block TLS-on-853 DoT,
rarely both -- v2 now speaks both:

- `internal/relay.DoTServer` runs an [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858)
  DNS-over-TLS listener alongside the existing DoH `Server`, sharing the
  same allow-list, rate limiter, and upstream resolution via a common
  `resolve()` helper -- so both transports enforce identical policy. It
  needs its own certificate (DoT is raw TCP+TLS, not HTTP, so it generally
  can't be terminated by the same reverse proxy fronting the DoH endpoint).
- `internal/relay.Client` (what the client uses to reach its relay) now
  tries DoH first and falls back to DoT if configured, so a blocked
  transport doesn't take the whole client<->relay link down.
- `internal/upstream.DoTClient` adds direct DoT resolution (bypassing the
  relay entirely) as a fourth fallback strategy, alongside records, cache,
  relay, and DoH -- `internal/upstream.Chain` now tries DoH, then DoT, then
  plain DNS when resolving real queries.
- `internal/dnsserver` can also expose the *client's* local resolver over
  DoT (`[dns_server.dot]`), for LAN devices that speak DoT natively, in
  addition to the existing plain UDP/TCP listener.

One limitation worth calling out: the DoH endpoint's bearer-token auth
(`security.relay_auth_token`) has no DoT equivalent, since DoT is raw TLS
with no header to carry it in. If you need to restrict who can use your
relay's DoT endpoint, do it at the network layer (firewall by source IP) or
require mutual TLS -- `internal/relay/dotserver.go`'s doc comment has
details. The domain allow-list and rate limiter both still apply to DoT,
keyed by the connecting IP.

## Debug-level tracing: origin and resolution path, cache hit/miss metrics

Once DoH and DoT were both in place, tracing *why* a given query resolved
the way it did -- which strategy answered it, for which client, and whether
the cache actually helped -- needed its own logging, separate from the
Info-level lifecycle/failure logs already in place:

- `resolver.Resolve` now takes an `origin` (the querying client's address)
  and logs, at Debug level only, every strategy it tries for a query, why a
  strategy was skipped or failed, and which one ultimately answered (the
  `route` field) with how long the whole resolution took. At Info level and
  above, none of this appears -- only service lifecycle events and genuine
  failures do, so normal operation doesn't get a log line per query.
- The relay's `Server.resolve` (shared by both the DoH and DoT endpoints)
  logs the same shape at Debug level: origin, transport (`doh`/`dot`),
  qname/qtype, and duration for every query it resolves; failures still log
  at Warn since those indicate a real problem regardless of log level.
- `internal/metrics` gained two dedicated counters,
  `powerdns_cache_hits_total` and `powerdns_cache_misses_total`, alongside
  the existing per-strategy `powerdns_queries_total`. These increment on
  every cache lookup the "cache" strategy actually performs, independent of
  which strategy ultimately answers the query -- so they reflect real cache
  effectiveness even when, say, local records end up answering instead.

## An unconfigured relay is a valid, disabled state -- not a startup error

Previously, running the client with both `relay.url` and `relay.dot_addr`
empty caused `Config.Validate` to return an error, which `cmd/power-dns`
treats as fatal (the process refuses to start). That's backwards: an
unconfigured relay is a perfectly normal way to run Power-DNS as a plain
DoH/DoT/plain-DNS forwarder with no relay hop at all -- it shouldn't require
`config.toml` to lie about a relay it doesn't have.

`Config.Validate` no longer errors on this. A new `Config.RelayDisabled()`
helper reports whether the relay is unconfigured; `cmd/power-dns` uses it to
skip constructing a `relay.Client` and logs one Info-level line
("relay is disabled ... queries will use doh/dot/plain fallback directly")
instead. `resolver.Resolve` also skips the `relay` strategy silently (no log
line at all, since it's an intentionally disabled feature, not a failure)
whenever `RelayClient` is nil, rather than logging a "strategy failed" line
on every single query.

## Stale-while-revalidate

Prefetching (added earlier) refreshes a popular entry *before* it expires,
but says nothing about what happens to an entry that expires anyway --
which, for anything below the popularity threshold or just unlucky timing,
was still the normal path: remove the entry, report a miss, force the
caller through a synchronous upstream round trip. Stale-while-revalidate
closes that gap, and unlike prefetching, isn't gated by popularity at all:

- New `cache.stale_while_revalidate_seconds` config field (`0`, disabled,
  by default). When set above 0, `internal/cache.Cache.Get`'s handling of
  an expired entry gets a middle case: if the entry expired no more than
  this many seconds ago, it's still returned immediately -- the caller
  pays zero extra latency -- and a background refresh is triggered via the
  same `RefreshFunc`/in-flight/cooldown machinery prefetching already used.
  An entry older than the window is still a genuine miss, exactly as
  before.
- That machinery was generalized to serve both features: `RefreshFunc` and
  its timeout moved from `PrefetchOptions` up to the top-level
  `cache.Options` (a small breaking change to the package's Go API, not to
  any TOML field), and the in-flight/cooldown maps were renamed from
  `prefetchInFlight`/`prefetchLastTry` to `refreshInFlight`/`refreshLastTry`
  to reflect that they now guard both prefetch and stale-revalidation
  refreshes for the same key -- a hot record already being prefetched
  won't also trigger a redundant stale-revalidation the instant it
  crosses into "expired."
- New metrics: `powerdns_cache_stale_hits_total`,
  `powerdns_cache_stale_revalidations_total`, and
  `powerdns_cache_stale_revalidation_failures_total` -- kept separate from
  the ordinary hit/miss/prefetch counters, since they answer a genuinely
  different question (a stale hit is not a miss, and revalidation is not
  prefetch, even though the underlying refresh call is identical code).
  `powerdns_cache_hit_rate` deliberately still excludes stale hits --
  the new `powerdns_cache_effective_hit_rate` reports
  `(hits + stale hits) / (hits + stale hits + misses)` instead: the more
  meaningful number for "what fraction of queries did the caller
  experience as instant," since a stale hit is indistinguishable from a
  fresh one on the caller's side.
- Verified live against a real (if synthetic) upstream with a 2-second TTL:
  a query at t=0 costs a real upstream call; at t=1s (within TTL) is a
  fresh hit; at t=2.5s (past TTL, within a configured 10s stale window) is
  a stale hit -- still sub-millisecond -- that triggers exactly one
  background revalidation; at t=3.5s is fresh again. The upstream saw
  exactly 2 real calls across 4 queries, and the caller never once waited
  on one after the first.

## Request coalescing extended to the relay itself

The first round of coalescing metrics only covered `internal/resolver`'s
client-side fallback chain. That left exactly the scenario that originally
motivated coalescing -- many clients hitting one relay for the same
freshly-expired domain at once -- uncovered, since `internal/relay.Server`
had no coalescing at all, only latency instrumentation
(`ObserveRelayServerLatency`). This closes that gap:

- `internal/relay.Server` now coalesces concurrent DoH/DoT requests for the
  same (qname, qtype) into a single call to `Upstream.Resolve`, using the
  same hand-rolled in-flight-map pattern as `internal/resolver` (for the
  same reason: precise calls-vs-coalesced partitioning isn't possible with
  `golang.org/x/sync/singleflight`'s shared `shared` flag). Coalescing spans
  both transports -- a DoH request and a DoT request for the same domain
  arriving at the same instant share one upstream resolution.
- New metrics: `powerdns_relay_calls_total`, `powerdns_relay_coalesced_total`,
  and `powerdns_relay_coalesce_rate`, mirroring the client-side
  `powerdns_upstream_*` metrics but unlabeled (relay-side coalescing isn't
  broken out by upstream path, since it coalesces the whole
  `Upstream.Resolve` call, which may itself try doh/dot/plain internally).
- Verified with the same style of concurrency test used for the client
  side: 20 goroutines issuing DoH requests for the same domain against a
  relay backed by a slow fake upstream produce exactly
  `powerdns_relay_calls_total 1` and `powerdns_relay_coalesced_total 19`,
  with every caller's response correctly re-stamped with its own request
  Id.

## Metrics for prefetching and request coalescing

Prefetching and request coalescing (added just above) shipped without any
way to see them actually working -- you could infer their effects
indirectly (lower tail latency, fewer upstream calls) but nothing surfaced
the mechanisms themselves. This closes that gap:

- **Coalescing got `powerdns_upstream_calls_total{path=...}`,
  `powerdns_upstream_coalesced_total{path=...}`, and a computed
  `powerdns_upstream_coalesce_rate{path=...}`.** Getting this right forced a
  design change: `internal/resolver.Resolver` no longer uses
  `golang.org/x/sync/singleflight`. That package reports the same `shared`
  bool to *every* caller in a coalesced group -- including whichever one
  actually executed the call -- so there's no way to tell, from a single
  caller's perspective, "was I the one who made the real network call, or
  did I just ride along." Counting "calls" and "coalesced" as a clean
  partition (so `coalesced / (coalesced + calls)` means what it says)
  needed that distinction. `internal/resolver` now uses a small hand-rolled
  in-flight tracker (`inflightCall`, an `*int64`-keyed map guarded by a
  mutex plus a `sync.WaitGroup` per key) that exposes exactly that:
  precisely one caller executes and increments `..._calls_total`, every
  other caller for the same key waits and increments `..._coalesced_total`.
  Verified with a real concurrency test: 20 goroutines querying the same
  name against a slow fake DoH server produce exactly
  `powerdns_upstream_calls_total{path="doh"} 1` and
  `powerdns_upstream_coalesced_total{path="doh"} 19` -- an exact partition,
  not an approximation.
- **Prefetching got `powerdns_cache_prefetch_total{result="success"|"failure"}`
  and `powerdns_cache_prefetch_skipped_total{reason="in_flight"|"cooldown"}`.**
  The skip-reason counter matters as much as the outcome counter here:
  without it, a prefetch feature that's silently never firing (misconfigured
  threshold/min_hits) and one that's firing constantly (no cooldown
  protection working) look identical from the outside -- both just show
  occasional successes. Now the `cooldown`/`in_flight` skip counts make the
  "protection against refreshing every low-TTL record continuously"
  described when prefetching shipped an observable fact, not an assumption.

## Deeper cache observability, per-path latency, prefetching, and request coalescing

The first cut of cache metrics (`powerdns_cache_hits_total` /
`powerdns_cache_misses_total`) told you *that* something missed, not *why*,
and the only latency histogram was one aggregate number for "the relay,"
with no way to tell whether a slow relay meant a slow DoH leg, a slow DoT
leg, or a slow plain-DNS fallback. Cache misses were also a dead end --
nothing ever refreshed a popular record before it actually expired, and N
concurrent identical queries after an expiry meant N simultaneous upstream
calls. This round of changes addresses all of that:

- **Miss reasons, not just miss counts.** `powerdns_cache_misses_total` is
  now labeled `reason="not_found"|"expired"|"disabled"` --
  `internal/cache.Cache.Get` distinguishes a key that was never cached from
  one that expired in place, and `internal/resolver` records `"disabled"`
  when caching is off entirely (something no `Cache` object exists to
  report on its own). `powerdns_cache_evictions_total{reason="lru"}` is new
  too, separate from ordinary misses, since an entry pushed out to make
  room under `max_entries` is a capacity signal, not a locality one.
- **Cache hit rate and occupancy gauges.** `powerdns_cache_hit_rate` is a
  cumulative `hits / (hits + misses)` convenience gauge (for a
  time-windowed rate, use Prometheus's own `rate()` over the counters
  instead). `powerdns_cache_entries` and `powerdns_cache_capacity` report
  current occupancy against `max_entries` via a callback
  (`metrics.Registry.SetCacheSizeFunc`) rather than the metrics package
  importing the cache package, to keep the dependency pointing one way.
- **Per-path upstream latency.** `powerdns_upstream_latency_ms{path=...}`
  now breaks latency down by `relay`, `doh`, `dot`, and `plain`, both for
  the client's own fallback chain (`internal/resolver`) and for the relay's
  *internal* doh/dot/plain sub-attempts (`internal/upstream.Chain`, which
  the relay uses to resolve real queries). The relay's own end-to-end
  resolution time is now a separate metric,
  `powerdns_relay_server_latency_ms`, so it's never confused with "how long
  did it take a client to reach the relay" (`path="relay"` under the
  upstream histogram).
- **Prefetching** (`[cache.prefetch]`, off by default): `internal/cache`
  now tracks a hit count and last-hit time per entry. Once an entry's
  remaining TTL drops below `threshold_seconds` and it's been hit at least
  `min_hits` times, the next `Get` kicks off a background refresh via a
  `RefreshFunc` callback (wired to `resolver.ResolveUpstreamOnly`) --
  guarded by an in-flight map and a cooldown so a persistently-failing
  upstream isn't hammered once per query during a hot key's last few
  seconds of TTL. A refreshed entry keeps its accumulated hit count rather
  than resetting it, so popularity tracking survives the refresh.
- **Request coalescing.** `internal/resolver.Resolver` now runs every
  network-bound strategy attempt through a `golang.org/x/sync/singleflight`
  group keyed by `(qname, qtype, strategy)`. Concurrent callers share the
  one in-flight upstream round trip, but each still gets back its own
  independent, correctly-ID-stamped `*dns.Msg` (`restampReply` deep-copies
  the shared answer and re-stamps `Id`/`Question` per caller) -- sharing
  the response object itself, Id included, would have broken the DNS
  protocol for every caller but whichever one happened to trigger the
  request. The same coalescing key space is used by prefetch refreshes, so
  a background prefetch and a concurrent real query for the same record
  share one round trip rather than racing each other.
- **Cache key hygiene, confirmed.** The cache key was already exactly
  `FQDN + query type` (see `internal/cache`'s `key` function) and nothing
  else -- no client identity, transport, or request ID folds into it. This
  round added an explicit doc comment on `key` recording that invariant
  deliberately, so it doesn't erode by accident later.

## The core relay protocol was rebuilt

**v1:** the relay spoke a bespoke protocol: the client did an HTTP `GET
/dns/Query/<domain>` (or the standalone `HttpQuery`/`HttpRelay` methods hit
`GET <relayURL><domain>`), and the relay replied with hand-rolled JSON:
```json
{"domain": "example.com", "response": {"answer": [{"Hdr": {...}, "A": "1.2.3.4"}]}}
```
That shape only has a field for `A` records. AAAA, CNAME, MX, TXT, NS -- any
other record type -- had nowhere to go; `localDNSrelay`/`httpDNSrelay` in
`internal/dns/main.go` only ever built `*dns.A` answers. Queries also always
hardcoded `dns.TypeA` when going through `forwardDNSOverHttps`, regardless of
what the client actually asked for. There was no timeout on any HTTP call,
so a hung relay meant a hung DNS query, forever.

**v2:** the relay carries full DNS wire format (what `(*dns.Msg).Pack()`
already produces) over HTTP, exactly as [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)
specifies: GET with a base64url `?dns=` parameter, or POST with
`Content-Type: application/dns-message`. Every record type round-trips
intact because nothing is re-interpreted in the middle. This also means the
relay endpoint is a real, spec-compliant DoH server -- any DoH client
(browsers, `systemd-resolved`, `curl`) can use it, not just this project's
own client. Every relay/DoH/plain call now has an explicit timeout
(`relay.timeout_seconds`, `upstream.timeout_seconds`).

See `internal/wire/`, `internal/relay/`, `internal/upstream/`.

## The cache had no bound, no real TTLs, and a write race

**v1** (`internal/dns/cache.go`): every cached response used a single fixed
24h expiry (`NewCache(24*time.Hour, ...)`) regardless of what TTL the actual
DNS answer carried. There was no size limit -- the map just grows forever.
Worse, `Set`/`Delete` launched `go c.saveToFile()` on every single call:
`saveToFile` takes the same mutex `Set`/`Delete` already released, so under
load you get a pile of goroutines all fighting to serialize the whole cache
to disk on every write, with no ordering guarantee about which write wins.

**v2** (`internal/cache/`): TTL comes from the real answer (clamped to
`min_ttl_seconds`/`max_ttl_seconds`), negative answers (NXDOMAIN/SERVFAIL)
are cached briefly too (`negative_ttl_seconds`), the cache is a bounded
LRU (`max_entries`), and persistence is a periodic snapshot
(`StartPersistLoop`, every 5 minutes plus on shutdown) instead of a
write-amplifying goroutine per mutation.

## The DNS server dropped queries and never stopped cleanly

**v1** (`internal/dns/main.go`, `ServeDNS`): if both the relay and the plain
DNS fallback failed, the handler just `return`ed -- no response was ever
written back to the client, which means the client sits there until its own
timeout instead of getting an immediate SERVFAIL. The server only listened
on UDP (no TCP, needed for large/truncated responses). Shutdown was a bare
`select {}` with no signal handling, so the process could never be stopped
gracefully; a `defer` meant to save the cache and shut the server down could
only ever run if `StartDNSserver` returned, which it structurally never did.

**v2** (`internal/dnsserver/`): `Resolver.Resolve` always returns a message,
falling back to `SERVFAIL` if every strategy fails, so clients get a fast,
correct answer either way. Both UDP and TCP listeners run. `main.go` uses
`signal.NotifyContext` for SIGINT/SIGTERM and shuts every component down via
context cancellation.

## Custom record management and "Kubernetes integration" didn't exist

**v1**'s README promised "custom DNS record management via API endpoints
for adding, deleting, and showing DNS records in the hosts file" and
"integration with Kubernetes (k8s) CoreDNS to resolve local names to
services." Neither existed: there was no hosts-file code anywhere, and
`internal/k8s/client.go` was a one-line empty package.

**v2** actually implements the record-management half: `internal/records/`
is a small JSON-backed CRUD store, exposed over `/api/v1/records`
(GET/POST/DELETE), and checked first by the resolver so local overrides
always win. Rather than embed a bespoke Kubernetes client (which would need
in-cluster credentials and RBAC just to demo), v2 treats this API as the
integration point: anything that can watch Kubernetes Services and make an
HTTP call -- a small controller, a cron job, CoreDNS's own config -- can
push records in. Less code, works outside Kubernetes too, and is testable
without a cluster (see `internal/records/store_test.go`).

## eBPF metrics were replaced with a real, working metrics endpoint

**v1**'s README describes "packet flow monitoring with eBPF," "dynamic
routing methods using eBPF," and "metrics and monitoring capabilities ...
using eBPF" -- but `internal/ebpf` was an empty package; none of this was
built. Kernel-level packet tracing also needs elevated privileges and is
awkward to run portably (containers, non-Linux hosts), for a userspace
HTTP/DNS relay where the actually-useful signal is "which strategy answered
this query and how long did it take," not raw packet flow.

**v2** drops eBPF and exposes real counters and a latency histogram in
standard Prometheus text format at `/metrics`
(`powerdns_queries_total{strategy=...}`, `powerdns_relay_latency_ms`,
`powerdns_uptime_seconds`) -- see `internal/metrics/`. Zero extra
dependencies, zero extra privileges, works anywhere Go runs.

## Configuration was hardcoded; now it's a real config file

**v1** hardcoded the relay URL, the DoH server, the listen port, and the
cache file path directly as package-level `var`s in
`internal/dns/main.go` (including a personal path, `/home/milx/cache.gob`,
and a specific `trycloudflare.com` tunnel URL). `config/config.go` existed
but was an empty package -- `config.toml`/`config.toml.example` were present
in the repo but nothing ever read them. `docker-compose.yml` set a
`PUBLIC_DOH_SERVER` environment variable that, likewise, nothing read.

**v2** (`internal/config/`) loads everything from `config.toml`, with
defaults for anything you omit, and validates the result on startup (e.g.
refusing to start a client with an empty relay URL without at least warning
you why every query will fall through to direct DoH/plain DNS).

## The HTTP API no longer needs Gin, or a network-interface scan

**v1** (`internal/api/server.go`) used Gin + `gin-contrib/cors` for two
routes, and guessed its own bind address by scanning for `eth0`/`eth1`
network interfaces (`getContainerIP`) instead of just binding an address
from config -- which silently falls back to `:8000` on any host where that
guess fails (e.g. anything not named `eth0`/`eth1`, common outside default
Docker networking). It also opened `DNS-HTTP.log` once at `init()` time with
no rotation.

**v2** (`internal/api/`) uses the standard library's `net/http.ServeMux`
(pattern-based routing has been built into Go's stdlib since 1.22), binds
whatever `api.listen_addr` says, and logs through `log/slog`. One fewer
dependency, no interface-scanning heuristics.

## Security: the original was an open, unauthenticated relay

**v1** had no authentication anywhere and no rate limiting -- anyone who
found the relay's tunnel URL could use it as an open DNS proxy indefinitely.

**v2** adds three optional, off-by-default controls: a bearer token for the
relay endpoint (`security.relay_auth_token`), a bearer token for the
records-management API (`security.admin_auth_token`), and a per-source-IP
rate limit on the relay (`security.relay_rate_limit_per_minute`). You can
still run a fully open relay by leaving these blank, but now it's a choice.

## Smaller fixes

- `scripts/relay.sh` had two shell syntax errors (`if! command` and `cd..`,
  both missing a space) that would fail immediately on `bash scripts/relay.sh`.
  v2's version (`set -euo pipefail`, correct syntax) actually runs, and
  prints the resulting DoH URL instead of dumping a raw log file.
- The `Dockerfile` builds with a non-root user and a `HEALTHCHECK` hitting
  `/healthz`, instead of running the server as root with no health signal.
- Dependencies dropped: `gin-gonic/gin`, `gin-contrib/cors`. Kept/added:
  `miekg/dns` (DNS message handling and, via its `tcp-tls` transport, DoT
  client/server support -- no extra dependency needed), `BurntSushi/toml`
  (config parsing, zero transitive dependencies), and
  `golang.org/x/sync/singleflight` (request coalescing -- a single
  well-audited function from the Go team, not a general-purpose framework).
