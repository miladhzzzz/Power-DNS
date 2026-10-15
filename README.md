# Power-DNS

A local DNS resolver and optional remote relay for networks that interfere with DNS — especially where cleartext DNS is poisoned and public DoH/DoT endpoints are blocked or throttled.

```
device ──UDP/TCP DNS──► power-dns client ──DoH and/or DoT──► power-dns relay ──DoH/DoT/plain──► real resolvers
                              │
                              ├── local records (authoritative overrides)
                              ├── answer cache (TTL, prefetch, SWR)
                              ├── poison filter (ban 10.10.34.0/24 on plain DNS)
                              └── upstream health (per-endpoint EWMA + adaptive order)
```

One binary, three modes (`mode` in config):

| Mode | Role |
|------|------|
| `client` | Local DNS listener + full resolution chain |
| `relay` | Public DoH (+ optional DoT) that resolves against real upstreams |
| `both` | Client and relay in one process (dev / single box) |

---

## Why it exists

1. **Cleartext DNS is poisoned.** On networks like Iran’s GFI, blocked names return private addresses in `10.10.34.0/24` (`.34` / `.35` / `.36`). Those answers are black holes outside the national network and must never be cached.
2. **Encrypted DNS helps**, but known public DoH endpoints are often blocked too — so you need a **relay** on a host with open DNS, reached over whatever transport still works (DoH, DoT, or both).
3. **Tunnels drop.** When a VPN/VLESS path fails, traffic can fall to plain DNS and every popular domain gets poisoned in seconds. Power-DNS rejects those answers and will not store them.
4. **Upstreams are not equal.** One DoH provider may be fine while another is degraded. Power-DNS tracks each configured server independently and can prefer healthier paths.

---

## Quick start

```bash
go build -o power-dns ./cmd/power-dns
cp config.example.toml config.toml
# edit mode, listen addresses, relay URL / upstreams
./power-dns -config config.toml
```

Docker (relay + client wired together):

```bash
docker compose up -d --build
```

Point devices at the client listen address (default `127.0.0.1:5335`, or `0.0.0.0:5335` on a LAN host).

### Minimal client

```toml
mode = "client"

[dns_server]
listen_addr = "0.0.0.0:5335"

[relay]
url = "https://your-relay.example/dns-query"  # DoH
dot_addr = "your-relay.example:853"           # DoT; tried if DoH fails
auth_token = ""                               # must match relay if set

[upstream]
doh_servers = ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"]
dot_servers = ["1.1.1.1:853", "8.8.8.8:853"]
plain_servers = ["1.1.1.1:53", "8.8.8.8:53"]

[resolution]
order = ["records", "cache", "relay", "doh", "dot", "plain"]
adaptive = false   # set true to prefer healthier transports within the chain

[security]
banned_answer_cidrs = ["10.10.34.0/24"]
```

### Minimal relay

```toml
mode = "relay"

[api]
listen_addr = "0.0.0.0:8000"
relay_path = "/dns-query"

[api.relay_dot]
listen_addr = "0.0.0.0:853"
cert_file = "/etc/letsencrypt/live/your-domain/fullchain.pem"
key_file = "/etc/letsencrypt/live/your-domain/privkey.pem"

[security]
relay_auth_token = "change-me"
```

Put the HTTP (DoH) side behind Caddy / Traefik / nginx for TLS. DoT terminates TLS itself (raw TCP+TLS, not HTTP).

---

## Feature map

| Area | What you get |
|------|----------------|
| **Client DNS** | UDP+TCP listener; optional local DoT (`[dns_server.dot]`) for LAN devices |
| **Relay** | RFC 8484 DoH + optional RFC 7858 DoT; domain allow-list; per-IP rate limit; DoH bearer auth |
| **Resolution chain** | Configurable order: records → cache → relay → doh → dot → plain |
| **Adaptive routing** | Opt-in: reorder upstream transports by measured health; within each transport, prefer best server |
| **Upstream health** | Passive EWMA + four-state machine per configured server; no synthetic probes |
| **Incidents** | Classified conditions from health data (provider/transport degradation, etc.) |
| **Poison filter** | Ban list of answer CIDRs on plain DNS; never cached |
| **Local records** | JSON-backed A/AAAA/CNAME/TXT overrides + REST API |
| **Cache** | TTL clamp, LRU bound, optional persistence, prefetch, stale-while-revalidate |
| **Coalescing** | Concurrent identical queries share one upstream round-trip (client + relay) |
| **Admin API** | Cache flush/refresh, status |
| **Metrics** | Prometheus text; can be fully disabled |
| **Grafana** | Resolver/cache dashboard + Upstream Health dashboard |
| **Hot-reload** | Edit config on disk (or SIGHUP); most tunables apply live |

---

## Resolution chain

Default order (`resolution.order`):

1. **records** — local authoritative overrides  
2. **cache** — TTL-aware answer cache  
3. **relay** — your Power-DNS relay (DoH, then DoT if configured)  
4. **doh** — direct public DoH  
5. **dot** — direct public DoT  
6. **plain** — classic UDP/53 (last resort; poison-filtered)

The first strategy that returns a usable answer wins.

**Request coalescing** (always on): concurrent queries for the same name/type(/strategy) share one in-flight upstream call. Tracked as `powerdns_upstream_calls_total` vs `powerdns_upstream_coalesced_total` (and the relay equivalents).

### Adaptive transport failover (`resolution.adaptive`)

When `adaptive = true` (default `false`):

- Upstream strategies (`relay` / `doh` / `dot` / `plain`) are reordered by aggregate path health.
- **records** and **cache** keep their configured positions.
- Encrypted paths are never ranked below plain solely because plain is faster; plain only rises when encrypted paths are unhealthy.
- Hysteresis lives in the per-endpoint state machine (consecutive failures → degraded → unhealthy, cooldown, then probing on the next real query).

Within a single transport, servers are always tried in health-preferred order (fastest healthy first). Every configured server is still tried on failure — nothing is dropped from the list.

---

## Upstream health tracking

Each configured DoH URL, DoT `host:port`, and plain `host:port` is an independent **endpoint**.

For every real attempt Power-DNS records:

- success / failure  
- latency → **EWMA** (α = 0.2)  
- state: `healthy` → `degraded` → `unhealthy` → `probing` → back  

No synthetic probe traffic: the next real query is the probe after cooldown.

```bash
curl localhost:8000/api/v1/health/upstreams
```

Example shape:

```json
[
  {
    "path": "doh",
    "endpoint": "https://dns.google/dns-query",
    "state": "healthy",
    "score": 2870.5,
    "ewma_latency_ms": 129.5,
    "requests": 1204,
    "successes": 1198,
    "failures": 6
  }
]
```

Prometheus series (also on `/metrics`):

| Metric | Labels |
|--------|--------|
| `powerdns_upstream_endpoint_requests_total` | `path`, `endpoint` |
| `powerdns_upstream_endpoint_failures_total` | `path`, `endpoint` |
| `powerdns_upstream_endpoint_latency_ewma_ms` | `path`, `endpoint` |
| `powerdns_upstream_endpoint_state` | `path`, `endpoint`, `state` |

---

## Incident engine

Passive classification of health snapshots (observation only — does not change routing by itself):

| Kind | Meaning |
|------|---------|
| `provider_degradation` | One endpoint bad while peers on the same transport stay healthy |
| `transport_degradation` | All endpoints on a transport are degraded or worse |
| `upstream_unavailable` | All endpoints on a transport are unhealthy |
| `latency_degradation` | Endpoint EWMA is elevated vs peers |
| `dns_error_spike` | High failure ratio on an endpoint |

```bash
curl localhost:8000/api/v1/health/incidents
```

---

## Poison filter (answer ban list)

Classic GFI injection only works on **plain** DNS (cleartext query name).

Power-DNS:

- Rejects plain-DNS answers whose A/AAAA fall in `security.banned_answer_cidrs` (default `10.10.34.0/24`)
- Tries the next plain server; records a failure for health tracking
- **Never stores** banned answers in the cache (resolver-level second check)
- Does **not** filter DoH/DoT responses

```text
powerdns_poisoned_answers_total{path="plain"}
```

If a tunnel drops and traffic hits plain DNS, this counter should rise while the cache stays clean. Flush a previously polluted cache with the admin API.

The ban-list structure is shared infrastructure for future ad-block / bad-domain lists.

---

## Local records

JSON-backed overrides, checked before cache and upstream. Types: A, AAAA, CNAME, TXT.

```bash
# Add
curl -X POST localhost:8000/api/v1/records \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"grafana.internal","type":"A","value":"10.0.0.5","ttl":300}'

# List
curl localhost:8000/api/v1/records

# Delete (optional value= limits to one RDATA)
curl -X DELETE 'localhost:8000/api/v1/records?name=grafana.internal&type=A'
```

Auth is optional; set `security.admin_auth_token` to require a bearer token on records and admin APIs.

---

## Management API

Mounted under `api.admin_path_prefix` (default `/api/v1/admin`). Empty prefix disables these endpoints. Same bearer token as records when configured.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/status` | Feature flags + live settings (mode, resolution, upstreams, security, health counts, cache) |
| `GET` | `/cache` | Cache entries / capacity |
| `POST` | `/cache/flush` | Clear all, or `?name=` / `?name=&type=` |
| `POST` | `/cache/refresh` | Force upstream re-resolve + store (`?name=&type=`) |

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8000/api/v1/admin/cache/flush

curl -X POST -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8000/api/v1/admin/cache/refresh?name=example.com&type=A'
```

Other always-on HTTP routes on the API port:

| Path | Purpose |
|------|---------|
| `GET /healthz` | Liveness |
| `GET /metrics` | Prometheus exposition (404 if metrics disabled) |
| `GET /api/v1/health/upstreams` | Per-endpoint health JSON |
| `GET /api/v1/health/incidents` | Active incident JSON |
| relay path (default `/dns-query`) | RFC 8484 DoH (relay/both mode) |

---

## Cache

| Setting | Behaviour |
|---------|-----------|
| `cache.enabled` | Master switch (restart to change) |
| `max_entries` | LRU eviction bound |
| `min_ttl_seconds` / `max_ttl_seconds` | Clamp upstream TTLs |
| `negative_ttl_seconds` | Cache NXDOMAIN / failures briefly |
| `persist_path` | Periodic snapshot to disk |
| `stale_while_revalidate_seconds` | Serve recently expired answers while refreshing (0 = off) |
| `[cache.prefetch]` | Background refresh of popular, soon-to-expire entries (off by default) |

Prefetch and SWR trade a little upstream load for lower tail latency. Coalescing of in-flight refreshes and a short cooldown prevent hammering a dead upstream.

---

## Metrics & Grafana

`GET /metrics` — Prometheus text format.

Disable all instrumentation with:

```toml
[metrics]
enabled = false
```

No registry is created; `/metrics` returns 404. Requires process restart to toggle.

### Core series

| Metric | Meaning |
|--------|---------|
| `powerdns_queries_total{strategy}` | Which strategy answered (or `failed`) |
| `powerdns_cache_hits_total` | Fresh cache hits |
| `powerdns_cache_stale_hits_total` | SWR hits |
| `powerdns_cache_misses_total{reason}` | `not_found` / `expired` / `disabled` |
| `powerdns_cache_effective_hit_rate` | (hits + stale) / total |
| `powerdns_cache_entries` / `capacity` | Occupancy |
| `powerdns_upstream_latency_ms{path}` | Histogram per transport |
| `powerdns_upstream_calls_total` / `coalesced_total` | Coalescing |
| `powerdns_relay_*` | Relay-side latency and coalescing |
| `powerdns_cache_prefetch_*` | Prefetch outcomes / skips / protected hits |
| `powerdns_poisoned_answers_total{path}` | Banned answers rejected |
| `powerdns_upstream_endpoint_*` | Per-server health (see above) |
| `powerdns_uptime_seconds` | Process age |

### Dashboards

Under `monitoring/grafana/provisioning/dashboards/`:

- **Power-DNS — Resolver & Cache** — hit rates, coalescing, prefetch, path latency  
- **Power-DNS — Upstream Health** — endpoint state, EWMA, failure rates, strategy vs path (“configured vs actual route”), poison rejects  

```bash
docker compose -f docker-compose.monitoring.yml up -d
# Grafana :3000  (default admin/admin — change it)
# Prometheus scrapes power-dns:8000/metrics
```

---

## Security

| Setting | Effect |
|---------|--------|
| `security.relay_auth_token` | Bearer required on relay **DoH** (DoT has no HTTP header; restrict DoT at the firewall or with mTLS) |
| `security.admin_auth_token` | Bearer on records + admin APIs |
| `security.allowed_domains` | Relay only resolves these suffixes (empty = all) |
| `security.relay_rate_limit_per_minute` | Per-source-IP cap on the relay (0 = off) |
| `security.banned_answer_cidrs` | Answer IPs rejected on plain DNS and never cached |

---

## Config hot-reload

The process watches the config file (mtime/size, ~1s) and reloads on change. `SIGHUP` also triggers a reload.

**Applies live (no restart):**

- `log.level`
- Cache TTL / SWR / prefetch runtime options
- Upstream server lists and timeouts
- Relay client URL / DoT / token / timeout
- `resolution.order`, `resolution.adaptive`
- Security tokens, allow-list, rate limit, banned CIDRs

**Requires restart:**

- `mode`
- DNS / API / DoT listen addresses and certificates
- `api.admin_path_prefix`, path prefixes
- `metrics.enabled`
- `cache.enabled`, `max_entries`, `persist_path`
- `records.*` (store path / enable)
- `log.format`

In-memory cache entries are kept across live reloads.

Every field is documented in [`config.example.toml`](./config.example.toml).  
Design rationale and milestone history: [`Design-improvements.md`](./Design-improvements.md), [`CHANGES.md`](./CHANGES.md).

---

## Logging

```toml
[log]
level = "info"    # debug | info | warn | error
format = "text"   # text | json
```

At `debug`, each query logs origin, strategy tried, and outcome. At `info` and above, only lifecycle and genuine failures are logged.

---

## Development

```bash
make build   # go build
make test    # go test ./...
make vet     # go vet ./...
```

Package layout:

```
cmd/power-dns/          main, config watch, wiring
internal/api/           HTTP: healthz, metrics, records, admin, health APIs, DoH mount
internal/cache/         answer cache, prefetch, SWR
internal/config/        TOML load, validate, reload plan
internal/dnsserver/     client-facing UDP/TCP (+ optional DoT)
internal/filter/        answer ban list (CIDRs)
internal/metrics/       Prometheus registry
internal/records/       local overrides store
internal/relay/         DoH/DoT server + client
internal/resolver/      resolution chain + adaptive order
internal/upstream/      DoH/DoT/plain clients + Chain
internal/upstream/health/  Tracker, Order, incidents
internal/wire/          DNS message pack/unpack for DoH
monitoring/             Prometheus + Grafana provisioning
```

---

## License

MIT. See [LICENSE](./LICENSE).
