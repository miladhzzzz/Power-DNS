# Power-DNS v2

Power-DNS relays DNS resolution over an encrypted transport for people on
networks where DNS-over-HTTPS (or DNS-over-TLS) is blocked or throttled. You
run a **relay** somewhere with unrestricted DNS access; your **client** runs
locally and forwards its queries to the relay over DoH and/or DoT --
whichever transport your network doesn't block.

This is a from-scratch v2 of the original project. It keeps the same goal
but replaces most of the implementation. See [CHANGES.md](./CHANGES.md) for
a detailed list of what changed and why -- this file covers what v2 *is* and
how to run it.

## How it works

```
your device --DNS--> power-dns client --DoH and/or DoT--> power-dns relay --DoH/DoT/DNS--> real internet
                            |
                            +-- local records (your own overrides)
                            +-- cache (TTL-aware)
                            +-- direct DoH / DoT / plain DNS (if the relay is down)
```

A single binary plays either role, or both, controlled by `mode` in
`config.toml`:

- **`relay`** -- a spec-compliant [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484)
  DNS-over-HTTPS server, and optionally an [RFC 7858](https://datatracker.ietf.org/doc/html/rfc7858)
  DNS-over-TLS server on the same or a different port. Deploy it somewhere
  with normal internet access, behind whatever TLS-terminating reverse proxy
  you already run (for DoH) and/or with its own certificate (for DoT, since
  DoT is raw TLS, not HTTP, so it can't share an HTTP reverse proxy the same
  way). Because it speaks both protocols exactly to spec, you can also point
  *any* DoH- or DoT-capable client at it directly (a browser, `systemd-resolved`,
  `curl`), not just this project's own client.
- **`client`** -- the resolver you point your devices at. For each query it
  tries, in order: your own local records, its cache, the relay (DoH, then
  DoT, if both are configured), then (if the relay is unreachable over
  either transport) a direct DoH server, a direct DoT server, then plain
  DNS. The order is configurable.
- **`both`** -- runs both roles in one process, for local development or a
  single-box deployment.

Running DoH and DoT side by side matters because they're blocked
independently: a network that blocks HTTPS-based DoH may leave port 853 DoT
alone, and vice versa. If one transport is unreachable, the client
automatically falls back to the other before giving up.

## Quick start

```bash
go build -o power-dns ./cmd/power-dns
cp config.example.toml config.toml
# edit config.toml: set mode, and relay.url / relay.dot_addr if running as a client
./power-dns -config config.toml
```

Or with Docker Compose, which brings up a relay and a client already wired
together (see `docker-compose.yml` and `config/{relay,client}.toml`):

```bash
docker compose up -d --build
```

### Running as a relay

```toml
mode = "relay"
[api]
listen_addr = "0.0.0.0:8000"
relay_path = "/dns-query"

# Optional: also serve DoT on 853, alongside DoH.
[api.relay_dot]
listen_addr = "0.0.0.0:853"
cert_file = "/etc/letsencrypt/live/your-domain/fullchain.pem"
key_file = "/etc/letsencrypt/live/your-domain/privkey.pem"
```

Put the HTTP side behind TLS (Caddy, Traefik, nginx -- whatever you already
use) and give your client `https://your-domain/dns-query` as `relay.url`.
The DoT side terminates its own TLS directly (see `[api.relay_dot]` above),
since DoT is raw TCP+TLS and generally can't be proxied the same way HTTP
can. Set `security.relay_auth_token` if you don't want DoH to be a fully
open relay (DoT has no equivalent -- see the note in
`internal/relay/dotserver.go`).

### Running as a client

```toml
mode = "client"
[dns_server]
listen_addr = "0.0.0.0:5335"
[relay]
url = "https://your-domain/dns-query" # DoH
dot_addr = "your-domain:853"          # DoT; tried if DoH fails
auth_token = "" # must match the relay's relay_auth_token, if set (DoH only)
```

Point your device or router at `<client-host>:5335` as its DNS server.

### Managing local records

The records API is the real implementation of what used to be a promise in
the v1 README ("custom DNS record management ... in the hosts file"):

```bash
# Add an override
curl -X POST localhost:8000/api/v1/records \
  -d '{"name":"grafana.internal","type":"A","value":"10.0.0.5","ttl":300}'

# List everything
curl localhost:8000/api/v1/records

# Delete it
curl -X DELETE 'localhost:8000/api/v1/records?name=grafana.internal&type=A'
```

Records are checked first, before cache or relay, so they always take
priority. This also replaces the never-implemented Kubernetes/CoreDNS
integration: point a small controller (or a shell script, or CoreDNS's own
`forward` config) at this API to sync Service IPs in, instead of embedding a
Kubernetes client in Power-DNS itself.

### Metrics

`GET /metrics` on the API port exposes Prometheus text-format counters
(`powerdns_queries_total{strategy=...}`, `powerdns_relay_latency_ms`,
`powerdns_uptime_seconds`). See [CHANGES.md](./CHANGES.md) for why this
replaces the originally-planned eBPF metrics.

## Configuration reference

See the comments in [`config.example.toml`](./config.example.toml) -- every
field is documented there.

## Development

```bash
make build   # go build
make test    # go test ./...
make vet     # go vet ./...
```

## License

MIT. See [LICENSE](./LICENSE).
