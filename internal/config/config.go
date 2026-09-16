// Package config defines Power-DNS's configuration and how it is loaded.
//
// v1 hardcoded every meaningful value (relay URL, cache path, ports) directly
// in source files, which meant a rebuild was required to point the binary at
// a different relay or upstream. v2 loads everything from a TOML file with
// built-in defaults, so the same binary can run as a relay, a client, or
// both, purely by config.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Mode selects which role(s) this process performs.
type Mode string

const (
	// ModeClient runs the local DNS listener that answers queries for
	// machines on your network, resolving them via records, cache, relay,
	// DoH, DoT, and plain DNS, in that order (see Resolution.Order).
	ModeClient Mode = "client"
	// ModeRelay runs only the public-facing HTTP(S)/DoH endpoint that
	// resolves queries against real upstreams. This is what you deploy
	// somewhere with unrestricted DNS access.
	ModeRelay Mode = "relay"
	// ModeBoth runs client and relay in a single process, useful for local
	// development or a single-box deployment.
	ModeBoth Mode = "both"
)

// Config is the root configuration structure, mirroring config.example.toml.
type Config struct {
	Mode Mode `toml:"mode"`

	Log LogConfig `toml:"log"`

	DNSServer  DNSServerConfig  `toml:"dns_server"`
	API        APIConfig        `toml:"api"`
	Cache      CacheConfig      `toml:"cache"`
	Records    RecordsConfig    `toml:"records"`
	Relay      RelayConfig      `toml:"relay"`
	Upstream   UpstreamConfig   `toml:"upstream"`
	Resolution ResolutionConfig `toml:"resolution"`
	Security   SecurityConfig   `toml:"security"`
}

// LogConfig controls structured logging.
type LogConfig struct {
	Level  string `toml:"level"`  // debug|info|warn|error
	Format string `toml:"format"` // text|json
}

// DNSServerConfig controls the client-facing DNS listener(s).
type DNSServerConfig struct {
	ListenAddr string `toml:"listen_addr"` // UDP+TCP, e.g. "127.0.0.1:5335" or ":53"

	// DoT lets client/both mode also expose a local RFC 7858 DNS-over-TLS
	// listener (e.g. for LAN devices that speak DoT), in addition to the
	// plain UDP/TCP listener above. Empty ListenAddr disables it.
	DoT DoTListenerConfig `toml:"dot"`
}

// DoTListenerConfig configures a single DNS-over-TLS (RFC 7858) listener.
// Used both by the client's optional local DoT listener and the relay's
// DoT endpoint.
type DoTListenerConfig struct {
	ListenAddr string `toml:"listen_addr"` // e.g. "0.0.0.0:853"; empty disables DoT
	CertFile   string `toml:"cert_file"`   // PEM certificate
	KeyFile    string `toml:"key_file"`    // PEM private key
}

// APIConfig controls the HTTP admin/relay API.
type APIConfig struct {
	ListenAddr string `toml:"listen_addr"` // e.g. "127.0.0.1:8000"
	// RelayPath is where the DoH-compatible relay endpoint is mounted when
	// running in relay/both mode. Defaults to "/dns-query" (the RFC 8484
	// convention) so standard DoH clients can point at it directly.
	RelayPath string `toml:"relay_path"`
	// RecordsPathPrefix is where the custom-records CRUD API is mounted.
	RecordsPathPrefix string `toml:"records_path_prefix"`
	// RelayDoT, if ListenAddr is set, also exposes the relay over RFC 7858
	// DNS-over-TLS (conventionally port 853) alongside the DoH endpoint
	// above -- so a network blocking one transport doesn't block the other.
	// Only used in relay/both mode.
	RelayDoT DoTListenerConfig `toml:"relay_dot"`
}

// CacheConfig controls the answer cache.
type CacheConfig struct {
	Enabled bool `toml:"enabled"`
	// MaxEntries bounds memory use; least-recently-used entries are evicted
	// once the cache is full. v1 had no bound at all.
	MaxEntries int `toml:"max_entries"`
	// MinTTLSeconds/MaxTTLSeconds clamp the TTL taken from upstream answers,
	// so a misbehaving upstream can't force us to cache for 0s or forever.
	MinTTLSeconds int `toml:"min_ttl_seconds"`
	MaxTTLSeconds int `toml:"max_ttl_seconds"`
	// NegativeTTLSeconds is how long NXDOMAIN/SERVFAIL answers are cached,
	// to avoid hammering a broken upstream with the same failing query.
	NegativeTTLSeconds int `toml:"negative_ttl_seconds"`
	// PersistPath, if set, is where the cache is periodically snapshotted
	// and reloaded from on startup. Empty disables persistence.
	PersistPath string `toml:"persist_path"`

	// StaleWhileRevalidateSeconds enables stale-while-revalidate when
	// greater than zero (the default, disabled): a lookup for an entry
	// whose TTL has expired, but not more than this many seconds ago, is
	// still served immediately -- with zero extra latency -- while a
	// background refresh brings it up to date. An entry older than that is
	// a genuine miss, resolved synchronously, same as when this is 0.
	// This is a distinct mechanism from [cache.prefetch]: prefetch tries to
	// refresh a popular entry *before* it expires; this instead changes
	// what happens the moment(s) after it already has, for any entry, not
	// just popular ones.
	StaleWhileRevalidateSeconds int `toml:"stale_while_revalidate_seconds"`

	Prefetch PrefetchConfig `toml:"prefetch"`
}

// PrefetchConfig controls background refresh of popular, soon-to-expire
// cache entries so a hot record's TTL never actually reaches zero from a
// caller's point of view. Disabled by default -- it trades a little extra
// upstream load for lower tail latency on hot records, and that's an
// opt-in trade, not a default.
type PrefetchConfig struct {
	Enabled bool `toml:"enabled"`
	// ThresholdSeconds is how much TTL an entry needs left before it's
	// considered "soon to expire" and a candidate for prefetching.
	ThresholdSeconds int `toml:"threshold_seconds"`
	// MinHits is the minimum number of times an entry must have been
	// served from cache before it's considered popular enough to bother
	// prefetching -- this is what keeps a one-off lookup from generating
	// background upstream traffic for a record nobody else wants.
	MinHits uint64 `toml:"min_hits"`
	// TimeoutSeconds bounds each background refresh attempt.
	TimeoutSeconds int `toml:"timeout_seconds"`
}

// RecordsConfig controls the local authoritative overrides store (the v1
// "custom DNS record management" feature, actually implemented in v2).
type RecordsConfig struct {
	Enabled bool   `toml:"enabled"`
	Path    string `toml:"path"` // JSON file the records store persists to
}

// RelayConfig controls how the client talks to its relay. Leaving both URL
// and DoTAddr empty disables the relay entirely (see Config.RelayDisabled)
// -- the client just skips straight to its doh/dot/plain fallbacks. This is
// a normal, supported configuration, not an error.
type RelayConfig struct {
	// URL is the relay's DoH endpoint, e.g. "https://relay.example.com/dns-query".
	// Empty disables DoH specifically; if DoTAddr is also empty, the relay
	// strategy is disabled entirely.
	URL string `toml:"url"`
	// DoTAddr is the relay's DoT endpoint (host:port, e.g.
	// "relay.example.com:853"). If both URL and DoTAddr are set, the
	// client tries DoH first and falls back to DoT -- useful when a
	// network blocks one transport but not the other.
	DoTAddr string `toml:"dot_addr"`
	// TimeoutSeconds bounds every relay call (DoH or DoT); v1 had no
	// timeout at all, so a hung relay meant a hung query forever.
	TimeoutSeconds int `toml:"timeout_seconds"`
	// AuthToken, if set, is sent as a Bearer token on DoH requests to the
	// relay. Configure the same value in [security].relay_auth_token on
	// the relay side. Not applicable to DoT (see DoTServer's doc comment).
	AuthToken string `toml:"auth_token"`
}

// UpstreamConfig controls fallback resolution when the relay is unreachable.
type UpstreamConfig struct {
	// DoHServers are RFC 8484 DoH endpoints tried directly, bypassing the
	// relay. Only useful if DoH itself isn't blocked for this client.
	DoHServers []string `toml:"doh_servers"`
	// DoTServers are RFC 7858 DoT endpoints (host:port, e.g. "1.1.1.1:853")
	// tried directly, bypassing the relay, after DoHServers and before
	// PlainServers.
	DoTServers []string `toml:"dot_servers"`
	// PlainServers are classic UDP/TCP:53 resolvers, used as the last
	// resort so the client still works even if every encrypted path fails.
	PlainServers []string `toml:"plain_servers"`
	// TimeoutSeconds bounds every upstream call.
	TimeoutSeconds int `toml:"timeout_seconds"`
}

// ResolutionConfig controls the order resolution strategies are tried in.
type ResolutionConfig struct {
	// Order is a list drawn from: "records", "cache", "relay", "doh",
	// "dot", "plain". The first strategy to produce an answer wins; later
	// ones are only tried if the earlier ones fail or are disabled.
	Order []string `toml:"order"`
}

// SecurityConfig controls access control for the relay and admin API.
type SecurityConfig struct {
	// RelayAuthToken, if set, requires "Authorization: Bearer <token>" on
	// the relay endpoint. Leave empty to run an open relay.
	RelayAuthToken string `toml:"relay_auth_token"`
	// AdminAuthToken, if set, requires "Authorization: Bearer <token>" on
	// the records-management API.
	AdminAuthToken string `toml:"admin_auth_token"`
	// AllowedDomains, if non-empty, is an allow-list of suffixes the relay
	// will resolve (e.g. "example.com"). Empty means allow everything.
	AllowedDomains []string `toml:"allowed_domains"`
	// RelayRateLimitPerMinute caps requests per source IP on the relay
	// endpoint. 0 disables rate limiting.
	RelayRateLimitPerMinute int `toml:"relay_rate_limit_per_minute"`
}

// Default returns a Config populated with sensible defaults. Load starts
// from this and overlays whatever the TOML file specifies.
func Default() Config {
	return Config{
		Mode: ModeClient,
		Log: LogConfig{
			Level:  "info",
			Format: "text",
		},
		DNSServer: DNSServerConfig{
			ListenAddr: "127.0.0.1:5335",
		},
		API: APIConfig{
			ListenAddr:        "127.0.0.1:8000",
			RelayPath:         "/dns-query",
			RecordsPathPrefix: "/api/v1/records",
		},
		Cache: CacheConfig{
			Enabled:                     true,
			MaxEntries:                  10000,
			MinTTLSeconds:               30,
			MaxTTLSeconds:               3600,
			NegativeTTLSeconds:          30,
			PersistPath:                 "",
			StaleWhileRevalidateSeconds: 0, // disabled by default
			Prefetch: PrefetchConfig{
				Enabled:          false,
				ThresholdSeconds: 30,
				MinHits:          5,
				TimeoutSeconds:   5,
			},
		},
		Records: RecordsConfig{
			Enabled: true,
			Path:    "records.json",
		},
		Relay: RelayConfig{
			URL:            "",
			TimeoutSeconds: 5,
		},
		Upstream: UpstreamConfig{
			DoHServers:     []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"},
			DoTServers:     []string{"1.1.1.1:853", "8.8.8.8:853"},
			PlainServers:   []string{"1.1.1.1:53", "8.8.8.8:53"},
			TimeoutSeconds: 3,
		},
		Resolution: ResolutionConfig{
			Order: []string{"records", "cache", "relay", "doh", "dot", "plain"},
		},
		Security: SecurityConfig{
			RelayRateLimitPerMinute: 600,
		},
	}
}

// Load reads a TOML file at path over top of Default(). If path is empty,
// the defaults are returned as-is (a valid, if minimal, configuration).
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, fmt.Errorf("config file %q not found", path)
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	return cfg, cfg.Validate()
}

// Validate sanity-checks a loaded configuration. An unconfigured relay
// (both Relay.URL and Relay.DoTAddr empty) is a valid, normal
// configuration -- it simply disables the "relay" resolution strategy, and
// the client falls straight through to doh/dot/plain, so Validate does not
// treat it as an error.
func (c Config) Validate() error {
	switch c.Mode {
	case ModeClient, ModeRelay, ModeBoth:
	default:
		return fmt.Errorf("invalid mode %q (want client, relay, or both)", c.Mode)
	}
	for _, step := range c.Resolution.Order {
		switch step {
		case "records", "cache", "relay", "doh", "dot", "plain":
		default:
			return fmt.Errorf("invalid resolution.order entry %q", step)
		}
	}
	return nil
}

// RelayDisabled reports whether the client has no way to reach a relay --
// both Relay.URL and Relay.DoTAddr are empty. Treat this as "the relay
// resolution strategy is disabled", not an error: callers should skip
// constructing a relay client entirely and, if useful, log it once at
// startup.
func (c Config) RelayDisabled() bool {
	return c.Relay.URL == "" && c.Relay.DoTAddr == ""
}

// ReloadPlan describes what a hot-reload of newCfg on top of old can apply
// without restarting the process, and which changes require a full restart.
type ReloadPlan struct {
	// Applied lists human-readable descriptions of settings that will be
	// live-updated.
	Applied []string
	// RestartRequired lists settings that changed but cannot be applied
	// without restarting (listen addresses, mode, enabling/disabling
	// major subsystems, etc.).
	RestartRequired []string
}

// PlanReload compares old with newCfg and reports which differences are
// hot-reloadable versus restart-only. It does not mutate either config.
func PlanReload(old, newCfg Config) ReloadPlan {
	var p ReloadPlan

	// --- Restart-only ---
	if old.Mode != newCfg.Mode {
		p.RestartRequired = append(p.RestartRequired, "mode")
	}
	if old.DNSServer.ListenAddr != newCfg.DNSServer.ListenAddr {
		p.RestartRequired = append(p.RestartRequired, "dns_server.listen_addr")
	}
	if old.DNSServer.DoT != newCfg.DNSServer.DoT {
		p.RestartRequired = append(p.RestartRequired, "dns_server.dot")
	}
	if old.API.ListenAddr != newCfg.API.ListenAddr {
		p.RestartRequired = append(p.RestartRequired, "api.listen_addr")
	}
	if old.API.RelayPath != newCfg.API.RelayPath {
		p.RestartRequired = append(p.RestartRequired, "api.relay_path")
	}
	if old.API.RecordsPathPrefix != newCfg.API.RecordsPathPrefix {
		p.RestartRequired = append(p.RestartRequired, "api.records_path_prefix")
	}
	if old.API.RelayDoT != newCfg.API.RelayDoT {
		p.RestartRequired = append(p.RestartRequired, "api.relay_dot")
	}
	if old.Cache.Enabled != newCfg.Cache.Enabled {
		p.RestartRequired = append(p.RestartRequired, "cache.enabled")
	}
	if old.Cache.MaxEntries != newCfg.Cache.MaxEntries {
		p.RestartRequired = append(p.RestartRequired, "cache.max_entries")
	}
	if old.Cache.PersistPath != newCfg.Cache.PersistPath {
		p.RestartRequired = append(p.RestartRequired, "cache.persist_path")
	}
	if old.Records != newCfg.Records {
		p.RestartRequired = append(p.RestartRequired, "records")
	}
	if old.Log.Format != newCfg.Log.Format {
		p.RestartRequired = append(p.RestartRequired, "log.format")
	}

	// --- Hot-reloadable ---
	if old.Log.Level != newCfg.Log.Level {
		p.Applied = append(p.Applied, "log.level")
	}

	if old.Cache.MinTTLSeconds != newCfg.Cache.MinTTLSeconds {
		p.Applied = append(p.Applied, "cache.min_ttl_seconds")
	}
	if old.Cache.MaxTTLSeconds != newCfg.Cache.MaxTTLSeconds {
		p.Applied = append(p.Applied, "cache.max_ttl_seconds")
	}
	if old.Cache.NegativeTTLSeconds != newCfg.Cache.NegativeTTLSeconds {
		p.Applied = append(p.Applied, "cache.negative_ttl_seconds")
	}
	if old.Cache.StaleWhileRevalidateSeconds != newCfg.Cache.StaleWhileRevalidateSeconds {
		p.Applied = append(p.Applied, "cache.stale_while_revalidate_seconds")
	}
	if old.Cache.Prefetch != newCfg.Cache.Prefetch {
		p.Applied = append(p.Applied, "cache.prefetch")
	}

	if old.Relay != newCfg.Relay {
		p.Applied = append(p.Applied, "relay")
	}
	if !stringSlicesEqual(old.Upstream.DoHServers, newCfg.Upstream.DoHServers) ||
		!stringSlicesEqual(old.Upstream.DoTServers, newCfg.Upstream.DoTServers) ||
		!stringSlicesEqual(old.Upstream.PlainServers, newCfg.Upstream.PlainServers) ||
		old.Upstream.TimeoutSeconds != newCfg.Upstream.TimeoutSeconds {
		p.Applied = append(p.Applied, "upstream")
	}
	if !stringSlicesEqual(old.Resolution.Order, newCfg.Resolution.Order) {
		p.Applied = append(p.Applied, "resolution.order")
	}
	if old.Security.RelayAuthToken != newCfg.Security.RelayAuthToken ||
		old.Security.AdminAuthToken != newCfg.Security.AdminAuthToken ||
		old.Security.RelayRateLimitPerMinute != newCfg.Security.RelayRateLimitPerMinute ||
		!stringSlicesEqual(old.Security.AllowedDomains, newCfg.Security.AllowedDomains) {
		p.Applied = append(p.Applied, "security")
	}

	return p
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
