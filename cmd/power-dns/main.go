// Command power-dns runs a DNS-over-HTTPS relay, a client that uses one, or
// both in a single process, per its config file.
//
// v1's cmd/main.go unconditionally started both the DNS server and the API
// server in every process ("the same codebase can be used for both the DNS
// relay server and the client" per the README, but there was no actual
// switch to run just one). v2 makes the split explicit via config.Mode.
//
// Configuration is hot-reloaded automatically when the config file changes
// on disk (polled every second). SIGHUP still triggers a reload as a
// fallback. Listen addresses and mode require a full restart; cache
// SWR/prefetch, upstreams, resolution order, security tokens, and log
// level apply live — see config.PlanReload.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miladhzzzz/power-dns/internal/api"
	"github.com/miladhzzzz/power-dns/internal/cache"
	"github.com/miladhzzzz/power-dns/internal/config"
	"github.com/miladhzzzz/power-dns/internal/dnsserver"
	"github.com/miladhzzzz/power-dns/internal/filter"
	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/records"
	"github.com/miladhzzzz/power-dns/internal/relay"
	"github.com/miladhzzzz/power-dns/internal/resolver"
	"github.com/miladhzzzz/power-dns/internal/upstream"
	"github.com/miladhzzzz/power-dns/internal/upstream/health"
)

func main() {
	configPath := flag.String("config", "config.toml", "path to config.toml")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "power-dns:", err)
		os.Exit(1)
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(parseLogLevel(cfg.Log.Level))
	logger := newLogger(cfg.Log, levelVar)
	slog.SetDefault(logger)

	if err := run(*configPath, cfg, logger, levelVar); err != nil {
		logger.Error("power-dns exited with error", "error", err)
		os.Exit(1)
	}
}

// app holds process-wide handles that SIGHUP reload mutates.
type app struct {
	path     string
	mu       sync.Mutex
	cfg      config.Config
	logger   *slog.Logger
	levelVar *slog.LevelVar

	reg         *metrics.Registry
	answerCache *cache.Cache
	res         *resolver.Resolver
	relayHandler  *relay.Server
	apiServer     *api.Server
	healthTracker *health.Tracker
	detector      *health.Detector
}

func run(configPath string, cfg config.Config, logger *slog.Logger, levelVar *slog.LevelVar) error {
	var reg *metrics.Registry
	if cfg.Metrics.Enabled {
		reg = metrics.New()
	}

	banList, err := filter.NewBanList(cfg.Security.BannedAnswerCIDRs)
	if err != nil {
		logger.Warn("some banned_answer_cidrs failed to parse", "error", err)
	}
	if banList != nil && !banList.Empty() {
		logger.Info("answer ban list active", "cidrs", cfg.Security.BannedAnswerCIDRs)
	}

	healthTracker := health.NewTracker()
	detector := health.NewDetector(healthTracker)

	var recStore *records.Store
	if cfg.Records.Enabled {
		var err error
		recStore, err = records.Open(cfg.Records.Path)
		if err != nil {
			return fmt.Errorf("opening records store: %w", err)
		}
	}

	// Created early (mostly empty) so cache prefetching can bind its
	// RefreshFunc to res.ResolveUpstreamOnly now; res's other fields are
	// filled in below, well before anything actually calls Refresh.
	res := &resolver.Resolver{}

	var answerCache *cache.Cache
	if cfg.Cache.Enabled {
		answerCache = cache.New(cache.Options{
			MaxEntries:     cfg.Cache.MaxEntries,
			MinTTL:         time.Duration(cfg.Cache.MinTTLSeconds) * time.Second,
			MaxTTL:         time.Duration(cfg.Cache.MaxTTLSeconds) * time.Second,
			NegativeTTL:    time.Duration(cfg.Cache.NegativeTTLSeconds) * time.Second,
			PersistPath:    cfg.Cache.PersistPath,
			Metrics:        reg,
			Refresh:        res.ResolveUpstreamOnly,
			RefreshTimeout: time.Duration(cfg.Cache.Prefetch.TimeoutSeconds) * time.Second,
			Prefetch: cache.PrefetchOptions{
				Enabled:   cfg.Cache.Prefetch.Enabled,
				Threshold: time.Duration(cfg.Cache.Prefetch.ThresholdSeconds) * time.Second,
				MinHits:   cfg.Cache.Prefetch.MinHits,
			},
			StaleMaxAge: time.Duration(cfg.Cache.StaleWhileRevalidateSeconds) * time.Second,
		})
		if reg != nil {
			reg.SetCacheSizeFunc(func() (int, int) { return answerCache.Len(), answerCache.Cap() })
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	runService := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil {
				errCh <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	// Relay-side: an RFC 8484 DoH endpoint (and, if configured, an RFC 7858
	// DoT endpoint) backed by real upstreams. Only started in relay/both
	// mode. Chain.Metrics gives per-sub-path (doh/dot/plain) latency for
	// the relay's own upstream resolution, not just one aggregate number.
	var relayHandler *relay.Server
	if cfg.Mode == config.ModeRelay || cfg.Mode == config.ModeBoth {
		relayHandler = relay.NewServer(
			&upstream.Chain{
				DoH:      newDoHClient(cfg.Upstream.DoHServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second, healthTracker),
				DoT:      newDoTClient(cfg.Upstream.DoTServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second, healthTracker),
				Plain:    newPlainClient(cfg.Upstream.PlainServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second, banList, reg, healthTracker),
				Metrics:  reg,
				Health:   healthTracker,
				Adaptive: cfg.Resolution.Adaptive,
			},
			logger.With("component", "relay"),
			reg,
			cfg.Security.RelayAuthToken,
			cfg.Security.AllowedDomains,
			cfg.Security.RelayRateLimitPerMinute,
		)

		if cfg.API.RelayDoT.ListenAddr != "" {
			dotSrv := relay.NewDoTServer(relayHandler, cfg.API.RelayDoT.CertFile, cfg.API.RelayDoT.KeyFile)
			runService("relay dot server", func(ctx context.Context) error {
				return dotSrv.Run(ctx, cfg.API.RelayDoT.ListenAddr)
			})
		}
	}

	apiServer := api.New(api.Config{
		Addr:              cfg.API.ListenAddr,
		RelayPath:         cfg.API.RelayPath,
		RecordsPathPrefix: cfg.API.RecordsPathPrefix,
		AdminPathPrefix:   cfg.API.AdminPathPrefix,
		AdminAuthToken:    cfg.Security.AdminAuthToken,
	}, logger.With("component", "api"), reg, recStore, answerCache, res, relayHandler)

	apiServer.SetUpstreamHealthFunc(func() []api.UpstreamEndpointHealth {
		snaps := healthTracker.Snapshot()
		out := make([]api.UpstreamEndpointHealth, len(snaps))
		for i, s := range snaps {
			out[i] = api.UpstreamEndpointHealth{
				Path:                 s.Path,
				Endpoint:             s.Endpoint,
				State:                s.State.String(),
				Score:                s.Score,
				EWMALatencyMs:        s.EWMALatencyMs,
				Requests:             s.Requests,
				Successes:            s.Successes,
				Failures:             s.Failures,
				ConsecutiveFailures:  s.ConsecutiveFailures,
				ConsecutiveSuccesses: s.ConsecutiveSuccesses,
			}
		}
		return out
	})
	apiServer.SetIncidentsFunc(func() []api.HealthIncident {
		incs := detector.Evaluate()
		out := make([]api.HealthIncident, len(incs))
		for i, inc := range incs {
			out[i] = api.HealthIncident{
				Kind:     string(inc.Kind),
				Path:     inc.Path,
				Endpoint: inc.Endpoint,
				Message:  inc.Message,
				Since:    inc.Since.In(time.Local).Format(time.RFC3339),
				Severity: inc.Severity,
			}
		}
		return out
	})
	if reg != nil {
		reg.SetUpstreamHealthFunc(func() []metrics.UpstreamEndpointHealth {
			snaps := healthTracker.Snapshot()
			out := make([]metrics.UpstreamEndpointHealth, len(snaps))
			for i, s := range snaps {
				out[i] = metrics.UpstreamEndpointHealth{
					Path:          s.Path,
					Endpoint:      s.Endpoint,
					State:         s.State.String(),
					EWMALatencyMs: s.EWMALatencyMs,
					Requests:      s.Requests,
					Failures:      s.Failures,
				}
			}
			return out
		})
	}

	runService("api server", apiServer.Run)

	// Client-side: the local DNS listener(s), resolving through
	// records -> cache -> relay -> doh -> dot -> plain. Only started in
	// client/both mode.
	if cfg.Mode == config.ModeClient || cfg.Mode == config.ModeBoth {
		var relayClient *relay.Client
		if cfg.RelayDisabled() {
			logger.Info("relay is disabled (relay.url and relay.dot_addr are both empty); queries will use doh/dot/plain fallback directly")
		} else {
			relayClient = relay.NewClient(cfg.Relay.URL, cfg.Relay.DoTAddr, cfg.Relay.AuthToken, time.Duration(cfg.Relay.TimeoutSeconds)*time.Second)
		}

		res.Order = cfg.Resolution.Order
		res.Records = recStore
		res.Cache = answerCache
		res.RelayClient = relayClient
		res.DoH = newDoHClient(cfg.Upstream.DoHServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second, healthTracker)
		res.DoT = newDoTClient(cfg.Upstream.DoTServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second, healthTracker)
		res.Plain = newPlainClient(cfg.Upstream.PlainServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second, banList, reg, healthTracker)
		res.Timeout = time.Duration(cfg.Relay.TimeoutSeconds) * time.Second
		res.Logger = logger.With("component", "resolver")
		res.Metrics = reg
		res.Ban = banList
		res.Health = healthTracker
		res.Adaptive = cfg.Resolution.Adaptive

		dnsSrv := dnsserver.New(
			cfg.DNSServer.ListenAddr,
			dnsserver.DoTConfig{
				Addr:     cfg.DNSServer.DoT.ListenAddr,
				CertFile: cfg.DNSServer.DoT.CertFile,
				KeyFile:  cfg.DNSServer.DoT.KeyFile,
			},
			res,
			logger.With("component", "dns"),
		)
		runService("dns server", dnsSrv.Run)
	}

	if answerCache != nil && cfg.Cache.PersistPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answerCache.StartPersistLoop(5*time.Minute, ctx.Done(), func(err error) {
				logger.Warn("cache persist failed", "error", err)
			})
		}()
	}

	a := &app{
		path:          configPath,
		cfg:           cfg,
		logger:        logger,
		levelVar:      levelVar,
		reg:           reg,
		answerCache:   answerCache,
		res:           res,
		relayHandler:  relayHandler,
		apiServer:     apiServer,
		healthTracker: healthTracker,
		detector:      detector,
	}

	a.apiServer.SetStatusFunc(a.buildStatus)

	// Watch config file for changes and reload automatically. SIGHUP still
	// works as a manual fallback (e.g. if the editor writes in place without
	// updating mtime on some exotic FS).
	go a.watchConfig(ctx)
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				if err := a.reload(); err != nil {
					logger.Error("config reload failed", "error", err)
				}
			}
		}
	}()

	logger.Info("power-dns started", "mode", cfg.Mode, "config", configPath)
	logger.Info("watching config for changes; edit the file to hot-reload (listen addresses and mode still require restart)")

	select {
	case <-ctx.Done():
	case err := <-errCh:
		stop()
		wg.Wait()
		return err
	}
	wg.Wait()
	return nil
}

// watchConfig polls the config file's mtime/size and triggers reload when
// either changes. Polling avoids an extra dependency (fsnotify) and works
// through atomic editor saves (write temp + rename).
func (a *app) watchConfig(ctx context.Context) {
	const interval = time.Second
	var lastMod time.Time
	var lastSize int64
	if st, err := os.Stat(a.path); err == nil {
		lastMod = st.ModTime()
		lastSize = st.Size()
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st, err := os.Stat(a.path)
			if err != nil {
				continue // transient missing file during atomic replace
			}
			if st.ModTime().Equal(lastMod) && st.Size() == lastSize {
				continue
			}
			lastMod = st.ModTime()
			lastSize = st.Size()
			// Brief settle so editors that write then fsync finish first.
			time.Sleep(200 * time.Millisecond)
			if err := a.reload(); err != nil {
				a.logger.Error("config reload failed", "error", err, "path", a.path)
			}
		}
	}
}

// reload loads the config file again and applies every change that does not
// require restarting listeners. Restart-only diffs are logged as warnings.

// buildStatus fills the admin status snapshot from the live config and
// subsystem pointers. Slice fields (server lists, CIDRs, order) share the
// headers currently held in a.cfg — no deep copy. Tokens are never
// returned; only "configured" booleans.
func (a *app) buildStatus() api.StatusSnapshot {
	a.mu.Lock()
	cfg := a.cfg
	reg := a.reg
	c := a.answerCache
	res := a.res
	relayH := a.relayHandler
	ht := a.healthTracker
	det := a.detector
	a.mu.Unlock()

	modeClient := cfg.Mode == config.ModeClient || cfg.Mode == config.ModeBoth
	modeRelay := cfg.Mode == config.ModeRelay || cfg.Mode == config.ModeBoth

	snap := api.StatusSnapshot{
		Status: "ok",
		Mode:   string(cfg.Mode),
		Features: api.StatusFeatures{
			Metrics:   reg != nil,
			Records:   cfg.Records.Enabled,
			Cache:     cfg.Cache.Enabled && c != nil,
			Resolver:  modeClient && res != nil,
			Relay:     modeRelay && relayH != nil,
			RelayDoT:  modeRelay && cfg.API.RelayDoT.ListenAddr != "",
			DNSServer: modeClient && cfg.DNSServer.ListenAddr != "",
			Adaptive:  cfg.Resolution.Adaptive,
			AdminAPI:  cfg.API.AdminPathPrefix != "",
			AdminAuth: cfg.Security.AdminAuthToken != "",
		},
		Log: api.StatusLog{
			Level:  cfg.Log.Level,
			Format: cfg.Log.Format,
		},
		Listen: api.StatusListen{
			API:       cfg.API.ListenAddr,
			DNS:       cfg.DNSServer.ListenAddr,
			DNSDoT:    cfg.DNSServer.DoT.ListenAddr,
			RelayDoT:  cfg.API.RelayDoT.ListenAddr,
			RelayPath: cfg.API.RelayPath,
		},
		Resolution: api.StatusResolution{
			Order:    cfg.Resolution.Order,
			Adaptive: cfg.Resolution.Adaptive,
		},
		Relay: api.StatusRelay{
			Configured:     !cfg.RelayDisabled(),
			URL:            cfg.Relay.URL,
			DoTAddr:        cfg.Relay.DoTAddr,
			TimeoutSeconds: cfg.Relay.TimeoutSeconds,
			AuthConfigured: cfg.Relay.AuthToken != "",
		},
		Upstream: api.StatusUpstream{
			TimeoutSeconds: cfg.Upstream.TimeoutSeconds,
			DoHServers:     cfg.Upstream.DoHServers,
			DoTServers:     cfg.Upstream.DoTServers,
			PlainServers:   cfg.Upstream.PlainServers,
			DoHCount:       len(cfg.Upstream.DoHServers),
			DoTCount:       len(cfg.Upstream.DoTServers),
			PlainCount:     len(cfg.Upstream.PlainServers),
		},
		Security: api.StatusSecurity{
			RelayAuthConfigured:  cfg.Security.RelayAuthToken != "",
			AdminAuthConfigured:  cfg.Security.AdminAuthToken != "",
			AllowedDomains:       cfg.Security.AllowedDomains,
			AllowedDomainsCount:  len(cfg.Security.AllowedDomains),
			RelayRateLimitPerMin: cfg.Security.RelayRateLimitPerMinute,
			BannedAnswerCIDRs:    cfg.Security.BannedAnswerCIDRs,
			BanListActive:        len(cfg.Security.BannedAnswerCIDRs) > 0,
		},
	}

	if cfg.Cache.Enabled {
		sc := &api.StatusCache{
			MinTTLSeconds:               cfg.Cache.MinTTLSeconds,
			MaxTTLSeconds:               cfg.Cache.MaxTTLSeconds,
			NegativeTTLSeconds:          cfg.Cache.NegativeTTLSeconds,
			StaleWhileRevalidateSeconds: cfg.Cache.StaleWhileRevalidateSeconds,
			PersistPath:                 cfg.Cache.PersistPath,
			PrefetchEnabled:             cfg.Cache.Prefetch.Enabled,
			PrefetchThresholdSeconds:    cfg.Cache.Prefetch.ThresholdSeconds,
			PrefetchMinHits:             cfg.Cache.Prefetch.MinHits,
		}
		if c != nil {
			sc.Entries = c.Len()
			sc.Capacity = c.Cap()
		} else {
			sc.Capacity = cfg.Cache.MaxEntries
		}
		snap.Cache = sc
	}

	if cfg.Records.Enabled {
		snap.Records = &api.StatusRecords{Path: cfg.Records.Path}
	}

	if ht != nil {
		snap.Health.EndpointsObserved = ht.EndpointCount()
	}
	if det != nil {
		// Refresh classification then report count (admin endpoint, rare).
		_ = det.Evaluate()
		snap.Health.ActiveIncidents = det.ActiveCount()
	}
	return snap
}

func (a *app) reload() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	newCfg, err := config.Load(a.path)
	if err != nil {
		return err
	}
	plan := config.PlanReload(a.cfg, newCfg)
	if len(plan.Applied) == 0 && len(plan.RestartRequired) == 0 {
		a.logger.Info("config reload: no changes")
		return nil
	}
	if len(plan.RestartRequired) > 0 {
		a.logger.Warn("config reload: some changes require process restart",
			"restart_required", plan.RestartRequired)
	}
	if len(plan.Applied) == 0 {
		return nil
	}

	// Log level
	if a.levelVar != nil {
		a.levelVar.Set(parseLogLevel(newCfg.Log.Level))
	}

	// Cache SWR / prefetch / TTLs
	if a.answerCache != nil {
		a.answerCache.UpdateRuntime(cache.RuntimeOptions{
			MinTTL:         time.Duration(newCfg.Cache.MinTTLSeconds) * time.Second,
			MaxTTL:         time.Duration(newCfg.Cache.MaxTTLSeconds) * time.Second,
			NegativeTTL:    time.Duration(newCfg.Cache.NegativeTTLSeconds) * time.Second,
			RefreshTimeout: time.Duration(newCfg.Cache.Prefetch.TimeoutSeconds) * time.Second,
			StaleMaxAge:    time.Duration(newCfg.Cache.StaleWhileRevalidateSeconds) * time.Second,
			Prefetch: cache.PrefetchOptions{
				Enabled:   newCfg.Cache.Prefetch.Enabled,
				Threshold: time.Duration(newCfg.Cache.Prefetch.ThresholdSeconds) * time.Second,
				MinHits:   newCfg.Cache.Prefetch.MinHits,
			},
		})
	}

	// Resolver: order, upstreams, relay client, timeouts
	if a.res != nil && (a.cfg.Mode == config.ModeClient || a.cfg.Mode == config.ModeBoth) {
		var relayClient *relay.Client
		if !newCfg.RelayDisabled() {
			relayClient = relay.NewClient(
				newCfg.Relay.URL,
				newCfg.Relay.DoTAddr,
				newCfg.Relay.AuthToken,
				time.Duration(newCfg.Relay.TimeoutSeconds)*time.Second,
			)
		}
		timeout := time.Duration(newCfg.Relay.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = time.Duration(newCfg.Upstream.TimeoutSeconds) * time.Second
		}
		newBan, banErr := filter.NewBanList(newCfg.Security.BannedAnswerCIDRs)
		if banErr != nil {
			a.logger.Warn("some banned_answer_cidrs failed to parse on reload", "error", banErr)
		}
		a.res.Ban = newBan
		a.res.ApplyRuntime(resolver.RuntimeConfig{
			Order:       newCfg.Resolution.Order,
			RelayClient: relayClient,
			DoH:         newDoHClient(newCfg.Upstream.DoHServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second, a.healthTracker),
			DoT:         newDoTClient(newCfg.Upstream.DoTServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second, a.healthTracker),
			Plain:       newPlainClient(newCfg.Upstream.PlainServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second, newBan, a.reg, a.healthTracker),
			Timeout:     timeout,
			Adaptive:    newCfg.Resolution.Adaptive,
		})
	}

	// Relay server security + upstream chain
	if a.relayHandler != nil {
		a.relayHandler.ApplySecurity(
			newCfg.Security.RelayAuthToken,
			newCfg.Security.AllowedDomains,
			newCfg.Security.RelayRateLimitPerMinute,
		)
		newBan, _ := filter.NewBanList(newCfg.Security.BannedAnswerCIDRs)
		a.relayHandler.ApplyUpstream(&upstream.Chain{
			DoH:      newDoHClient(newCfg.Upstream.DoHServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second, a.healthTracker),
			DoT:      newDoTClient(newCfg.Upstream.DoTServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second, a.healthTracker),
			Plain:    newPlainClient(newCfg.Upstream.PlainServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second, newBan, a.reg, a.healthTracker),
			Metrics:  a.reg,
			Health:   a.healthTracker,
			Adaptive: newCfg.Resolution.Adaptive,
		})
	}

	// API admin token
	if a.apiServer != nil {
		a.apiServer.ApplyAdminAuth(newCfg.Security.AdminAuthToken)
	}

	a.cfg = newCfg
	a.logger.Info("config reloaded", "applied", plan.Applied)
	return nil
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func newLogger(cfg config.LogConfig, levelVar *slog.LevelVar) *slog.Logger {
	if levelVar == nil {
		levelVar = new(slog.LevelVar)
		levelVar.Set(parseLogLevel(cfg.Level))
	}
	opts := &slog.HandlerOptions{Level: levelVar}
	if strings.ToLower(cfg.Format) == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// newPlainClient builds a plain UDP/53 client with ban list, metrics, and health tracking.
func newPlainClient(servers []string, timeout time.Duration, ban *filter.BanList, reg *metrics.Registry, ht *health.Tracker) *upstream.PlainClient {
	p := upstream.NewPlainClient(servers, timeout)
	p.Ban = ban
	p.Metrics = reg
	p.Health = ht
	return p
}

func newDoHClient(servers []string, timeout time.Duration, ht *health.Tracker) *upstream.DoHClient {
	c := upstream.NewDoHClient(servers, timeout)
	c.Health = ht
	return c
}

func newDoTClient(servers []string, timeout time.Duration, ht *health.Tracker) *upstream.DoTClient {
	c := upstream.NewDoTClient(servers, timeout)
	c.Health = ht
	return c
}
