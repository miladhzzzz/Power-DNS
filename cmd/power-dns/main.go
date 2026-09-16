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
	"github.com/miladhzzzz/power-dns/internal/metrics"
	"github.com/miladhzzzz/power-dns/internal/records"
	"github.com/miladhzzzz/power-dns/internal/relay"
	"github.com/miladhzzzz/power-dns/internal/resolver"
	"github.com/miladhzzzz/power-dns/internal/upstream"
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
	relayHandler *relay.Server
	apiServer   *api.Server
}

func run(configPath string, cfg config.Config, logger *slog.Logger, levelVar *slog.LevelVar) error {
	reg := metrics.New()

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
		reg.SetCacheSizeFunc(func() (int, int) { return answerCache.Len(), answerCache.Cap() })
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
				DoH:     upstream.NewDoHClient(cfg.Upstream.DoHServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second),
				DoT:     upstream.NewDoTClient(cfg.Upstream.DoTServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second),
				Plain:   upstream.NewPlainClient(cfg.Upstream.PlainServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second),
				Metrics: reg,
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
		AdminAuthToken:    cfg.Security.AdminAuthToken,
	}, logger.With("component", "api"), reg, recStore, relayHandler)
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
		res.DoH = upstream.NewDoHClient(cfg.Upstream.DoHServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second)
		res.DoT = upstream.NewDoTClient(cfg.Upstream.DoTServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second)
		res.Plain = upstream.NewPlainClient(cfg.Upstream.PlainServers, time.Duration(cfg.Upstream.TimeoutSeconds)*time.Second)
		res.Timeout = time.Duration(cfg.Relay.TimeoutSeconds) * time.Second
		res.Logger = logger.With("component", "resolver")
		res.Metrics = reg

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
		path:         configPath,
		cfg:          cfg,
		logger:       logger,
		levelVar:     levelVar,
		reg:          reg,
		answerCache:  answerCache,
		res:          res,
		relayHandler: relayHandler,
		apiServer:    apiServer,
	}

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
		a.res.ApplyRuntime(resolver.RuntimeConfig{
			Order:       newCfg.Resolution.Order,
			RelayClient: relayClient,
			DoH:         upstream.NewDoHClient(newCfg.Upstream.DoHServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second),
			DoT:         upstream.NewDoTClient(newCfg.Upstream.DoTServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second),
			Plain:       upstream.NewPlainClient(newCfg.Upstream.PlainServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second),
			Timeout:     timeout,
		})
	}

	// Relay server security + upstream chain
	if a.relayHandler != nil {
		a.relayHandler.ApplySecurity(
			newCfg.Security.RelayAuthToken,
			newCfg.Security.AllowedDomains,
			newCfg.Security.RelayRateLimitPerMinute,
		)
		a.relayHandler.ApplyUpstream(&upstream.Chain{
			DoH:     upstream.NewDoHClient(newCfg.Upstream.DoHServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second),
			DoT:     upstream.NewDoTClient(newCfg.Upstream.DoTServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second),
			Plain:   upstream.NewPlainClient(newCfg.Upstream.PlainServers, time.Duration(newCfg.Upstream.TimeoutSeconds)*time.Second),
			Metrics: a.reg,
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
