// Command power-dns runs a DNS-over-HTTPS relay, a client that uses one, or
// both in a single process, per its config file.
//
// v1's cmd/main.go unconditionally started both the DNS server and the API
// server in every process ("the same codebase can be used for both the DNS
// relay server and the client" per the README, but there was no actual
// switch to run just one). v2 makes the split explicit via config.Mode.
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

	logger := newLogger(cfg.Log)
	slog.SetDefault(logger)

	if err := run(cfg, logger); err != nil {
		logger.Error("power-dns exited with error", "error", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, logger *slog.Logger) error {
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
			MaxEntries:  cfg.Cache.MaxEntries,
			MinTTL:      time.Duration(cfg.Cache.MinTTLSeconds) * time.Second,
			MaxTTL:      time.Duration(cfg.Cache.MaxTTLSeconds) * time.Second,
			NegativeTTL: time.Duration(cfg.Cache.NegativeTTLSeconds) * time.Second,
			PersistPath: cfg.Cache.PersistPath,
			Metrics:     reg,
			Prefetch: cache.PrefetchOptions{
				Enabled:   cfg.Cache.Prefetch.Enabled,
				Threshold: time.Duration(cfg.Cache.Prefetch.ThresholdSeconds) * time.Second,
				MinHits:   cfg.Cache.Prefetch.MinHits,
				Refresh:   res.ResolveUpstreamOnly,
				Timeout:   time.Duration(cfg.Cache.Prefetch.TimeoutSeconds) * time.Second,
			},
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

	logger.Info("power-dns started", "mode", cfg.Mode)

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

func newLogger(cfg config.LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.ToLower(cfg.Format) == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}
