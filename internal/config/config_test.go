package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

func TestDefaultIsValidForRelayMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeRelay
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default relay config to validate, got: %v", err)
	}
}

func TestLoadOverlaysDefaults(t *testing.T) {
	path := writeTemp(t, `
mode = "client"
[relay]
url = "https://relay.example.com/dns-query"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Relay.URL != "https://relay.example.com/dns-query" {
		t.Fatalf("expected relay.url to be overlaid, got %q", cfg.Relay.URL)
	}
	// Untouched fields should still carry their defaults.
	if cfg.Cache.MaxEntries != 10000 {
		t.Fatalf("expected cache.max_entries to keep its default, got %d", cfg.Cache.MaxEntries)
	}
	if len(cfg.Resolution.Order) == 0 {
		t.Fatalf("expected resolution.order to keep its default")
	}
}

func TestRelayDisabledWhenURLAndDoTAddrEmpty(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeClient
	cfg.Relay.URL = ""
	cfg.Relay.DoTAddr = ""

	// An unconfigured relay is valid, not an error -- it just means the
	// "relay" resolution strategy is disabled and the client falls
	// straight through to its doh/dot/plain fallbacks.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected an unconfigured relay to validate cleanly, got: %v", err)
	}
	if !cfg.RelayDisabled() {
		t.Fatalf("expected RelayDisabled() to be true when both relay.url and relay.dot_addr are empty")
	}

	cfg.Relay.URL = "https://relay.example.com/dns-query"
	if cfg.RelayDisabled() {
		t.Fatalf("expected RelayDisabled() to be false once relay.url is set")
	}

	cfg.Relay.URL = ""
	cfg.Relay.DoTAddr = "relay.example.com:853"
	if cfg.RelayDisabled() {
		t.Fatalf("expected RelayDisabled() to be false when only relay.dot_addr is set")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected dot_addr alone to validate, got: %v", err)
	}
}

func TestInvalidResolutionOrderEntryRejected(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeRelay
	cfg.Resolution.Order = []string{"records", "carrier-pigeon"}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected an invalid resolution.order entry to be rejected")
	}
}

func TestDotResolutionOrderEntryAccepted(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeRelay
	cfg.Resolution.Order = []string{"records", "cache", "relay", "doh", "dot", "plain"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected \"dot\" to be a valid resolution.order entry, got: %v", err)
	}
}

func TestInvalidModeRejected(t *testing.T) {
	cfg := Default()
	cfg.Mode = "sidecar"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected an invalid mode to be rejected")
	}
}

func TestStaleWhileRevalidateDisabledByDefault(t *testing.T) {
	cfg := Default()
	if cfg.Cache.StaleWhileRevalidateSeconds != 0 {
		t.Fatalf("expected stale_while_revalidate_seconds to default to 0 (disabled), got %d", cfg.Cache.StaleWhileRevalidateSeconds)
	}
}

func TestStaleWhileRevalidateOverlaysFromFile(t *testing.T) {
	path := writeTemp(t, `
mode = "client"
[relay]
url = "https://relay.example.com/dns-query"
[cache]
stale_while_revalidate_seconds = 30
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cache.StaleWhileRevalidateSeconds != 30 {
		t.Fatalf("expected stale_while_revalidate_seconds to be overlaid to 30, got %d", cfg.Cache.StaleWhileRevalidateSeconds)
	}
}
