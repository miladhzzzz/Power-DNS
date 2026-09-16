// Package cache implements the answer cache: a bounded, TTL-aware,
// LRU-evicted store of DNS answers, with optional background prefetching
// of popular entries before they expire, and optional stale-while-revalidate
// serving of recently-expired entries while they're refreshed in the
// background.
//
// v1's cache (internal/dns/cache.go) always cached for a fixed 24h
// regardless of the upstream's actual TTL, had no size bound (an unbounded
// map that grows forever), wrote the entire cache to disk on every single
// Set/Delete (an fsync-per-query bottleneck plus a data race: saveToFile
// took the same mutex Set/Delete already held, so the mutation and the
// snapshot serialized on top of each other via a background goroutine
// racing the next mutation), never cached negative answers, and gave no
// visibility into *why* a lookup missed. v2 fixes all of that: real TTLs
// (clamped to sane bounds), bounded LRU eviction, debounced/periodic
// persistence, short-lived negative caching, a miss reason
// (not-found/expired/disabled) and an eviction reason on every metric,
// optional prefetching so a hot record never actually expires from a
// caller's point of view, and optional stale-while-revalidate so a record
// that *does* expire before anyone refreshes it still doesn't cost the
// caller a synchronous upstream round trip.
package cache

import (
	"container/list"
	"context"
	"encoding/gob"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/miladhzzzz/power-dns/internal/metrics"
)

// refreshCooldown bounds how often a single key can trigger a background
// refresh attempt -- whether that refresh was triggered by prefetch or by
// stale-while-revalidate -- so a persistently-failing upstream doesn't get
// hammered once per incoming query.
const refreshCooldown = 5 * time.Second

// RefreshFunc re-resolves (name, qtype) against real upstreams (bypassing
// the cache, obviously). It's supplied by whatever owns both the Cache and
// the resolution logic (internal/resolver), since the cache package itself
// has no notion of relay/DoH/DoT/plain -- this keeps the dependency
// pointing one way (resolver -> cache), not both. Both prefetching and
// stale-while-revalidate share this single callback and its in-flight/
// cooldown protection (see triggerRefresh); they differ only in *when*
// they decide a background refresh is worth triggering.
type RefreshFunc func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)

// PrefetchOptions controls background refresh of soon-to-expire, popular
// entries, *before* they actually expire. Disabled by default: it trades
// some extra upstream load for lower tail latency on hot records, and that
// trade should be opt-in.
type PrefetchOptions struct {
	Enabled bool
	// Threshold is how much TTL a hit needs left to *avoid* triggering a
	// refresh -- an entry with less than this remaining is a candidate.
	Threshold time.Duration
	// MinHits is the minimum observed hit count (since the entry was last
	// stored) before it's considered "popular enough" to prefetch. This is
	// what keeps a single one-off lookup from generating background
	// traffic for a record nobody else cares about.
	MinHits uint64
}

// Options configures a Cache.
type Options struct {
	MaxEntries  int
	MinTTL      time.Duration
	MaxTTL      time.Duration
	NegativeTTL time.Duration
	PersistPath string // empty disables persistence

	// Metrics, if set, receives cache hit/miss/eviction/prefetch/stale
	// counters. Nil is safe -- metrics just aren't recorded.
	Metrics *metrics.Registry

	// Refresh performs the actual re-resolution for both Prefetch and
	// StaleMaxAge. Both features are no-ops if this is nil, regardless of
	// their other settings.
	Refresh RefreshFunc
	// RefreshTimeout bounds each background refresh attempt (prefetch or
	// stale-while-revalidate). Defaults to 5s if zero.
	RefreshTimeout time.Duration

	Prefetch PrefetchOptions

	// StaleMaxAge enables stale-while-revalidate when greater than zero
	// (the default, disabled): a Get for an entry whose TTL has expired,
	// but not more than StaleMaxAge ago, is still served immediately --
	// the caller pays zero extra latency -- while a background refresh
	// brings the entry up to date. An entry older than that is a genuine
	// miss, same as when this is disabled. This trades a small, bounded
	// window of possibly-stale answers for eliminating the synchronous
	// upstream round trip a normal expiry would otherwise cost every
	// caller until the first one refreshes it.
	StaleMaxAge time.Duration
}

// Cache is a bounded, TTL-aware, LRU-evicted store of packed DNS answers,
// keyed by "<qname>|<qtype>" so an A and AAAA query for the same name don't
// collide (see the package-level note in Get about what else is, and isn't,
// part of that key).
type Cache struct {
	opts Options

	mu    sync.Mutex
	items map[string]*list.Element
	order *list.List // front = most recently used

	// refreshMu/refreshInFlight/refreshLastTry guard the shared background
	// refresh mechanism used by both Prefetch and StaleMaxAge -- one
	// refresh per key at a time, with a cooldown between attempts,
	// regardless of which feature triggered it.
	refreshMu       sync.Mutex
	refreshInFlight map[string]bool
	refreshLastTry  map[string]time.Time
}

type entry struct {
	key      string
	packed   []byte // wire-format answer, re-Unpack on Get
	expireAt time.Time
	hits     uint64 // popularity counter, used to decide what's worth prefetching
	// fromPrefetch is true when this entry's current payload was last
	// written by a successful background prefetch. Fresh Get hits while
	// this is set increment powerdns_cache_prefetch_protected_hits_total.
	// Cleared when the entry is stored by any non-prefetch path (client
	// miss resolve or stale-while-revalidate refresh).
	fromPrefetch bool
}

// New creates a Cache and, if opts.PersistPath is set, loads any
// previously-persisted entries.
func New(opts Options) *Cache {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 10000
	}
	c := &Cache{
		opts:            opts,
		items:           make(map[string]*list.Element),
		order:           list.New(),
		refreshInFlight: make(map[string]bool),
		refreshLastTry:  make(map[string]time.Time),
	}
	if opts.PersistPath != "" {
		_ = c.loadFromFile() // best-effort; a missing/corrupt file just means a cold start
	}
	return c
}

// key intentionally includes only the query name and type -- nothing about
// the requesting client, transport (DoH/DoT/plain/UDP/TCP), EDNS options,
// or the request's own ID. Two clients asking the same question, over
// different transports, should share one cache entry; folding any of that
// extra context into the key would silently fragment the cache into many
// smaller, less-effective ones for no behavioral benefit (nothing in this
// resolver varies its answer by any of those dimensions). If that ever
// changes, extend this key deliberately -- don't let it happen by accident.
func key(name string, qtype uint16) string {
	return dns.Fqdn(name) + "|" + dns.TypeToString[qtype]
}

// Get returns a cached response for (name, qtype), rewritten as a reply to
// req so the ID and question section match what the caller expects.
//
// There are three possible outcomes, each recorded via opts.Metrics:
//   - a fresh hit (TTL not yet expired): returned immediately, and if it's
//     popular and running low on TTL, may kick off a background prefetch
//     (see PrefetchOptions).
//   - a stale hit (TTL expired, but not more than opts.StaleMaxAge ago,
//     and StaleMaxAge > 0): still returned immediately, and always kicks
//     off a background revalidation. This is stale-while-revalidate: the
//     caller never pays for the upstream round trip a plain expiry would
//     otherwise cost.
//   - a miss (no entry, or expired beyond the stale window): the entry (if
//     any) is dropped and the caller must resolve normally.
func (c *Cache) Get(req *dns.Msg, name string, qtype uint16) (*dns.Msg, bool) {
	k := key(name, qtype)

	c.mu.Lock()
	el, ok := c.items[k]
	if !ok {
		c.mu.Unlock()
		c.recordMiss(metrics.MissNotFound)
		return nil, false
	}
	e := el.Value.(*entry)
	now := time.Now()

	if now.After(e.expireAt) {
		age := now.Sub(e.expireAt)
		if c.opts.Metrics != nil {
			// Recorded unconditionally -- before deciding whether SWR
			// serves this or it's a genuine miss -- so the distribution
			// is unbiased by whatever stale window happens to be
			// configured right now.
			c.opts.Metrics.ObserveExpiredEntryAge(age)
		}
		staleUsable := c.opts.StaleMaxAge > 0 && c.opts.Refresh != nil && age <= c.opts.StaleMaxAge
		if !staleUsable {
			c.removeLocked(el)
			c.mu.Unlock()
			c.recordMiss(metrics.MissExpired)
			return nil, false
		}

		e.hits++
		packed := e.packed
		c.order.MoveToFront(el)
		c.mu.Unlock()

		msg, err := restampFromPacked(packed, req)
		if err != nil {
			c.Delete(name, qtype)
			c.recordMiss(metrics.MissNotFound)
			return nil, false
		}
		if c.opts.Metrics != nil {
			c.opts.Metrics.IncStaleHit()
		}
		c.triggerRefresh(name, qtype, refreshReasonStale)
		return msg, true
	}

	e.hits++
	hits := e.hits
	remaining := e.expireAt.Sub(now)
	packed := e.packed
	fromPrefetch := e.fromPrefetch
	c.order.MoveToFront(el)
	c.mu.Unlock()

	msg, err := restampFromPacked(packed, req)
	if err != nil {
		// A corrupted entry (e.g. a persisted file from an incompatible
		// version) is functionally absent -- drop it and report a miss
		// rather than returning garbage.
		c.Delete(name, qtype)
		c.recordMiss(metrics.MissNotFound)
		return nil, false
	}

	if c.opts.Metrics != nil {
		c.opts.Metrics.IncCacheHit()
		// Attribute the hit to prefetch only while the entry's last fill
		// was a successful prefetch (see entry.fromPrefetch / store).
		if fromPrefetch {
			c.opts.Metrics.IncPrefetchProtectedHit()
		}
	}
	c.maybePrefetch(name, qtype, remaining, hits)
	return msg, true
}

// restampFromPacked unpacks a stored wire-format answer and re-stamps it as
// a reply to req, preserving the stored Answer/Ns/Extra content. Shared by
// both the fresh-hit and stale-hit paths in Get.
func restampFromPacked(packed []byte, req *dns.Msg) (*dns.Msg, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(packed); err != nil {
		return nil, err
	}
	answer, ns, extra := msg.Answer, msg.Ns, msg.Extra
	msg.SetReply(req)
	msg.Answer, msg.Ns, msg.Extra = answer, ns, extra
	return msg, nil
}

func (c *Cache) recordMiss(reason string) {
	if c.opts.Metrics != nil {
		c.opts.Metrics.IncCacheMiss(reason)
	}
}

// maybePrefetch kicks off a background refresh for (name, qtype) if
// prefetching is enabled, the entry is popular enough, and it's running low
// on TTL (but not yet expired -- see triggerRefresh's stale-hit caller in
// Get for the "already expired" case). It never blocks the caller.
func (c *Cache) maybePrefetch(name string, qtype uint16, remaining time.Duration, hits uint64) {
	p := c.opts.Prefetch
	if !p.Enabled || c.opts.Refresh == nil {
		return
	}
	if remaining > p.Threshold || hits < p.MinHits {
		return
	}
	c.triggerRefresh(name, qtype, refreshReasonPrefetch)
}

// refreshReason distinguishes why a background refresh was triggered, for
// metrics purposes -- the mechanism (in-flight/cooldown protection, the
// actual RefreshFunc call, calling Set on success) is identical either way.
type refreshReason int

const (
	refreshReasonPrefetch refreshReason = iota
	refreshReasonStale
)

// triggerRefresh kicks off a background RefreshFunc call for (name, qtype)
// unless one is already in flight or was tried too recently (see
// refreshCooldown). It never blocks the caller -- the actual refresh
// happens in its own goroutine. Both PrefetchOptions and StaleMaxAge share
// this single in-flight/cooldown guard per key: a hot record nearing
// expiry that's already being prefetched won't *also* trigger a redundant
// stale-revalidation the instant it crosses into "expired," and vice versa.
func (c *Cache) triggerRefresh(name string, qtype uint16, reason refreshReason) {
	if c.opts.Refresh == nil {
		return
	}
	k := key(name, qtype)

	c.refreshMu.Lock()
	if c.refreshInFlight[k] {
		c.refreshMu.Unlock()
		if reason == refreshReasonPrefetch && c.opts.Metrics != nil {
			c.opts.Metrics.IncPrefetchSkipped(metrics.PrefetchSkipInFlight)
		}
		return
	}
	if last, tried := c.refreshLastTry[k]; tried && time.Since(last) < refreshCooldown {
		c.refreshMu.Unlock()
		if reason == refreshReasonPrefetch && c.opts.Metrics != nil {
			c.opts.Metrics.IncPrefetchSkipped(metrics.PrefetchSkipCooldown)
		}
		return
	}
	c.refreshInFlight[k] = true
	c.refreshLastTry[k] = time.Now()
	c.refreshMu.Unlock()

	go func() {
		defer func() {
			c.refreshMu.Lock()
			delete(c.refreshInFlight, k)
			c.refreshMu.Unlock()
		}()

		timeout := c.opts.RefreshTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		resp, err := c.opts.Refresh(ctx, name, qtype)
		if err != nil || resp == nil {
			if c.opts.Metrics != nil {
				switch reason {
				case refreshReasonPrefetch:
					c.opts.Metrics.IncPrefetch(metrics.PrefetchFailure)
				case refreshReasonStale:
					c.opts.Metrics.IncStaleRevalidationFailure()
				}
			}
			return // next Get() within the cooldown window just won't retry immediately
		}
		// Prefetch-sourced fills mark the entry so subsequent fresh hits
		// increment powerdns_cache_prefetch_protected_hits_total. Stale
		// revalidation is not prefetch -- those hits are already counted
		// as staleHits, so leave fromPrefetch false.
		c.store(name, qtype, resp, reason == refreshReasonPrefetch)
		if c.opts.Metrics != nil {
			switch reason {
			case refreshReasonPrefetch:
				c.opts.Metrics.IncPrefetch(metrics.PrefetchSuccess)
			case refreshReasonStale:
				c.opts.Metrics.IncStaleRevalidation()
			}
		}
	}()
}

// Set stores resp under (name, qtype), choosing a TTL from the response's
// own answers (clamped to [MinTTL, MaxTTL]), or NegativeTTL if resp has no
// answers (e.g. NXDOMAIN). Updating an existing entry keeps its accumulated
// hit count rather than resetting it, so popularity tracking survives a
// refresh. Entries stored via Set are not marked as prefetch-sourced
// (fromPrefetch=false); background prefetch uses store(..., true) instead.
func (c *Cache) Set(name string, qtype uint16, resp *dns.Msg) {
	c.store(name, qtype, resp, false)
}

// store is the shared implementation behind Set and background refresh.
// fromPrefetch marks whether this fill came from a successful prefetch so
// later fresh hits can be attributed via prefetch_protected_hits_total.
func (c *Cache) store(name string, qtype uint16, resp *dns.Msg, fromPrefetch bool) {
	ttl := c.opts.NegativeTTL
	if minTTL, ok := minAnswerTTL(resp); ok {
		ttl = time.Duration(minTTL) * time.Second
		if ttl < c.opts.MinTTL {
			ttl = c.opts.MinTTL
		}
		if c.opts.MaxTTL > 0 && ttl > c.opts.MaxTTL {
			ttl = c.opts.MaxTTL
		}
	}
	if ttl <= 0 {
		return
	}

	packed, err := resp.Pack()
	if err != nil {
		return
	}

	k := key(name, qtype)
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[k]; ok {
		ent := el.Value.(*entry)
		ent.packed = packed
		ent.expireAt = time.Now().Add(ttl)
		ent.fromPrefetch = fromPrefetch
		c.order.MoveToFront(el)
		return
	}

	e := &entry{
		key:          k,
		packed:       packed,
		expireAt:     time.Now().Add(ttl),
		fromPrefetch: fromPrefetch,
	}
	el := c.order.PushFront(e)
	c.items[k] = el

	for c.order.Len() > c.opts.MaxEntries {
		back := c.order.Back()
		if back == nil {
			break
		}
		c.removeLocked(back)
		if c.opts.Metrics != nil {
			c.opts.Metrics.IncCacheEviction(metrics.EvictionLRU)
		}
	}
}

// Delete removes any cached entry for (name, qtype).
func (c *Cache) Delete(name string, qtype uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key(name, qtype)]; ok {
		c.removeLocked(el)
	}
}

// Len returns the current number of cached entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Cap returns the configured maximum number of entries.
func (c *Cache) Cap() int {
	return c.opts.MaxEntries
}

// RuntimeOptions holds cache settings that can be changed without rebuilding
// the cache or dropping entries (hot-reload).
type RuntimeOptions struct {
	MinTTL         time.Duration
	MaxTTL         time.Duration
	NegativeTTL    time.Duration
	RefreshTimeout time.Duration
	StaleMaxAge    time.Duration
	Prefetch       PrefetchOptions
}

// UpdateRuntime applies hot-reloadable cache settings. MaxEntries, PersistPath,
// Metrics, and Refresh are not changed (those need a process restart).
func (c *Cache) UpdateRuntime(ro RuntimeOptions) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ro.MinTTL > 0 {
		c.opts.MinTTL = ro.MinTTL
	}
	if ro.MaxTTL > 0 {
		c.opts.MaxTTL = ro.MaxTTL
	}
	if ro.NegativeTTL > 0 {
		c.opts.NegativeTTL = ro.NegativeTTL
	}
	if ro.RefreshTimeout > 0 {
		c.opts.RefreshTimeout = ro.RefreshTimeout
	}
	c.opts.StaleMaxAge = ro.StaleMaxAge // 0 disables SWR
	c.opts.Prefetch = ro.Prefetch
}

func (c *Cache) removeLocked(el *list.Element) {
	e := el.Value.(*entry)
	delete(c.items, e.key)
	c.order.Remove(el)
}

func minAnswerTTL(m *dns.Msg) (uint32, bool) {
	var ttl uint32
	found := false
	for i, rr := range m.Answer {
		if i == 0 || rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
		found = true
	}
	return ttl, found
}

// persistedEntry is the on-disk shape written/read by SaveToFile/loadFromFile.
type persistedEntry struct {
	Key      string
	Packed   []byte
	ExpireAt time.Time
	Hits     uint64 // added after the initial format; absent in old files decodes as 0
}

// SaveToFile snapshots all non-expired entries to opts.PersistPath. It is
// meant to be called periodically (e.g. every few minutes) and on shutdown,
// not after every mutation as v1 did. Entries only within their
// stale-while-revalidate window are not persisted -- that window is meant
// to be short-lived, and a restarted process re-resolving them fresh is
// simpler than reasoning about a stale entry's remaining staleness budget
// surviving a restart.
func (c *Cache) SaveToFile() error {
	if c.opts.PersistPath == "" {
		return nil
	}
	c.mu.Lock()
	snapshot := make([]persistedEntry, 0, c.order.Len())
	now := time.Now()
	for el := c.order.Front(); el != nil; el = el.Next() {
		e := el.Value.(*entry)
		if now.After(e.expireAt) {
			continue
		}
		snapshot = append(snapshot, persistedEntry{Key: e.key, Packed: e.packed, ExpireAt: e.expireAt, Hits: e.hits})
	}
	c.mu.Unlock()

	tmp := c.opts.PersistPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := gob.NewEncoder(f).Encode(snapshot); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, c.opts.PersistPath) // atomic on the same filesystem
}

func (c *Cache) loadFromFile() error {
	f, err := os.Open(c.opts.PersistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	var snapshot []persistedEntry
	if err := gob.NewDecoder(f).Decode(&snapshot); err != nil {
		return err
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pe := range snapshot {
		if now.After(pe.ExpireAt) {
			continue
		}
		e := &entry{key: pe.Key, packed: pe.Packed, expireAt: pe.ExpireAt, hits: pe.Hits}
		c.items[pe.Key] = c.order.PushBack(e)
	}
	return nil
}

// StartPersistLoop periodically calls SaveToFile until stop is closed. It is
// a no-op if persistence is disabled.
func (c *Cache) StartPersistLoop(interval time.Duration, stop <-chan struct{}, onErr func(error)) {
	if c.opts.PersistPath == "" {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			if err := c.SaveToFile(); err != nil && onErr != nil {
				onErr(err)
			}
			return
		case <-ticker.C:
			if err := c.SaveToFile(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}
