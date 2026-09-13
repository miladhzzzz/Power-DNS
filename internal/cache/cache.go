// Package cache implements the answer cache: a bounded, TTL-aware,
// LRU-evicted store of DNS answers, with optional background prefetching
// of popular entries before they expire.
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
// (not-found/expired/disabled) and an eviction reason on every metric, and
// optional prefetching so a hot record never actually expires from a
// caller's point of view.
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

// prefetchCooldown bounds how often a single key can trigger a background
// refresh attempt, so a persistently-failing upstream doesn't get hammered
// once per incoming query during a hot key's last few seconds of TTL.
const prefetchCooldown = 5 * time.Second

// RefreshFunc re-resolves (name, qtype) against real upstreams (bypassing
// the cache, obviously), for use by prefetching. It's supplied by whatever
// owns both the Cache and the resolution logic (internal/resolver), since
// the cache package itself has no notion of relay/DoH/DoT/plain -- this
// keeps the dependency pointing one way (resolver -> cache), not both.
type RefreshFunc func(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)

// PrefetchOptions controls background refresh of soon-to-expire, popular
// entries. Disabled by default: it trades some extra upstream load for
// lower tail latency on hot records, and that trade should be opt-in.
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
	// Refresh performs the actual re-resolution. Prefetching is a no-op if
	// this is nil, even when Enabled is true.
	Refresh RefreshFunc
	// Timeout bounds each background refresh attempt. Defaults to 5s if
	// zero.
	Timeout time.Duration
}

// Options configures a Cache.
type Options struct {
	MaxEntries  int
	MinTTL      time.Duration
	MaxTTL      time.Duration
	NegativeTTL time.Duration
	PersistPath string // empty disables persistence

	// Metrics, if set, receives cache hit/miss/eviction counters. Nil is
	// safe -- metrics just aren't recorded.
	Metrics *metrics.Registry

	Prefetch PrefetchOptions
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

	prefetchMu       sync.Mutex
	prefetchInFlight map[string]bool
	prefetchLastTry  map[string]time.Time
}

type entry struct {
	key      string
	packed   []byte // wire-format answer, re-Unpack on Get
	expireAt time.Time
	hits     uint64 // popularity counter, used to decide what's worth prefetching
}

// New creates a Cache and, if opts.PersistPath is set, loads any
// previously-persisted entries.
func New(opts Options) *Cache {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 10000
	}
	c := &Cache{
		opts:             opts,
		items:            make(map[string]*list.Element),
		order:            list.New(),
		prefetchInFlight: make(map[string]bool),
		prefetchLastTry:  make(map[string]time.Time),
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
// req so the ID and question section match what the caller expects. Every
// call records exactly one hit or one miss (with a reason) via
// opts.Metrics, and a hit that's running low on TTL may kick off a
// background prefetch (see PrefetchOptions).
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
	if time.Now().After(e.expireAt) {
		c.removeLocked(el)
		c.mu.Unlock()
		c.recordMiss(metrics.MissExpired)
		return nil, false
	}
	e.hits++
	hits := e.hits
	remaining := time.Until(e.expireAt)
	packed := e.packed
	c.order.MoveToFront(el)
	c.mu.Unlock()

	msg := new(dns.Msg)
	if err := msg.Unpack(packed); err != nil {
		// A corrupted entry (e.g. a persisted file from an incompatible
		// version) is functionally absent -- drop it and report a miss
		// rather than returning garbage.
		c.Delete(name, qtype)
		c.recordMiss(metrics.MissNotFound)
		return nil, false
	}
	answers := msg.Answer
	msg.SetReply(req)
	msg.Answer = answers // SetReply doesn't touch Answer, but be explicit about intent

	if c.opts.Metrics != nil {
		c.opts.Metrics.IncCacheHit()
	}
	c.maybePrefetch(name, qtype, remaining, hits)
	return msg, true
}

func (c *Cache) recordMiss(reason string) {
	if c.opts.Metrics != nil {
		c.opts.Metrics.IncCacheMiss(reason)
	}
}

// maybePrefetch kicks off a background RefreshFunc call for (name, qtype)
// if prefetching is enabled, the entry is popular enough, it's running low
// on TTL, and no attempt for this key is already in flight or was tried too
// recently. It never blocks the caller -- the actual refresh happens in its
// own goroutine.
func (c *Cache) maybePrefetch(name string, qtype uint16, remaining time.Duration, hits uint64) {
	p := c.opts.Prefetch
	if !p.Enabled || p.Refresh == nil {
		return
	}
	if remaining > p.Threshold || hits < p.MinHits {
		return
	}

	k := key(name, qtype)

	c.prefetchMu.Lock()
	if c.prefetchInFlight[k] {
		c.prefetchMu.Unlock()
		if c.opts.Metrics != nil {
			c.opts.Metrics.IncPrefetchSkipped(metrics.PrefetchSkipInFlight)
		}
		return
	}
	if last, tried := c.prefetchLastTry[k]; tried && time.Since(last) < prefetchCooldown {
		c.prefetchMu.Unlock()
		if c.opts.Metrics != nil {
			c.opts.Metrics.IncPrefetchSkipped(metrics.PrefetchSkipCooldown)
		}
		return
	}
	c.prefetchInFlight[k] = true
	c.prefetchLastTry[k] = time.Now()
	c.prefetchMu.Unlock()

	go func() {
		defer func() {
			c.prefetchMu.Lock()
			delete(c.prefetchInFlight, k)
			c.prefetchMu.Unlock()
		}()

		timeout := p.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		resp, err := p.Refresh(ctx, name, qtype)
		if err != nil || resp == nil {
			if c.opts.Metrics != nil {
				c.opts.Metrics.IncPrefetch(metrics.PrefetchFailure)
			}
			return // next Get() within the cooldown window just won't retry immediately
		}
		c.Set(name, qtype, resp) // preserves the existing entry's hit count -- see Set
		if c.opts.Metrics != nil {
			c.opts.Metrics.IncPrefetch(metrics.PrefetchSuccess)
		}
	}()
}

// Set stores resp under (name, qtype), choosing a TTL from the response's
// own answers (clamped to [MinTTL, MaxTTL]), or NegativeTTL if resp has no
// answers (e.g. NXDOMAIN). Updating an existing entry (including via a
// prefetch refresh) keeps its accumulated hit count rather than resetting
// it, so popularity tracking survives a refresh.
func (c *Cache) Set(name string, qtype uint16, resp *dns.Msg) {
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
		el.Value.(*entry).packed = packed
		el.Value.(*entry).expireAt = time.Now().Add(ttl)
		c.order.MoveToFront(el)
		return
	}

	e := &entry{key: k, packed: packed, expireAt: time.Now().Add(ttl)}
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
// not after every mutation as v1 did.
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
