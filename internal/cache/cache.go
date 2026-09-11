// Package cache implements the answer cache.
//
// v1's cache (internal/dns/cache.go) always cached for a fixed 24h
// regardless of the upstream's actual TTL, had no size bound (an unbounded
// map that grows forever), wrote the entire cache to disk on every single
// Set/Delete (an fsync-per-query bottleneck plus a data race: saveToFile
// took the same mutex Set/Delete already held, so the mutation and the
// snapshot serialized on top of each other via a background goroutine
// racing the next mutation), and never cached negative answers. v2 fixes
// all four: real TTLs (clamped to sane bounds), bounded LRU eviction,
// debounced/periodic persistence, and short-lived negative caching.
package cache

import (
	"container/list"
	"encoding/gob"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Options configures a Cache.
type Options struct {
	MaxEntries  int
	MinTTL      time.Duration
	MaxTTL      time.Duration
	NegativeTTL time.Duration
	PersistPath string // empty disables persistence
}

// Cache is a bounded, TTL-aware, LRU-evicted store of packed DNS answers,
// keyed by "<qname>|<qtype>" so an A and AAAA query for the same name don't
// collide.
type Cache struct {
	opts Options

	mu    sync.Mutex
	items map[string]*list.Element
	order *list.List // front = most recently used
}

type entry struct {
	key      string
	packed   []byte // wire-format answer, re-Unpack on Get
	expireAt time.Time
}

// New creates a Cache and, if opts.PersistPath is set, loads any
// previously-persisted entries.
func New(opts Options) *Cache {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 10000
	}
	c := &Cache{
		opts:  opts,
		items: make(map[string]*list.Element),
		order: list.New(),
	}
	if opts.PersistPath != "" {
		_ = c.loadFromFile() // best-effort; a missing/corrupt file just means a cold start
	}
	return c
}

func key(name string, qtype uint16) string {
	return dns.Fqdn(name) + "|" + dns.TypeToString[qtype]
}

// Get returns a cached response for (name, qtype), rewritten as a reply to
// req so the ID and question section match what the caller expects.
func (c *Cache) Get(req *dns.Msg, name string, qtype uint16) (*dns.Msg, bool) {
	c.mu.Lock()
	el, ok := c.items[key(name, qtype)]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	e := el.Value.(*entry)
	if time.Now().After(e.expireAt) {
		c.removeLocked(el)
		c.mu.Unlock()
		return nil, false
	}
	c.order.MoveToFront(el)
	packed := e.packed
	c.mu.Unlock()

	msg := new(dns.Msg)
	if err := msg.Unpack(packed); err != nil {
		return nil, false
	}
	answers := msg.Answer
	msg.SetReply(req)
	msg.Answer = answers // SetReply doesn't touch Answer, but be explicit about intent
	return msg, true
}

// Set stores resp under (name, qtype), choosing a TTL from the response's
// own answers (clamped to [MinTTL, MaxTTL]), or NegativeTTL if resp has no
// answers (e.g. NXDOMAIN).
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
		snapshot = append(snapshot, persistedEntry{Key: e.key, Packed: e.packed, ExpireAt: e.expireAt})
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
		e := &entry{key: pe.Key, packed: pe.Packed, expireAt: pe.ExpireAt}
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
