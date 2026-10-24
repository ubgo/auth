package apikey

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Cache keeps looked-up keys for a short time so a busy key is not read from
// the database on every request: a secondary store in front of the
// database, which stays the source of truth. It is a
// plain byte store so any shared store (Redis, memcached) fits in a few
// lines; NewMemoryCache is the in-process one.
//
// Values are keyed by the SHA-256 of the key, never the key, and hold the
// key's row without the secret. Get reports a miss as ok false; an error is
// a failure of the store itself.
//
//ds:def id=cache-n5vq2xkr owner=@khanakia stability=stable
type Cache interface {
	Get(ctx context.Context, key string) (value []byte, ok bool, err error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
}

// Cache TTL bounds.
const (
	// DefaultCacheTTL is used when WithCache gets 0: short, because a key
	// revoked on another instance (or while a request was filling the cache)
	// keeps working until its entry expires.
	//ds:def id=defaultcachettl-w8kc3nzq owner=@khanakia stability=stable
	DefaultCacheTTL = time.Minute
	// MaxCacheTTL is the longest WithCache accepts: past it, "revoke" would
	// stop meaning "now" in any useful sense.
	//ds:def id=maxcachettl-j4rx7mbs owner=@khanakia stability=stable
	MaxCacheTTL = 15 * time.Minute
	// cacheKeyPrefix starts every cache key, so the plugin's entries can be
	// told apart in a shared store.
	cacheKeyPrefix = "apikey:"
)

// ErrBadCacheTTL is a configuration error: a WithCache TTL that is negative
// or above MaxCacheTTL.
var ErrBadCacheTTL = errors.New("apikey: the cache TTL is between 0 (the default) and 15 minutes")

// WithCache puts c in front of the key lookup for ttl (0 is DefaultCacheTTL,
// at most MaxCacheTTL). A hit spares the lookup; the rate limit and quota
// still run as guarded writes against the database, re-reading the row when
// the cached counters are stale, so neither can be exceeded through the
// cache. Revoke, Update and SetLimits delete the entry. What stays true only
// up to the TTL: a key revoked on another instance with an in-process cache,
// or while a request was filling the entry, keeps working until the entry
// expires; and last_used_at moves only when the database is read, so at most
// once per TTL. A failing cache is logged and the database is read instead.
//
//ds:def id=withcache-p2hm6wtv owner=@khanakia stability=stable
func WithCache(c Cache, ttl time.Duration) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("apikey.WithCache", c) {
			return
		}
		p.cache, p.cacheTTL = c, ttl
	}
}

// cacheEntry is a keyRow as stored in the cache: every column but the
// secret's hash, which is the entry's key.
type cacheEntry struct {
	Key         Key        `json:"key"`
	UserID      string     `json:"userId"`
	Scopes      string     `json:"scopes"`
	DisabledAt  *time.Time `json:"disabledAt"`
	Metadata    *string    `json:"metadata"`
	RateMax     int64      `json:"rateMax"`
	RateWindow  int64      `json:"rateWindow"`
	RateCount   int64      `json:"rateCount"`
	WindowStart *time.Time `json:"windowStart"`
	Remaining   *int64     `json:"remaining"`
	RefillAmt   int64      `json:"refillAmount"`
	RefillEvery int64      `json:"refillEvery"`
	LastRefill  *time.Time `json:"lastRefill"`
	ConfigID    string     `json:"configId"`
	Prefix      *string    `json:"prefix"`
	OrgID       *string    `json:"orgId"`
	Permissions *string    `json:"permissions"`
}

func entryOf(r keyRow) cacheEntry {
	return cacheEntry{Key: r.k, UserID: r.userID, Scopes: r.scopes, DisabledAt: r.disabledAt, Metadata: r.metadata,
		RateMax: r.rateMax, RateWindow: r.rateWindow, RateCount: r.rateCount, WindowStart: r.windowStart, Remaining: r.remaining,
		RefillAmt: r.refillAmt, RefillEvery: r.refillEvery, LastRefill: r.lastRefill, ConfigID: r.configID, Prefix: r.prefix, OrgID: r.orgID, Permissions: r.permissions}
}

func (e cacheEntry) row(hash []byte) keyRow {
	r := keyRow{k: e.Key, userID: e.UserID, scopes: e.Scopes, disabledAt: e.DisabledAt, metadata: e.Metadata,
		rateMax: e.RateMax, rateWindow: e.RateWindow, rateCount: e.RateCount, windowStart: e.WindowStart, remaining: e.Remaining,
		refillAmt: e.RefillAmt, refillEvery: e.RefillEvery, lastRefill: e.LastRefill, configID: e.ConfigID, prefix: e.Prefix, orgID: e.OrgID, permissions: e.Permissions, hash: hash}
	r.k = r.key()
	return r
}

// cacheKey names hash's entry.
func cacheKey(hash []byte) string { return cacheKeyPrefix + hex.EncodeToString(hash) }

// cacheGet reads hash's entry; a miss or a failing cache is ok false, the
// failure logged, so the caller reads the database.
func (p *Plugin) cacheGet(ctx context.Context, hash []byte) (keyRow, bool) {
	b, ok, err := p.cache.Get(ctx, cacheKey(hash))
	if err != nil {
		p.core.Logger().Warn("apikey: cache get", "error", err)
		return keyRow{}, false
	}
	if !ok {
		return keyRow{}, false
	}
	var e cacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		p.core.Logger().Warn("apikey: cache entry", "error", err)
		return keyRow{}, false
	}
	return e.row(hash), true
}

// cacheSet stores r under its hash; a failure is only logged, since the
// database still answers.
func (p *Plugin) cacheSet(ctx context.Context, r keyRow) {
	b, err := json.Marshal(entryOf(r))
	if err == nil {
		err = p.cache.Set(ctx, cacheKey(r.hash), b, p.cacheTTL)
	}
	if err != nil {
		p.core.Logger().Warn("apikey: cache set", "error", err)
	}
}

// cacheDrop deletes hash's entry. Its failure is returned: a revoke or an
// update that could not drop the entry would leave the old key working, so
// the operation fails and its transaction rolls back.
func (p *Plugin) cacheDrop(ctx context.Context, hash []byte) error {
	if p.cache == nil {
		return nil
	}
	if err := p.cache.Delete(ctx, cacheKey(hash)); err != nil {
		return fmt.Errorf("apikey: cache delete: %w", err)
	}
	return nil
}

// MemoryCache is an in-process Cache: a map with expiries, safe for
// concurrent use. Each instance of the app has its own, so a revoke on one
// instance reaches another only when that instance's entry expires; use a
// shared store when that matters. Expired entries are removed when read and
// by Prune.
//
//ds:def id=memorycache-t9bw4qcz owner=@khanakia stability=stable
type MemoryCache struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
	now     func() time.Time
}

type memoryEntry struct {
	value []byte
	until time.Time
}

// NewMemoryCache returns an empty MemoryCache on the wall clock.
func NewMemoryCache() *MemoryCache { return NewMemoryCacheAt(time.Now) }

// NewMemoryCacheAt is NewMemoryCache on the given clock, for tests that move
// time.
func NewMemoryCacheAt(now func() time.Time) *MemoryCache {
	return &MemoryCache{entries: map[string]memoryEntry{}, now: now}
}

// Get returns key's value while it has not expired.
func (m *MemoryCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return nil, false, nil
	}
	if !m.now().Before(e.until) {
		delete(m.entries, key)
		return nil, false, nil
	}
	return e.value, true, nil
}

// Set stores value under key for ttl.
func (m *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key] = memoryEntry{value: value, until: m.now().Add(ttl)}
	return nil
}

// Delete forgets key.
func (m *MemoryCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

// Prune removes every expired entry and reports how many, for an app that
// wants to bound the map between reads.
func (m *MemoryCache) Prune() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	now := m.now()
	for k, e := range m.entries {
		if !now.Before(e.until) {
			delete(m.entries, k)
			n++
		}
	}
	return n
}
