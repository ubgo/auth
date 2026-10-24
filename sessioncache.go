package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// SessionCache lets a request skip the session lookup for a short time. It
// sits in front of the store, or of stateless mode. A revocation reaches a
// cached request only when its entry expires, which is why the TTL is capped
// at MaxSessionCacheTTL and why a pending second-factor session is never
// cached.
//
// The core passes its own clock as now and until, so a cache keeps no clock
// of its own and a test can move time. An entry never outlives the session's
// expiry: the core caps until at it.
//
//ds:def id=core-sessioncache-2gkmh8gk owner=@khanakia stability=stable
type SessionCache interface {
	// Get returns the cached session and user for k, valid at now, or
	// ok=false. An error is a failure of the cache itself, not a miss.
	Get(ctx context.Context, k CacheKey, now time.Time) (s Session, u User, ok bool, err error)
	// Put remembers a looked-up session until until. The returned string,
	// when not empty, is handed to the client to send back on later requests
	// as Request.CachedSession; the snapshot cache uses it, a server-side
	// cache returns "".
	Put(ctx context.Context, k CacheKey, s Session, u User, until time.Time) (clientValue string, err error)
	// Drop forgets the entry for this token: sign-out on this device.
	Drop(ctx context.Context, k CacheKey) error
}

// CacheKey identifies one client's session in a SessionCache.
//
//ds:def id=core-cachekey-mrdw3a5z owner=@khanakia stability=stable
type CacheKey struct {
	// TokenHash is the hash of the request's session token.
	TokenHash []byte
	// Client is what the client sent back from an earlier Put, or "".
	Client string
}

// Session cache TTL bounds.
const (
	// DefaultSessionCacheTTL is used when WithSessionCache gets 0.
	//ds:def id=defaultsessioncachettl-8knzqpgz owner=@khanakia stability=stable
	DefaultSessionCacheTTL = time.Minute
	// MaxSessionCacheTTL caps the TTL: it is how long a revoked or banned
	// session keeps working on a device that holds a cached entry, so it
	// stays short whatever the option says.
	//ds:def id=maxsessioncachettl-2sh2x4n6 owner=@khanakia stability=stable
	MaxSessionCacheTTL = 15 * time.Minute
)

// WithSessionCache puts c in front of the session lookup for ttl per entry:
// 0 means DefaultSessionCacheTTL, more than MaxSessionCacheTTL is clamped to
// it. Built-in caches: NewSnapshotCache (the client holds a sealed copy) and
// NewMemorySessionCache (this process); contrib/redis has a shared one.
//
//ds:def id=opt-withsessioncache-3rwgvmug owner=@khanakia stability=stable
func WithSessionCache(c SessionCache, ttl time.Duration) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithSessionCache", c) {
			return
		}
		s.cache, s.cacheTTL = c, ttl
	}
}

// clampCacheTTL applies the TTL bounds.
func clampCacheTTL(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		return DefaultSessionCacheTTL
	}
	if ttl > MaxSessionCacheTTL {
		return MaxSessionCacheTTL
	}
	return ttl
}

// snapshotAAD binds a sealed snapshot to its purpose; see statelessAAD.
const snapshotAAD = "auth.snapshot.v1"

// snapshot is what the client holds for the snapshot cache.
type snapshot struct {
	Session   Session   `json:"s"`
	User      User      `json:"u"`
	Until     time.Time `json:"until"`
	TokenHash []byte    `json:"h"`
}

// snapshotCache seals the session into a value the client carries. keys are
// checked at the first use, not at construction, because the constructor
// has no error result; a wrong key size is then reported by Get and Put on
// every request, which the first test catches.
type snapshotCache struct {
	keys [][]byte
	once sync.Once
	ring *KeyRing
	err  error
}

// NewSnapshotCache returns a SessionCache that stores nothing on the server:
// Put seals the session and user, with the token hash and the expiry of the
// entry, under the first key (SealKeySize bytes each, AES-256-GCM) and hands
// the client the result; Get opens what the client sent back, with any of
// the keys, and accepts it only for the token it was sealed for, compared in
// constant time, so a snapshot is useless with another session's token. More
// than one key is a rotation: the first seals, every one opens (KeyRing).
// Drop has nothing to forget: the transport clears the client's copy through
// EffectClearCache.
func NewSnapshotCache(keys ...[]byte) SessionCache { return &snapshotCache{keys: keys} }

// keyRing builds the ring once; see snapshotCache.
func (c *snapshotCache) keyRing() (*KeyRing, error) {
	c.once.Do(func() { c.ring, c.err = ringOf("NewSnapshotCache", c.keys) })
	return c.ring, c.err
}

// Get opens the client's snapshot, if it is for this token and still valid.
func (c *snapshotCache) Get(_ context.Context, k CacheKey, now time.Time) (Session, User, bool, error) {
	if k.Client == "" {
		return Session{}, User{}, false, nil
	}
	ring, err := c.keyRing()
	if err != nil {
		return Session{}, User{}, false, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(k.Client)
	if err != nil {
		return Session{}, User{}, false, nil
	}
	plain, err := ring.openRaw(raw, snapshotAAD)
	if err != nil {
		return Session{}, User{}, false, nil
	}
	var snap snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return Session{}, User{}, false, nil
	}
	if !now.Before(snap.Until) || subtle.ConstantTimeCompare(snap.TokenHash, k.TokenHash) != 1 {
		return Session{}, User{}, false, nil
	}
	return snap.Session, snap.User, true, nil
}

// Put seals the entry for the client to hold.
func (c *snapshotCache) Put(_ context.Context, k CacheKey, s Session, u User, until time.Time) (string, error) {
	ring, err := c.keyRing()
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(snapshot{Session: s, User: u, Until: until, TokenHash: k.TokenHash})
	if err != nil {
		return "", fmt.Errorf("auth: encode snapshot: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(ring.sealRaw(plain, snapshotAAD)), nil
}

// Drop is a no-op: the client's copy is cleared by the transport.
func (c *snapshotCache) Drop(context.Context, CacheKey) error { return nil }

// memoryCacheEntry is one cached lookup.
type memoryCacheEntry struct {
	s     Session
	u     User
	until time.Time
}

// memorySessionCache is an in-process cache keyed by token hash.
type memorySessionCache struct {
	mu  sync.Mutex
	max int
	m   map[string]memoryCacheEntry
}

// NewMemorySessionCache returns a SessionCache in this process's memory,
// holding at most maxEntries; when full it drops the entry expiring soonest,
// which is an expired one whenever any is. Per instance, so a revocation on another instance is
// not seen until the entry expires; with several instances use a shared cache.
func NewMemorySessionCache(maxEntries int) SessionCache {
	return &memorySessionCache{max: maxEntries, m: map[string]memoryCacheEntry{}}
}

// Get returns the entry for the token, if still valid.
func (c *memorySessionCache) Get(_ context.Context, k CacheKey, now time.Time) (Session, User, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[hex.EncodeToString(k.TokenHash)]
	if !ok || !now.Before(e.until) {
		return Session{}, User{}, false, nil
	}
	return e.s, e.u, true, nil
}

// Put stores the entry, making room first when the cache is full.
func (c *memorySessionCache) Put(_ context.Context, k CacheKey, s Session, u User, until time.Time) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := hex.EncodeToString(k.TokenHash)
	if _, exists := c.m[key]; !exists && len(c.m) >= c.max {
		c.evictSoonest()
	}
	c.m[key] = memoryCacheEntry{s: s, u: u, until: until}
	return "", nil
}

// evictSoonest drops the entry that expires first. The caller holds mu.
func (c *memorySessionCache) evictSoonest() {
	soonest, soonestAt := "", time.Time{}
	for key, e := range c.m {
		if soonest == "" || e.until.Before(soonestAt) {
			soonest, soonestAt = key, e.until
		}
	}
	delete(c.m, soonest)
}

// Drop forgets the token's entry.
func (c *memorySessionCache) Drop(_ context.Context, k CacheKey) error {
	c.mu.Lock()
	delete(c.m, hex.EncodeToString(k.TokenHash))
	c.mu.Unlock()
	return nil
}

// SessionCacheUserDropper is a SessionCache that can forget every entry of
// one user at once. A server-side cache keeps the entries it hands out, so
// it can find a user's; the snapshot caches cannot, because the client
// holds the only copy, and do not implement it. The core asks for it after
// a write that must reach every device of the user before the TTL: a ban, a
// suspension, revoking sessions, deleting the user (EvictCachedSessions).
//
// Entries are matched by Session.UserID. An entry Put concurrently with the
// drop, from a lookup that read the store before the write committed, may
// survive it; it then lives at most the cache TTL, which is the bound
// without eviction.
//
//ds:def id=core-sessioncacheuserdropper-7mzq4k2w owner=@khanakia stability=stable
type SessionCacheUserDropper interface {
	// DropUser forgets every entry whose session belongs to userID. A user
	// with no entry is not an error.
	DropUser(ctx context.Context, userID string) error
}

// EvictCachedSessions drops every SessionCache entry of userID once the
// transaction in ctx commits, or at once outside one, so a ban or a
// suspension reaches the user's cached devices on their next request
// rather than when the entries expire. After the commit, because a drop
// before it would let a concurrent request cache the old state again.
//
// It reports whether the eviction can happen: false with no cache or a
// cache that is not a SessionCacheUserDropper (the snapshot caches), where
// the user's devices keep their entries until the cache TTL. A failure of
// the cache is logged rather than returned: the write it follows is
// committed, and the entries still expire within the TTL. DeleteSession,
// DeleteUserSessions and DeleteUser call it; a plugin that suspends a user
// without ending sessions calls it itself.
//
//ds:def id=core-evictcachedsessions-4hp9xw3n owner=@khanakia stability=stable
func (a *Auth) EvictCachedSessions(ctx context.Context, userID string) bool {
	d, ok := a.cache.(SessionCacheUserDropper)
	if !ok {
		return false
	}
	a.AfterCommit(ctx, func(ctx context.Context) {
		if err := d.DropUser(ctx, userID); err != nil {
			a.logger.Error("auth: session cache eviction failed", "user", userID, "error", err)
		}
	})
	return true
}

// DropUser forgets every entry of userID. The scan is bounded by the
// cache's size, which is the price of keeping no second index.
func (c *memorySessionCache) DropUser(_ context.Context, userID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, e := range c.m {
		if e.s.UserID == userID {
			delete(c.m, key)
		}
	}
	return nil
}
