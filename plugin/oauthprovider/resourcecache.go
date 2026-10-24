package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/ubgo/auth"
)

// Bounds of CacheResources.
//
//ds:def id=oauthprovider-resourcecache-ttl-5vq8mz2k owner=@khanakia stability=stable
const (
	// DefaultResourceCacheTTL is how long CacheResources keeps a resource
	// when it is given 0.
	DefaultResourceCacheTTL = time.Minute
	// MaxResourceCacheTTL caps CacheResources: a resource disabled or
	// deleted on another instance is served at most this long after.
	MaxResourceCacheTTL = 15 * time.Minute
)

// resourceCacheKeyPrefix starts every cache key, followed by the
// resource's id (the hex SHA-256 of its identifier), so the entries share a
// store with other users of it without colliding and a key never holds a
// caller's raw identifier.
const resourceCacheKeyPrefix = "oauthprovider:resource:"

// ErrBadResourceCacheTTL is a configuration error: a CacheResources TTL
// that is negative or above MaxResourceCacheTTL.
var ErrBadResourceCacheTTL = fmt.Errorf("oauthprovider: the CacheResources TTL is between 0 (the default, %s) and %s", DefaultResourceCacheTTL, MaxResourceCacheTTL)

// CacheResources keeps the registered resources the provider reads when it
// issues, refreshes or introspects a token in this process's memory for ttl
// (0 is DefaultResourceCacheTTL, at most MaxResourceCacheTTL). Without it each
// issuance reads the resource's row by primary key. Off by default.
// CacheResourcesIn keeps them in a store of the app's choosing instead, such as
// Redis.
//
// CreateResource, UpdateResource, PatchResource, SeedResources and
// DeleteResource drop the entry once they have written, so this instance's
// own writes are seen at once (and every instance's, with a shared store).
// What stays true only up to the TTL: a resource created,
// changed, disabled or deleted on another instance with a per-process cache
// (or by SQL), or inside a transaction a concurrent issuance read before it
// committed, is served as it was until the entry expires. Resource and
// Resources, the admin reads, always read the database. An identifier with
// no row is remembered only when it is a ProtectedResource declared in
// code, so a client asking for random identifiers cannot grow the cache. A
// failing store is logged and the database is read instead.
//
//ds:def id=oauthprovider-cacheresources-8xk2wq4n owner=@khanakia stability=stable
func CacheResources(ttl time.Duration) Option {
	return func(p *Plugin) {
		// The store's own expiry runs on the core's clock, the one every
		// entry is judged by; p.core exists by the time anything is stored.
		p.resourceCache = &resourceCache{store: auth.NewMemoryStorage(func() time.Time { return p.core.Now() }), ttl: ttl}
	}
}

// CacheResourcesIn is CacheResources in kv instead of this process's
// memory: any auth.SecondaryStorage, such as contrib/redis's NewStorage or
// the one the app already passes to auth.WithSecondaryStorage, so every
// instance sees one cache and a write on any instance drops the entry for
// all of them. Only Get, Set and Delete are used. Entries carry their own
// expiry, judged by the core's clock, and are stored with ttl so the store
// also forgets them. nil is refused (auth.ErrNilOption).
//
//ds:def id=oauthprovider-cacheresourcesin-4nw7qk2z owner=@khanakia stability=stable
func CacheResourcesIn(kv auth.SecondaryStorage, ttl time.Duration) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.CacheResourcesIn", kv) {
			return
		}
		p.resourceCache = &resourceCache{store: kv, ttl: ttl}
	}
}

// resourceCache is the resource cache over a SecondaryStorage: the core's
// memory storage for CacheResources, the app's for CacheResourcesIn.
type resourceCache struct {
	store auth.SecondaryStorage
	ttl   time.Duration
}

// resourceCacheEntry is one remembered lookup, as stored (JSON): the
// resource, or Found false for an identifier with no row (a code-declared
// ProtectedResource only). Expires is judged by the core's clock, so a
// store's own TTL is only the cleanup.
type resourceCacheEntry struct {
	Resource Resource  `json:"resource"`
	Found    bool      `json:"found"`
	Expires  time.Time `json:"expires"`
}

// validate refuses a TTL outside [0, MaxResourceCacheTTL] and fills the
// default for 0. A nil cache (the option off) is valid.
func (c *resourceCache) validate() error {
	if c == nil {
		return nil
	}
	if c.ttl == 0 {
		c.ttl = DefaultResourceCacheTTL
	}
	if c.ttl < 0 || c.ttl > MaxResourceCacheTTL {
		return ErrBadResourceCacheTTL
	}
	return nil
}

// resourceCacheKey is identifier's key in the store.
func resourceCacheKey(identifier string) string {
	return resourceCacheKeyPrefix + resourceID(identifier)
}

// cached is the fresh entry for identifier, if the store has one. A store
// failure or an entry that does not decode is logged and reads as a miss.
func (p *Plugin) cached(ctx context.Context, identifier string) (resourceCacheEntry, bool) {
	raw, ok, err := p.resourceCache.store.Get(ctx, resourceCacheKey(identifier))
	if err != nil {
		p.core.Logger().Warn("oauthprovider: resource cache get", "error", err)
		return resourceCacheEntry{}, false
	}
	if !ok {
		return resourceCacheEntry{}, false
	}
	var e resourceCacheEntry
	// Plain Unmarshal, as resourceRow decodes the stored custom claims, so
	// a cached resource is the same Go value as one read from the database.
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		p.core.Logger().Warn("oauthprovider: resource cache entry", "error", err)
		return resourceCacheEntry{}, false
	}
	if !p.core.Now().Before(e.Expires) {
		return resourceCacheEntry{}, false
	}
	return e, true
}

// remember stores a lookup until now plus the TTL; a failure is logged.
func (p *Plugin) remember(ctx context.Context, identifier string, e resourceCacheEntry) {
	e.Expires = p.core.Now().Add(p.resourceCache.ttl)
	b, err := json.Marshal(e)
	if err == nil {
		err = p.resourceCache.store.Set(ctx, resourceCacheKey(identifier), string(b), p.resourceCache.ttl)
	}
	if err != nil {
		p.core.Logger().Warn("oauthprovider: resource cache set", "error", err)
	}
}

// dropCached forgets identifier after this instance wrote its row; a nil
// cache (the option off) does nothing. A failure is logged: the entry then
// lives until its expiry.
func (p *Plugin) dropCached(ctx context.Context, identifier string) {
	if p.resourceCache == nil {
		return
	}
	if err := p.resourceCache.store.Delete(ctx, resourceCacheKey(identifier)); err != nil {
		p.core.Logger().Warn("oauthprovider: resource cache delete", "error", err)
	}
}

// lookupResource is Resource through the cache when one is configured: the
// read every issuance makes (policyOf, resourceKnown). A database error is
// never cached.
func (p *Plugin) lookupResource(ctx context.Context, identifier string) (Resource, error) {
	if p.resourceCache == nil {
		return p.Resource(ctx, identifier)
	}
	if e, ok := p.cached(ctx, identifier); ok {
		if !e.Found {
			return Resource{}, ErrInvalidTarget
		}
		return e.Resource, nil
	}
	r, err := p.Resource(ctx, identifier)
	switch {
	case err == nil:
		p.remember(ctx, identifier, resourceCacheEntry{Resource: r, Found: true})
	case errors.Is(err, ErrInvalidTarget) && slices.ContainsFunc(p.resources, func(s resourceSpec) bool { return s.url == identifier }):
		p.remember(ctx, identifier, resourceCacheEntry{})
	}
	return r, err
}
