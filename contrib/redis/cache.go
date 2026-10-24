package redisrate

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
)

// DefaultCacheKeyPrefix namespaces the session cache keys in a shared Redis.
const DefaultCacheKeyPrefix = "ubgo:auth:cache:"

// SessionCache keeps looked-up sessions in Redis for a short time, so every
// instance skips the session lookup after the first. Entries are keyed by the
// token hash and expire with the TTL the core chose; the client holds
// nothing, so Put returns "". Each Put also files the entry's key in a set
// per user (prefix + "user:" + user id) so DropUser can find them: the core
// evicts a user's entries when their sessions end, a ban included
// (auth.EvictCachedSessions), so the end reaches every instance at once.
type SessionCache struct {
	optionErr
	client redis.Cmdable
	prefix string
	now    func() time.Time
}

var (
	_ auth.SessionCache            = (*SessionCache)(nil)
	_ auth.SessionCacheUserDropper = (*SessionCache)(nil)
)

// userSetInfix separates a user's index set from the entry keys, which are
// hex and so never contain it.
const userSetInfix = "user:"

// NewSessionCache wraps a go-redis client. Pass it to auth.WithSessionCache.
//
//ds:def id=newsessioncache-6jfraqyb
func NewSessionCache(client redis.Cmdable, opts ...Option) *SessionCache {
	c := newConfig(DefaultCacheKeyPrefix, opts)
	return &SessionCache{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix, now: c.now}
}

// cacheEntry is what one key holds. Until is kept so a Get is judged by the
// core's clock, not only by Redis's TTL.
type cacheEntry struct {
	Session auth.Session `json:"s"`
	User    auth.User    `json:"u"`
	Until   time.Time    `json:"until"`
}

func (c *SessionCache) key(k auth.CacheKey) string { return c.prefix + hex.EncodeToString(k.TokenHash) }

// userKey is the set holding the entry keys of userID.
func (c *SessionCache) userKey(userID string) string { return c.prefix + userSetInfix + userID }

// Get returns the entry for k when it is still valid at now.
func (c *SessionCache) Get(ctx context.Context, k auth.CacheKey, now time.Time) (auth.Session, auth.User, bool, error) {
	raw, err := c.client.Get(ctx, c.key(k)).Bytes()
	if errors.Is(err, redis.Nil) {
		return auth.Session{}, auth.User{}, false, nil
	}
	if err != nil {
		return auth.Session{}, auth.User{}, false, fmt.Errorf("redisrate: read cache: %w", err)
	}
	var e cacheEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return auth.Session{}, auth.User{}, false, fmt.Errorf("redisrate: decode cache: %w", err)
	}
	if !e.Until.After(now) {
		return auth.Session{}, auth.User{}, false, nil
	}
	return e.Session, e.User, true, nil
}

// Put stores the entry until until, with a Redis TTL of the same length by
// this process's clock. An entry that would already be expired is not
// written.
func (c *SessionCache) Put(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, until time.Time) (string, error) {
	ttl := until.Sub(c.now())
	if ttl <= 0 {
		return "", nil
	}
	// A session, a user and a time are plain values; encoding cannot fail.
	raw, _ := json.Marshal(cacheEntry{Session: s, User: u, Until: until})
	key, set := c.key(k), c.userKey(s.UserID)
	// Not MULTI: the entry and the set hash to different cluster slots. The
	// set lives as long as its longest entry (EXPIRE GT after the first,
	// which NX sets); a key left in it after its entry expired costs one
	// DEL of nothing.
	_, err := c.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		p.Set(ctx, key, raw, ttl)
		p.SAdd(ctx, set, key)
		p.ExpireNX(ctx, set, ttl)
		p.ExpireGT(ctx, set, ttl)
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("redisrate: write cache: %w", err)
	}
	return "", nil
}

// DropUser forgets every entry of userID: the keys filed in its set, then
// the set.
func (c *SessionCache) DropUser(ctx context.Context, userID string) error {
	set := c.userKey(userID)
	keys, err := c.client.SMembers(ctx, set).Result()
	if err != nil {
		return fmt.Errorf("redisrate: read cache index: %w", err)
	}
	// One DEL per key, not one DEL of many: the keys hash to different
	// cluster slots.
	_, err = c.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		for _, k := range keys {
			p.Del(ctx, k)
		}
		p.Del(ctx, set)
		return nil
	})
	if err != nil {
		return fmt.Errorf("redisrate: drop user cache: %w", err)
	}
	return nil
}

// Drop forgets the entry for k.
func (c *SessionCache) Drop(ctx context.Context, k auth.CacheKey) error {
	if err := c.client.Del(ctx, c.key(k)).Err(); err != nil {
		return fmt.Errorf("redisrate: drop cache: %w", err)
	}
	return nil
}

// Clear drops every cached entry under the cache's prefix. The next request
// of each session goes to the store once; nothing is signed out. See the
// package-level Clear.
func (c *SessionCache) Clear(ctx context.Context) error { return Clear(ctx, c.client, c.prefix) }
