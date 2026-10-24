// Package redisrate keeps auth's shared state on Redis, for apps that run
// several instances and already operate Redis: an auth.RateStore (New), an
// auth.SessionStore (NewSessionStore) and an auth.SessionCache
// (NewSessionCache). It is a separate module so go-redis reaches only the
// apps that use it; auth.WithDBRateStore needs no new infrastructure at all.
package redisrate

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
)

// DefaultKeyPrefix namespaces the counters in a shared Redis, so they never
// collide with the app's own keys.
//
//ds:def id=defaultkeyprefix-a9s33p3m owner=@khanakia stability=stable
const DefaultKeyPrefix = "ubgo:auth:rate:"

// slotSeparator joins a limiter key to its window number. The limiter's keys
// already use "|" between their parts, so the window number is always the
// last "|"-separated field of a Redis key.
const slotSeparator = "|"

// Store counts hits in fixed windows: one Redis key per key and window, set
// to expire with the window. It needs Redis 7 or later (EXPIRE NX). INCR and
// EXPIRE run in one MULTI, so a counter can never be left without its expiry
// and live forever.
type Store struct {
	optionErr
	client redis.Cmdable
	prefix string
	now    func() time.Time
}

// config is what every constructor in this package reads from its options.
// An empty prefix means the constructor's own default.
type config struct {
	// optErrs collects the options given nil (auth.ErrNilOption); each
	// constructor hands them to its store (optionErr).
	optErrs auth.OptionErrors
	prefix  string
	now     func() time.Time
}

// Option configures New, NewSessionStore and NewSessionCache.
type Option func(*config)

// KeyPrefix overrides the constructor's default prefix (DefaultKeyPrefix,
// DefaultSessionKeyPrefix or DefaultCacheKeyPrefix), for two apps sharing one
// Redis that must not share state, or a test that must not see another
// run's keys.
func KeyPrefix(p string) Option { return func(c *config) { c.prefix = p } }

// Clock replaces time.Now; tests pass the same clock as auth.WithClock. The
// rate store counts windows with it. The session store and cache take every
// instant from the core and use it only to turn an expiry into a Redis TTL.
func Clock(now func() time.Time) Option {
	return func(c *config) {
		if c.optErrs.RefuseNil("redisrate.Clock", now) {
			return
		}
		c.now = now
	}
}

// optionErr carries what a constructor's options recorded (a nil Clock) into
// the value it builds. Embedded in every store, so each is an
// auth.OptionChecker and auth.New refuses to start with it instead of the
// first call panicking on the nil clock.
type optionErr struct{ err error }

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming Clock(nil); auth.New refuses to start while it is not nil.
func (o optionErr) OptionErr() error { return o.err }

// newConfig applies opts over the constructor's default prefix.
func newConfig(defaultPrefix string, opts []Option) config {
	c := config{prefix: defaultPrefix, now: time.Now}
	for _, o := range opts {
		o(&c)
	}
	return c
}

var _ auth.RateStore = (*Store)(nil)

// New wraps a go-redis client: *redis.Client, *redis.ClusterClient or a ring.
// The store owns no connection; closing the client is the app's job.
//
//ds:def id=new-fgn22edu
func New(client redis.Cmdable, opts ...Option) *Store {
	c := newConfig(DefaultKeyPrefix, opts)
	return &Store{optionErr: optionErr{c.optErrs.OptionErr()}, client: client, prefix: c.prefix, now: c.now}
}

// Hit adds one to key's counter for the window that contains now and returns
// the new count. A Redis failure is an error, never a count of zero, because
// zero would read as "under the limit" and let every request through.
//
// window must be positive; auth.New refuses a rate rule without one, which is
// the only caller.
func (s *Store) Hit(ctx context.Context, key string, window time.Duration) (int, error) {
	slot := s.now().UnixNano() / int64(window)
	k := s.prefix + key + slotSeparator + strconv.FormatInt(slot, 10)
	var incr *redis.IntCmd
	_, err := s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		incr = p.Incr(ctx, k)
		p.ExpireNX(ctx, k, window)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("redisrate: %w", err)
	}
	return int(incr.Val()), nil
}

// Peek returns key's count in the window that contains now without adding
// to it (auth.RatePeeker), 0 when the window has no counter yet. A Redis
// failure is an error, never a zero.
func (s *Store) Peek(ctx context.Context, key string, window time.Duration) (int, error) {
	slot := s.now().UnixNano() / int64(window)
	n, err := s.client.Get(ctx, s.prefix+key+slotSeparator+strconv.FormatInt(slot, 10)).Int()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("redisrate: %w", err)
	}
	return n, nil
}

var _ auth.RatePeeker = (*Store)(nil)

// Clear deletes every counter under the store's prefix, for a test that
// wants a clean slate or an operator resetting limits after an incident; see
// the package-level Clear for what it scans.
func (s *Store) Clear(ctx context.Context) error { return Clear(ctx, s.client, s.prefix) }

// scanBatch is how many keys one SCAN asks for and one DEL removes: large
// enough that a store of thousands of keys clears in a few round trips,
// small enough that no single command blocks Redis for long.
//
//ds:def id=redis-scanbatch-6pw3qk8m owner=@khanakia stability=stable
const scanBatch = 1000

// Clear deletes every key that starts with prefix, in batches of scanBatch,
// with SCAN rather than KEYS so a large Redis is never blocked by one
// command. It is what the three stores' Clear methods run, exported for an
// app that namespaced its keys under a prefix of its own. Nothing in the
// library calls it: a store never deletes what it did not write, and a clear
// during traffic would sign every session out (session store), let every
// client through once (rate store) or merely refetch (cache), so it is for
// tests and maintenance, run on purpose. SCAN sees the node the client is
// connected to; on a Redis Cluster run it through ForEachMaster, and on a
// ring once per shard.
//
//ds:def id=redis-clear-4kn9xw2t owner=@khanakia stability=stable
func Clear(ctx context.Context, client redis.Cmdable, prefix string) error {
	var cursor uint64
	for {
		keys, next, err := client.Scan(ctx, cursor, prefix+"*", scanBatch).Result()
		if err != nil {
			return fmt.Errorf("redisrate: clear: %w", err)
		}
		if len(keys) > 0 {
			if err := client.Del(ctx, keys...).Err(); err != nil {
				return fmt.Errorf("redisrate: clear: %w", err)
			}
		}
		if next == 0 {
			return nil
		}
		cursor = next
	}
}
