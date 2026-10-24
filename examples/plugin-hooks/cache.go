package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/ubgo/auth"
)

// countingCache is a SessionCache of the app's own: it wraps the in-process
// cache and counts hits and misses, which is how an app finds out what a
// cache saves it before choosing one. A real custom cache would talk to a
// shared store instead of delegating; the contract it keeps is the same, and
// the core gives it every time it needs (now, until), so it holds no clock.
//
//ds:def id=hooks-countingcache-8v7wkjw9 owner=@khanakia stability=stable
type countingCache struct {
	next         auth.SessionCache
	hits, misses atomic.Int64
}

// newCountingCache wraps next.
func newCountingCache(next auth.SessionCache) *countingCache { return &countingCache{next: next} }

// Get answers from the wrapped cache and counts the outcome.
func (c *countingCache) Get(ctx context.Context, k auth.CacheKey, now time.Time) (auth.Session, auth.User, bool, error) {
	s, u, ok, err := c.next.Get(ctx, k, now)
	if ok {
		c.hits.Add(1)
	} else {
		c.misses.Add(1)
	}
	return s, u, ok, err
}

// Put remembers a looked-up session until until.
func (c *countingCache) Put(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, until time.Time) (string, error) {
	return c.next.Put(ctx, k, s, u, until)
}

// Drop forgets the entry for this token.
func (c *countingCache) Drop(ctx context.Context, k auth.CacheKey) error { return c.next.Drop(ctx, k) }
