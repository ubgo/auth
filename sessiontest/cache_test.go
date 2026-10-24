package sessiontest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func TestRunCache_PassesTheCoreCaches(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		RunCache(t, func(*testing.T) auth.SessionCache { return auth.NewMemorySessionCache(16) })
	})
	t.Run("sealed snapshot", func(t *testing.T) {
		RunCache(t, func(*testing.T) auth.SessionCache { return auth.NewSnapshotCache(make([]byte, auth.SealKeySize)) })
	})
	t.Run("signed compact", func(t *testing.T) {
		RunCache(t, func(*testing.T) auth.SessionCache { return auth.NewCompactSessionCache(make([]byte, auth.SealKeySize)) })
	})
}

// runCache runs every cache case against a fresh cache from open and
// returns the failures by case name.
func runCache(open func() auth.SessionCache) map[string]string {
	out := map[string]string{}
	for name, c := range cacheCases {
		func() {
			t := &fakeT{}
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(stop); !ok {
						panic(r)
					}
					out[name] = t.failure
				}
			}()
			c(t, open())
		}()
	}
	return out
}

// brokenCache wraps a working cache and overrides one method when its field
// is set.
type brokenCache struct {
	auth.SessionCache
	get  func(ctx context.Context, k auth.CacheKey, now time.Time) (auth.Session, auth.User, bool, error)
	put  func(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, until time.Time) (string, error)
	drop func(ctx context.Context, k auth.CacheKey) error
}

func (b *brokenCache) Get(ctx context.Context, k auth.CacheKey, now time.Time) (auth.Session, auth.User, bool, error) {
	if b.get != nil {
		return b.get(ctx, k, now)
	}
	return b.SessionCache.Get(ctx, k, now)
}

func (b *brokenCache) Put(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, until time.Time) (string, error) {
	if b.put != nil {
		return b.put(ctx, k, s, u, until)
	}
	return b.SessionCache.Put(ctx, k, s, u, until)
}

func (b *brokenCache) Drop(ctx context.Context, k auth.CacheKey) error {
	if b.drop != nil {
		return b.drop(ctx, k)
	}
	return b.SessionCache.Drop(ctx, k)
}

func TestRunCache_CatchesEachBrokenRule(t *testing.T) {
	errBroken := errors.New("broken cache")
	for name, tc := range map[string]struct {
		open func() auth.SessionCache
		want string
	}{
		"a lost field": {func() auth.SessionCache {
			c := auth.NewMemorySessionCache(16)
			return &brokenCache{SessionCache: c, put: func(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, until time.Time) (string, error) {
				s.Data = nil
				return c.Put(ctx, k, s, u, until)
			}}
		}, "an entry comes back whole for its token"},
		"no expiry": {func() auth.SessionCache {
			c := auth.NewMemorySessionCache(16)
			return &brokenCache{SessionCache: c, put: func(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, _ time.Time) (string, error) {
				return c.Put(ctx, k, s, u, now.Add(24*time.Hour))
			}}
		}, "an entry is used until its expiry and never at or after it"},
		"one entry for every token": {func() auth.SessionCache {
			c := auth.NewMemorySessionCache(16)
			one := func(auth.CacheKey) auth.CacheKey { return auth.CacheKey{TokenHash: hash("the one")} }
			return &brokenCache{SessionCache: c,
				put: func(ctx context.Context, k auth.CacheKey, s auth.Session, u auth.User, until time.Time) (string, error) {
					return c.Put(ctx, one(k), s, u, until)
				},
				get: func(ctx context.Context, k auth.CacheKey, at time.Time) (auth.Session, auth.User, bool, error) {
					return c.Get(ctx, one(k), at)
				}}
		}, "an entry is never used with another token"},
		"a client copy that fails instead of missing": {func() auth.SessionCache {
			c := auth.NewSnapshotCache(make([]byte, auth.SealKeySize))
			return &brokenCache{SessionCache: c, get: func(ctx context.Context, k auth.CacheKey, at time.Time) (auth.Session, auth.User, bool, error) {
				s, u, ok, err := c.Get(ctx, k, at)
				if !ok && k.Client != "" {
					return s, u, false, errBroken
				}
				return s, u, ok, err
			}}
		}, "a changed or made-up client copy is a miss"},
		"a Drop that forgets nothing": {func() auth.SessionCache {
			return &brokenCache{SessionCache: auth.NewMemorySessionCache(16), drop: func(context.Context, auth.CacheKey) error { return nil }}
		}, "a server-side entry needs no client copy and is forgotten by Drop"},
		"a Drop that fails": {func() auth.SessionCache {
			return &brokenCache{SessionCache: auth.NewMemorySessionCache(16), drop: func(context.Context, auth.CacheKey) error { return errBroken }}
		}, "Drop of an entry never put does not fail"},
	} {
		t.Run(name, func(t *testing.T) {
			failures := runCache(tc.open)
			if _, ok := failures[tc.want]; !ok {
				t.Fatalf("case %q did not catch it; failures: %v", tc.want, failures)
			}
			for got := range failures {
				if strings.TrimSpace(got) == "" {
					t.Fatal("a failure without a case name")
				}
			}
		})
	}
}

func TestRunCache_CatchesAFailingPut(t *testing.T) {
	failures := runCache(func() auth.SessionCache {
		return &brokenCache{SessionCache: auth.NewMemorySessionCache(16), put: func(context.Context, auth.CacheKey, auth.Session, auth.User, time.Time) (string, error) {
			return "", errors.New("broken cache")
		}}
	})
	if !strings.Contains(failures["an entry comes back whole for its token"], "Put") {
		t.Fatalf("failures = %v", failures)
	}
}

func TestRunCache_CatchesACacheThatForgetsEverything(t *testing.T) {
	failures := runCache(func() auth.SessionCache {
		return &brokenCache{SessionCache: auth.NewMemorySessionCache(16), get: func(context.Context, auth.CacheKey, time.Time) (auth.Session, auth.User, bool, error) {
			return auth.Session{}, auth.User{}, false, nil
		}}
	})
	for _, want := range []string{"an entry comes back whole for its token", "an entry is used until its expiry and never at or after it", "a server-side entry needs no client copy and is forgotten by Drop"} {
		if _, ok := failures[want]; !ok {
			t.Errorf("case %q did not catch it; failures: %v", want, failures)
		}
	}
}
