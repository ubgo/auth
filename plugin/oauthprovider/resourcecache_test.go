package oauthprovider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestCacheResources_TTL: 0 is DefaultResourceCacheTTL for both options,
// and auth.New refuses a negative TTL or one above MaxResourceCacheTTL;
// without either option there is no cache. The cache's behaviour against
// every engine, for the default and a plugged store, is integration's
// TestOAuthProvider_CacheResources.
func TestCacheResources_TTL(t *testing.T) {
	build := func(opts ...Option) (*Plugin, error) {
		j := newSigner(testIssuer)
		p := New(j, append([]Option{Issuer(testIssuer), LoginPage("/login")}, opts...)...)
		_, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), j, p))
		return p, err
	}
	if p, err := build(); err != nil || p.resourceCache != nil {
		t.Fatalf("off by default: %v", err)
	}
	kv := auth.NewMemoryStorage(nil)
	for name, opt := range map[string]func(time.Duration) Option{
		"CacheResources":   CacheResources,
		"CacheResourcesIn": func(ttl time.Duration) Option { return CacheResourcesIn(kv, ttl) },
	} {
		if p, err := build(opt(0)); err != nil || p.resourceCache.ttl != DefaultResourceCacheTTL {
			t.Fatalf("%s(0): %v", name, err)
		}
		if _, err := build(opt(MaxResourceCacheTTL)); err != nil {
			t.Fatalf("%s(MaxResourceCacheTTL): %v", name, err)
		}
		for _, ttl := range []time.Duration{-time.Second, MaxResourceCacheTTL + time.Second} {
			if _, err := build(opt(ttl)); !errors.Is(err, ErrBadResourceCacheTTL) {
				t.Errorf("%s(%s) = %v, want ErrBadResourceCacheTTL", name, ttl, err)
			}
		}
	}
}

// brokenKV is a SecondaryStorage whose every call fails, or whose Get
// answers garbage.
type brokenKV struct {
	auth.SecondaryStorage
	garbage bool
}

func (b brokenKV) Get(context.Context, string) (string, bool, error) {
	if b.garbage {
		return "{not json", true, nil
	}
	return "", false, errors.New("store down")
}

func (brokenKV) Set(context.Context, string, string, time.Duration) error {
	return errors.New("store down")
}

func (brokenKV) Delete(context.Context, string) error { return errors.New("store down") }

// TestResourceCache_Entries: an entry is served until its expiry and not
// at it, by the core's clock; dropCached forgets it and is a no-op with the
// cache off; a failing store or an entry that does not decode reads as a
// miss (the caller then reads the database), and failing writes are only
// logged.
func TestResourceCache_Entries(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	ctx := context.Background()
	p := newJWKSPlugin(t, &now, nil)
	p.dropCached(ctx, "https://r")
	p.resourceCache = &resourceCache{store: auth.NewMemoryStorage(func() time.Time { return now }), ttl: time.Minute}
	p.remember(ctx, "https://r", resourceCacheEntry{Resource: Resource{Identifier: "https://r", CustomClaims: map[string]any{"n": 1.5}}, Found: true})
	now = now.Add(time.Minute - time.Nanosecond)
	if e, ok := p.cached(ctx, "https://r"); !ok || e.Resource.Identifier != "https://r" || e.Resource.CustomClaims["n"] != 1.5 {
		t.Fatalf("a fresh entry was not served: %+v %v", e, ok)
	}
	now = now.Add(time.Nanosecond)
	if _, ok := p.cached(ctx, "https://r"); ok {
		t.Fatal("an entry was served at its expiry")
	}
	p.remember(ctx, "https://r", resourceCacheEntry{Found: true})
	p.dropCached(ctx, "https://r")
	if _, ok := p.cached(ctx, "https://r"); ok {
		t.Fatal("dropCached kept the entry")
	}
	for _, kv := range []brokenKV{{}, {garbage: true}} {
		p.resourceCache = &resourceCache{store: kv, ttl: time.Minute}
		p.remember(ctx, "https://r", resourceCacheEntry{Found: true})
		p.dropCached(ctx, "https://r")
		if _, ok := p.cached(ctx, "https://r"); ok {
			t.Fatalf("a broken store (garbage %v) was served", kv.garbage)
		}
	}
}
