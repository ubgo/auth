package apikey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func TestConfigurations_Validate(t *testing.T) {
	wire := func(opts ...Option) error {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(append([]Option{Scopes("s")}, opts...)...)))
		return err
	}
	for name, opts := range map[string][]Option{
		"empty id":        {Configuration("", Prefix("sk_x_"))},
		"default id":      {Configuration(DefaultConfig, Prefix("sk_x_"))},
		"bad id":          {Configuration("live key", Prefix("sk_x_"))},
		"long id":         {Configuration("a234567890123456789012345678901234", Prefix("sk_x_"))},
		"repeated id":     {Configuration("live", Prefix("sk_x_")), Configuration("live", Prefix("sk_y_"))},
		"nested":          {Configuration("live", Configuration("inner"))},
		"cache inside":    {Configuration("live", WithCache(NewMemoryCache(), 0))},
		"distinct inside": {Configuration("live", DistinctErrors())},
		"defer inside":    {Configuration("live", DeferUpdates())},
	} {
		if err := wire(opts...); !errors.Is(err, ErrBadConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A configuration's own rules are checked too, and name it.
	if err := wire(Configuration("live", Prefix("x"))); !errors.Is(err, ErrBadPrefix) {
		t.Fatalf("bad prefix in a configuration: %v", err)
	}
	if err := wire(DefaultScopes("undeclared")); !errors.Is(err, ErrBadScope) {
		t.Fatalf("undeclared default scope: %v", err)
	}
	if err := wire(AllowKeyPrefix(-1)); !errors.Is(err, ErrBadLimits) {
		t.Fatalf("negative key prefix bound: %v", err)
	}
	for name, ttl := range map[string]time.Duration{"negative": -time.Second, "too long": MaxCacheTTL + time.Second} {
		if err := wire(WithCache(NewMemoryCache(), ttl)); !errors.Is(err, ErrBadCacheTTL) {
			t.Errorf("cache %s: %v", name, err)
		}
	}
	if err := wire(Configuration("live", Prefix("sk_live_")), Configuration("test", Prefix("sk_test_")), WithCache(NewMemoryCache(), 0)); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurations_InheritAndRoute(t *testing.T) {
	p := New(Scopes("a"), MaxKeys(3), RequireName(), Configuration("live", Prefix("sk_live_"), Scopes("b"), MaxKeys(7)), Prefix("ak_"))
	if _, err := auth.New(auth.WithPlugins(stubSignIn{}, p)); err != nil {
		t.Fatal(err)
	}
	live, ok := p.config("live")
	if !ok || live.prefix != "sk_live_" || live.maxKeys != 7 || !live.requireName || len(live.scopes) != 2 {
		t.Fatalf("live = %+v", live)
	}
	// The default is untouched by the configuration's options, and an
	// option given after the Configuration is still inherited.
	if def, _ := p.config(""); def.prefix != "ak_" || def.maxKeys != 3 || len(def.scopes) != 1 {
		t.Fatalf("default = %+v", def)
	}
	if got := p.TokenPrefixes(); len(got) != 2 || got[0] != "ak_" || got[1] != "sk_live_" {
		t.Fatalf("prefixes = %v", got)
	}
	if _, ok := p.config("nope"); ok {
		t.Fatal("an unknown configuration was found")
	}
	// The longest matching prefix chooses the configuration.
	q := New(Scopes("a"), Prefix("sk_"), Configuration("live", Prefix("sk_live_")))
	if s, ok := q.configForKey("sk_live_abc"); !ok || s.id != "live" {
		t.Fatalf("longest = %+v", s)
	}
	if s, ok := q.configForKey("sk_abc"); !ok || s.id != DefaultConfig {
		t.Fatalf("shorter = %+v", s)
	}
	if _, ok := q.configForKey("zz_abc"); ok {
		t.Fatal("a foreign key matched")
	}
}

func TestKeyPrefixAndScopes(t *testing.T) {
	s := &settings{prefix: "ak_"}
	if got, err := s.keyPrefix(""); err != nil || got != "ak_" {
		t.Fatalf("none = %q %v", got, err)
	}
	if _, err := s.keyPrefix("acme"); !errors.Is(err, ErrBadKeyPrefix) {
		t.Fatalf("not allowed: %v", err)
	}
	s.keyPrefixMax = 5
	if got, err := s.keyPrefix("ac_m-"); err != nil || got != "ak_ac_m-" {
		t.Fatalf("allowed = %q %v", got, err)
	}
	for _, bad := range []string{"acme12", "ac.me", "ac me"} {
		if _, err := s.keyPrefix(bad); !errors.Is(err, ErrBadKeyPrefix) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if New(AllowKeyPrefix(0)).keyPrefixMax != maxKeyPrefixLength {
		t.Fatal("AllowKeyPrefix(0) is not the default bound")
	}
	ctx := context.Background()
	s.defaultScopes = []string{"d"}
	if got := s.scopesFor(ctx, "u", nil); len(got) != 1 || got[0] != "d" {
		t.Fatalf("defaults = %v", got)
	}
	if got := s.scopesFor(ctx, "u", []string{}); len(got) != 0 {
		t.Fatalf("explicit empty = %v", got)
	}
	s.defaultScopesFn = func(_ context.Context, userID string) []string { return []string{userID} }
	if got := s.scopesFor(ctx, "u", nil); len(got) != 1 || got[0] != "u" {
		t.Fatalf("function = %v", got)
	}
}

func TestMemoryCache(t *testing.T) {
	now := time.Unix(1000, 0)
	m := NewMemoryCacheAt(func() time.Time { return now })
	ctx := context.Background()
	if _, ok, err := m.Get(ctx, "k"); ok || err != nil {
		t.Fatal("empty cache hit")
	}
	if err := m.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := m.Set(ctx, "short", []byte("s"), time.Second); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := m.Get(ctx, "k"); !ok || string(v) != "v" {
		t.Fatalf("hit = %q %v", v, ok)
	}
	now = now.Add(2 * time.Second)
	if n := m.Prune(); n != 1 {
		t.Fatalf("pruned %d, want the short entry", n)
	}
	now = now.Add(time.Minute)
	if _, ok, _ := m.Get(ctx, "k"); ok {
		t.Fatal("expired entry hit")
	}
	if err := m.Set(ctx, "d", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, "d"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := m.Get(ctx, "d"); ok {
		t.Fatal("deleted entry hit")
	}
	if NewMemoryCache().now == nil {
		t.Fatal("no clock")
	}
}

func TestCacheEntry_RoundTrip(t *testing.T) {
	remaining, prefix, meta := int64(3), "ak_", `{"a":1}`
	start := time.Unix(50, 0).UTC()
	r := keyRow{k: Key{ID: "key_1", Name: "n", Hint: "ak_x"}, userID: "usr_1", scopes: "a b", metadata: &meta, rateMax: 2, rateWindow: 60,
		rateCount: 1, windowStart: &start, remaining: &remaining, refillAmt: 4, refillEvery: 3600, configID: "live", prefix: &prefix, hash: []byte{1, 2}}
	r.k = r.key()
	got := entryOf(r).row(r.hash)
	if got.k.Config != "live" || got.k.Prefix != "ak_" || len(got.k.Scopes) != 2 || *got.remaining != 3 || got.rateCount != 1 || !got.windowStart.Equal(start) ||
		string(got.k.Metadata) != meta || got.userID != "usr_1" || got.k.Limits.RefillAmount != 4 || string(got.hash) != string(r.hash) {
		t.Fatalf("round trip = %+v", got)
	}
	if cacheKey([]byte{0xab}) != cacheKeyPrefix+"ab" {
		t.Fatal("cache key")
	}
}

func TestRefusals(t *testing.T) {
	p := New(Scopes("s"))
	if !errors.Is(p.refuse(ErrKeyDisabled), auth.ErrSignedOut) {
		t.Fatal("the default named a refusal")
	}
	p.distinct = true
	if !errors.Is(p.refuse(ErrKeyDisabled), ErrKeyDisabled) {
		t.Fatal("DistinctErrors kept it silent")
	}
	for _, err := range []error{auth.ErrSignedOut, auth.ErrRateLimited, ErrUsageExceeded, ErrInvalidKey, ErrKeyDisabled, ErrKeyExpired, ErrKeyOwnerGone} {
		if !isRefusal(err) {
			t.Errorf("%v is not a refusal", err)
		}
	}
	if isRefusal(errors.New("database down")) {
		t.Fatal("an infrastructure error read as a refusal")
	}
}
