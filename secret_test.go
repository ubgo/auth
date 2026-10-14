package auth_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// appSecret is a valid secret for these tests, exactly the minimum.
var appSecret = bytes.Repeat([]byte("s"), auth.MinSecretSize)

func TestWithSecret_DerivesDistinctStableKeys(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(appSecret))
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.Config()
	if !cfg.HasSecret() {
		t.Fatal("HasSecret must be true")
	}
	k1, err := cfg.DeriveKey("twofactor")
	if err != nil || len(k1) != auth.SealKeySize {
		t.Fatalf("DeriveKey = %x, %v", k1, err)
	}
	k2, _ := cfg.DeriveKey("twofactor")
	if !bytes.Equal(k1, k2) {
		t.Fatal("the same label must give the same key")
	}
	k3, _ := cfg.DeriveKey("oauth")
	if bytes.Equal(k1, k3) {
		t.Fatal("different labels must give different keys")
	}
	if bytes.Contains(k1, appSecret[:8]) || bytes.Equal(k1, appSecret) {
		t.Fatal("a derived key must not contain the secret")
	}
	// Another secret, another key.
	b, _ := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(bytes.Repeat([]byte("t"), auth.MinSecretSize)))
	k4, _ := b.Config().DeriveKey("twofactor")
	if bytes.Equal(k1, k4) {
		t.Fatal("different secrets must give different keys")
	}
	if _, err := cfg.DeriveKey(""); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("empty label: %v", err)
	}
	// Without a secret: ErrNoSecret, and HasSecret is false.
	none, _ := newAuth(auth.WithPlugins(basic("s")))
	if none.Config().HasSecret() {
		t.Fatal("HasSecret without WithSecret")
	}
	if _, err := none.Config().DeriveKey("twofactor"); !errors.Is(err, auth.ErrNoSecret) {
		t.Fatalf("no secret: %v", err)
	}
}

func TestNew_RefusesAShortOrEmptySecret(t *testing.T) {
	for name, secret := range map[string][]byte{"empty from an unset variable": []byte(""), "nil": nil, "31 bytes": appSecret[:31]} {
		if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(secret)); !errors.Is(err, auth.ErrSecretTooShort) {
			t.Errorf("%s: got %v, want ErrSecretTooShort", name, err)
		}
	}
}

func TestWithSecret_FeedsStatelessSessionsAndTheSnapshotCache(t *testing.T) {
	// No key anywhere: refused at New, naming the option.
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithStatelessSessions()); !errors.Is(err, auth.ErrNoKeys) || !strings.Contains(err.Error(), "WithSecret") {
		t.Fatalf("stateless with no key and no secret: %v", err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSessionCache(auth.NewSnapshotCache(), time.Minute)); !errors.Is(err, auth.ErrNoKeys) || !strings.Contains(err.Error(), "WithSecret") {
		t.Fatalf("snapshot cache with no key and no secret: %v", err)
	}
	// The stateless store's derived key is proven in the internal test
	// (TestWithSecret_StatelessInstancesShareTheDerivedKey).
	// The derived snapshot cache seals and opens too.
	ctx := context.Background()
	c := auth.NewSnapshotCache()
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(appSecret), auth.WithSessionCache(c, time.Minute)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	key := auth.CacheKey{TokenHash: auth.HashToken("t")}
	v, err := c.Put(ctx, key, auth.Session{ID: "s", UserID: "u"}, auth.User{ID: "u"}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, u, ok, err := c.Get(ctx, auth.CacheKey{TokenHash: key.TokenHash, Client: v}, now); err != nil || !ok || u.ID != "u" {
		t.Fatalf("derived snapshot cache: ok=%v u=%+v err=%v", ok, u, err)
	}
}

func TestEnvOptions_ReadsTheSecret(t *testing.T) {
	env := map[string]string{auth.EnvSecret: string(appSecret)}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	opts, err := auth.EnvOptions(lookup)
	if err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(append(opts, auth.WithPlugins(signIn{on: true}))...)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Config().HasSecret() {
		t.Fatal("the secret from the environment was not applied")
	}
	// Set but empty is passed on and refused by New, never silently none.
	env[auth.EnvSecret] = ""
	opts, err = auth.EnvOptions(lookup)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.New(append(opts, auth.WithPlugins(signIn{on: true}))...); !errors.Is(err, auth.ErrSecretTooShort) {
		t.Fatalf("empty AUTH_SECRET: %v", err)
	}
	// Unset: no option, no secret.
	delete(env, auth.EnvSecret)
	opts, _ = auth.EnvOptions(lookup)
	a, _ = auth.New(append(opts, auth.WithPlugins(signIn{on: true}))...)
	if a.Config().HasSecret() {
		t.Fatal("an unset variable must leave no secret")
	}
	if !strings.Contains(strings.Join(auth.EnvVars, ","), auth.EnvSecret) {
		t.Fatal("EnvVars must list the secret")
	}
}

func TestWithSecret_RotationKeepsOldKeysOpening(t *testing.T) {
	old := bytes.Repeat([]byte("o"), auth.MinSecretSize)
	cur := bytes.Repeat([]byte("n"), auth.MinSecretSize)
	before, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(old))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(cur, old))
	if err != nil {
		t.Fatal(err)
	}
	// DeriveKeys is current first, then previous, which is NewKeyRing's order.
	keys, err := rotated.Config().DeriveKeys("x")
	if err != nil || len(keys) != 2 {
		t.Fatalf("DeriveKeys = %d keys, %v", len(keys), err)
	}
	oldKey, _ := before.Config().DeriveKey("x")
	curKey, _ := rotated.Config().DeriveKey("x")
	if !bytes.Equal(keys[0], curKey) || !bytes.Equal(keys[1], oldKey) || bytes.Equal(curKey, oldKey) {
		t.Fatal("DeriveKeys must be the current key, then the key of each previous secret")
	}
	// A value sealed before the rotation opens through a ring built from them.
	sealed, err := auth.Seal(oldKey, []byte("v"), "aad")
	if err != nil {
		t.Fatal(err)
	}
	ring, err := auth.NewKeyRing(keys[0], keys[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ring.Open(sealed, "aad"); err != nil || string(got) != "v" {
		t.Fatalf("old value after rotation: %q %v", got, err)
	}
	// A previous secret is checked like the current one.
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(cur, []byte("short"))); !errors.Is(err, auth.ErrSecretTooShort) {
		t.Fatalf("short previous secret: %v", err)
	}
	// The snapshot cache built from the rotated secret opens a value the
	// old-only instance sealed.
	oldCache, newCache := auth.NewSnapshotCache(), auth.NewSnapshotCache()
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(old), auth.WithSessionCache(oldCache, time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(cur, old), auth.WithSessionCache(newCache, time.Minute)); err != nil {
		t.Fatal(err)
	}
	ctx, now := context.Background(), time.Now()
	key := auth.CacheKey{TokenHash: auth.HashToken("t")}
	v, err := oldCache.Put(ctx, key, auth.Session{ID: "s", UserID: "u"}, auth.User{ID: "u"}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, u, ok, err := newCache.Get(ctx, auth.CacheKey{TokenHash: key.TokenHash, Client: v}, now); err != nil || !ok || u.ID != "u" {
		t.Fatalf("snapshot sealed under the old secret after rotation: ok=%v %v", ok, err)
	}
}

// TestDeriveSecretKeys_MatchesConfig: the free function a package without an
// Auth (authgate) derives with gives exactly the keys Config.DeriveKeys
// gives for the same secrets and label, so the two can never drift, and it
// refuses what New would refuse.
func TestDeriveSecretKeys_MatchesConfig(t *testing.T) {
	old := bytes.Repeat([]byte("o"), auth.MinSecretSize)
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecret(appSecret, old))
	if err != nil {
		t.Fatal(err)
	}
	want, err := a.Config().DeriveKeys(auth.KeyLabelAuthGate)
	if err != nil {
		t.Fatal(err)
	}
	got, err := auth.DeriveSecretKeys(auth.KeyLabelAuthGate, appSecret, old)
	if err != nil || len(got) != 2 || !bytes.Equal(got[0], want[0]) || !bytes.Equal(got[1], want[1]) {
		t.Fatalf("DeriveSecretKeys = %x, %v; Config.DeriveKeys = %x", got, err, want)
	}
	if _, err := auth.DeriveSecretKeys(auth.KeyLabelAuthGate); !errors.Is(err, auth.ErrNoSecret) {
		t.Fatalf("no secret: %v", err)
	}
	if _, err := auth.DeriveSecretKeys(auth.KeyLabelAuthGate, appSecret, []byte("short")); !errors.Is(err, auth.ErrSecretTooShort) {
		t.Fatalf("short previous secret: %v", err)
	}
	if _, err := auth.DeriveSecretKeys("", appSecret); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("empty label: %v", err)
	}
}
