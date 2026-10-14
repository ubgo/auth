package auth_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, auth.SealKeySize) }

func TestKeyRing_RotatesWithoutLosingSealedValues(t *testing.T) {
	old, err := auth.NewKeyRing(key(1))
	if err != nil {
		t.Fatal(err)
	}
	sealed := old.Seal([]byte("secret"), "row-1")
	// Also a value sealed by the single-key Seal: the ring opens it, so a
	// deployment can move from a key to a ring with nothing resealed.
	single, err := auth.Seal(key(1), []byte("legacy"), "row-2")
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := auth.NewKeyRing(key(2), key(1))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Len() != 2 {
		t.Fatalf("Len = %d", rotated.Len())
	}
	for _, c := range []struct{ sealed, aad, want string }{{sealed, "row-1", "secret"}, {single, "row-2", "legacy"}} {
		got, err := rotated.Open(c.sealed, c.aad)
		if err != nil || string(got) != c.want {
			t.Fatalf("open %q after rotation: %q %v", c.want, got, err)
		}
	}
	fresh := rotated.Seal([]byte("new"), "row-3")
	if _, err := old.Open(fresh, "row-3"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("the old ring must not open a value sealed with the new key: %v", err)
	}
	if got, err := auth.Open(key(2), fresh, "row-3"); err != nil || string(got) != "new" {
		t.Fatalf("the ring seals with its first key: %q %v", got, err)
	}
	// Wrong aad, tampering and garbage are one error.
	if _, err := rotated.Open(sealed, "row-9"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("wrong aad: %v", err)
	}
	if _, err := rotated.Open("!!not base64", "row-1"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("garbage: %v", err)
	}
	if _, err := rotated.Open("AAAA", "row-1"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("too short: %v", err)
	}
	// After the old key is dropped, its values stop opening.
	final, _ := auth.NewKeyRing(key(2))
	if _, err := final.Open(sealed, "row-1"); !errors.Is(err, auth.ErrSealedCorrupt) {
		t.Fatalf("a dropped key's value still opens: %v", err)
	}
}

func TestNewKeyRing_RefusesABadKey(t *testing.T) {
	if _, err := auth.NewKeyRing(key(1), []byte("short")); err == nil {
		t.Fatal("a 5-byte previous key was accepted")
	}
	if _, err := auth.NewKeyRing(nil); err == nil {
		t.Fatal("a nil current key was accepted")
	}
}

func TestStatelessSessions_KeyRotation(t *testing.T) {
	// No database: CreateSession needs one, so the rotation is proven on the
	// sealed token through New's own checks and the integration suite; here
	// the option's refusals.
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithStatelessSessions()); !errors.Is(err, auth.ErrNoKeys) {
		t.Fatalf("no key: %v, want ErrNoKeys", err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithStatelessSessions(key(1), []byte("short"))); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("a short previous key: %v, want ErrBadOperation", err)
	}
	if _, err := newAuth(auth.WithPlugins(basic("s")), auth.WithStatelessSessions(key(1), key(2))); err != nil {
		t.Fatalf("two keys: %v", err)
	}
}

func TestSnapshotCache_KeyRotationAndBadKeys(t *testing.T) {
	ctx := context.Background()
	k := auth.CacheKey{TokenHash: auth.HashToken("tok")}
	s, u := auth.Session{ID: "ses_1", UserID: "usr_1"}, auth.User{ID: "usr_1", Name: "Ada"}
	until := time.Now().Add(time.Hour)
	first := auth.NewSnapshotCache(key(1))
	v, err := first.Put(ctx, k, s, u, until)
	if err != nil {
		t.Fatal(err)
	}
	rotated := auth.NewSnapshotCache(key(2), key(1))
	k.Client = v
	if gs, gu, ok, err := rotated.Get(ctx, k, time.Now()); err != nil || !ok || gs.ID != s.ID || gu.Name != u.Name {
		t.Fatalf("a snapshot from the previous key: ok=%v %v %+v", ok, err, gs)
	}
	bad := auth.NewSnapshotCache([]byte("short"))
	if _, err := bad.Put(ctx, k, s, u, until); err == nil {
		t.Fatal("a short key was accepted by Put")
	}
	if _, _, _, err := bad.Get(ctx, k, time.Now()); err == nil {
		t.Fatal("a short key was accepted by Get")
	}
	if _, err := auth.NewSnapshotCache().Put(ctx, k, s, u, until); !errors.Is(err, auth.ErrNoKeys) {
		t.Fatalf("no key: %v", err)
	}
}
