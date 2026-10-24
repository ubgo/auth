package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// failingNX is key-value storage whose SetIfAbsent fails, as a store that
// lost its connection does.
type failingNX struct{ auth.GetAndDeleter }

var errNXDown = errors.New("setnx down")

func (failingNX) SetIfAbsent(context.Context, string, string, time.Duration) (bool, error) {
	return false, errNXDown
}

// plainKV hides every upgrade of the storage it wraps but GetAndDelete.
type plainKV struct{ auth.GetAndDeleter }

// The key-value verification store promises exclusive inserts only over
// storage that can set a key if absent: there a duplicate is ErrTokenExists
// and a storage failure is passed on; over plain storage it makes no promise
// and a duplicate replaces the record, as before.
func TestStorageVerificationStore_ExclusiveOnlyWithSetIfAbsent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	v := auth.Verification{ID: "v", Identifier: "i", Purpose: "p", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	h := auth.HashToken("tok")
	mem := func() auth.GetAndDeleter { return auth.NewMemoryStorage(nil).(auth.GetAndDeleter) }

	nx := auth.NewStorageVerificationStore(mem())
	if x, ok := nx.(auth.ExclusiveVerificationStore); !ok || !x.RefusesDuplicateTokens() {
		t.Fatal("the store over memory storage must promise exclusive inserts")
	}
	if err := nx.Insert(ctx, v, h); err != nil {
		t.Fatal(err)
	}
	if err := nx.Insert(ctx, v, h); !errors.Is(err, auth.ErrTokenExists) {
		t.Fatalf("duplicate = %v, want ErrTokenExists", err)
	}

	plain := auth.NewStorageVerificationStore(plainKV{mem()})
	if x, ok := plain.(auth.ExclusiveVerificationStore); !ok || x.RefusesDuplicateTokens() {
		t.Fatal("the store over plain storage must not promise exclusive inserts")
	}
	if err := plain.Insert(ctx, v, h); err != nil {
		t.Fatal(err)
	}
	if err := plain.Insert(ctx, v, h); err != nil {
		t.Fatalf("plain storage refused a duplicate it cannot detect: %v", err)
	}

	if err := auth.NewStorageVerificationStore(failingNX{mem()}).Insert(ctx, v, h); !errors.Is(err, errNXDown) {
		t.Fatalf("a failing SetIfAbsent = %v, want it passed on", err)
	}
}

// Memory storage's SetIfAbsent: refuses a negative ttl, keeps a live value,
// stores again once the first expired, and 0 means no expiry.
func TestMemoryStorage_SetIfAbsent(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s := auth.NewMemoryStorage(func() time.Time { return now }).(auth.SetIfAbsenter)
	if _, err := s.SetIfAbsent(ctx, "k", "v", -time.Second); err == nil {
		t.Fatal("a negative ttl was accepted")
	}
	if ok, err := s.SetIfAbsent(ctx, "k", "a", time.Minute); !ok || err != nil {
		t.Fatalf("first = %v %v", ok, err)
	}
	if ok, err := s.SetIfAbsent(ctx, "k", "b", time.Minute); ok || err != nil {
		t.Fatalf("second = %v %v, want refused", ok, err)
	}
	now = now.Add(time.Minute)
	if ok, err := s.SetIfAbsent(ctx, "k", "c", 0); !ok || err != nil {
		t.Fatalf("after expiry = %v %v", ok, err)
	}
	now = now.Add(24 * time.Hour)
	if v, ok, _ := s.Get(ctx, "k"); !ok || v != "c" {
		t.Fatalf("a ttl of 0 expired: %q %v", v, ok)
	}
}
