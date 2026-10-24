package redisrate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/verificationtest"
)

// The Redis verification store meets the shared contract, spends with
// GETDEL, and writes no raw token or identifier into a key.
func TestVerificationStore_OnRedis(t *testing.T) {
	addr := os.Getenv(EnvAddr)
	if addr == "" {
		t.Skipf("SKIP: set %s (task test:redis does)", EnvAddr)
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	base := fmt.Sprintf("ubgo:auth:test:ver:%d:", time.Now().UnixNano())
	defer func() { _ = Clear(ctx, client, base) }()

	verificationtest.Run(t, func(*testing.T) auth.VerificationStore {
		return NewVerificationStore(client, KeyPrefix(fmt.Sprintf("%s%d:", base, time.Now().UnixNano())))
	})

	s := NewStorage(client, KeyPrefix(base+"kv:"))
	if err := s.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.GetAndDelete(ctx, "k"); v != "v" || !ok || err != nil {
		t.Fatalf("GetAndDelete = %q %v %v", v, ok, err)
	}
	if _, ok, err := s.GetAndDelete(ctx, "k"); ok || err != nil {
		t.Fatalf("second GetAndDelete = %v %v, want a miss", ok, err)
	}
	// SET NX: the first claim stores the key with its expiry, the second
	// changes nothing.
	if ok, err := s.SetIfAbsent(ctx, "nx", "first", time.Minute); !ok || err != nil {
		t.Fatalf("first SetIfAbsent = %v %v", ok, err)
	}
	if ok, err := s.SetIfAbsent(ctx, "nx", "second", time.Minute); ok || err != nil {
		t.Fatalf("second SetIfAbsent = %v %v, want refused", ok, err)
	}
	if v, ok, err := s.Get(ctx, "nx"); v != "first" || !ok || err != nil {
		t.Fatalf("Get after SetIfAbsent = %q %v %v", v, ok, err)
	}
	if ttl := client.TTL(ctx, base+"kv:nx").Val(); ttl <= 0 {
		t.Fatalf("SetIfAbsent left the key without an expiry: %v", ttl)
	}

	prefix := base + "hashed:"
	vs := NewVerificationStore(client, KeyPrefix(prefix))
	raw, ident := "raw-token-r20", "ada-r20@example.com"
	now := time.Now()
	if err := vs.Insert(ctx, auth.Verification{ID: "v", Identifier: ident, Purpose: "p", ExpiresAt: now.Add(time.Hour), CreatedAt: now}, auth.HashToken(auth.Token(raw))); err != nil {
		t.Fatal(err)
	}
	if err := vs.ConsumeAll(ctx, "other", ident, now); err != nil {
		t.Fatal(err)
	}
	keys, err := client.Keys(ctx, prefix+"*").Result()
	if err != nil || len(keys) == 0 {
		t.Fatalf("keys = %v %v", keys, err)
	}
	for _, k := range keys {
		if strings.Contains(k, raw) || strings.Contains(k, ident) {
			t.Fatalf("key %q holds a raw token or identifier", k)
		}
		if ttl := client.TTL(ctx, k).Val(); strings.Contains(k, "-cutoff:") && (ttl <= 0 || ttl < auth.MinVerificationCutoffTTL-time.Minute) {
			t.Fatalf("cutoff key %q ttl %v, want about auth.MinVerificationCutoffTTL", k, ttl)
		}
		if ttl := client.TTL(ctx, k).Val(); strings.Contains(k, "auth:verification:p:") && (ttl <= 0 || ttl > time.Hour) {
			t.Fatalf("token key %q ttl %v, want the token's life", k, ttl)
		}
	}
	if !strings.HasPrefix(DefaultVerificationKeyPrefix, DefaultStorageKeyPrefix[:len("ubgo:auth:")]) {
		t.Fatalf("default prefix %q is outside the library's namespace", DefaultVerificationKeyPrefix)
	}
}
