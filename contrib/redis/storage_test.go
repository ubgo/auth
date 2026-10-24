package redisrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
)

// The Redis storage reads, writes, deletes and counts in fixed windows, and
// the storage-backed session store over it meets the SessionStore contract.
func TestStorage_OnRedis(t *testing.T) {
	addr := os.Getenv(EnvAddr)
	if addr == "" {
		t.Skipf("SKIP: set %s (task test:redis does)", EnvAddr)
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	prefix := fmt.Sprintf("ubgo:auth:test:kv:%d:", time.Now().UnixNano())
	s := NewStorage(client, KeyPrefix(prefix))
	defer func() { _ = s.Clear(ctx) }()
	if _, ok, err := s.Get(ctx, "k"); ok || err != nil {
		t.Fatalf("missing key: %v %v", ok, err)
	}
	if err := s.Set(ctx, "k", "v", time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok, err := s.Get(ctx, "k"); v != "v" || !ok || err != nil {
		t.Fatalf("get: %q %v %v", v, ok, err)
	}
	if ttl := client.TTL(ctx, prefix+"k").Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("ttl %v", ttl)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get(ctx, "k"); ok {
		t.Fatal("deleted key read")
	}
	for want := int64(1); want <= 2; want++ {
		if n, err := s.Increment(ctx, "c", time.Minute); n != want || err != nil {
			t.Fatalf("increment: %d %v", n, err)
		}
	}
	if ttl := client.TTL(ctx, prefix+"c").Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("counter ttl %v", ttl)
	}
	if n, err := s.Increment(ctx, "forever", 0); n != 1 || err != nil || client.TTL(ctx, prefix+"forever").Val() != -1 {
		t.Fatalf("increment without ttl: %d %v", n, err)
	}
	sessiontest.Run(t, func(*testing.T) auth.SessionStore {
		return auth.NewStorageSessionStore(NewStorage(client, KeyPrefix(fmt.Sprintf("%s%d:", prefix, time.Now().UnixNano()))))
	})
}

// Every method reports a Redis failure as an error, never as a miss or a
// zero count.
func TestStorage_ARedisFailureIsAnError(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	client.Close()
	s := NewStorage(client)
	ctx := context.Background()
	if _, _, err := s.Get(ctx, "k"); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("get: %v", err)
	}
	if err := s.Set(ctx, "k", "v", 0); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("set: %v", err)
	}
	if err := s.Delete(ctx, "k"); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("delete: %v", err)
	}
	if n, err := s.Increment(ctx, "k", time.Minute); !errors.Is(err, redis.ErrClosed) || n != 0 {
		t.Errorf("increment: %d %v", n, err)
	}
	if v, ok, err := s.GetAndDelete(ctx, "k"); !errors.Is(err, redis.ErrClosed) || ok || v != "" {
		t.Errorf("getdel: %q %v %v", v, ok, err)
	}
	if ok, err := s.SetIfAbsent(ctx, "k", "v", time.Minute); !errors.Is(err, redis.ErrClosed) || ok {
		t.Errorf("setnx: %v %v", ok, err)
	}
}
