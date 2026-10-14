package redisrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// EnvAddr points the test at a Redis; unset, the test is skipped loudly.
const EnvAddr = "AUTH_TEST_REDIS_ADDR"

func TestHit_CountsPerWindowAndExpires(t *testing.T) {
	addr := os.Getenv(EnvAddr)
	if addr == "" {
		t.Skipf("SKIP: set %s (task test:redis does)", EnvAddr)
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	prefix := fmt.Sprintf("ubgo:auth:test:%d:", time.Now().UnixNano())
	s := New(client, KeyPrefix(prefix), Clock(func() time.Time { return now }))
	for want := 1; want <= 3; want++ {
		n, err := s.Hit(ctx, "k", time.Minute)
		if err != nil || n != want {
			t.Fatalf("hit %d = %d %v", want, n, err)
		}
	}
	now = now.Add(time.Minute)
	if n, _ := s.Hit(ctx, "k", time.Minute); n != 1 {
		t.Fatalf("a new window = %d, want 1", n)
	}
	keys, err := client.Keys(ctx, prefix+"*").Result()
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys = %v %v", keys, err)
	}
	for _, k := range keys {
		if ttl := client.TTL(ctx, k).Val(); ttl <= 0 || ttl > time.Minute {
			t.Fatalf("key %s has TTL %v; every counter must expire", k, ttl)
		}
	}
	client.Del(ctx, keys...)
}

// TestHit_ARedisFailureIsAnError needs no server: a closed client fails every
// command, and Hit must report that rather than a count of zero, which the
// limiter would read as "under the limit" and let every request through.
func TestHit_ARedisFailureIsAnError(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	client.Close()
	n, err := New(client).Hit(context.Background(), "k", time.Minute)
	if !errors.Is(err, redis.ErrClosed) || n != 0 {
		t.Fatalf("Hit on a closed client = %d %v, want 0 and redis.ErrClosed", n, err)
	}
}
