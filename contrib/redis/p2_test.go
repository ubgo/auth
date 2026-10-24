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

// Peek reads the current window's count without adding to it, 0 for a new
// window, and reports a Redis failure as an error.
func TestPeek(t *testing.T) {
	closed := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	closed.Close()
	if n, err := New(closed).Peek(context.Background(), "k", time.Minute); !errors.Is(err, redis.ErrClosed) || n != 0 {
		t.Fatalf("closed client: %d %v", n, err)
	}
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
	defer func() { _ = s.Clear(ctx) }()
	if n, err := s.Peek(ctx, "k", time.Minute); err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
	}
	for range 2 {
		if _, err := s.Hit(ctx, "k", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if n, err := s.Peek(ctx, "k", time.Minute); err != nil || n != 2 {
			t.Fatalf("peek: %d %v", n, err)
		}
	}
	now = now.Add(time.Minute)
	if n, _ := s.Peek(ctx, "k", time.Minute); n != 0 {
		t.Fatalf("a new window: %d", n)
	}
}
