package redisrate

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
)

// TestClear_RemovesOnlyThePrefix: each store's Clear deletes every key under
// its own prefix, in more than one SCAN batch, and nothing under another.
func TestClear_RemovesOnlyThePrefix(t *testing.T) {
	client := redisClient(t)
	ctx := context.Background()
	mine, other := freshPrefix(t, client), freshPrefix(t, client)
	now := storeClock()
	rate := New(client, KeyPrefix(mine), Clock(storeClock))
	sessions := NewSessionStore(client, KeyPrefix(mine), Clock(storeClock))
	cache := NewSessionCache(client, KeyPrefix(mine), Clock(storeClock))
	for i := 0; i < scanBatch+scanBatch/2; i++ {
		if err := client.Set(ctx, mine+"bulk:"+strconv.Itoa(i), "x", time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := rate.Hit(ctx, "k", time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Insert(ctx, auth.Session{ID: "s1", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastSeenAt: now}, tokenHash("t1")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Put(ctx, auth.CacheKey{TokenHash: tokenHash("t1")}, auth.Session{ID: "s1"}, auth.User{ID: "u1"}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, other+"keep", "x", time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
	count := func(prefix string) int {
		n, err := client.Keys(ctx, prefix+"*").Result()
		if err != nil {
			t.Fatal(err)
		}
		return len(n)
	}
	if count(mine) < scanBatch+scanBatch/2+3 {
		t.Fatalf("setup wrote %d keys", count(mine))
	}
	for name, clear := range map[string]func(context.Context) error{"rate": rate.Clear, "sessions": sessions.Clear, "cache": cache.Clear} {
		if err := clear(ctx); err != nil {
			t.Fatalf("%s.Clear: %v", name, err)
		}
	}
	if n := count(mine); n != 0 {
		t.Fatalf("%d keys survived Clear", n)
	}
	if n := count(other); n != 1 {
		t.Fatalf("another prefix lost keys: %d left", n)
	}
	if _, err := sessions.Find(ctx, tokenHash("t1"), now); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("the cleared session: %v", err)
	}
	// Clear of nothing is fine.
	if err := Clear(ctx, client, mine); err != nil {
		t.Fatal(err)
	}
}

// TestClear_FailuresAreErrors: a failing SCAN or DEL, and a closed client,
// are reported with the package prefix, never swallowed.
func TestClear_FailuresAreErrors(t *testing.T) {
	ctx := context.Background()
	for _, cmd := range []string{"scan", "del"} {
		client := redisClient(t)
		prefix := freshPrefix(t, client)
		if err := client.Set(ctx, prefix+"k", "x", time.Hour).Err(); err != nil {
			t.Fatal(err)
		}
		client.AddHook(faultHook{cmd: cmd})
		err := Clear(ctx, client, prefix)
		if !errors.Is(err, errFault) || !strings.HasPrefix(err.Error(), "redisrate: clear: ") {
			t.Errorf("%s failing: %v", cmd, err)
		}
	}
	closed := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	closed.Close()
	if err := New(closed).Clear(ctx); !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("a closed client: %v", err)
	}
}
