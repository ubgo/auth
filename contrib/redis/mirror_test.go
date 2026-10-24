package redisrate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
)

// TestSessionStore_ConformsAsAMirrorSecondary: Redis as the fast copy in
// front of another store, and as the primary behind one, keeps the session
// store contract, as auth.MirrorSessionStore promises.
func TestSessionStore_ConformsAsAMirrorSecondary(t *testing.T) {
	client := redisClient(t)
	t.Run("redis secondary", func(t *testing.T) {
		sessiontest.Run(t, func(t *testing.T) auth.SessionStore {
			return auth.MirrorSessionStore(auth.NewMemorySessionStore(), NewSessionStore(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock)))
		})
	})
	t.Run("redis primary", func(t *testing.T) {
		sessiontest.Run(t, func(t *testing.T) auth.SessionStore {
			return auth.MirrorSessionStore(NewSessionStore(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock)), auth.NewMemorySessionStore())
		})
	})
}

// TestMirror_ADownRedisSecondary: with the Redis copy unreachable, a session
// is still created, found and refreshed through the primary, and ending it
// fails rather than leave a copy that could answer later.
func TestMirror_ADownRedisSecondary(t *testing.T) {
	closed := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	closed.Close()
	primary := auth.NewMemorySessionStore()
	m := auth.MirrorSessionStore(primary, NewSessionStore(closed))
	ctx := context.Background()
	now := storeClock()
	h := tokenHash("t")
	s := auth.Session{ID: "s", UserID: "u", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := m.Insert(ctx, s, h); err != nil {
		t.Fatalf("Insert with Redis down: %v, want the primary to carry it", err)
	}
	if got, err := m.Find(ctx, h, now); err != nil || got.ID != "s" {
		t.Fatalf("Find with Redis down = %v %v", got, err)
	}
	if moved, err := m.Touch(ctx, "s", now.Add(2*time.Hour), now); err != nil || !moved {
		t.Fatalf("Touch with Redis down = %v %v", moved, err)
	}
	if err := m.Delete(ctx, "u", "s"); !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("Delete with Redis down = %v, want its failure", err)
	}
	if _, err := primary.Find(ctx, h, now); err != nil {
		t.Fatalf("the failed Delete ended the primary's session: %v", err)
	}
}
