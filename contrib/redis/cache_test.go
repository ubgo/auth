package redisrate

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
)

// TestSessionCache_PutGetDrop: an entry is answered until its instant and
// dropped on demand, and the client holds nothing.
func TestSessionCache_PutGetDrop(t *testing.T) {
	client := redisClient(t)
	ctx := context.Background()
	c := NewSessionCache(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock))
	now := storeClock()
	key := auth.CacheKey{TokenHash: tokenHash("t1")}
	sess := auth.Session{ID: "s1", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastSeenAt: now}
	user := auth.User{ID: "u1", Name: "Ada", CreatedAt: now, UpdatedAt: now}
	if _, _, ok, err := c.Get(ctx, key, now); ok || err != nil {
		t.Fatalf("Get before Put = %v %v", ok, err)
	}
	v, err := c.Put(ctx, key, sess, user, now.Add(time.Minute))
	if err != nil || v != "" {
		t.Fatalf("Put = %q %v; a server-side cache hands the client nothing", v, err)
	}
	if ttl := client.TTL(ctx, c.key(key)).Val(); ttl <= 0 || ttl > time.Minute {
		t.Fatalf("TTL = %v, want at most a minute", ttl)
	}
	gs, gu, ok, err := c.Get(ctx, key, now.Add(30*time.Second))
	if err != nil || !ok || gs.ID != "s1" || gu.Name != "Ada" || !gs.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatalf("Get = %+v %+v %v %v", gs, gu, ok, err)
	}
	if _, _, ok, err := c.Get(ctx, key, now.Add(time.Minute)); ok || err != nil {
		t.Fatalf("Get at the instant = %v %v; the entry must be judged by the core's clock", ok, err)
	}
	if err := c.Drop(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := c.Get(ctx, key, now); ok {
		t.Fatal("the entry survived Drop")
	}
	// An entry already past its instant by this process's clock is not
	// written at all.
	if _, err := c.Put(ctx, key, sess, user, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if n := client.Exists(ctx, c.key(key)).Val(); n != 0 {
		t.Fatal("an expired entry was written")
	}
	// A corrupted entry is an error, not a miss.
	if err := client.Set(ctx, c.key(key), "{not json", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := c.Get(ctx, key, now); err == nil {
		t.Fatal("Get of a corrupt entry succeeded")
	}
}

// TestSessionCache_ClosedClient needs no server: a failing cache is an
// error, never a miss that would make every request cost a lookup in
// silence, nor a hit.
func TestSessionCache_ClosedClient(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	client.Close()
	ctx := context.Background()
	now := storeClock()
	c := NewSessionCache(client, Clock(storeClock))
	key := auth.CacheKey{TokenHash: tokenHash("t1")}
	if _, _, ok, err := c.Get(ctx, key, now); ok || !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Get = %v %v", ok, err)
	}
	if _, err := c.Put(ctx, key, auth.Session{}, auth.User{}, now.Add(time.Minute)); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Put = %v", err)
	}
	if err := c.Drop(ctx, key); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Drop = %v", err)
	}
	if err := c.DropUser(ctx, "u1"); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("DropUser = %v", err)
	}
}

// TestSessionCache_UserIndex: each Put files its key in the user's set,
// which lives as long as the longest entry and never shorter; DropUser
// removes the entries and the set; a failed delete is an error.
func TestSessionCache_UserIndex(t *testing.T) {
	client := redisClient(t)
	ctx := context.Background()
	c := NewSessionCache(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock))
	now := storeClock()
	put := func(tok string, ttl time.Duration) auth.CacheKey {
		k := auth.CacheKey{TokenHash: tokenHash(tok)}
		if _, err := c.Put(ctx, k, auth.Session{ID: tok, UserID: "u1", ExpiresAt: now.Add(time.Hour)}, auth.User{ID: "u1"}, now.Add(ttl)); err != nil {
			t.Fatal(err)
		}
		return k
	}
	k1 := put("t1", 10*time.Minute)
	put("t2", time.Minute)
	if ttl := client.TTL(ctx, c.userKey("u1")).Val(); ttl <= 9*time.Minute {
		t.Fatalf("index TTL = %v; a shorter entry must not shorten it", ttl)
	}
	if n := client.SCard(ctx, c.userKey("u1")).Val(); n != 2 {
		t.Fatalf("index holds %d keys, want 2", n)
	}
	if err := c.DropUser(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if n := client.Exists(ctx, c.key(k1), c.userKey("u1")).Val(); n != 0 {
		t.Fatalf("%d keys survived DropUser", n)
	}

	put("t3", time.Minute)
	failing := redis.NewClient(&redis.Options{Addr: os.Getenv(EnvAddr)})
	t.Cleanup(func() { failing.Close() })
	failing.AddHook(faultHook{cmd: "del"})
	f := NewSessionCache(failing, KeyPrefix(c.prefix), Clock(storeClock))
	if err := f.DropUser(ctx, "u1"); !errors.Is(err, errFault) || !strings.Contains(err.Error(), "drop user cache") {
		t.Fatalf("DropUser with a failing delete = %v, want the delete's failure", err)
	}
}

func TestSessionCache_Conforms(t *testing.T) {
	client := redisClient(t)
	sessiontest.RunCache(t, func(t *testing.T) auth.SessionCache {
		return NewSessionCache(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock))
	})
}
