package redisrate

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
)

func TestSessionRevocations_Conforms(t *testing.T) {
	client := redisClient(t)
	sessiontest.RunRevocations(t, func(t *testing.T) auth.SessionRevocations {
		return NewSessionRevocations(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock))
	})
}

// TestSessionRevocations_KeysAndFailures: the key holds the session id and
// expires with the entry, a corrupt value and a dead connection are errors,
// never "not revoked".
func TestSessionRevocations_KeysAndFailures(t *testing.T) {
	client := redisClient(t)
	ctx := context.Background()
	prefix := freshPrefix(t, client)
	r := NewSessionRevocations(client, KeyPrefix(prefix), Clock(storeClock))
	now := storeClock()
	if err := r.Revoke(ctx, "ses_a", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ttl := client.TTL(ctx, prefix+"ses_a").Val(); ttl <= 59*time.Minute || ttl > time.Hour {
		t.Fatalf("TTL = %v, want about an hour", ttl)
	}
	// An entry already past its instant by this clock still gets the
	// minimum TTL, and is judged by the core's clock.
	if err := r.Revoke(ctx, "ses_old", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if ttl := client.TTL(ctx, prefix+"ses_old").Val(); ttl <= 0 || ttl > minTTL {
		t.Fatalf("TTL of a past entry = %v, want at most %v", ttl, minTTL)
	}
	if ok, err := r.Revoked(ctx, "ses_old", now); ok || err != nil {
		t.Fatalf("a past entry = %v %v, want not revoked", ok, err)
	}
	if err := client.Set(ctx, prefix+"ses_bad", "not a time", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Revoked(ctx, "ses_bad", now); err == nil {
		t.Fatal("a corrupt entry must be an error")
	}
	closed := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	closed.Close()
	dead := NewSessionRevocations(closed, KeyPrefix(prefix))
	if err := dead.Revoke(ctx, "ses_a", now.Add(time.Hour)); err == nil {
		t.Fatal("Revoke on a dead connection must fail")
	}
	if _, err := dead.Revoked(ctx, "ses_a", now); err == nil {
		t.Fatal("Revoked on a dead connection must fail")
	}
	if NewSessionRevocations(client).prefix != DefaultRevocationKeyPrefix {
		t.Fatal("the default prefix")
	}
}
