package redisrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
)

// storeClock is the process clock the session tests give the store. It is
// before the instant the conformance suite reasons from, so every TTL the
// store computes is long, as in a real deployment; the suite's own checks
// never depend on the TTL.
var storeClock = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// redisClient connects to the test Redis, or skips the test loudly.
func redisClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv(EnvAddr)
	if addr == "" {
		t.Skipf("SKIP: set %s (task test:redis does)", EnvAddr)
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { client.Close() })
	return client
}

// freshPrefix is a key prefix no other run shares; its keys are deleted when
// the test ends.
func freshPrefix(t *testing.T, client *redis.Client) string {
	t.Helper()
	prefix := fmt.Sprintf("ubgo:auth:test:%d:", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx := context.Background()
		keys, _ := client.Keys(ctx, prefix+"*").Result()
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
	})
	return prefix
}

func TestSessionStore_Conforms(t *testing.T) {
	client := redisClient(t)
	sessiontest.Run(t, func(t *testing.T) auth.SessionStore {
		return NewSessionStore(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock))
	})
}

func tokenHash(label string) []byte {
	h := sha256.Sum256([]byte(label))
	return h[:]
}

// TestSessionStore_KeysExpireWithTheSession: every key of a session carries
// a TTL, and one whose expiry the process clock already passed still lives
// for minTTL rather than vanishing at once.
func TestSessionStore_KeysExpireWithTheSession(t *testing.T) {
	client := redisClient(t)
	ctx := context.Background()
	prefix := freshPrefix(t, client)
	s := NewSessionStore(client, KeyPrefix(prefix), Clock(storeClock))
	live := auth.Session{ID: "s1", UserID: "u1", ExpiresAt: storeClock().Add(time.Hour), CreatedAt: storeClock(), LastSeenAt: storeClock()}
	if err := s.Insert(ctx, live, tokenHash("t1")); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{s.sessionKey(tokenHash("t1")), s.idKey("s1")} {
		if ttl := client.TTL(ctx, k).Val(); ttl <= 59*time.Minute || ttl > time.Hour {
			t.Errorf("TTL of %s = %v, want about an hour", k, ttl)
		}
	}
	past := auth.Session{ID: "s2", UserID: "u1", ExpiresAt: storeClock().Add(-time.Hour), CreatedAt: storeClock(), LastSeenAt: storeClock()}
	if err := s.Insert(ctx, past, tokenHash("t2")); err != nil {
		t.Fatal(err)
	}
	if ttl := client.TTL(ctx, s.sessionKey(tokenHash("t2"))).Val(); ttl <= 0 || ttl > minTTL {
		t.Errorf("TTL of an already expired session = %v, want at most %v and not gone", ttl, minTTL)
	}
	// Touch re-arms the TTL of both keys.
	if moved, err := s.Touch(ctx, "s1", storeClock().Add(2*time.Hour), storeClock()); err != nil || !moved {
		t.Fatalf("Touch = %v %v", moved, err)
	}
	for _, k := range []string{s.sessionKey(tokenHash("t1")), s.idKey("s1")} {
		if ttl := client.TTL(ctx, k).Val(); ttl <= time.Hour {
			t.Errorf("TTL of %s after Touch = %v, want about two hours", k, ttl)
		}
	}
}

// TestSessionStore_ListPrunesAndRefusesCorruptEntries: an id whose session
// key is gone is dropped from the user's set, and a hash someone corrupted
// is an error, never a silent sign-out.
func TestSessionStore_ListPrunesAndRefusesCorruptEntries(t *testing.T) {
	client := redisClient(t)
	ctx := context.Background()
	prefix := freshPrefix(t, client)
	s := NewSessionStore(client, KeyPrefix(prefix), Clock(storeClock))
	now := storeClock()
	for i, id := range []string{"s1", "s2"} {
		sess := auth.Session{ID: id, UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(time.Duration(i) * time.Second), LastSeenAt: now}
		if err := s.Insert(ctx, sess, tokenHash(id)); err != nil {
			t.Fatal(err)
		}
	}
	// s2's keys expired (deleted here), its id stays in the set until List.
	client.Del(ctx, s.sessionKey(tokenHash("s2")), s.idKey("s2"))
	list, err := s.List(ctx, "u1", now)
	if err != nil || len(list) != 1 || list[0].ID != "s1" {
		t.Fatalf("List = %v %v", list, err)
	}
	if n := client.SCard(ctx, s.userKey("u1")).Val(); n != 1 {
		t.Fatalf("the stale id was not pruned: %d members", n)
	}
	for name, fields := range map[string][]string{
		"body":      {fieldSession, "{not json"},
		"expiry":    {fieldExpires, "soon"},
		"last-seen": {fieldLastSeen, "earlier"},
		"reauth":    {fieldReauth, "recently"},
	} {
		if err := client.HSet(ctx, s.sessionKey(tokenHash("s1")), fields[0], fields[1]).Err(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Find(ctx, tokenHash("s1"), now); err == nil || errors.Is(err, auth.ErrSessionNotFound) {
			t.Errorf("Find with a corrupt %s = %v, want a store error", name, err)
		}
		if _, err := s.List(ctx, "u1", now); err == nil {
			t.Errorf("List with a corrupt %s succeeded", name)
		}
		if err := s.Delete(ctx, "u1", "s1"); err == nil {
			t.Errorf("Delete with a corrupt %s succeeded", name)
		}
		if err := s.DeleteUser(ctx, "u1", ""); err == nil {
			t.Errorf("DeleteUser with a corrupt %s succeeded", name)
		}
		// Restore the field for the next case.
		good := auth.Session{ID: "s1", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastSeenAt: now}
		if err := s.Insert(ctx, good, tokenHash("s1")); err != nil {
			t.Fatal(err)
		}
		// Insert writes its own fields only; the reauth field is the
		// re-authentication's, so the restore drops it by hand.
		client.HDel(ctx, s.sessionKey(tokenHash("s1")), fieldReauth)
	}
}

// errFault is what a faulting hook answers.
var errFault = errors.New("redisrate test: injected failure")

// faultHook fails every command named cmd, alone or inside a pipeline, so a
// test can reach the store's failure branches on a real server.
type faultHook struct{ cmd string }

func (faultHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h faultHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if cmd.Name() == h.cmd {
			return errFault
		}
		return next(ctx, cmd)
	}
}
func (h faultHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, cmd := range cmds {
			if cmd.Name() == h.cmd {
				return errFault
			}
		}
		return next(ctx, cmds)
	}
}

// TestSessionStore_EveryFailureIsAnError: whichever command Redis fails, the
// store reports it; a failure never reads as "not found" or "nothing to do".
func TestSessionStore_EveryFailureIsAnError(t *testing.T) {
	addr := os.Getenv(EnvAddr)
	if addr == "" {
		t.Skipf("SKIP: set %s (task test:redis does)", EnvAddr)
	}
	ctx := context.Background()
	now := storeClock()
	sess := auth.Session{ID: "s1", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastSeenAt: now}
	for _, c := range []struct {
		cmd string
		// fresh runs against an empty store: the Insert case, whose own
		// command is the one that fails.
		fresh bool
		op    func(s *SessionStore) error
	}{
		{"hset", true, func(s *SessionStore) error { return s.Insert(ctx, sess, tokenHash("t1")) }},
		{"hgetall", false, func(s *SessionStore) error { _, err := s.Find(ctx, tokenHash("t1"), now); return err }},
		{"get", false, func(s *SessionStore) error { _, err := s.Touch(ctx, "s1", now.Add(2*time.Hour), now); return err }},
		{"evalsha", false, func(s *SessionStore) error { _, err := s.Touch(ctx, "s1", now.Add(2*time.Hour), now); return err }},
		{"pexpire", false, func(s *SessionStore) error { _, err := s.Touch(ctx, "s1", now.Add(2*time.Hour), now); return err }},
		{"smembers", false, func(s *SessionStore) error { _, err := s.List(ctx, "u1", now); return err }},
		{"get", false, func(s *SessionStore) error { _, err := s.List(ctx, "u1", now); return err }},
		{"srem", false, func(s *SessionStore) error { _, err := s.List(ctx, "u1", now); return err }},
		{"del", false, func(s *SessionStore) error { return s.Delete(ctx, "u1", "s1") }},
		{"smembers", false, func(s *SessionStore) error { return s.DeleteUser(ctx, "u1", "") }},
		{"del", false, func(s *SessionStore) error { return s.DeleteUser(ctx, "u1", "") }},
		{"get", false, func(s *SessionStore) error { return s.SetData(ctx, "s1", auth.AppData(`1`)) }},
		{"hgetall", false, func(s *SessionStore) error { return s.SetData(ctx, "s1", auth.AppData(`1`)) }},
		{"hset", false, func(s *SessionStore) error { return s.SetData(ctx, "s1", auth.AppData(`1`)) }},
		{"get", false, func(s *SessionStore) error { return s.SetReauthenticatedAt(ctx, "s1", now) }},
		{"evalsha", false, func(s *SessionStore) error { return s.SetReauthenticatedAt(ctx, "s1", now) }},
	} {
		client := redis.NewClient(&redis.Options{Addr: addr})
		prefix := freshPrefix(t, client)
		s := NewSessionStore(client, KeyPrefix(prefix), Clock(storeClock))
		if !c.fresh {
			if err := s.Insert(ctx, sess, tokenHash("t1")); err != nil {
				t.Fatal(err)
			}
		}
		if c.cmd == "srem" {
			client.Del(ctx, s.idKey("s1")) // a stale member to prune
		}
		if c.cmd == "evalsha" {
			// The script is cached under its SHA, so the first run is EVAL
			// and the ones after are EVALSHA; both must fail the same way.
			_, _ = s.Touch(ctx, "s1", now.Add(90*time.Minute), now)
		}
		client.AddHook(faultHook{cmd: c.cmd})
		err := c.op(s)
		if !errors.Is(err, errFault) || !strings.HasPrefix(err.Error(), "redisrate: ") {
			t.Errorf("%s failing: %v, want the injected failure with the redisrate prefix", c.cmd, err)
		}
		client.Close()
	}
}

// TestSessionStore_ClosedClient needs no server: every method reports the
// closed client rather than an empty answer.
func TestSessionStore_ClosedClient(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	client.Close()
	ctx := context.Background()
	now := storeClock()
	s := NewSessionStore(client)
	for name, err := range map[string]error{
		"Insert": s.Insert(ctx, auth.Session{ID: "s1", UserID: "u1", ExpiresAt: now.Add(time.Hour)}, tokenHash("t1")),
		"Find":   func() error { _, err := s.Find(ctx, tokenHash("t1"), now); return err }(),
		"Touch":  func() error { _, err := s.Touch(ctx, "s1", now, now); return err }(),
		"List":   func() error { _, err := s.List(ctx, "u1", now); return err }(),
		"Delete": s.Delete(ctx, "u1", "s1"),
	} {
		if !errors.Is(err, redis.ErrClosed) {
			t.Errorf("%s on a closed client = %v", name, err)
		}
	}
	if n, err := s.Sweep(ctx, now); n != 0 || err != nil {
		t.Errorf("Sweep = %d %v; Redis expires the keys itself", n, err)
	}
}

// TestSessionStore_UnknownIdIsNotAnError: Touch of an id the store never
// saw reports false, and Delete of one changes nothing.
func TestSessionStore_UnknownIdIsNotAnError(t *testing.T) {
	client := redisClient(t)
	ctx := context.Background()
	s := NewSessionStore(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock))
	if moved, err := s.Touch(ctx, "nope", storeClock().Add(time.Hour), storeClock()); moved || err != nil {
		t.Fatalf("Touch of an unknown id = %v %v", moved, err)
	}
	if err := s.Delete(ctx, "u1", "nope"); err != nil {
		t.Fatalf("Delete of an unknown id: %v", err)
	}
}

// standaloneFault fails the named commands only when sent alone, never
// inside a pipeline, so a test can fail the steps after a pipeline that
// itself must succeed.
type standaloneFault struct{ cmds []string }

func (standaloneFault) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h standaloneFault) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if slices.Contains(h.cmds, cmd.Name()) {
			return errFault
		}
		return next(ctx, cmd)
	}
}
func (standaloneFault) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}

// TestSessionStore_RotationFailures: each Redis failure inside RotateToken
// and FindRotated is reported, never read as "not moved" or "not found"; a
// session found ended after the move is unwound; a re-authentication time
// moves with the session; a malformed rotated key is an error.
func TestSessionStore_RotationFailures(t *testing.T) {
	addr := os.Getenv(EnvAddr)
	if addr == "" {
		t.Skipf("SKIP: set %s (task test:redis does)", EnvAddr)
	}
	ctx := context.Background()
	now := storeClock()
	sess := auth.Session{ID: "s1", UserID: "u1", ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastSeenAt: now}
	open := func(t *testing.T, hook redis.Hook) (*SessionStore, *redis.Client) {
		t.Helper()
		client := redis.NewClient(&redis.Options{Addr: addr})
		t.Cleanup(func() { client.Close() })
		s := NewSessionStore(client, KeyPrefix(freshPrefix(t, client)), Clock(storeClock))
		if err := s.Insert(ctx, sess, tokenHash("t1")); err != nil {
			t.Fatal(err)
		}
		if hook != nil {
			client.AddHook(hook)
		}
		return s, client
	}
	rotate := func(s *SessionStore) error {
		_, err := s.RotateToken(ctx, "s1", tokenHash("t1"), tokenHash("t2"), now.Add(time.Minute), now.Add(2*time.Hour), now)
		return err
	}
	for name, hook := range map[string]redis.Hook{
		"reading the session":  faultHook{cmd: "hgetall"},
		"moving the id":        faultHook{cmd: "evalsha"},
		"writing the session":  faultHook{cmd: "set"},
		"reading the id after": standaloneFault{cmds: []string{"get"}},
		"undoing after":        standaloneFault{cmds: []string{"get", "del"}},
	} {
		t.Run(name, func(t *testing.T) {
			// EvalSha is tried first and an injected failure is not
			// NOSCRIPT, so a fault on evalsha is not answered by EVAL.
			s, _ := open(t, hook)
			if err := rotate(s); !errors.Is(err, errFault) || !strings.HasPrefix(err.Error(), "redisrate: ") {
				t.Fatalf("RotateToken = %v, want the injected failure", err)
			}
		})
	}

	t.Run("a session ended mid-rotation is unwound", func(t *testing.T) {
		s, client := open(t, nil)
		client.AddHook(standaloneFault{cmds: []string{"get"}})
		_ = rotate(s)
		if n, err := client.Exists(ctx, s.sessionKey(tokenHash("t2"))).Result(); err != nil || n != 0 {
			t.Fatalf("the new hash survives an unwound rotation: %d %v", n, err)
		}
	})

	t.Run("the re-authentication time moves with the session", func(t *testing.T) {
		s, _ := open(t, nil)
		if err := s.SetReauthenticatedAt(ctx, "s1", now); err != nil {
			t.Fatal(err)
		}
		if err := rotate(s); err != nil {
			t.Fatal(err)
		}
		got, err := s.Find(ctx, tokenHash("t2"), now)
		if err != nil || got.ReauthenticatedAt == nil || !got.ReauthenticatedAt.Equal(now) {
			t.Fatalf("after rotation: %+v %v", got, err)
		}
	})

	t.Run("FindRotated reports a failing read and a malformed key", func(t *testing.T) {
		s, client := open(t, nil)
		if err := rotate(s); err != nil {
			t.Fatal(err)
		}
		bad := s.prefix + segmentRotated + hex.EncodeToString(tokenHash("bad"))
		if err := client.Set(ctx, bad, "no-separator", time.Minute).Err(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.FindRotated(ctx, tokenHash("bad"), now); err == nil || !strings.HasPrefix(err.Error(), "redisrate: decode rotated token") {
			t.Fatalf("FindRotated of a malformed key = %v", err)
		}
		client.AddHook(faultHook{cmd: "get"})
		if _, _, err := s.FindRotated(ctx, tokenHash("t1"), now); !errors.Is(err, errFault) {
			t.Fatalf("FindRotated with a failing read = %v", err)
		}
	})
}
