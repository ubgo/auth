package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/sqlb"
)

// sessKey is a valid stateless/snapshot key for these tests.
var sessKey = bytes.Repeat([]byte{9}, SealKeySize)

func TestNew_SessionModeRefusals(t *testing.T) {
	for name, opts := range map[string][]Option{
		"a store and stateless": {WithSessionStore(NewMemorySessionStore()), WithStatelessSessions(sessKey)},
		"a short stateless key": {WithStatelessSessions([]byte("short"))},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(append(opts, WithPlugins(scriptSignIn{}))...); !errors.Is(err, ErrBadOperation) {
				t.Fatalf("err = %v, want ErrBadOperation", err)
			}
		})
	}
}

func TestNew_SessionCacheTTLIsBounded(t *testing.T) {
	for ttl, want := range map[time.Duration]time.Duration{0: DefaultSessionCacheTTL, time.Hour: MaxSessionCacheTTL, 5 * time.Minute: 5 * time.Minute} {
		a, err := New(WithPlugins(scriptSignIn{}), WithSessionCache(NewMemorySessionCache(1), ttl))
		if err != nil {
			t.Fatal(err)
		}
		if a.cacheTTL != want {
			t.Errorf("ttl %v: cacheTTL = %v, want %v", ttl, a.cacheTTL, want)
		}
	}
}

func TestSessionStore_AccessorReportsTheMode(t *testing.T) {
	mem := NewMemorySessionStore()
	a, err := New(WithPlugins(scriptSignIn{}), WithSessionStore(mem))
	if err != nil {
		t.Fatal(err)
	}
	if a.SessionStore() != mem {
		t.Fatal("SessionStore must return the configured store")
	}
	sl, err := New(WithPlugins(scriptSignIn{}), WithStatelessSessions(sessKey))
	if err != nil {
		t.Fatal(err)
	}
	if sl.SessionStore() != nil {
		t.Fatal("stateless mode has no store")
	}
	if _, _, _, err := sl.ResolveSession(context.Background(), "x"); !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("stateless resolve with no database: %v, want ErrNoDatabase (the user must be loaded)", err)
	}
}

func TestSessionLifetime_DefaultsAndBounds(t *testing.T) {
	cfg := SessionConfig{IdleTimeout: 7 * time.Hour, MaxLifetime: 30 * time.Hour, RefreshAfter: time.Hour, TransientIdleTimeout: 2 * time.Hour}
	got := cfg.fill(SessionLifetime{Idle: -1, Max: -1, RefreshAfter: -1}, false)
	if got != (SessionLifetime{Idle: 7 * time.Hour, Max: 30 * time.Hour, RefreshAfter: time.Hour}) {
		t.Fatalf("negative fields: %+v, want the defaults", got)
	}
	if got := cfg.fill(SessionLifetime{}, true); got.Idle != 2*time.Hour {
		t.Fatalf("transient idle = %v, want the transient default", got.Idle)
	}
	if got := (SessionConfig{}).fill(SessionLifetime{}, true); got.Idle != DefaultTransientIdleTimeout {
		t.Fatalf("transient idle with no config = %v, want %v", got.Idle, DefaultTransientIdleTimeout)
	}
	if got := cfg.fill(SessionLifetime{Max: 10 * MaxSessionLifetime}, false); got.Max != MaxSessionLifetime {
		t.Fatalf("Max = %v, want it capped at %v", got.Max, MaxSessionLifetime)
	}
	created := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	maxAt := created.Add(3 * time.Hour)
	s := Session{CreatedAt: created, IdleSeconds: 60, RefreshSeconds: 30, MaxExpiresAt: &maxAt}
	if lt := s.Lifetime(cfg); lt != (SessionLifetime{Idle: time.Minute, Max: 3 * time.Hour, RefreshAfter: 30 * time.Second}) {
		t.Fatalf("Lifetime = %+v, want the stored values", lt)
	}
	if exp := s.expiryAt(cfg, created.Add(179*time.Minute+30*time.Second)); !exp.Equal(maxAt) {
		t.Fatalf("expiry near the hard stop = %v, want %v", exp, maxAt)
	}
	byCred := ByCredential(SessionLifetime{Idle: 1}, SessionLifetime{Idle: 2})
	if byCred(context.Background(), SessionPolicyInput{Credential: CredentialNone}).Idle != 1 {
		t.Fatal("a Go call must get the cookie lifetime")
	}
}

func TestSnapshotCache_AcceptsOnlyItsOwnValidValue(t *testing.T) {
	ctx := context.Background()
	c := NewSnapshotCache(sessKey)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	key := CacheKey{TokenHash: HashToken("t")}
	sess, u := Session{ID: "s", UserID: "u"}, User{ID: "u"}
	v, err := c.Put(ctx, key, sess, u, now.Add(time.Minute))
	if err != nil || v == "" {
		t.Fatalf("Put = %q, %v", v, err)
	}
	gcm, _ := newGCM(sessKey)
	nonce := randomBytes(gcm.NonceSize())
	notJSON := base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("not json"), []byte(snapshotAAD)))
	otherPurpose := base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("{}"), []byte(statelessAAD)))
	for name, k := range map[string]CacheKey{
		"no client value":            {TokenHash: key.TokenHash},
		"garbage":                    {TokenHash: key.TokenHash, Client: "!!!"},
		"too short":                  {TokenHash: key.TokenHash, Client: "AAAA"},
		"sealed for another purpose": {TokenHash: key.TokenHash, Client: otherPurpose},
		"not a snapshot":             {TokenHash: key.TokenHash, Client: notJSON},
		"another session's token":    {TokenHash: HashToken("other"), Client: v},
	} {
		if _, _, ok, err := c.Get(ctx, k, now); ok || err != nil {
			t.Errorf("%s: ok=%v err=%v, want a miss", name, ok, err)
		}
	}
	if _, _, ok, _ := c.Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: v}, now.Add(time.Minute)); ok {
		t.Error("an entry at its expiry must be a miss")
	}
	gotS, gotU, ok, err := c.Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: v}, now)
	if err != nil || !ok || gotS.ID != sess.ID || gotU.ID != u.ID {
		t.Fatalf("Get = %+v %+v %v %v, want the snapshot", gotS, gotU, ok, err)
	}
	if err := c.Drop(ctx, key); err != nil {
		t.Fatal(err)
	}
	bad := NewSnapshotCache([]byte("short"))
	if _, err := bad.Put(ctx, key, sess, u, now); err == nil {
		t.Error("Put with a bad key must fail")
	}
	if _, _, _, err := bad.Get(ctx, CacheKey{TokenHash: key.TokenHash, Client: v}, now); err == nil {
		t.Error("Get with a bad key must fail")
	}
}

func TestMemorySessionCache_EvictsTheEntryExpiringSoonest(t *testing.T) {
	ctx := context.Background()
	c := NewMemorySessionCache(2)
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	put := func(tok string, until time.Time) {
		if _, err := c.Put(ctx, CacheKey{TokenHash: HashToken(Token(tok))}, Session{ID: tok}, User{}, until); err != nil {
			t.Fatal(err)
		}
	}
	put("soon", now.Add(time.Minute))
	put("late", now.Add(time.Hour))
	put("late", now.Add(time.Hour)) // a replace makes no room
	put("new", now.Add(30*time.Minute))
	has := func(tok string) bool {
		_, _, ok, _ := c.Get(ctx, CacheKey{TokenHash: HashToken(Token(tok))}, now)
		return ok
	}
	if has("soon") || !has("late") || !has("new") {
		t.Fatalf("after filling: soon=%v late=%v new=%v; want soon evicted", has("soon"), has("late"), has("new"))
	}
	if _, _, ok, _ := c.Get(ctx, CacheKey{TokenHash: HashToken("new")}, now.Add(30*time.Minute)); ok {
		t.Fatal("an entry at its expiry must be a miss")
	}
	if err := c.Drop(ctx, CacheKey{TokenHash: HashToken("late")}); err != nil || has("late") {
		t.Fatal("Drop must forget the entry")
	}
}

func TestStateless_OpenRefusesWhatIsNotASession(t *testing.T) {
	gcm, _ := newGCM(sessKey)
	ring, _ := NewKeyRing(sessKey)
	st := &statelessSessions{ring: ring}
	nonce := randomBytes(gcm.NonceSize())
	for name, tok := range map[string]Token{
		"garbage":                    "!!!",
		"too short":                  "AAAA",
		"a stored-session token":     NewToken(),
		"sealed for another purpose": Token(base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("{}"), []byte(snapshotAAD)))),
		"not a session":              Token(base64.RawURLEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte("nope"), []byte(statelessAAD)))),
	} {
		if _, err := st.open(tok); !errors.Is(err, ErrSessionNotFound) {
			t.Errorf("%s: %v, want ErrSessionNotFound", name, err)
		}
	}
	admin := "adm"
	maxAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	want := Session{ID: "s", UserID: "u", CreatedAt: maxAt.Add(-time.Hour), ExpiresAt: maxAt, LastSeenAt: maxAt.Add(-time.Hour),
		SecondFactorPending: true, Transient: true, ImpersonatedBy: &admin, IdleSeconds: 1, RefreshSeconds: 2, MaxExpiresAt: &maxAt}
	tok, err := st.seal(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.open(tok)
	if err != nil || got.ID != want.ID || !got.ExpiresAt.Equal(want.ExpiresAt) || *got.ImpersonatedBy != admin || !got.SecondFactorPending || !got.Transient || got.IdleSeconds != 1 || got.RefreshSeconds != 2 || !got.MaxExpiresAt.Equal(maxAt) {
		t.Fatalf("round trip = %+v, %v; want %+v", got, err, want)
	}
	if strings.ContainsAny(tok.Reveal(), "+/=") {
		t.Fatal("a stateless token must be base64url, like every other token")
	}
}

func TestMemorySessionStore_TouchOfAnUnknownIDMovesNothing(t *testing.T) {
	ctx := context.Background()
	m := NewMemorySessionStore()
	moved, err := m.Touch(ctx, "nobody", time.Now(), time.Now())
	if err != nil || moved {
		t.Fatalf("Touch = %v, %v", moved, err)
	}
	if _, ok := currentSession(ctx, "u"); ok {
		t.Fatal("no current session outside a request")
	}
}

func TestSessionCheck_UserOnlyLookupNamesTheAllowedAlias(t *testing.T) {
	msg := allowedAliases(map[string]bool{TableAliasUser: true})
	if !strings.Contains(msg, "does not join") {
		t.Fatalf("message %q must say why auth_session is missing", msg)
	}
	_, err := New(WithPlugins(scriptSignIn{}, checkerPlugin{sqlb.Eq(SessionTransient, false)}), WithSessionStore(NewMemorySessionStore()))
	if !errors.Is(err, ErrBadSessionCheck) || !strings.Contains(err.Error(), "does not join") {
		t.Fatalf("err = %v", err)
	}
}

// checkerPlugin adds one session condition.
type checkerPlugin []sqlb.Predicate

func (checkerPlugin) Name() string                          { return "chk" }
func (c checkerPlugin) SessionPredicates() []sqlb.Predicate { return c }
