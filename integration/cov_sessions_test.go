package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/sessiontest"
	"github.com/ubgo/sqlb"
)

// Pluggable sessions: the SQL store against the conformance suite on every
// engine, then each mode (memory store, stateless, cached) end to end.

// sessKey is the 32-byte key stateless sessions and the snapshot cache use.
var sessKey = bytes.Repeat([]byte{42}, auth.SealKeySize)

// sessUsers are the users the conformance suite refers to, so the single-query
// lookup, which joins auth_user, finds them.
var sessUsers = []string{"u1", "u2"}

// TestSessionStore_SQLConforms runs the shared suite over the SQL store on
// every engine. Each case starts from an empty auth_session and the users
// the suite names; the sessions are deleted explicitly, since no foreign key
// removes them with their users (ADR-0002).
func TestSessionStore_SQLConforms(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil)
		sessiontest.Run(t, func(t *testing.T) auth.SessionStore {
			ctx := context.Background()
			if _, err := a.Exec(ctx, sqlb.NewDelete(a.Dialect()).From(auth.TableSession).Where(sqlb.In(auth.SessionUserID, sessUsers...))); err != nil {
				t.Fatal(err)
			}
			if _, err := a.Exec(ctx, sqlb.NewDelete(a.Dialect()).From(auth.TableUser).Where(sqlb.In(auth.UserID, sessUsers...))); err != nil {
				t.Fatal(err)
			}
			for _, id := range sessUsers {
				now := a.Now()
				if _, err := a.Exec(ctx, sqlb.NewInsert(a.Dialect()).Into(auth.TableUser).Row(
					sqlb.Set(auth.UserID, id), sqlb.Set(auth.UserName, id), sqlb.Set(auth.UserImage, ""),
					sqlb.Set(auth.UserCreatedAt, now), sqlb.Set(auth.UserUpdatedAt, now))); err != nil {
					t.Fatal(err)
				}
			}
			return a.SessionStore()
		})
	})
}

// sessBanned is a plugin that bans users named "banned" through the session
// lookup, with a condition on auth_user only, so it works in every mode.
type sessBanned struct{}

func (sessBanned) Name() string { return "sessbanned" }
func (sessBanned) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.NotEq(auth.UserName, "banned")}
}

// sessRowCheck is a plugin whose condition names auth_session, which only the
// SQL store can serve.
type sessRowCheck struct{}

func (sessRowCheck) Name() string { return "sessrowcheck" }
func (sessRowCheck) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.Eq(auth.SessionTransient, false)}
}

// sessSignIn creates a user with a verified address and signs them in with
// the request's credential, returning the token.
func sessSignIn(t *testing.T, a *auth.Auth, ctx context.Context) (auth.User, auth.Token) {
	t.Helper()
	u, _ := coreUser(t, a)
	_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return u, tok
}

// sessResolve resolves tok through a browser request and returns the request
// context, so the caller can read its effects.
func sessResolve(t *testing.T, a *auth.Auth, tok auth.Token) (context.Context, error) {
	t.Helper()
	ctx := request(a, tok)
	return ctx, a.Resolve(ctx)
}

func TestSessions_EveryModeSignsInRefreshesAndSignsOutEverywhere(t *testing.T) {
	modes := map[string][]auth.Option{
		"sql":       nil,
		"memory":    {auth.WithSessionStore(auth.NewMemorySessionStore())},
		"stateless": {auth.WithStatelessSessions(sessKey)},
	}
	for name, opts := range modes {
		t.Run(name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				a := e.newAuth(t, opts, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName}, sessBanned{})
				bg := context.Background()
				u, tok := sessSignIn(t, a, bg)
				if _, ok := auth.CurrentUser(func() context.Context { ctx, _ := sessResolve(t, a, tok); return ctx }()); !ok {
					t.Fatal("the new session does not sign in")
				}
				if name == "stateless" && len(tok.Reveal()) <= 43 {
					t.Fatalf("a stateless token must carry the session; got %d characters", len(tok.Reveal()))
				}

				// A refresh past RefreshAfter moves the expiry and re-issues
				// the token (a new one in stateless mode).
				e.clock.Advance(auth.DefaultSessionConfig.RefreshAfter + time.Minute)
				ctx, err := sessResolve(t, a, tok)
				if err != nil {
					t.Fatal(err)
				}
				effects := auth.RequestEffects(ctx)
				if len(effects) != 1 || effects[0].Kind != auth.EffectIssueSession {
					t.Fatalf("effects after a refresh = %+v, want the session re-issued", effects)
				}
				sess, _ := auth.CurrentSession(ctx)
				if want := e.clock.Now().Add(auth.DefaultSessionConfig.IdleTimeout); !sess.ExpiresAt.Equal(want) {
					t.Fatalf("expiry after refresh = %v, want %v", sess.ExpiresAt, want)
				}
				current := effects[0].Token
				if name == "stateless" && current == tok {
					t.Fatal("a stateless refresh must issue a new token")
				}
				if _, _, _, err := a.ResolveSession(bg, current); err != nil {
					t.Fatalf("the re-issued token: %v", err)
				}

				// A tampered token is signed out, not an error.
				bad := auth.Token(strings.Map(func(r rune) rune {
					if r == 'A' {
						return 'B'
					}
					return 'A'
				}, current.Reveal()))
				if _, _, _, err := a.ResolveSession(bg, bad); !errors.Is(err, auth.ErrSignedOut) {
					t.Fatalf("tampered token: %v, want ErrSignedOut", err)
				}

				// Sign out everywhere: every token stops, in every mode.
				if err := a.DeleteUserSessions(bg, u.ID, ""); err != nil {
					t.Fatal(err)
				}
				for _, old := range []auth.Token{tok, current} {
					if _, _, _, err := a.ResolveSession(bg, old); !errors.Is(err, auth.ErrSignedOut) {
						t.Fatalf("after sign-out everywhere: %v, want ErrSignedOut", err)
					}
				}
				// And a session created afterwards works, even in the same
				// clock instant, which is what a password reset followed by
				// a sign-in needs.
				_, again, err := a.CreateSession(bg, u.ID, auth.Client{})
				if err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := a.ResolveSession(bg, again); err != nil {
					t.Fatalf("a session after sign-out everywhere: %v", err)
				}

				// A ban applies on the next request, whatever the mode.
				name := "banned"
				if _, err := a.UpdateUser(bg, u.ID, auth.UserUpdate{Name: &name}); err != nil {
					t.Fatal(err)
				}
				if _, _, _, err := a.ResolveSession(bg, again); !errors.Is(err, auth.ErrSignedOut) {
					t.Fatalf("banned user: %v, want ErrSignedOut", err)
				}
			})
		})
	}
}

func TestSessions_StoreModesListRevokeAndSweep(t *testing.T) {
	for name, store := range map[string]func() auth.SessionStore{
		"sql":    func() auth.SessionStore { return nil },
		"memory": func() auth.SessionStore { return auth.NewMemorySessionStore() },
	} {
		t.Run(name, func(t *testing.T) {
			e := newFaultEnv(t)
			var opts []auth.Option
			if s := store(); s != nil {
				opts = append(opts, auth.WithSessionStore(s))
			}
			a := coreAuth(t, e.env, nil, opts...)
			bg := context.Background()
			u, first := sessSignIn(t, a, bg)
			_, second, err := a.CreateSession(bg, u.ID, auth.Client{})
			if err != nil {
				t.Fatal(err)
			}
			list := must[auth.SessionsResult](t)(a.ListSessions(request(a, first)))
			if len(list.Sessions) != 2 {
				t.Fatalf("sessions = %+v, want both", list.Sessions)
			}
			other := list.Sessions[0].ID
			if list.Sessions[0].Current {
				other = list.Sessions[1].ID
			}
			if err := a.RevokeSession(request(a, first), other); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := a.ResolveSession(bg, second); !errors.Is(err, auth.ErrSignedOut) {
				t.Fatalf("revoked session: %v, want ErrSignedOut", err)
			}
			if err := a.SignOut(request(a, first)); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := a.ResolveSession(bg, first); !errors.Is(err, auth.ErrSignedOut) {
				t.Fatalf("after sign-out: %v, want ErrSignedOut", err)
			}
			_, third, err := a.CreateSession(bg, u.ID, auth.Client{})
			if err != nil {
				t.Fatal(err)
			}
			e.clock.Advance(auth.DefaultSessionConfig.MaxLifetime + time.Hour)
			res := must[auth.SweepResult](t)(a.Sweep(bg, time.Hour))
			if res[auth.CorePluginName+"."+auth.TableNameSession] != 1 {
				t.Fatalf("Sweep = %v, want the expired session counted under the core table", res)
			}
			if _, _, _, err := a.ResolveSession(bg, third); !errors.Is(err, auth.ErrSignedOut) {
				t.Fatalf("expired session: %v, want ErrSignedOut", err)
			}
		})
	}
}

func TestSessions_StatelessAnswersOnlyForTheCurrentSession(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{corePromoteOp()}}, auth.WithStatelessSessions(sessKey))
	bg := context.Background()
	u, tok := sessSignIn(t, a, bg)
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameSession)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("auth_session rows = %d, %v; a stateless session must write none", n, err)
	}
	list := must[auth.SessionsResult](t)(a.ListSessions(request(a, tok)))
	if len(list.Sessions) != 1 || !list.Sessions[0].Current {
		t.Fatalf("sessions = %+v, want only the current one", list.Sessions)
	}
	if _, err := a.Sessions(bg, u.ID); !errors.Is(err, auth.ErrSessionsUnavailable) {
		t.Fatalf("Sessions with no request: %v, want ErrSessionsUnavailable", err)
	}
	if err := a.RevokeSession(request(a, tok), "ses_other"); !errors.Is(err, auth.ErrSessionsUnavailable) {
		t.Fatalf("revoke another session: %v, want ErrSessionsUnavailable", err)
	}
	if err := a.DeleteUserSessions(bg, u.ID, list.Sessions[0].ID); !errors.Is(err, auth.ErrSessionsUnavailable) {
		t.Fatalf("sign out others: %v, want ErrSessionsUnavailable", err)
	}
	ctx := request(a, tok)
	if err := a.SignOut(ctx); err != nil {
		t.Fatalf("sign out of the current session: %v", err)
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 1 || effects[0].Kind != auth.EffectClearSession {
		t.Fatalf("effects after sign-out = %+v, want the cookie cleared", effects)
	}
	if res := must[auth.SweepResult](t)(a.Sweep(bg, time.Hour)); res[auth.CorePluginName+"."+auth.TableNameSession] != 0 {
		t.Fatalf("Sweep = %v; stateless mode has no sessions to sweep", res)
	}

	// A key rotation is the global logout switch.
	rotated := coreAuth(t, e.env, nil, auth.WithStatelessSessions(bytes.Repeat([]byte{7}, auth.SealKeySize)))
	if _, _, _, err := rotated.ResolveSession(bg, tok); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("after a key rotation: %v, want ErrSignedOut", err)
	}
}

func TestSessions_StatelessPendingSecondFactorIsPromoted(t *testing.T) {
	e := newFaultEnv(t)
	promote := corePromoteOp()
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{promote}, second: true}, auth.WithStatelessSessions(sessKey))
	_, tok := sessSignIn(t, a, context.Background())
	if _, ok := auth.CurrentUser(func() context.Context { ctx, _ := sessResolve(t, a, tok); return ctx }()); ok {
		t.Fatal("a pending session must not sign in")
	}
	ctx := request(a, tok)
	full := must[auth.Session](t)(promote.Call(ctx, struct{}{}))
	if full.SecondFactorPending {
		t.Fatal("promoted session is still pending")
	}
	effects := auth.RequestEffects(ctx)
	if len(effects) != 1 || effects[0].Kind != auth.EffectIssueSession || effects[0].Token == tok {
		t.Fatalf("effects = %+v, want a new full-session token", effects)
	}
	if _, _, _, err := a.ResolveSession(context.Background(), effects[0].Token); err != nil {
		t.Fatal(err)
	}
}

func TestSessions_NonJoiningStoreRefusesASessionRowCheck(t *testing.T) {
	e := newFaultEnv(t)
	for name, opt := range map[string]auth.Option{
		"memory store": auth.WithSessionStore(auth.NewMemorySessionStore()),
		"stateless":    auth.WithStatelessSessions(sessKey),
	} {
		_, err := auth.New(e.withDB(), auth.WithPlugins(&coreStub{name: coreStubName}, sessRowCheck{}), opt)
		if !errors.Is(err, auth.ErrBadSessionCheck) || !strings.Contains(err.Error(), "sessrowcheck") {
			t.Errorf("%s: %v, want ErrBadSessionCheck naming the plugin", name, err)
		}
	}
	if _, err := auth.New(e.withDB(), auth.WithPlugins(&coreStub{name: coreStubName}, sessRowCheck{})); err != nil {
		t.Fatalf("the SQL store joins auth_session, so the same check is fine: %v", err)
	}
}

// sessFailingCache is a SessionCache whose calls fail as its fields say;
// Get misses when it does not fail.
type sessFailingCache struct{ get, put, drop bool }

var errSessCache = errors.New("sesscache: down")

func (c sessFailingCache) Get(context.Context, auth.CacheKey, time.Time) (auth.Session, auth.User, bool, error) {
	if c.get {
		return auth.Session{}, auth.User{}, false, errSessCache
	}
	return auth.Session{}, auth.User{}, false, nil
}

func (c sessFailingCache) Put(context.Context, auth.CacheKey, auth.Session, auth.User, time.Time) (string, error) {
	if c.put {
		return "", errSessCache
	}
	return "", nil
}

func (c sessFailingCache) Drop(context.Context, auth.CacheKey) error {
	if c.drop {
		return errSessCache
	}
	return nil
}

func TestSessions_SnapshotCacheSkipsTheDatabase(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithSessionCache(auth.NewSnapshotCache(sessKey), time.Minute))
	bg := context.Background()
	_, tok := sessSignIn(t, a, bg)

	ctx, err := sessResolve(t, a, tok)
	if err != nil {
		t.Fatal(err)
	}
	effects := auth.RequestEffects(ctx)
	if len(effects) != 1 || effects[0].Kind != auth.EffectCacheSession || effects[0].Value == "" || !effects[0].ExpiresAt.Equal(e.clock.Now().Add(time.Minute)) {
		t.Fatalf("effects after the first request = %+v, want a snapshot to hold for a minute", effects)
	}
	snap := effects[0].Value

	withSnap := func(tok auth.Token) context.Context {
		return a.WithRequest(bg, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: tok, CachedSession: snap, Client: auth.Client{Origin: testBaseURL}})
	}
	e.f.arm(1)
	ctx = withSnap(tok)
	err = a.Resolve(ctx)
	if e.f.disarm() {
		t.Fatal("a request with a valid snapshot reached the database")
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := auth.CurrentUser(ctx); !ok {
		t.Fatal("the snapshot did not sign in")
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 0 {
		t.Fatalf("a cache hit recorded effects: %+v", effects)
	}

	// Another session's token with this snapshot is a miss, then a lookup.
	_, other, err := a.CreateSession(bg, must[auth.User](t)(a.CreateUser(bg, auth.NewUser{})).ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	e.f.arm(1)
	ctx = withSnap(other)
	err = a.Resolve(ctx)
	if !e.f.disarm() || err == nil {
		t.Fatalf("a snapshot with another session's token must be a miss that reaches the database: hit=%v err=%v", !e.f.disarm(), err)
	}

	// After the TTL the snapshot is a miss; the lookup issues a fresh one.
	e.clock.Advance(2 * time.Minute)
	ctx = withSnap(tok)
	if err := a.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 1 || effects[0].Kind != auth.EffectCacheSession || effects[0].Value == snap {
		t.Fatalf("effects after the snapshot expired = %+v, want a new snapshot", effects)
	}

	// Sign-out clears the client's copy.
	ctx = withSnap(tok)
	if err := a.SignOut(ctx); err != nil {
		t.Fatal(err)
	}
	kinds := map[auth.EffectKind]bool{}
	for _, ef := range auth.RequestEffects(ctx) {
		kinds[ef.Kind] = true
	}
	if !kinds[auth.EffectClearCache] || !kinds[auth.EffectClearSession] {
		t.Fatalf("effects after sign-out = %v, want the cache and the session cleared", kinds)
	}
}

func TestSessions_MemoryCacheAndItsLimits(t *testing.T) {
	e := newFaultEnv(t)
	cache := auth.NewMemorySessionCache(10)
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{corePromoteOp()}}, auth.WithSessionCache(cache, time.Hour), auth.WithSession(auth.SessionConfig{IdleTimeout: 5 * time.Minute, MaxLifetime: time.Hour, RefreshAfter: time.Hour}))
	bg := context.Background()
	u, tok := sessSignIn(t, a, bg)
	if _, err := sessResolve(t, a, tok); err != nil {
		t.Fatal(err)
	}
	// The second request is served from memory: no database call.
	e.f.arm(1)
	ctx := request(a, tok)
	err := a.Resolve(ctx)
	if e.f.disarm() || err != nil {
		t.Fatalf("second request: reached the database or failed: %v", err)
	}
	if effects := auth.RequestEffects(ctx); len(effects) != 0 {
		t.Fatalf("a memory cache hands the client nothing, got %+v", effects)
	}
	// The entry never outlives the session: the TTL is an hour (clamped to
	// fifteen minutes), the session expires in five, so at six minutes the
	// lookup runs again and finds nothing.
	e.clock.Advance(6 * time.Minute)
	if _, _, _, err := a.ResolveSession(bg, tok); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("expired session: %v, want ErrSignedOut", err)
	}
	if _, ok := auth.CurrentUser(func() context.Context { c, _ := sessResolve(t, a, tok); return c }()); ok {
		t.Fatal("a cache entry outlived the session")
	}

	// Sign-out drops the entry, so the next request looks the session up
	// and finds it gone.
	_, tok2, err := a.CreateSession(bg, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessResolve(t, a, tok2); err != nil {
		t.Fatal(err)
	}
	if err := a.SignOut(request(a, tok2)); err != nil {
		t.Fatal(err)
	}
	if _, ok := auth.CurrentUser(func() context.Context { c, _ := sessResolve(t, a, tok2); return c }()); ok {
		t.Fatal("a signed-out session was still served from the cache")
	}

	// A pending session is never cached: its second request looks it up
	// again.
	pe := newFaultEnv(t)
	pending := coreAuth(t, pe.env, &coreStub{second: true}, auth.WithSessionCache(auth.NewMemorySessionCache(10), time.Hour))
	_, ptok := sessSignIn(t, pending, bg)
	if _, err := sessResolve(t, pending, ptok); err != nil {
		t.Fatal(err)
	}
	pe.f.arm(1)
	_ = pending.Resolve(request(pending, ptok))
	if !pe.f.disarm() {
		t.Fatal("a pending session was served from the cache")
	}
}

func TestSessions_ACacheFailureIsAnErrorNotASignOut(t *testing.T) {
	for name, c := range map[string]sessFailingCache{"Get": {get: true}, "Put": {put: true}} {
		e := newFaultEnv(t)
		a := coreAuth(t, e.env, nil, auth.WithSessionCache(c, time.Minute))
		_, tok := sessSignIn(t, a, context.Background())
		if _, err := sessResolve(t, a, tok); !errors.Is(err, errSessCache) {
			t.Errorf("%s fails: Resolve = %v, want the cache's failure", name, err)
		}
	}
	// A Drop failure fails the operation that must forget the session, so a
	// sign-out never reports success while a cache still answers for it.
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithSessionCache(sessFailingCache{drop: true}, time.Minute))
	_, tok := sessSignIn(t, a, context.Background())
	cur := must[auth.SessionsResult](t)(a.ListSessions(request(a, tok))).Sessions[0].ID
	for name, err := range map[string]error{
		"sign out":            a.SignOut(request(a, tok)),
		"sign out everywhere": a.SignOutAll(request(a, tok)),
		"revoke current":      a.RevokeSession(request(a, tok), cur),
	} {
		if !errors.Is(err, errSessCache) {
			t.Errorf("%s: %v, want the cache's failure", name, err)
		}
	}
}

func TestSessions_StatelessExpiryAndHooks(t *testing.T) {
	e := newFaultEnv(t)
	on := false
	a := coreAuth(t, e.env, &coreStub{hooks: coreRefusingHooks(&on)}, auth.WithStatelessSessions(sessKey))
	bg := context.Background()
	u, tok := sessSignIn(t, a, bg)
	e.clock.Advance(auth.DefaultSessionConfig.IdleTimeout + time.Minute)
	if _, _, _, err := a.ResolveSession(bg, tok); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("an expired stateless token: %v, want ErrSignedOut", err)
	}
	on = true
	if _, _, err := a.CreateSession(bg, u.ID, auth.Client{}); !errors.Is(err, errCoreHook) {
		t.Fatalf("a refused stateless session: %v, want the hook's refusal", err)
	}
}

func TestSessions_PolicyChoosesAndStoresTheLifetime(t *testing.T) {
	e := newFaultEnv(t)
	web := auth.SessionLifetime{Idle: time.Hour, Max: 24 * time.Hour, RefreshAfter: 10 * time.Minute}
	app := auth.SessionLifetime{Idle: 30 * 24 * time.Hour, Max: 2 * auth.MaxSessionLifetime}
	a := coreAuth(t, e.env, nil, auth.WithSessionPolicy(auth.ByCredential(web, app)))
	bg := context.Background()
	u, _ := coreUser(t, a)
	start := e.clock.Now()

	bearer := a.WithRequest(bg, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialBearer})
	appSess, appTok, err := a.CreateSession(bearer, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if appSess.IdleSeconds != int64(app.Idle/time.Second) || appSess.MaxExpiresAt == nil || !appSess.MaxExpiresAt.Equal(start.Add(auth.MaxSessionLifetime)) {
		t.Fatalf("app session = %+v, want the bearer lifetime with Max capped at %v", appSess, auth.MaxSessionLifetime)
	}
	if appSess.RefreshSeconds != int64(auth.DefaultSessionConfig.RefreshAfter/time.Second) {
		t.Fatalf("app RefreshSeconds = %d, want the default filled in", appSess.RefreshSeconds)
	}
	webSess, _, err := a.CreateSession(bg, u.ID, auth.Client{}) // a Go call gets the cookie lifetime
	if err != nil {
		t.Fatal(err)
	}
	if webSess.IdleSeconds != 3600 || !webSess.ExpiresAt.Equal(start.Add(time.Hour)) {
		t.Fatalf("web session = %+v, want an hour idle", webSess)
	}

	// A refresh uses the session's own lifetime, not the default.
	e.clock.Advance(auth.DefaultSessionConfig.RefreshAfter + time.Minute)
	ctx, err := sessResolve(t, a, appTok)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := auth.CurrentSession(ctx)
	if want := e.clock.Now().Add(app.Idle); !got.ExpiresAt.Equal(want) {
		t.Fatalf("refreshed expiry = %v, want %v from the session's own idle timeout", got.ExpiresAt, want)
	}

	// A row from before lifetimes were stored slides by the defaults.
	old := auth.Session{ID: "ses_old", UserID: u.ID, CreatedAt: start, LastSeenAt: start, ExpiresAt: start.Add(2 * 24 * time.Hour)} // live now, and short enough to slide
	oldTok := auth.NewToken()
	if err := a.SessionStore().Insert(bg, old, auth.HashToken(oldTok)); err != nil {
		t.Fatal(err)
	}
	ctx, err = sessResolve(t, a, oldTok)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = auth.CurrentSession(ctx)
	if want := e.clock.Now().Add(auth.DefaultSessionConfig.IdleTimeout); !got.ExpiresAt.Equal(want) {
		t.Fatalf("old row's refreshed expiry = %v, want the default %v", got.ExpiresAt, want)
	}
}

func TestSessionFaults_NewPaths(t *testing.T) {
	t.Run("resolve through a store that does not join", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithSessionStore(auth.NewMemorySessionStore()))
			_, tok := sessSignIn(t, a, context.Background())
			return func(context.Context) error { return a.Resolve(request(a, tok)) }
		})
	})
	t.Run("resolve stateless with a refresh", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey))
			_, tok := sessSignIn(t, a, context.Background())
			e.clock.Advance(auth.DefaultSessionConfig.RefreshAfter + time.Minute)
			return func(context.Context) error { return a.Resolve(request(a, tok)) }
		})
	})
	t.Run("create stateless", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey))
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error { _, _, err := a.CreateSession(ctx, u.ID, auth.Client{}); return err }
		})
	})
	for name, opts := range map[string][]auth.Option{"sql": nil, "stateless": {auth.WithStatelessSessions(sessKey)}} {
		t.Run("sign out everywhere "+name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				a := coreAuth(t, e.env, nil, opts...)
				u, _ := sessSignIn(t, a, context.Background())
				return func(ctx context.Context) error { return a.DeleteUserSessions(ctx, u.ID, "") }
			})
		})
	}
	t.Run("cached lookup", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil, auth.WithSessionCache(auth.NewSnapshotCache(sessKey), time.Minute))
			_, tok := sessSignIn(t, a, context.Background())
			return func(context.Context) error { return a.Resolve(request(a, tok)) }
		})
	})
}

// TestSessions_BearerDeliveryGetsTheAppLifetimeOverHTTP: an app signing in
// has no token yet, so its request carries only Auth-Token-Mode: bearer; the
// policy must still give it the bearer lifetime, through the real transport.
func TestSessions_BearerDeliveryGetsTheAppLifetimeOverHTTP(t *testing.T) {
	e := newFaultEnv(t)
	op := coreProvenOp()
	app := auth.SessionLifetime{Idle: 30 * 24 * time.Hour}
	a := coreAuth(t, e.env, &coreStub{ops: []auth.Operation{op}}, auth.WithSessionPolicy(auth.ByCredential(auth.SessionLifetime{Idle: time.Hour}, app)))
	coreUser(t, a)
	srv := httptest.NewServer(authhttp.OperationHandler(a, op))
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		mode string
		want int64
	}{{authhttp.TokenModeBearer, int64(app.Idle / time.Second)}, {"", 3600}} {
		req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"Raw":"`+alice+`","Create":false}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if tc.mode != "" {
			req.Header.Set(authhttp.TokenModeHeader, tc.mode)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var out auth.ProvenSignIn
		if err := json.NewDecoder(res.Body).Decode(&out); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("mode %q: status %d, decode %v", tc.mode, res.StatusCode, err)
		}
		res.Body.Close()
		if out.Session.IdleSeconds != tc.want {
			t.Fatalf("mode %q: IdleSeconds = %d, want %d", tc.mode, out.Session.IdleSeconds, tc.want)
		}
	}
}
