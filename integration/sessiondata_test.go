package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/sessiondata"
	"github.com/ubgo/sqlb"
)

// Per-session app data, both shapes (owner decision 2026-10-03): Session.Data
// carried by every store, token and cache, and plugin/sessiondata's table
// kept in step with the sessions through the core's lifecycle notices.

// sdPrefs is the app's own type for what a session carries.
type sdPrefs struct {
	Workspace string `json:"ws"`
	Dark      bool   `json:"dark,omitempty"`
}

var sdStart, sdNext = sdPrefs{Workspace: "start"}, sdPrefs{Workspace: "acme", Dark: true}

// sdStartHook is the app's Session.BeforeCreate hook that gives every new
// session its starting data.
func sdStartHook(v any) auth.DataHooks {
	return auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		BeforeCreate: func(_ context.Context, _ sqlb.DBTX, s *auth.Session) (err error) {
			s.Data, err = auth.EncodeSessionData(v)
			return err
		},
	}}
}

// sdModes are the session modes the inline data must survive: each store,
// stateless, and the two client-facing caches in front of the SQL store.
var sdModes = map[string][]auth.Option{
	"sql":       nil,
	"memory":    {auth.WithSessionStore(auth.NewMemorySessionStore())},
	"stateless": {auth.WithStatelessSessions(sessKey)},
	"snapshot":  {auth.WithSessionCache(auth.NewSnapshotCache(sessKey), time.Minute)},
	"memcache":  {auth.WithSessionCache(auth.NewMemorySessionCache(16), time.Minute)},
}

// sdRead resolves tok with the client's cached value, if any, and returns the
// data the request sees.
func sdRead(t *testing.T, a *auth.Auth, tok auth.Token, cached string) (context.Context, sdPrefs, bool) {
	t.Helper()
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: tok, CachedSession: cached, Client: auth.Client{Origin: testBaseURL}})
	if err := a.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	v, ok, err := auth.SessionData[sdPrefs](ctx)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, v, ok
}

// sdEffect returns the first effect of kind in ctx, or nil.
func sdEffect(ctx context.Context, kind auth.EffectKind) *auth.Effect {
	for _, ef := range auth.RequestEffects(ctx) {
		if ef.Kind == kind {
			return &ef
		}
	}
	return nil
}

// TestSessionData_EveryMode: a hook sets the data a session starts with, the
// request reads it with no query, SetSessionData replaces it for the rest of
// the request and for every later request, and the data survives a refresh
// and a token rotation, in every mode and on every engine.
func TestSessionData_EveryMode(t *testing.T) {
	for name, opts := range sdModes {
		t.Run(name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				a := coreAuth(t, e, &coreStub{hooks: sdStartHook(sdStart)}, opts...)
				_, tok := sessSignIn(t, a, context.Background())

				ctx, got, ok := sdRead(t, a, tok, "")
				if !ok || got != sdStart {
					t.Fatalf("data after sign-in = %+v, %v; want %+v from the hook", got, ok, sdStart)
				}
				cached := ""
				if ef := sdEffect(ctx, auth.EffectCacheSession); ef != nil {
					cached = ef.Value
				}

				// A write is seen by the rest of the request and by the next
				// one. In stateless mode the next request needs the new
				// token; with a cache the client's copy is cleared.
				ctx, _, _ = sdRead(t, a, tok, cached)
				if err := auth.SetSessionData(ctx, a, sdNext); err != nil {
					t.Fatal(err)
				}
				if got, ok, _ := auth.SessionData[sdPrefs](ctx); !ok || got != sdNext {
					t.Fatalf("data in the same request after SetSessionData = %+v, %v; want %+v", got, ok, sdNext)
				}
				switch name {
				case "stateless":
					ef := sdEffect(ctx, auth.EffectIssueSession)
					if ef == nil || ef.Token == tok {
						t.Fatalf("effects = %+v, want a new token carrying the data", auth.RequestEffects(ctx))
					}
					tok = ef.Token
				case "snapshot", "memcache":
					if sdEffect(ctx, auth.EffectClearCache) == nil {
						t.Fatalf("effects = %+v, want the client's cached copy cleared", auth.RequestEffects(ctx))
					}
				default:
					if len(auth.RequestEffects(ctx)) != 0 {
						t.Fatalf("effects = %+v, want none: the row changed in place", auth.RequestEffects(ctx))
					}
				}
				if _, got, ok := sdRead(t, a, tok, ""); !ok || got != sdNext {
					t.Fatalf("data on the next request = %+v, %v; want %+v", got, ok, sdNext)
				}

				// A sliding refresh keeps it.
				e.clock.Advance(auth.DefaultSessionConfig.RefreshAfter + time.Minute)
				ctx, got, ok = sdRead(t, a, tok, "")
				if !ok || got != sdNext {
					t.Fatalf("data after a refresh = %+v, %v; want %+v", got, ok, sdNext)
				}
				if ef := sdEffect(ctx, auth.EffectIssueSession); ef == nil {
					t.Fatal("the refresh did not reissue the token")
				} else {
					tok = ef.Token
				}

				// A token rotation keeps it (the same row under a new hash;
				// a new sealed token in stateless mode).
				ctx, _, _ = sdRead(t, a, tok, "")
				rotated, err := a.RotateSessionToken(ctx, &auth.Call{Session: func() *auth.Session { s, _ := auth.CurrentSession(ctx); return &s }(), User: func() *auth.User { u, _ := auth.CurrentUser(ctx); return &u }(), Effects: &auth.Effects{}})
				if err != nil {
					t.Fatal(err)
				}
				if _, got, ok := sdRead(t, a, rotated, ""); !ok || got != sdNext {
					t.Fatalf("data after a rotation = %+v, %v; want %+v", got, ok, sdNext)
				}

				// Nil clears it; the bound and the JSON check refuse before
				// anything is written.
				ctx, _, _ = sdRead(t, a, rotated, "")
				if err := auth.SetSessionData(ctx, a, strings.Repeat("x", auth.MaxSessionDataSize)); !errors.Is(err, auth.ErrSessionDataTooLarge) {
					t.Fatalf("oversized = %v, want ErrSessionDataTooLarge", err)
				}
				if err := auth.SetSessionData(ctx, a, make(chan int)); !errors.Is(err, auth.ErrSessionDataInvalid) {
					t.Fatalf("unencodable = %v, want ErrSessionDataInvalid", err)
				}
				if got, ok, _ := auth.SessionData[sdPrefs](ctx); !ok || got != sdNext {
					t.Fatalf("a refused write changed the data: %+v, %v", got, ok)
				}
				if err := auth.SetSessionData(ctx, a, nil); err != nil {
					t.Fatal(err)
				}
				if name == "stateless" {
					rotated = sdEffect(ctx, auth.EffectIssueSession).Token
				}
				if _, _, ok := sdRead(t, a, rotated, ""); ok {
					t.Fatal("data after SetSessionData(nil) is still there")
				}
			})
		})
	}
}

// TestSessionData_PromotionCarriesIt: the data a pending second-factor session
// got at the first factor is on the full session after the second, under a
// new id and token.
func TestSessionData_PromotionCarriesIt(t *testing.T) {
	for _, name := range []string{"sql", "stateless"} {
		t.Run(name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				promote := corePromoteOp()
				a := coreAuth(t, e, &coreStub{second: true, hooks: sdStartHook(sdStart), ops: []auth.Operation{promote}}, sdModes[name]...)
				u, _ := coreUser(t, a)
				pending, tok, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
				if err != nil || !pending.SecondFactorPending {
					t.Fatalf("CreateSession = %+v, %v; want pending", pending, err)
				}
				ctx := request(a, tok)
				full, err := promote.Call(ctx, struct{}{})
				if err != nil {
					t.Fatal(err)
				}
				if full.ID == pending.ID || string(full.Data) != string(pending.Data) {
					t.Fatalf("promoted = %+v, want a new id with the pending session's data %s", full, pending.Data)
				}
				if _, got, ok := sdRead(t, a, sdEffect(ctx, auth.EffectIssueSession).Token, ""); !ok || got != sdStart {
					t.Fatalf("data on the promoted session = %+v, %v; want %+v", got, ok, sdStart)
				}
			})
		})
	}
}

// TestSessionData_HookDataIsChecked: what a BeforeCreate hook puts in
// Session.Data passes the same bound and JSON check as SetSessionData, at the
// insert, so no store ever holds a value a reader cannot decode.
func TestSessionData_HookDataIsChecked(t *testing.T) {
	for name, tc := range map[string]struct {
		data auth.AppData
		want error
	}{
		"too large": {auth.AppData(`"` + strings.Repeat("x", auth.MaxSessionDataSize) + `"`), auth.ErrSessionDataTooLarge},
		"not JSON":  {auth.AppData(`{oops`), auth.ErrSessionDataInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			e := newFaultEnv(t)
			hooks := auth.DataHooks{Session: auth.TableHooks[auth.Session]{
				BeforeCreate: func(_ context.Context, _ sqlb.DBTX, s *auth.Session) error { s.Data = tc.data; return nil },
			}}
			a := coreAuth(t, e.env, &coreStub{hooks: hooks})
			u, _ := coreUser(t, a)
			if _, _, err := a.CreateSession(context.Background(), u.ID, auth.Client{}); !errors.Is(err, tc.want) {
				t.Fatalf("CreateSession = %v, want %v", err, tc.want)
			}
			if list, err := a.Sessions(context.Background(), u.ID); err != nil || len(list) != 0 {
				t.Fatalf("sessions after a refused insert = %v, %v; want none", list, err)
			}
		})
	}
}

// TestSessionData_UpdateHooksRunAndCanVeto: SetSessionData runs the
// Session.BeforeUpdate and AfterUpdate hooks with the old and new rows, in
// the transaction, and a veto leaves the data as it was.
func TestSessionData_UpdateHooksRunAndCanVeto(t *testing.T) {
	e := newFaultEnv(t)
	veto := errors.New("not now")
	var seen []string
	hooks := auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		BeforeUpdate: func(_ context.Context, _ sqlb.DBTX, old, next *auth.Session) error {
			seen = append(seen, "before:"+string(old.Data)+">"+string(next.Data))
			if strings.Contains(string(next.Data), "veto") {
				return veto
			}
			return nil
		},
		AfterUpdate: func(_ context.Context, _ sqlb.DBTX, old, next *auth.Session) error {
			seen = append(seen, "after:"+string(old.Data)+">"+string(next.Data))
			return nil
		},
	}}
	a := coreAuth(t, e.env, &coreStub{hooks: hooks})
	_, tok := sessSignIn(t, a, context.Background())
	ctx, _, _ := sdRead(t, a, tok, "")
	if err := auth.SetSessionData(ctx, a, "one"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SetSessionData(ctx, a, "veto"); !errors.Is(err, veto) {
		t.Fatalf("vetoed write = %v, want the hook's error", err)
	}
	if got, _, _ := auth.SessionData[string](ctx); got != "one" {
		t.Fatalf("data after a veto = %q, want the previous value", got)
	}
	// "one" is a string, not an sdPrefs: reading it as one is the error the
	// app gets when it changes its type without migrating live sessions.
	next := request(a, tok)
	if err := a.Resolve(next); err != nil {
		t.Fatal(err)
	}
	if _, _, err := auth.SessionData[sdPrefs](next); err == nil || !strings.Contains(err.Error(), "decode session data") {
		t.Fatalf("reading a string as a struct = %v, want a decode error", err)
	}
	if got, ok, err := auth.SessionData[string](next); err != nil || !ok || got != "one" {
		t.Fatalf("stored data = %q, %v, %v; want \"one\"", got, ok, err)
	}
	want := []string{`before:>"one"`, `after:>"one"`, `before:"one">"veto"`}
	if strings.Join(seen, " ") != strings.Join(want, " ") {
		t.Fatalf("hooks seen = %v, want %v", seen, want)
	}
}

// TestSessionData_APIKeyRequestHasNone: a request signed in with an API key
// has a session built for the request and no row, so it carries no data and
// cannot be given any.
func TestSessionData_APIKeyRequestHasNone(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil)
	u, _ := coreUser(t, a)
	b := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName}, coreKeys{p: auth.Principal{UserID: u.ID, KeyID: "k1"}})
	ctx := coreBearer(b)
	if err := b.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := auth.SessionData[sdPrefs](ctx); ok || err != nil {
		t.Fatalf("SessionData on a key request = %v, %v; want none", ok, err)
	}
	if err := auth.SetSessionData(ctx, b, sdNext); !errors.Is(err, auth.ErrSessionDataUnavailable) {
		t.Fatalf("SetSessionData on a key request = %v, want ErrSessionDataUnavailable", err)
	}
	// A signed-out request is refused as such.
	if err := auth.SetSessionData(anon(a), a, sdNext); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("SetSessionData signed out = %v, want ErrSignedOut", err)
	}
}

// TestSessionData_CacheDropFailureIsAnError: SetSessionData that cannot drop
// the cache entry fails rather than leave a cache answering with the old
// data, like a sign-out that cannot forget the session.
func TestSessionData_CacheDropFailureIsAnError(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithSessionCache(sessFailingCache{drop: true}, time.Minute))
	_, tok := sessSignIn(t, a, context.Background())
	ctx, _, _ := sdRead(t, a, tok, "")
	if err := auth.SetSessionData(ctx, a, sdNext); !errors.Is(err, errSessCache) {
		t.Fatalf("SetSessionData with a cache that cannot drop = %v, want the cache's failure", err)
	}
}

// TestSessionData_ColumnHoldsText: a row from before the column existed
// reads as no data, and the column holds what the store wrote, as text, on
// every engine.
func TestSessionData_ColumnHoldsText(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, &coreStub{hooks: sdStartHook(sdStart)})
		_, tok := sessSignIn(t, a, context.Background())
		ctx, _, _ := sdRead(t, a, tok, "")
		s, _ := auth.CurrentSession(ctx)
		var raw *string
		q := a.Select().Columns(sqlb.Bind(sqlb.Col[*string](auth.TableSession, auth.ColSessionData), &raw)).From(auth.TableSession).Where(sqlb.Eq(auth.SessionID, s.ID)).Limit(1)
		if err := a.One(ctx, q); err != nil || raw == nil || *raw != `{"ws":"start"}` {
			t.Fatalf("column = %v, %v; want the JSON as text", raw, err)
		}
		// NULL, as on a row from before the column existed, is no data.
		if _, err := a.Exec(ctx, sqlb.NewUpdate(a.Dialect()).Table(auth.TableSession).Set(sqlb.Set(sqlb.Col[*string](auth.TableSession, auth.ColSessionData), nil)).Where(sqlb.Eq(auth.SessionID, s.ID))); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := sdRead(t, a, tok, ""); ok {
			t.Fatal("a NULL column read as data")
		}
	})
}

// sdLife is a SessionLifecycle plugin that records every notice and can fail
// each, so the core's calls and its error paths are both pinned.
type sdLife struct {
	seen []string
	fail error
}

func (*sdLife) Name() string { return "sdlife" }
func (l *sdLife) SessionEnded(_ context.Context, userID, id string) error {
	l.seen = append(l.seen, "ended:"+userID+":"+id)
	return l.fail
}
func (l *sdLife) UserSessionsEnded(_ context.Context, userID, exceptID string) error {
	l.seen = append(l.seen, "all:"+userID+":"+exceptID)
	return l.fail
}
func (l *sdLife) SessionReplaced(_ context.Context, old, new auth.Session) error {
	l.seen = append(l.seen, "replaced:"+old.ID+">"+new.ID)
	return l.fail
}

// TestSessionLifecycle_NoticesAndTheirErrors: every way a session ends or is
// replaced reaches a SessionLifecycle plugin, in the transaction, and a
// plugin's error fails the operation and keeps the session.
func TestSessionLifecycle_NoticesAndTheirErrors(t *testing.T) {
	for _, name := range []string{"sql", "memory", "stateless"} {
		t.Run(name, func(t *testing.T) {
			e := newFaultEnv(t)
			life := &sdLife{}
			promote := corePromoteOp()
			stub := &coreStub{ops: []auth.Operation{promote}}
			a := coreAuth(t, e.env, stub, append([]auth.Option{auth.WithPlugins(life)}, sdModes[name]...)...)
			bg := context.Background()
			u, _ := coreUser(t, a)
			_, tok1, _ := a.CreateSession(bg, u.ID, auth.Client{})
			s2, tok2, _ := a.CreateSession(bg, u.ID, auth.Client{})

			// Sign-out: one id. Sign-out everywhere: the user, no exception.
			if err := a.SignOut(request(a, tok1)); err != nil {
				t.Fatal(err)
			}
			if name != "stateless" {
				if err := a.DeleteUserSessions(bg, u.ID, s2.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.SignOutAll(request(a, tok2)); err != nil {
				t.Fatal(err)
			}
			// A promotion is a replacement, not an end.
			stub.second = true
			pending, tok3, _ := a.CreateSession(bg, u.ID, auth.Client{})
			full, err := promote.Call(request(a, tok3), struct{}{})
			if err != nil {
				t.Fatal(err)
			}
			stub.second = false
			want := []string{"ended:" + u.ID + ":", "all:" + u.ID + ":" + s2.ID, "all:" + u.ID + ":", "replaced:" + pending.ID + ">" + full.ID}
			if name == "stateless" {
				want = []string{"ended:" + u.ID + ":", "all:" + u.ID + ":", "replaced:" + pending.ID + ">" + full.ID}
			}
			if len(life.seen) != len(want) {
				t.Fatalf("notices = %v, want %v", life.seen, want)
			}
			for i := range want {
				if !strings.HasPrefix(life.seen[i], want[i]) {
					t.Fatalf("notice %d = %q, want prefix %q (all: %v)", i, life.seen[i], want[i], life.seen)
				}
			}

			// A failing plugin fails the operation and the session stays.
			life.fail = errors.New("plugin down")
			_, tok4, _ := a.CreateSession(bg, u.ID, auth.Client{})
			if err := a.SignOut(request(a, tok4)); err == nil || !strings.Contains(err.Error(), "plugin down") {
				t.Fatalf("sign-out with a failing lifecycle plugin = %v, want its error", err)
			}
			// The plugin is told before the store, so the session stays in
			// every store, the ones outside the transaction included.
			if _, _, _, err := a.ResolveSession(bg, tok4); err != nil {
				t.Fatalf("the session after a failed sign-out: %v, want it still live", err)
			}
			if err := a.DeleteUserSessions(bg, u.ID, ""); err == nil || !strings.Contains(err.Error(), "plugin down") {
				t.Fatalf("sign-out everywhere with a failing plugin = %v", err)
			}
			if name != "stateless" {
				if err := a.DeleteUserSessions(bg, u.ID, tok4.Reveal()); err == nil || !strings.Contains(err.Error(), "plugin down") {
					t.Fatalf("sign-out of others with a failing plugin = %v", err)
				}
			}
			stub.second = true
			_, tok5, _ := a.CreateSession(bg, u.ID, auth.Client{})
			if _, err := promote.Call(request(a, tok5), struct{}{}); err == nil || !strings.Contains(err.Error(), "plugin down") {
				t.Fatalf("promotion with a failing plugin = %v", err)
			}
		})
	}
}

// sdPlugin wires the sessiondata plugin with an initial value on the quick
// start, in the given session mode.
func sdPlugin(t *testing.T, e *env, initial sessiondata.Initial, opts ...auth.Option) (*auth.Auth, *sessiondata.Plugin) {
	t.Helper()
	p := sessiondata.New(sessiondata.WithInitial(initial))
	a := e.newAuth(t, opts, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName, ops: []auth.Operation{corePromoteOp()}}, p)
	return a, p
}

// sdResolved is a browser request carrying tok with its session resolved, as
// the pipeline or the middleware leaves it for the app's own code.
func sdResolved(t *testing.T, a *auth.Auth, tok auth.Token) context.Context {
	t.Helper()
	ctx := request(a, tok)
	if err := a.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	return ctx
}

// sdInitial records the start value for every session.
func sdInitial(context.Context, auth.Session) (any, error) { return sdStart, nil }

// sdRows counts the plugin's rows for a user.
func sdRows(t *testing.T, a *auth.Auth, userID string) int {
	t.Helper()
	var id string
	n := 0
	q := a.Select().Columns(sqlb.Bind(sessiondata.DataSessionID, &id)).From(sessiondata.TableData).Where(sqlb.Eq(sessiondata.DataUserID, userID))
	if err := a.Each(context.Background(), q, func() error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestSessionDataPlugin_GetSetAndLifecycle: the table shape of the same API.
// A row is written at sign-in, read and replaced through the request, moved
// at a promotion, and removed by sign-out, sign-out everywhere, a deleted
// user and the sweep after the hard stop, in every store and in stateless
// mode, on every engine.
func TestSessionDataPlugin_GetSetAndLifecycle(t *testing.T) {
	for _, name := range []string{"sql", "memory", "stateless"} {
		t.Run(name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				a, p := sdPlugin(t, e, sdInitial, sdModes[name]...)
				bg := context.Background()
				u, _ := coreUser(t, a)
				_, tok, err := a.CreateSession(bg, u.ID, auth.Client{})
				if err != nil {
					t.Fatal(err)
				}
				ctx := sdResolved(t, a, tok)
				if got, ok, err := sessiondata.Get[sdPrefs](ctx, p); err != nil || !ok || got != sdStart {
					t.Fatalf("Get after sign-in = %+v, %v, %v; want the initial value", got, ok, err)
				}
				if err := p.Set(ctx, sdNext); err != nil {
					t.Fatal(err)
				}
				if got, ok, err := sessiondata.Get[sdPrefs](sdResolved(t, a, tok), p); err != nil || !ok || got != sdNext {
					t.Fatalf("Get after Set = %+v, %v, %v", got, ok, err)
				}
				if err := p.Set(ctx, strings.Repeat("x", auth.MaxSessionDataSize)); !errors.Is(err, auth.ErrSessionDataTooLarge) {
					t.Fatalf("oversized = %v, want ErrSessionDataTooLarge", err)
				}
				if err := p.Set(ctx, nil); err != nil {
					t.Fatal(err)
				}
				if _, ok, err := sessiondata.Get[sdPrefs](ctx, p); ok || err != nil {
					t.Fatalf("Get after Set(nil) = %v, %v; want none", ok, err)
				}
				if err := p.Set(ctx, sdNext); err != nil {
					t.Fatal(err)
				}
				// Sign-out removes the row.
				if err := a.SignOut(ctx); err != nil {
					t.Fatal(err)
				}
				if n := sdRows(t, a, u.ID); n != 0 {
					t.Fatalf("%d rows after sign-out, want 0", n)
				}
				// Sign-out everywhere but one keeps that one; of all, none.
				var toks []auth.Token
				var sess []auth.Session
				for range 3 {
					s, tk, err := a.CreateSession(bg, u.ID, auth.Client{})
					if err != nil {
						t.Fatal(err)
					}
					toks, sess = append(toks, tk), append(sess, s)
				}
				if n := sdRows(t, a, u.ID); n != 3 {
					t.Fatalf("%d rows after three sign-ins, want 3", n)
				}
				if name != "stateless" {
					if err := a.DeleteUserSessions(bg, u.ID, sess[0].ID); err != nil {
						t.Fatal(err)
					}
					if got, ok, _ := sessiondata.Get[sdPrefs](sdResolved(t, a, toks[0]), p); !ok || got != sdStart || sdRows(t, a, u.ID) != 1 {
						t.Fatalf("after sign-out of the others: %+v, %v, %d rows; want the excepted session's row alone", got, ok, sdRows(t, a, u.ID))
					}
				}
				if err := a.DeleteUserSessions(bg, u.ID, ""); err != nil {
					t.Fatal(err)
				}
				if n := sdRows(t, a, u.ID); n != 0 {
					t.Fatalf("%d rows after sign-out everywhere, want 0", n)
				}
				// A deleted user takes the rows with them (UserTables), and
				// another user's rows stay.
				other, _ := a.CreateUser(bg, auth.NewUser{Name: "Bob"})
				if _, _, err := a.CreateSession(bg, other.ID, auth.Client{}); err != nil {
					t.Fatal(err)
				}
				if _, _, err := a.CreateSession(bg, u.ID, auth.Client{}); err != nil {
					t.Fatal(err)
				}
				if err := a.DeleteUser(bg, u.ID); err != nil {
					t.Fatal(err)
				}
				if sdRows(t, a, u.ID) != 0 || sdRows(t, a, other.ID) != 1 {
					t.Fatalf("rows after DeleteUser: %d of the deleted user, %d of the other; want 0 and 1", sdRows(t, a, u.ID), sdRows(t, a, other.ID))
				}
				// The sweep removes a row once its session's hard stop is
				// past the retention, and not before.
				if _, err := a.Sweep(bg, time.Hour); err != nil {
					t.Fatal(err)
				}
				if sdRows(t, a, other.ID) != 1 {
					t.Fatal("the sweep took a live session's row")
				}
				e.clock.Advance(auth.DefaultSessionConfig.MaxLifetime + 2*time.Hour)
				res, err := a.Sweep(bg, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				if res[sessiondata.PluginName] != 1 || sdRows(t, a, other.ID) != 0 {
					t.Fatalf("sweep = %v, %d rows left; want the row of the expired session gone", res, sdRows(t, a, other.ID))
				}
			})
		})
	}
}

// TestSessionDataPlugin_PromotionMovesTheRow: the row written at the first
// factor belongs to the full session after the second, with its hard stop.
func TestSessionDataPlugin_PromotionMovesTheRow(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		p := sessiondata.New(sessiondata.WithInitial(sdInitial))
		promote := corePromoteOp()
		a := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName, second: true, ops: []auth.Operation{promote}}, p)
		bg := context.Background()
		u, _ := coreUser(t, a)
		pending, tok, err := a.CreateSession(bg, u.ID, auth.Client{})
		if err != nil || !pending.SecondFactorPending {
			t.Fatalf("CreateSession = %+v, %v; want pending", pending, err)
		}
		ctx := request(a, tok)
		full, err := promote.Call(ctx, struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := sessiondata.GetFor[sdPrefs](bg, p, pending.ID); ok {
			t.Fatal("the pending session's row is still under its id")
		}
		got, ok, err := sessiondata.GetFor[sdPrefs](bg, p, full.ID)
		if err != nil || !ok || got != sdStart {
			t.Fatalf("row of the full session = %+v, %v, %v; want the first factor's value", got, ok, err)
		}
		var exp time.Time
		q := a.Select().Columns(sqlb.Bind(sessiondata.DataExpiresAt, &exp)).From(sessiondata.TableData).Where(sqlb.Eq(sessiondata.DataSessionID, full.ID)).Limit(1)
		if err := a.One(bg, q); err != nil || full.MaxExpiresAt == nil || !exp.Equal(*full.MaxExpiresAt) {
			t.Fatalf("row expiry = %v, %v; want the full session's hard stop %v", exp, err, full.MaxExpiresAt)
		}
		if sdRows(t, a, u.ID) != 1 {
			t.Fatalf("%d rows after the promotion, want 1", sdRows(t, a, u.ID))
		}
	})
}

// TestSessionDataPlugin_PromotionWithNoRow: a pending session that recorded
// nothing is promoted without a row to move, and no row appears.
func TestSessionDataPlugin_PromotionWithNoRow(t *testing.T) {
	e := newFaultEnv(t)
	p := sessiondata.New()
	promote := corePromoteOp()
	a := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName, second: true, ops: []auth.Operation{promote}}, p)
	u, _ := coreUser(t, a)
	_, tok, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	full, err := promote.Call(request(a, tok), struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := sessiondata.GetFor[sdPrefs](context.Background(), p, full.ID); ok || err != nil {
		t.Fatalf("row after a promotion with nothing recorded = %v, %v; want none", ok, err)
	}
}

// TestSessionDataPlugin_Refusals: a signed-out request, an API-key request
// and a failing initial function.
func TestSessionDataPlugin_Refusals(t *testing.T) {
	e := newFaultEnv(t)
	boom := errors.New("no initial")
	p := sessiondata.New(sessiondata.WithInitial(func(_ context.Context, s auth.Session) (any, error) {
		if s.UserAgent == "fail" {
			return nil, boom
		}
		if s.UserAgent == "none" {
			return nil, nil
		}
		return sdStart, nil
	}))
	a := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName}, coreKeys{p: auth.Principal{UserID: "u", KeyID: "k1"}}, p)
	bg := context.Background()
	u, _ := coreUser(t, a)
	if err := p.Set(anon(a), sdNext); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("Set signed out = %v, want ErrSignedOut", err)
	}
	if _, ok, err := sessiondata.Get[sdPrefs](anon(a), p); ok || err != nil {
		t.Fatalf("Get signed out = %v, %v; want none", ok, err)
	}
	if _, _, err := a.CreateSession(bg, u.ID, auth.Client{UserAgent: "fail"}); !errors.Is(err, boom) {
		t.Fatalf("a failing initial function = %v, want its error to fail the sign-in", err)
	}
	if _, _, err := a.CreateSession(bg, u.ID, auth.Client{UserAgent: "none"}); err != nil || sdRows(t, a, u.ID) != 0 {
		t.Fatalf("an initial function answering nil: %v, %d rows; want no row", err, sdRows(t, a, u.ID))
	}
	// An API-key request: nothing to read, nothing to write.
	k := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName}, coreKeys{p: auth.Principal{UserID: u.ID, KeyID: "k1"}}, sessiondata.New())
	kctx := coreBearer(k)
	if err := k.Resolve(kctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := sessiondata.Get[sdPrefs](kctx, sessiondata.New()); ok || err != nil {
		t.Fatalf("Get on a key request = %v, %v; want none", ok, err)
	}
	if err := sessiondata.New().Set(kctx, sdNext); !errors.Is(err, auth.ErrSessionDataUnavailable) {
		t.Fatalf("Set on a key request = %v, want ErrSessionDataUnavailable", err)
	}
}

// TestSessionDataFaults: every database call of the inline write and of the
// plugin's paths surfaces its failure.
func TestSessionDataFaults(t *testing.T) {
	t.Run("set session data", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := coreAuth(t, e.env, nil)
			_, tok := sessSignIn(t, a, context.Background())
			ctx, _, _ := sdRead(t, a, tok, "")
			return func(context.Context) error { return auth.SetSessionData(ctx, a, sdNext) }
		})
	})
	t.Run("sign-in with an initial value", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _ := sdPlugin(t, e.env, sdInitial)
			u, _ := coreUser(t, a)
			return func(ctx context.Context) error { _, _, err := a.CreateSession(ctx, u.ID, auth.Client{}); return err }
		})
	})
	t.Run("plugin set, insert and update", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, p := sdPlugin(t, e.env, func(context.Context, auth.Session) (any, error) { return nil, nil })
			_, tok := sessSignIn(t, a, context.Background())
			ctx := sdResolved(t, a, tok)
			return func(context.Context) error {
				if err := p.Set(ctx, sdStart); err != nil {
					return err
				}
				return p.Set(ctx, sdNext)
			}
		})
	})
	t.Run("plugin get and clear", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, p := sdPlugin(t, e.env, sdInitial)
			_, tok := sessSignIn(t, a, context.Background())
			ctx := sdResolved(t, a, tok)
			return func(context.Context) error {
				if _, _, err := sessiondata.Get[sdPrefs](ctx, p); err != nil {
					return err
				}
				return p.Set(ctx, nil)
			}
		})
	})
	t.Run("sign-out and sign-out everywhere with the plugin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _ := sdPlugin(t, e.env, sdInitial)
			u, tok := sessSignIn(t, a, context.Background())
			mine, _, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
			if err != nil {
				t.Fatal(err)
			}
			keep, _ := auth.CurrentSession(sdResolved(t, a, tok))
			return func(ctx context.Context) error {
				if err := a.DeleteUserSessions(ctx, u.ID, keep.ID); err != nil {
					return err
				}
				if err := a.SignOut(request(a, tok)); err != nil {
					return err
				}
				_ = mine
				return nil
			}
		})
	})
	t.Run("promotion with the plugin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			p := sessiondata.New(sessiondata.WithInitial(sdInitial))
			promote := corePromoteOp()
			a := e.newAuth(t, nil, e.emailPlugin(email.Multiple()), &coreStub{name: coreStubName, second: true, ops: []auth.Operation{promote}}, p)
			_, tok := sessSignIn(t, a, context.Background())
			return func(context.Context) error { _, err := promote.Call(request(a, tok), struct{}{}); return err }
		})
	})
	t.Run("sweep with the plugin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _ := sdPlugin(t, e.env, sdInitial)
			return func(ctx context.Context) error { _, err := a.Sweep(ctx, time.Hour); return err }
		})
	})
}
