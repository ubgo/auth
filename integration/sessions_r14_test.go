package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/sessiontest"
	"github.com/ubgo/sqlb"
)

// Round 14 of the session parity work, on real databases: the mirror store
// over the SQL store, the stateless read interval, the stateless revocation
// list, the device-session extras and the compact cache.

// TestSessionStore_MirrorOfSQLConforms runs the shared suite over the SQL
// store mirrored to a memory copy, on every engine; each case gets a fresh
// copy and an empty auth_session.
func TestSessionStore_MirrorOfSQLConforms(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sessiontest.Run(t, func(t *testing.T) auth.SessionStore {
			a := coreAuth(t, e, nil, auth.WithSessionStore(auth.MirrorSessionStore(auth.SQLSessionStore(), auth.NewMemorySessionStore())))
			if _, err := a.Exec(context.Background(), sqlb.NewDelete(a.Dialect()).From(auth.TableSession).Where(sqlb.In(auth.SessionUserID, sessUsers...))); err != nil {
				t.Fatal(err)
			}
			return a.SessionStore()
		})
	})
}

// r14FailingCopy is a memory store whose Delete fails while fail is set: a
// Redis copy that went away between the sign-in and the sign-out.
type r14FailingCopy struct {
	auth.SessionStore
	fail *bool
}

var errR14Copy = errors.New("copy: down")

func (c r14FailingCopy) Delete(ctx context.Context, userID, id string) error {
	if *c.fail {
		return errR14Copy
	}
	return c.SessionStore.Delete(ctx, userID, id)
}

func TestSessions_MirrorKeepsTheDatabaseAuthoritative(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		copyDown := false
		secondary := auth.NewMemorySessionStore()
		a := coreAuth(t, e, nil, auth.WithSessionStore(auth.MirrorSessionStore(auth.SQLSessionStore(), r14FailingCopy{secondary, &copyDown})))
		bg := context.Background()
		u, tok := sessSignIn(t, a, bg)
		// List reads the primary alone, so this is the database's answer.
		if list, err := a.Sessions(bg, u.ID); err != nil || len(list) != 1 {
			t.Fatalf("sessions in the database = %v %v, want the new one", list, err)
		}
		if _, err := secondary.Find(bg, auth.HashToken(tok), e.clock.Now()); err != nil {
			t.Fatalf("the copy lacks the session: %v", err)
		}
		if _, _, _, err := a.ResolveSession(bg, tok); err != nil {
			t.Fatal(err)
		}
		// The copy is down at sign-out: the sign-out fails, the database
		// row survives with the rolled-back transaction, and the session
		// still works, rather than living on in the copy alone.
		copyDown = true
		if err := a.SignOut(request(a, tok)); !errors.Is(err, errR14Copy) {
			t.Fatalf("sign-out with the copy down = %v, want its failure", err)
		}
		if _, _, _, err := a.ResolveSession(bg, tok); err != nil {
			t.Fatalf("the session after a failed sign-out: %v", err)
		}
		copyDown = false
		if err := a.SignOut(request(a, tok)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(bg, tok); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("after sign-out: %v, want ErrSignedOut", err)
		}
		if list, err := a.Sessions(bg, u.ID); err != nil || len(list) != 0 {
			t.Fatalf("sessions in the database after sign-out = %v %v", list, err)
		}
	})
}

func TestSessionFaults_MirrorSignOut(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil, auth.WithSessionStore(auth.MirrorSessionStore(auth.SQLSessionStore(), auth.NewMemorySessionStore())))
		_, tok := sessSignIn(t, a, context.Background())
		return func(context.Context) error { return a.SignOut(request(a, tok)) }
	})
}

// r14Reissued returns the token the request's effects reissued, or "".
func r14Reissued(ctx context.Context) auth.Token {
	for _, ef := range auth.RequestEffects(ctx) {
		if ef.Kind == auth.EffectIssueSession {
			return ef.Token
		}
	}
	return ""
}

func TestSessions_StatelessRefreshWithoutRead(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const interval = 5 * time.Minute
		a := e.newAuth(t, []auth.Option{auth.WithStatelessSessions(sessKey), auth.WithStatelessRefreshWithoutRead(interval), auth.WithAccountDeletion(auth.AccountDeletion{})},
			e.emailPlugin(), &coreStub{name: coreStubName}, sessBanned{})
		bg := context.Background()
		u, tok := sessSignIn(t, a, bg)
		// The first request reads the user and reissues the token carrying
		// the copy.
		ctx, err := sessResolve(t, a, tok)
		if err != nil {
			t.Fatal(err)
		}
		withCopy := r14Reissued(ctx)
		if withCopy == "" || withCopy == tok {
			t.Fatalf("effects = %+v, want a token carrying the read user", auth.RequestEffects(ctx))
		}
		// The trade-off: a ban reaches the token only at its next full read.
		banned := "banned"
		if _, err := a.UpdateUser(bg, u.ID, auth.UserUpdate{Name: &banned}); err != nil {
			t.Fatal(err)
		}
		ctx, err = sessResolve(t, a, withCopy)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := auth.CurrentUser(ctx); !ok {
			t.Fatal("within the interval the token's copy signs in")
		}
		// Except for a FreshSignIn operation, which always reads.
		if _, err := a.DeleteAccount(freshRequest(a, withCopy)); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("FreshSignIn on a banned user's copy = %v, want ErrSignedOut", err)
		}
		if _, err := a.User(bg, u.ID); err != nil {
			t.Fatalf("the refused deletion ran: %v", err)
		}
		// And no longer than the interval.
		e.clock.Advance(interval)
		if _, _, _, err := a.ResolveSession(bg, withCopy); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("after the interval: %v, want the ban applied", err)
		}

		// "Sign out everywhere" waits the same way, bounded the same way.
		u2, tok2 := secondUser(t, a, "dave@example.com")
		ctx, err = sessResolve(t, a, tok2)
		if err != nil {
			t.Fatal(err)
		}
		copy2 := r14Reissued(ctx)
		// A second on, so the cutoff is after both sessions' creation.
		e.clock.Advance(time.Second)
		if err := a.DeleteUserSessions(bg, u2.ID, ""); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(bg, copy2); err != nil {
			t.Fatalf("within the interval: %v, want the copy to answer", err)
		}
		if _, _, _, err := a.ResolveSession(bg, tok2); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a token with no copy reads at once: %v, want ErrSignedOut", err)
		}
		e.clock.Advance(interval)
		if _, _, _, err := a.ResolveSession(bg, copy2); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("after the interval: %v, want the cutoff applied", err)
		}
	})
}

func TestSessions_StatelessRefreshWithoutReadSkipsTheDatabase(t *testing.T) {
	e := newFaultEnv(t)
	a := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey), auth.WithStatelessRefreshWithoutRead(auth.MaxStatelessReadInterval),
		auth.WithSession(auth.SessionConfig{IdleTimeout: time.Hour, MaxLifetime: 24 * time.Hour, RefreshAfter: time.Minute}))
	_, tok := sessSignIn(t, a, context.Background())
	ctx, err := sessResolve(t, a, tok)
	if err != nil {
		t.Fatal(err)
	}
	withCopy := r14Reissued(ctx)
	// Within the interval: no query at all.
	e.f.arm(1)
	ctx = request(a, withCopy)
	err = a.Resolve(ctx)
	if e.f.disarm() || err != nil {
		t.Fatalf("a request within the interval reached the database or failed: %v", err)
	}
	if r14Reissued(ctx) != "" {
		t.Fatal("nothing was due, yet the token was reissued")
	}
	// A refresh due within the interval reissues the token without a read.
	e.clock.Advance(2 * time.Minute)
	e.f.arm(1)
	ctx = request(a, withCopy)
	err = a.Resolve(ctx)
	if e.f.disarm() || err != nil {
		t.Fatalf("the refresh reached the database or failed: %v", err)
	}
	slid := r14Reissued(ctx)
	sess, _ := auth.CurrentSession(ctx)
	if slid == "" || !sess.ExpiresAt.Equal(e.clock.Now().Add(time.Hour)) {
		t.Fatalf("reissued=%v expiry=%v, want the expiry slid", slid != "", sess.ExpiresAt)
	}
	// After the interval the read happens again.
	e.clock.Advance(auth.MaxStatelessReadInterval)
	e.f.arm(1)
	_ = a.Resolve(request(a, slid))
	if !e.f.disarm() {
		t.Fatal("after the interval the user must be read")
	}

	// Without the option every request reads, as before.
	plain := coreAuth(t, newFaultEnv(t).env, nil, auth.WithStatelessSessions(sessKey))
	_, ptok := sessSignIn(t, plain, context.Background())
	pctx, err := sessResolve(t, plain, ptok)
	if err != nil || r14Reissued(pctx) != "" {
		t.Fatalf("without the option nothing is reissued on a read: %v %+v", err, auth.RequestEffects(pctx))
	}
}

func TestSessionFaults_StatelessFullRead(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		a := coreAuth(t, e.env, nil, auth.WithStatelessSessions(sessKey), auth.WithStatelessRefreshWithoutRead(0))
		_, tok := sessSignIn(t, a, context.Background())
		ctx, err := sessResolve(t, a, tok)
		if err != nil {
			t.Fatal(err)
		}
		withCopy := r14Reissued(ctx)
		e.clock.Advance(auth.DefaultStatelessReadInterval)
		return func(context.Context) error { return a.Resolve(request(a, withCopy)) }
	})
}

func TestSessions_StatelessRevocationList(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		bg := context.Background()
		// Without the list a signed-out stateless token still opens until
		// it expires: only the cookie was cleared.
		plain := coreAuth(t, e, nil, auth.WithStatelessSessions(sessKey))
		_, ptok := secondUser(t, plain, "frank@example.com")
		if err := plain.SignOut(request(plain, ptok)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := plain.ResolveSession(bg, ptok); err != nil {
			t.Fatalf("without the list: %v, want the token to still open", err)
		}

		a := coreAuth(t, e, &coreStub{ops: []auth.Operation{corePromoteOp()}}, auth.WithStatelessSessions(sessKey),
			auth.WithSessionRevocations(auth.NewMemorySessionRevocations()), auth.WithSessionCache(auth.NewSnapshotCache(sessKey), time.Minute))
		_, tok := sessSignIn(t, a, bg)
		ctx, err := sessResolve(t, a, tok)
		if err != nil {
			t.Fatal(err)
		}
		var snap string
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectCacheSession {
				snap = ef.Value
			}
		}
		if err := a.SignOut(request(a, tok)); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(bg, tok); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a revoked token: %v, want ErrSignedOut", err)
		}
		// A client still holding the cache copy is refused too.
		cctx := a.WithRequest(bg, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: tok, CachedSession: snap, Client: auth.Client{Origin: testBaseURL}})
		if err := a.Resolve(cctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := auth.CurrentUser(cctx); ok {
			t.Fatal("a revoked session was served from the cache copy")
		}
		// Revoking by id ends the current session the same way.
		u2, tok2 := secondUser(t, a, "dave@example.com")
		list := must[auth.SessionsResult](t)(a.ListSessions(request(a, tok2)))
		if err := a.RevokeSession(request(a, tok2), list.Sessions[0].ID); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(bg, tok2); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("revoked by id: %v, want ErrSignedOut", err)
		}
		// A new session of the same user is untouched: the list holds ids.
		_, tok3, err := a.CreateSession(bg, u2.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(bg, tok3); err != nil {
			t.Fatalf("another session of the user: %v", err)
		}
	})
}

func TestSessions_StatelessPromotionRevokesThePendingToken(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		for name, opts := range map[string][]auth.Option{
			"without the list": {auth.WithStatelessSessions(sessKey)},
			"with the list":    {auth.WithStatelessSessions(sessKey), auth.WithSessionRevocations(auth.NewMemorySessionRevocations())},
		} {
			t.Run(name, func(t *testing.T) {
				promote := corePromoteOp()
				a := coreAuth(t, e, &coreStub{second: true, ops: []auth.Operation{promote}}, opts...)
				_, pending := secondUser(t, a, strings.ReplaceAll(name, " ", "")+"@example.com")
				if _, err := promote.Call(request(a, pending), struct{}{}); err != nil {
					t.Fatal(err)
				}
				_, err := promote.Call(request(a, pending), struct{}{})
				if name == "with the list" && !errors.Is(err, auth.ErrSignedOut) {
					t.Fatalf("the pending token after promotion: %v, want ErrSignedOut", err)
				}
				if name == "without the list" && err != nil {
					t.Fatalf("without the list the pending token lives to its expiry: %v", err)
				}
			})
		}
	})
}

func TestSessions_StatelessDeviceRevokeUsesTheList(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := coreAuth(t, e, nil, auth.WithStatelessSessions(sessKey), auth.WithMultiSession(0), auth.WithSessionRevocations(auth.NewMemorySessionRevocations()))
		_, active := coreSignedIn(t, a)
		_, other := secondUser(t, a, "dave@example.com")
		list := must[auth.DeviceSessionsResult](t)(a.DeviceSessions(deviceRequest(a, active, other)))
		if len(list.Sessions) != 2 {
			t.Fatalf("device sessions = %+v", list.Sessions)
		}
		if err := a.RevokeDeviceSession(deviceRequest(a, active, other), list.Sessions[1].ID); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), other); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the revoked account's token: %v, want ErrSignedOut everywhere", err)
		}
	})
}

func TestMultiSession_DeviceSessionExtras(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		extras := auth.WithSessionExtras(func(_ context.Context, c *auth.Call) (any, error) {
			c.Effects.ClearSession() // must not reach the response
			return map[string]string{"name": c.User.Name, "session": c.Session.ID}, nil
		})
		for name, opts := range map[string][]auth.Option{
			"on":  {auth.WithMultiSession(0), extras, auth.WithDeviceSessionExtras()},
			"off": {auth.WithMultiSession(0), extras},
		} {
			t.Run(name, func(t *testing.T) {
				a := coreAuth(t, e, nil, opts...)
				_, active := secondUser(t, a, "active-"+name+"@example.com")
				_, other := secondUser(t, a, "other-"+name+"@example.com")
				ctx := deviceRequest(a, active, other)
				list := must[auth.DeviceSessionsResult](t)(a.DeviceSessions(ctx))
				for _, ef := range auth.RequestEffects(ctx) {
					if ef.Kind == auth.EffectClearSession {
						t.Fatal("an effect the extras recorded reached the response")
					}
				}
				for _, s := range list.Sessions {
					if name == "off" {
						if s.Extras != nil {
							t.Fatalf("extras without the option: %+v", s)
						}
						continue
					}
					got, ok := s.Extras.(map[string]string)
					if !ok || got["name"] != s.User.Name || got["session"] != s.ID {
						t.Fatalf("extras of %s = %#v, want that session's own", s.ID, s.Extras)
					}
				}
			})
		}
	})
}

func TestSessions_CompactCacheSkipsTheDatabase(t *testing.T) {
	e := newFaultEnv(t)
	secret := []byte(strings.Repeat("s", auth.MinSecretSize))
	a := coreAuth(t, e.env, nil, auth.WithSecret(secret), auth.WithSessionCache(auth.NewCompactSessionCache(), time.Minute))
	bg := context.Background()
	_, tok := sessSignIn(t, a, bg)
	ctx, err := sessResolve(t, a, tok)
	if err != nil {
		t.Fatal(err)
	}
	effects := auth.RequestEffects(ctx)
	if len(effects) != 1 || effects[0].Kind != auth.EffectCacheSession || strings.Count(effects[0].Value, ".") != 1 {
		t.Fatalf("effects = %+v, want a signed compact copy", effects)
	}
	copyValue := effects[0].Value
	withCopy := func(tok auth.Token) context.Context {
		return a.WithRequest(bg, auth.Request{Transport: auth.TransportHTTP, Credential: auth.CredentialCookie, Token: tok, CachedSession: copyValue, Client: auth.Client{Origin: testBaseURL}})
	}
	e.f.arm(1)
	ctx = withCopy(tok)
	err = a.Resolve(ctx)
	if e.f.disarm() || err != nil {
		t.Fatalf("a valid compact copy reached the database or failed: %v", err)
	}
	if _, ok := auth.CurrentUser(ctx); !ok {
		t.Fatal("the compact copy did not sign in")
	}
	_, other, err := a.CreateSession(bg, must[auth.User](t)(a.CreateUser(bg, auth.NewUser{})).ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	e.f.arm(1)
	err = a.Resolve(withCopy(other))
	if !e.f.disarm() || err == nil {
		t.Fatal("the copy with another session's token must be a miss that reaches the database")
	}
}

func TestMultiSession_DeviceSessionExtrasFailure(t *testing.T) {
	e := newFaultEnv(t)
	errExtras := errors.New("extras: down")
	var failFor string
	a := coreAuth(t, e.env, nil, auth.WithMultiSession(0), auth.WithDeviceSessionExtras(),
		auth.WithSessionExtras(func(_ context.Context, c *auth.Call) (any, error) {
			if failFor == "all" || c.Session.ID == failFor {
				return nil, errExtras
			}
			return "ok", nil
		}))
	_, active := coreSignedIn(t, a)
	_, other := secondUser(t, a, "dave@example.com")
	list := must[auth.DeviceSessionsResult](t)(a.DeviceSessions(deviceRequest(a, active, other)))
	for _, fail := range []string{"all", list.Sessions[1].ID} {
		failFor = fail
		if _, err := a.DeviceSessions(deviceRequest(a, active, other)); !errors.Is(err, errExtras) {
			t.Fatalf("extras failing for %s: %v, want the failure", fail, err)
		}
	}
}
