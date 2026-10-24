package integration

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/sqlb"
)

// endLog records the SessionEnded hook calls of one test.
type endLog struct {
	mu  sync.Mutex
	got []auth.SessionEnd
	err error
}

func (l *endLog) hooks() auth.DataHooks {
	return auth.DataHooks{SessionEnded: func(_ context.Context, _ sqlb.DBTX, e auth.SessionEnd) error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.err != nil {
			return l.err
		}
		l.got = append(l.got, e)
		return nil
	}}
}

func (l *endLog) take() []auth.SessionEnd {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.got
	l.got = nil
	return out
}

// endStores are the session stores whose ends the core reports: the SQL
// default and the memory store.
func endStores() map[string][]auth.Option {
	return map[string][]auth.Option{"sql": nil, "memory": {auth.WithSessionStore(auth.NewMemorySessionStore())}}
}

func newSession(t *testing.T, a *auth.Auth, userID string) auth.Session {
	t.Helper()
	s, _, err := a.CreateSession(context.Background(), userID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestSessionEnded_EveryEndingPathReportsOncePerSession: each way a session
// ends reports each ended session once with its reason, on every store; a
// session of another user, an unknown id and the excepted session report
// nothing.
func TestSessionEnded_EveryEndingPathReportsOncePerSession(t *testing.T) {
	ctx := context.Background()
	for store, opts := range endStores() {
		t.Run(store, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				log := &endLog{}
				a := coreAuth(t, e, &coreStub{hooks: log.hooks()}, opts...)
				ada, _ := coreUser(t, a)
				bob := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Bob"}))
				s1, s2, s3 := newSession(t, a, ada.ID), newSession(t, a, ada.ID), newSession(t, a, ada.ID)
				b1 := newSession(t, a, bob.ID)

				// One session, with a reason.
				if err := a.EndSession(ctx, ada.ID, s1.ID, auth.SessionEndAdmin); err != nil {
					t.Fatal(err)
				}
				got := log.take()
				if len(got) != 1 || got[0].Session.ID != s1.ID || got[0].Session.UserID != ada.ID || got[0].Reason != auth.SessionEndAdmin {
					t.Fatalf("EndSession reported %+v, want %s ended as admin_revoked", got, s1.ID)
				}
				// Another user's id matches nothing and so reports nothing; nor does an unknown id.
				for _, id := range []string{b1.ID, "ses_nope"} {
					if err := a.EndSession(ctx, ada.ID, id, auth.SessionEndRevoked); err != nil {
						t.Fatal(err)
					}
				}
				if got := log.take(); len(got) != 0 {
					t.Fatalf("a session that was not ended reported %+v", got)
				}
				// The legacy call carries no reason.
				if err := a.DeleteSession(ctx, ada.ID, s2.ID); err != nil {
					t.Fatal(err)
				}
				if got := log.take(); len(got) != 1 || got[0].Reason != auth.SessionEndUnspecified {
					t.Fatalf("DeleteSession reported %+v, want one unspecified", got)
				}
				// All but one.
				s4 := newSession(t, a, ada.ID)
				if err := a.EndUserSessions(ctx, ada.ID, s3.ID, auth.SessionEndRevokedOthers); err != nil {
					t.Fatal(err)
				}
				got = log.take()
				if len(got) != 1 || got[0].Session.ID != s4.ID || got[0].Reason != auth.SessionEndRevokedOthers {
					t.Fatalf("revoking others reported %+v, want only %s", got, s4.ID)
				}
				// All of them.
				s5 := newSession(t, a, ada.ID)
				if err := a.EndUserSessions(ctx, ada.ID, "", auth.SessionEndBanned); err != nil {
					t.Fatal(err)
				}
				got = log.take()
				ids := map[string]bool{}
				for _, g := range got {
					ids[g.Session.ID] = true
					if g.Reason != auth.SessionEndBanned || g.Session.UserID != ada.ID {
						t.Errorf("event %+v", g)
					}
				}
				if len(got) != 2 || !ids[s3.ID] || !ids[s5.ID] {
					t.Fatalf("ending all reported %+v, want %s and %s", got, s3.ID, s5.ID)
				}
				// Bob's session was never touched by any of it.
				if _, err := a.Sessions(ctx, bob.ID); err != nil {
					t.Fatal(err)
				}
				if l, _ := a.Sessions(ctx, bob.ID); len(l) != 1 {
					t.Fatalf("bob has %d sessions, want 1", len(l))
				}
			})
		})
	}
}

// TestSessionEnded_UserDeletionReportsEachSession: deleting a user reports
// every live session as user_deleted, inside the deleting transaction.
func TestSessionEnded_UserDeletionReportsEachSession(t *testing.T) {
	ctx := context.Background()
	eachEngine(t, func(t *testing.T, e *env) {
		log := &endLog{}
		a := coreAuth(t, e, &coreStub{hooks: log.hooks()})
		ada, _ := coreUser(t, a)
		s1, s2 := newSession(t, a, ada.ID), newSession(t, a, ada.ID)
		if err := a.DeleteUser(ctx, ada.ID); err != nil {
			t.Fatal(err)
		}
		got := log.take()
		if len(got) != 2 {
			t.Fatalf("reported %+v, want %s and %s", got, s1.ID, s2.ID)
		}
		for _, g := range got {
			if g.Reason != auth.SessionEndUserDeleted || g.Session.UserID != ada.ID {
				t.Errorf("event %+v", g)
			}
		}
	})
}

// TestSessionEnded_HookErrorNeverKeepsASessionAlive: a hook that errors
// cannot refuse an ending. Every path (one, others, all, user deletion, the
// sweep) still ends the sessions, and each lost hook is reported on the
// security stream with the session, the reason and the error; a rolled-back
// caller transaction still leaves the session alive, because nothing ended.
func TestSessionEnded_HookErrorNeverKeepsASessionAlive(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	eachEngine(t, func(t *testing.T, e *env) {
		var mu sync.Mutex
		var seen []auth.SecurityEvent
		sink := auth.SecuritySinkFunc(func(_ context.Context, batch []auth.SecurityEvent) error {
			mu.Lock()
			defer mu.Unlock()
			seen = append(seen, batch...)
			return nil
		})
		reports := func() []auth.SecurityEvent {
			// The stream is asynchronous; poll for it to drain.
			deadline := time.Now().Add(2 * time.Second)
			for {
				mu.Lock()
				n := len(seen)
				mu.Unlock()
				if n > 0 || time.Now().After(deadline) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			mu.Lock()
			defer mu.Unlock()
			out := seen
			seen = nil
			return out
		}
		log := &endLog{err: boom}
		a := coreAuth(t, e, &coreStub{hooks: log.hooks()}, auth.WithSecuritySink(sink, auth.SecurityQueue{}))
		ada, _ := coreUser(t, a)
		left := func() int { l, _ := a.Sessions(ctx, ada.ID); return len(l) }

		s := newSession(t, a, ada.ID)
		if err := a.EndSession(ctx, ada.ID, s.ID, auth.SessionEndRevoked); err != nil {
			t.Fatalf("EndSession = %v, want the session ended anyway", err)
		}
		if left() != 0 {
			t.Fatal("a failing hook kept the session alive")
		}
		got := reports()
		if len(got) != 1 || got[0].Kind != auth.SecuritySessionEndHookFailed || got[0].UserID != ada.ID ||
			got[0].Attrs[auth.AttrSessionID] != s.ID || got[0].Attrs[auth.AttrReason] != string(auth.SessionEndRevoked) || got[0].Attrs[auth.AttrError] != boom.Error() {
			t.Fatalf("reported %+v, want one session.end_hook_failed naming %s", got, s.ID)
		}

		keep, _ := newSession(t, a, ada.ID), newSession(t, a, ada.ID)
		if err := a.EndUserSessions(ctx, ada.ID, keep.ID, auth.SessionEndRevokedOthers); err != nil || left() != 1 {
			t.Fatalf("EndUserSessions (others) = %v, %d left, want nil and the one kept", err, left())
		}
		if err := a.EndUserSessions(ctx, ada.ID, "", auth.SessionEndBanned); err != nil || left() != 0 {
			t.Fatalf("EndUserSessions (all) = %v, %d left, want nil and none", err, left())
		}
		if len(reports()) == 0 {
			t.Fatal("the lost hooks of the user-wide ends were not reported")
		}

		// A session the sweep removes goes whatever the hook says.
		newSession(t, a, ada.ID)
		e.clock.Advance(365 * 24 * time.Hour)
		if _, err := a.Sweep(ctx, time.Hour); err != nil {
			t.Fatalf("Sweep = %v", err)
		}
		if left() != 0 {
			t.Fatal("a failing hook kept an expired session in the store")
		}

		// Deleting the user goes through too.
		newSession(t, a, ada.ID)
		if err := a.DeleteUser(ctx, ada.ID); err != nil {
			t.Fatalf("DeleteUser = %v", err)
		}
		if _, err := a.User(ctx, ada.ID); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("user after delete: %v, want ErrUserNotFound", err)
		}

		// A caller's transaction that rolls back ends nothing.
		bob := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Bob"}))
		log.err = nil
		bs := newSession(t, a, bob.ID)
		err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			if err := a.EndSession(ctx, bob.ID, bs.ID, auth.SessionEndRevoked); err != nil {
				return err
			}
			return boom
		})
		if !errors.Is(err, boom) {
			t.Fatal(err)
		}
		if l, _ := a.Sessions(ctx, bob.ID); len(l) != 1 {
			t.Fatalf("a rolled-back end left %d sessions, want the session alive", len(l))
		}
	})
}

// TestSessionEnded_SweepReportsExpiredPerBatch: the sweep reports each live
// session it removes as expired, in batches, on the stores that can name them;
// the count it returns still matches.
func TestSessionEnded_SweepReportsExpiredPerBatch(t *testing.T) {
	ctx := context.Background()
	const stale = 505 // past one batch of 500
	for store, opts := range endStores() {
		t.Run(store, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				log := &endLog{}
				a := coreAuth(t, e, &coreStub{hooks: log.hooks()}, opts...)
				ada, _ := coreUser(t, a)
				for range stale {
					newSession(t, a, ada.ID)
				}
				e.clock.Advance(365 * 24 * time.Hour)
				live := newSession(t, a, ada.ID)
				res, err := a.Sweep(ctx, time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				got := log.take()
				if len(got) != stale {
					t.Fatalf("sweep reported %d sessions, want %d (result %v)", len(got), stale, res)
				}
				seen := map[string]bool{}
				for _, g := range got {
					if g.Reason != auth.SessionEndExpired || g.Session.ID == live.ID || seen[g.Session.ID] {
						t.Fatalf("bad or repeated event %+v", g)
					}
					seen[g.Session.ID] = true
				}
				if l, _ := a.Sessions(ctx, ada.ID); len(l) != 1 {
					t.Fatalf("%d sessions left, want the unexpired one", len(l))
				}
				if again, err := a.Sweep(ctx, time.Hour); err != nil || len(log.take()) != 0 {
					t.Fatalf("a second sweep reported again: %v, %v", again, err)
				}
			})
		})
	}
}

// TestSessionEnded_StatelessReportsTheOwnSessionAndTheUserWideEnd: with no
// session rows, a revoke of the request's own session is reported, and "end
// everything" is one event with an empty session id.
func TestSessionEnded_StatelessReportsTheUserWideEnd(t *testing.T) {
	ctx := context.Background()
	e := newFaultEnv(t)
	log := &endLog{}
	a := coreAuth(t, e.env, &coreStub{hooks: log.hooks()}, auth.WithStatelessSessions(sessKey))
	ada, _ := coreUser(t, a)
	if err := a.EndUserSessions(ctx, ada.ID, "", auth.SessionEndPasswordReset); err != nil {
		t.Fatal(err)
	}
	got := log.take()
	if len(got) != 1 || got[0].Session.ID != "" || got[0].Session.UserID != ada.ID || got[0].Reason != auth.SessionEndPasswordReset {
		t.Fatalf("stateless end-all reported %+v, want one event for the user with no session id", got)
	}
}

// TestSessionEnded_SetPasswordEndsSessionsAsPasswordSet: the password plugin's
// SetPassword signs the user out everywhere and says why.
func TestSessionEnded_SetPasswordEndsSessionsAsPasswordSet(t *testing.T) {
	ctx := context.Background()
	eachEngine(t, func(t *testing.T, e *env) {
		log := &endLog{}
		pw := e.passwordPlugin()
		a := e.newAuth(t, nil, e.emailPlugin(), pw, &coreStub{name: coreStubName, hooks: log.hooks()})
		ada, _ := coreUser(t, a)
		s := newSession(t, a, ada.ID)
		if err := pw.SetPassword(ctx, ada.ID, "a long enough passphrase, set by support"); err != nil {
			t.Fatal(err)
		}
		got := log.take()
		if len(got) != 1 || got[0].Session.ID != s.ID || got[0].Reason != auth.SessionEndPasswordSet {
			t.Fatalf("SetPassword reported %+v, want %s as password_set", got, s.ID)
		}
	})
}

// flakyStore wraps the memory session store and fails the calls a test turns
// on, so the ending paths' store-error branches run. It forwards SweepExpired
// (the optional upgrade the sweep looks for) so the sweep still reports.
type flakyStore struct {
	auth.SessionStore
	failList, failSweepExpired bool
}

var errFlaky = errors.New("flaky store")

func (f *flakyStore) List(ctx context.Context, userID string, now time.Time) ([]auth.Session, error) {
	if f.failList {
		return nil, errFlaky
	}
	return f.SessionStore.List(ctx, userID, now)
}

func (f *flakyStore) SweepExpired(ctx context.Context, now time.Time, limit int) ([]auth.Session, error) {
	if f.failSweepExpired {
		return nil, errFlaky
	}
	return f.SessionStore.(interface {
		SweepExpired(context.Context, time.Time, int) ([]auth.Session, error)
	}).SweepExpired(ctx, now, limit)
}

// TestSessionEnded_StoreFailuresAreReturned: when the store cannot list the
// sessions that are about to end, or cannot name the expired ones, the call
// fails with that error and nothing is reported as ended; the core never
// guesses what a session was.
func TestSessionEnded_StoreFailuresAreReturned(t *testing.T) {
	ctx := context.Background()
	eachEngine(t, func(t *testing.T, e *env) {
		store := &flakyStore{SessionStore: auth.NewMemorySessionStore()}
		log := &endLog{}
		a := coreAuth(t, e, &coreStub{hooks: log.hooks()}, auth.WithSessionStore(store))
		ada, _ := coreUser(t, a)
		s := newSession(t, a, ada.ID)
		log.take()

		store.failList = true
		if err := a.EndSession(ctx, ada.ID, s.ID, auth.SessionEndRevoked); !errors.Is(err, errFlaky) {
			t.Fatalf("EndSession with a failing List = %v, want the store error", err)
		}
		if err := a.EndUserSessions(ctx, ada.ID, "", auth.SessionEndBanned); !errors.Is(err, errFlaky) {
			t.Fatalf("EndUserSessions with a failing List = %v, want the store error", err)
		}
		store.failList = false
		if got := log.take(); len(got) != 0 {
			t.Fatalf("hooks ran for a failed end: %+v", got)
		}

		store.failSweepExpired = true
		e.clock.Advance(365 * 24 * time.Hour)
		if _, err := a.Sweep(ctx, time.Hour); !errors.Is(err, errFlaky) {
			t.Fatalf("Sweep with a failing SweepExpired = %v, want the store error", err)
		}
	})
}

// TestSessionEnded_HookErrorInsideACallersTransactionIsReported: inside a
// transaction the caller opened, a failing hook cannot be retried alone, so
// the ending goes ahead and the failure is reported to the log and security
// stream rather than returned.
func TestSessionEnded_HookErrorInsideACallersTransactionIsReported(t *testing.T) {
	ctx := context.Background()
	eachEngine(t, func(t *testing.T, e *env) {
		log := &endLog{err: errors.New("boom")}
		a := coreAuth(t, e, &coreStub{hooks: log.hooks()})
		ada, _ := coreUser(t, a)
		s := newSession(t, a, ada.ID)
		err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			return a.EndSession(ctx, ada.ID, s.ID, auth.SessionEndRevoked)
		})
		if err != nil {
			t.Fatalf("EndSession in a caller's transaction = %v, want the hook failure reported, not returned", err)
		}
		if l, _ := a.Sessions(ctx, ada.ID); len(l) != 0 {
			t.Fatalf("%d sessions left, want the session ended despite the failing hook", len(l))
		}
	})
}

// TestSessionEnded_HookFailureOverHTTPCarriesTheClientIP: a lost hook
// reported while serving a request names the caller's address, so the
// security stream can tie the failure to the request that ended the session.
func TestSessionEnded_HookFailureOverHTTPCarriesTheClientIP(t *testing.T) {
	var mu sync.Mutex
	var seen []auth.SecurityEvent
	sink := auth.SecuritySinkFunc(func(_ context.Context, batch []auth.SecurityEvent) error {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, batch...)
		return nil
	})
	log := &endLog{err: errors.New("boom")}
	e := authtest.New(t,
		authtest.WithOptions(auth.WithSecuritySink(sink, auth.SecurityQueue{})),
		authtest.WithPlugins(func(env *authtest.Env) []auth.Plugin {
			return append(harnessPlugins(env), &coreStub{name: coreStubName, hooks: log.hooks()})
		}))
	b := e.Browser(harnessHandler(e.Auth))
	b.Post("/auth/password/sign-up", map[string]string{"identifier": harnessUser, "password": "another correct horse battery staple", "name": "Ada"}).Expect(http.StatusOK)
	b.Post("/auth/sign-out", map[string]string{}).Expect(http.StatusOK)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].Kind != auth.SecuritySessionEndHookFailed || seen[0].IP == "" {
		t.Fatalf("security events = %+v, want one session.end_hook_failed with the client IP", seen)
	}
}

// TestSessionEnded_SweepFailureOnTheSessionTableIsReturned: when the SQL
// store cannot read its table, the sweep says so instead of reporting zero.
func TestSessionEnded_SweepFailureOnTheSessionTableIsReturned(t *testing.T) {
	ctx := context.Background()
	eachEngine(t, func(t *testing.T, e *env) {
		log := &endLog{}
		a := coreAuth(t, e, &coreStub{hooks: log.hooks()})
		if _, err := e.db.ExecContext(ctx, "DROP TABLE "+a.TableName(auth.TableSession)); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Sweep(ctx, time.Hour); err == nil {
			t.Fatal("Sweep over a missing session table = nil, want the store error")
		}
	})
}
