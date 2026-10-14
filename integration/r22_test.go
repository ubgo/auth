package integration

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// cachedAdminWorld is newAdminWorld with a server-side session cache in
// front of the store, and bob signed in on two devices whose entries are
// cached.
func cachedAdminWorld(t *testing.T, e *env) (*adminWorld, auth.Token) {
	t.Helper()
	w := &adminWorld{em: e.emailPlugin(), pw: e.passwordPlugin(), ad: admin.New()}
	w.a = e.newAuth(t, []auth.Option{auth.WithSessionCache(auth.NewMemorySessionCache(16), auth.MaxSessionCacheTTL)}, w.em, w.pw, w.ad)
	w.boss = signUpVerified(t, e, w.a, w.pw, w.em)
	if err := w.ad.Grant(context.Background(), w.boss.User.ID); err != nil {
		t.Fatal(err)
	}
	w.bob = must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
	if _, err := w.em.Verify(anon(w.a), e.mail.LastToken(t, w.a, "bob@example.com")); err != nil {
		t.Fatal(err)
	}
	w.bossCtx = func() context.Context { return request(w.a, w.boss.Token) }
	second := must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}))
	for _, tok := range []auth.Token{w.bob.Token, second.Token} {
		signedIn(t, w.a, tok, true, "before")
	}
	return w, second.Token
}

// signedIn asserts whether a request with tok is signed in.
func signedIn(t *testing.T, a *auth.Auth, tok auth.Token, want bool, when string) {
	t.Helper()
	_, err := a.Session(request(a, tok))
	if got := err == nil; got != want {
		t.Fatalf("%s: signed in = %v (%v), want %v", when, got, err, want)
	}
}

// TestSessionCache_ABanReachesEveryCachedDeviceAtOnce: with a server-side
// cache, a ban, revoking the user's sessions and deleting the user evict
// the user's entries after the commit, so every device is signed out on its
// next request rather than when its entry expires; a rolled-back write
// evicts nothing.
func TestSessionCache_ABanReachesEveryCachedDeviceAtOnce(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w, second := cachedAdminWorld(t, e)
		if err := w.ad.Ban(w.bossCtx(), w.bob.User.ID, "fraud"); err != nil {
			t.Fatal(err)
		}
		signedIn(t, w.a, w.bob.Token, false, "the banning device after the ban")
		signedIn(t, w.a, second, false, "the other device after the ban")
		signedIn(t, w.a, w.boss.Token, true, "the admin after the ban")
	})
	eachEngine(t, func(t *testing.T, e *env) {
		w, second := cachedAdminWorld(t, e)
		ctx := context.Background()
		// Revoking in a transaction that rolls back keeps the entries: the
		// eviction waits for the commit.
		errRollback := errors.New("roll back")
		err := w.a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			if err := w.a.DeleteUserSessions(ctx, w.bob.User.ID, ""); err != nil {
				return err
			}
			return errRollback
		})
		if !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
		signedIn(t, w.a, second, true, "after a rolled-back revoke")
		if err := w.ad.RevokeSessions(w.bossCtx(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		signedIn(t, w.a, w.bob.Token, false, "after revoking every session")
		signedIn(t, w.a, second, false, "the other device after revoking")
	})
	eachEngine(t, func(t *testing.T, e *env) {
		w, second := cachedAdminWorld(t, e)
		sess := must[[]auth.Session](t)(w.a.Sessions(context.Background(), w.bob.User.ID))
		if len(sess) != 2 {
			t.Fatalf("bob has %d sessions, want 2", len(sess))
		}
		// Revoking one session by id: the store row of the other device is
		// gone, and its cached entry with it.
		target, _, _, err := w.a.ResolveSession(context.Background(), second)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.ad.RevokeSession(w.bossCtx(), w.bob.User.ID, target.ID); err != nil {
			t.Fatal(err)
		}
		signedIn(t, w.a, second, false, "the revoked device")
		signedIn(t, w.a, w.bob.Token, true, "the device left alone, after one extra lookup")
		if err := w.a.DeleteUser(context.Background(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		signedIn(t, w.a, w.bob.Token, false, "after the user was deleted")
	})
}

// TestSessionCache_EvictCachedSessionsForASuspension: a plugin that blocks a
// user without ending sessions (a suspension through a session check) calls
// EvictCachedSessions itself; the cached device then meets the check.
func TestSessionCache_EvictCachedSessionsForASuspension(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w, second := cachedAdminWorld(t, e)
		now := e.clock.Now()
		ctx := context.Background()
		// The ban columns alone, as a suspension would set them: the session
		// check refuses the user, but the cache still answers.
		if err := auth.SetUserColumn(ctx, w.a, admin.PluginName, w.bob.User.ID, admin.BannedAt, &now); err != nil {
			t.Fatal(err)
		}
		signedIn(t, w.a, second, true, "cached, before the eviction")
		if !w.a.EvictCachedSessions(ctx, w.bob.User.ID) {
			t.Fatal("the memory cache can evict")
		}
		signedIn(t, w.a, second, false, "after the eviction")
	})
}

// TestAuthtest_SweepFaultsOnAnEnv: an Env built WithFaults runs its SQLite
// through the counter, stays disarmed through migration, and SweepFaults
// over it reaches every call of an operation; an Env without the option has
// no counter.
func TestAuthtest_SweepFaultsOnAnEnv(t *testing.T) {
	if e := authtest.New(t, authtest.WithPlugins(harnessPlugins)); e.Faults != nil {
		t.Fatal("an Env without WithFaults has a counter")
	}
	steps := 0
	authtest.SweepFaults(t,
		func() (*authtest.Env, *authtest.Faults) {
			e := authtest.New(t, authtest.WithPlugins(harnessPlugins), authtest.WithFaults(authtest.NewFaults()))
			return e, e.Faults
		},
		func(e *authtest.Env) func(context.Context) error {
			return func(ctx context.Context) error {
				steps++
				u, err := e.Auth.CreateUser(ctx, auth.NewUser{Name: "Ada"})
				if err != nil {
					return err
				}
				return e.Auth.DeleteUser(ctx, u.ID)
			}
		})
	if steps < 3 {
		t.Fatalf("the sweep ran %d times; the operation makes more database calls than that", steps)
	}
}

// flakyMailer records mail and fails while fail is set.
type flakyMailer struct {
	mu   sync.Mutex
	sent []string
	fail atomic.Bool
}

func (m *flakyMailer) Send(ctx context.Context, mail email.Mail) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.fail.Load() {
		return errors.New("smtp down")
	}
	m.mu.Lock()
	m.sent = append(m.sent, mail.To)
	m.mu.Unlock()
	return nil
}

func (m *flakyMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// outboxRows counts the outbox table.
func outboxRows(t *testing.T, e *env) int {
	t.Helper()
	var n int
	if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameDeliveryOutbox)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestDeliveryOutbox_ACrashBetweenCommitAndSendLosesNothing: with the
// outbox on, a message whose post-commit send never happened (the process
// died: here the task runs on a cancelled context) is sent by SendOutbox once
// its lease passes, exactly once even with two workers; a rolled-back
// transaction leaves no row; a send that keeps failing backs off, stops at
// MaxDeliveryAttempts and is swept after the retention; "auth sweep" sends
// the outbox too.
func TestDeliveryOutbox_ACrashBetweenCommitAndSendLosesNothing(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mailer := &flakyMailer{}
		// The post-commit task runs on a dead context, as in a process that
		// is going down: the send and the row update both fail, and the row
		// keeps its lease.
		dead, kill := context.WithCancel(context.Background())
		kill()
		crash := auth.WithBackground(func(_ context.Context, task func(context.Context)) { task(dead) })
		a := e.newAuth(t, []auth.Option{auth.WithDeliveryOutbox(sessKey), crash}, email.New(email.Login(), email.Recover(), email.WithMailer(mailer)), e.passwordPlugin())
		ctx := context.Background()
		to := auth.Identity{Kind: email.KindEmail, Value: "ada@example.com"}
		msg := auth.Message{Purpose: auth.PurposeVerify, Link: "https://app.example.com/verify?token=SECRET"}

		errRollback := errors.New("roll back")
		if err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
			if err := a.Deliver(ctx, to, msg); err != nil {
				return err
			}
			return errRollback
		}); !errors.Is(err, errRollback) {
			t.Fatal(err)
		}
		if n := outboxRows(t, e); n != 0 {
			t.Fatalf("a rolled-back message left %d rows", n)
		}

		if err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error { return a.Deliver(ctx, to, msg) }); err != nil {
			t.Fatal(err)
		}
		var payload string
		if err := e.db.QueryRow("SELECT payload FROM " + tbl(auth.TableNameDeliveryOutbox)).Scan(&payload); err != nil || strings.Contains(payload, "SECRET") || strings.Contains(payload, "ada@") {
			t.Fatalf("the stored payload is not sealed: %q %v", payload, err)
		}
		// The post-commit send still holds its lease: nothing is due.
		if res, err := a.SendOutbox(ctx); err != nil || res != (auth.OutboxResult{}) {
			t.Fatalf("within the lease: %+v %v", res, err)
		}
		e.clock.Advance(auth.DeliveryTimeout + 2*time.Minute)
		var wg sync.WaitGroup
		results := make([]auth.OutboxResult, 2)
		for i := range results {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := a.SendOutbox(ctx)
				if err != nil {
					t.Error(err)
				}
				results[i] = res
			}()
		}
		wg.Wait()
		if mailer.count() != 1 || results[0].Sent+results[1].Sent != 1 || outboxRows(t, e) != 0 {
			t.Fatalf("after the lease: sent %d, results %+v, rows %d", mailer.count(), results, outboxRows(t, e))
		}

		// A send that keeps failing: retried after each backoff, never more
		// than MaxDeliveryAttempts in all, then left for Sweep.
		mailer.fail.Store(true)
		if err := a.Deliver(ctx, to, msg); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(auth.DeliveryTimeout + 2*time.Minute)
		failed := 0
		for i := 0; i < 2*auth.MaxDeliveryAttempts; i++ {
			res, err := a.SendOutbox(ctx)
			if err != nil {
				t.Fatal(err)
			}
			failed += res.Failed
			e.clock.Advance(auth.DeliveryRetryMax)
		}
		// The first attempt was the (dropped) post-commit send.
		if failed != auth.MaxDeliveryAttempts-1 || outboxRows(t, e) != 1 {
			t.Fatalf("failed sends %d, rows %d", failed, outboxRows(t, e))
		}
		res, err := a.Sweep(ctx, time.Hour)
		if err != nil || res[auth.CorePluginName+"."+auth.TableNameDeliveryOutbox] != 1 || outboxRows(t, e) != 0 {
			t.Fatalf("sweep = %v %v, rows %d", res, err, outboxRows(t, e))
		}

		mailer.fail.Store(false)
		if err := a.Deliver(ctx, to, msg); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(auth.DeliveryTimeout + 2*time.Minute)
		var stdout, stderr bytes.Buffer
		if code := authcli.Main(ctx, a, []string{"sweep"}, &stdout, &stderr); code != authcli.ExitOK || !strings.Contains(stdout.String(), "outbox.sent\t1\noutbox.failed\t0") {
			t.Fatalf("auth sweep = %d %q %q", code, stdout.String(), stderr.String())
		}
	})
}

// TestDeliveryOutbox_TheDefaultPathSendsAndKeepsNothing: with the outbox on
// and a working background, the post-commit send deletes its row; with it
// off, nothing is written and Sweep reports no outbox key.
func TestDeliveryOutbox_TheDefaultPathSendsAndKeepsNothing(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mailer := &flakyMailer{}
		a := e.newAuth(t, []auth.Option{auth.WithDeliveryOutbox(sessKey)}, email.New(email.Login(), email.Recover(), email.WithMailer(mailer)), e.passwordPlugin())
		ctx := context.Background()
		to := auth.Identity{Kind: email.KindEmail, Value: "ada@example.com"}
		if err := a.Deliver(ctx, to, auth.Message{Purpose: auth.PurposeVerify, Link: "L"}); err != nil {
			t.Fatal(err)
		}
		a.WaitDeliveries()
		if mailer.count() != 1 || outboxRows(t, e) != 0 {
			t.Fatalf("sent %d, rows %d", mailer.count(), outboxRows(t, e))
		}
		// A failed post-commit send keeps its row for SendOutbox.
		mailer.fail.Store(true)
		if err := a.Deliver(ctx, to, auth.Message{Purpose: auth.PurposeVerify, Link: "L"}); err != nil {
			t.Fatal(err)
		}
		a.WaitDeliveries()
		mailer.fail.Store(false)
		if res, err := a.SendOutbox(ctx); err != nil || res.Sent != 0 {
			t.Fatalf("before the backoff: %+v %v", res, err)
		}
		e.clock.Advance(auth.DeliveryRetryBase)
		if res, err := a.SendOutbox(ctx); err != nil || res.Sent != 1 || mailer.count() != 2 {
			t.Fatalf("after the backoff: %+v %v, sent %d", res, err, mailer.count())
		}

		plain := e.newAuth(t, nil, email.New(email.Login(), email.Recover(), email.WithMailer(mailer)), e.passwordPlugin())
		res, err := plain.Sweep(ctx, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := res[auth.CorePluginName+"."+auth.TableNameDeliveryOutbox]; !ok {
			t.Fatal("the table outlives the option: Sweep must still clean it")
		}
	})
}

// TestDeliveryOutbox_ALostClaimSkipsTheRow: when another worker claims a due
// row between SendOutbox's read and its claim, SendOutbox sends nothing and
// leaves the row alone. The race itself (two goroutines) hits this only
// sometimes, so here the clock the claim reads is set back an hour on its
// second reading, which makes the conditional update match no row exactly as
// a competing claim would.
func TestDeliveryOutbox_ALostClaimSkipsTheRow(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mailer := &flakyMailer{}
		dead, kill := context.WithCancel(context.Background())
		kill()
		crash := auth.WithBackground(func(_ context.Context, task func(context.Context)) { task(dead) })
		var armed atomic.Bool
		var reads atomic.Int32
		// SendOutbox reads the clock once for the due query and once per row
		// for its claim; while armed, the claim's reading is an hour early.
		clock := auth.WithClock(func() time.Time {
			now := e.clock.Now()
			if armed.Load() && reads.Add(1)%2 == 0 {
				return now.Add(-time.Hour)
			}
			return now
		})
		a := e.newAuth(t, []auth.Option{auth.WithDeliveryOutbox(sessKey), crash, clock}, email.New(email.Login(), email.Recover(), email.WithMailer(mailer)), e.passwordPlugin())
		ctx := context.Background()
		to := auth.Identity{Kind: email.KindEmail, Value: "ada@example.com"}
		if err := a.Deliver(ctx, to, auth.Message{Purpose: auth.PurposeVerify, Link: "https://app.example.com/verify?token=T"}); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(auth.DeliveryTimeout + 2*time.Minute)

		armed.Store(true)
		if res, err := a.SendOutbox(ctx); err != nil || res != (auth.OutboxResult{}) || mailer.count() != 0 || outboxRows(t, e) != 1 {
			t.Fatalf("lost claim: %+v %v, sent %d, rows %d", res, err, mailer.count(), outboxRows(t, e))
		}
		armed.Store(false)
		if res, err := a.SendOutbox(ctx); err != nil || res.Sent != 1 || outboxRows(t, e) != 0 {
			t.Fatalf("after the competing claim: %+v %v, rows %d", res, err, outboxRows(t, e))
		}
	})
}
