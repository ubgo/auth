package integration

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/stale"
)

// Spans of the stale tests, shorter than a year so the stories read at a
// glance: an account is inactive after 30 days, and gets 14 to answer.
const (
	staleAfter = 30 * 24 * time.Hour
	staleGrace = 14 * 24 * time.Hour
	oneDay     = 24 * time.Hour
)

// staleWorld is an instance with the stale plugin, the email and password
// plugins and the delivery outbox.
type staleWorld struct {
	e  *env
	a  *auth.Auth
	pw *password.Plugin
	em *email.Plugin
	st *stale.Plugin
}

func newStaleWorld(t *testing.T, e *env, opts []auth.Option, so ...stale.Option) *staleWorld {
	t.Helper()
	w := &staleWorld{e: e, pw: e.passwordPlugin(), em: e.emailPlugin()}
	w.st = stale.New(append([]stale.Option{stale.InactiveAfter(staleAfter)}, so...)...)
	// Post-commit work runs inline: a run queues many messages one transaction
	// at a time, and SQLite refuses a read transaction that tries to write
	// after another connection did (the previous message's outbox update, run
	// in the background). Production SQLite apps use _txlock=immediate; the
	// test just keeps the order fixed.
	inline := auth.WithBackground(func(ctx context.Context, task func(context.Context)) { task(ctx) })
	w.a = e.newAuth(t, append([]auth.Option{auth.WithDeliveryOutbox(sessKey), inline}, opts...), w.em, w.pw, w.st)
	return w
}

// user signs up name@example.com with a verified address and returns its id.
func (w *staleWorld) user(t *testing.T, name string) string {
	t.Helper()
	w.a.WaitDeliveries()
	addr := name + "@example.com"
	res, err := w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: addr, Password: password.Secret(secret), Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.em.Verify(anon(w.a), w.e.mail.LastToken(t, w.a, addr)); err != nil {
		t.Fatal(err)
	}
	return res.User.ID
}

// signIn is name's password sign-in.
func (w *staleWorld) signIn(t *testing.T, name string) {
	t.Helper()
	if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: name + "@example.com", Password: password.Secret(secret)}); err != nil {
		t.Fatal(err)
	}
}

// mails counts the messages to name whose subject contains sub.
func (w *staleWorld) mails(name, sub string) int {
	n := 0
	for _, m := range w.e.mail.To(w.a, name+"@example.com") {
		if strings.Contains(m.Subject, sub) {
			n++
		}
	}
	return n
}

// run is one run, requiring no error.
func (w *staleWorld) run(t *testing.T, dry bool) stale.Result {
	t.Helper()
	r, err := w.st.Run(context.Background(), stale.RunOptions{DryRun: dry})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// exists reports whether the user is still there.
func (w *staleWorld) exists(t *testing.T, id string) bool {
	t.Helper()
	_, err := w.a.User(context.Background(), id)
	if errors.Is(err, auth.ErrUserNotFound) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// TestStale_WarnsOnceAfterTheInactivePeriod: nobody is warned before the
// period, everybody is after it, and a second run finds nothing left to do.
func TestStale_WarnsOnceAfterTheInactivePeriod(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil)
		w.user(t, "ada")
		w.user(t, "bob")
		e.clock.Advance(staleAfter - oneDay)
		if r := w.run(t, false); r != (stale.Result{}) {
			t.Fatalf("before the period: %+v, want nothing", r)
		}
		e.clock.Advance(2 * oneDay)
		r := w.run(t, false)
		if r.Warned != 2 || r.Failed != 0 {
			t.Fatalf("after the period: %+v, want 2 warned", r)
		}
		if w.mails("ada", "inactive") != 1 || w.mails("bob", "inactive") != 1 {
			t.Fatalf("mails: ada %d, bob %d, want one each", w.mails("ada", "inactive"), w.mails("bob", "inactive"))
		}
		if r := w.run(t, false); r != (stale.Result{}) {
			t.Fatalf("second run: %+v, want nothing (idempotent)", r)
		}
		if w.mails("ada", "inactive") != 1 {
			t.Fatal("a second run mailed again")
		}
		body := ""
		for _, m := range e.mail.To(w.a, "ada@example.com") {
			if strings.Contains(m.Subject, "inactive") {
				body = m.Text
			}
		}
		if !strings.Contains(body, "not used your account since") || strings.Contains(body, "will be deleted") {
			t.Fatalf("warning body (deletion is off):\n%s", body)
		}
	})
}

// TestStale_ASignInClearsTheWarningAndTheClockRestarts: a user who signs in
// after the warning is not warned again until they have been quiet for the
// whole period once more, and then is warned again.
func TestStale_ASignInClearsTheWarningAndTheClockRestarts(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil)
		w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		w.run(t, false)
		w.signIn(t, "ada")
		e.clock.Advance(staleAfter - oneDay)
		if r := w.run(t, false); r.Warned != 0 {
			t.Fatalf("still within the period of the new sign-in: %+v", r)
		}
		e.clock.Advance(2 * oneDay)
		if r := w.run(t, false); r.Warned != 1 {
			t.Fatalf("quiet again for the whole period: %+v, want a second warning", r)
		}
		if w.mails("ada", "inactive") != 2 {
			t.Fatalf("%d warnings, want 2", w.mails("ada", "inactive"))
		}
	})
}

// TestStale_DeletionIsOptInAndWaitsForTheGrace: without DeleteAfterWarning no
// account is ever deleted; with it, deletion waits for the grace period after
// the warning, sends the final message, and a second run deletes nothing.
func TestStale_DeletionIsOptInAndWaitsForTheGrace(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		off := newStaleWorld(t, e, nil)
		keep := off.user(t, "keep")
		e.clock.Advance(staleAfter + oneDay)
		off.run(t, false)
		e.clock.Advance(10 * 365 * oneDay)
		if r := off.run(t, false); r.Deleted != 0 || !off.exists(t, keep) {
			t.Fatalf("deletion off: %+v, exists %v", r, off.exists(t, keep))
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil, stale.DeleteAfterWarning(staleGrace))
		ada := w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		if r := w.run(t, false); r.Warned != 1 || r.Deleted != 0 {
			t.Fatalf("warning run: %+v", r)
		}
		body := ""
		for _, m := range e.mail.To(w.a, "ada@example.com") {
			if strings.Contains(m.Subject, "inactive") {
				body = m.Text
			}
		}
		if !strings.Contains(body, "will be deleted") {
			t.Fatalf("warning does not say when the account will be deleted:\n%s", body)
		}
		e.clock.Advance(staleGrace - oneDay)
		if r := w.run(t, false); r.Deleted != 0 || !w.exists(t, ada) {
			t.Fatalf("inside the grace: %+v", r)
		}
		e.clock.Advance(2 * oneDay)
		r := w.run(t, false)
		if r.Deleted != 1 || w.exists(t, ada) {
			t.Fatalf("after the grace: %+v, exists %v", r, w.exists(t, ada))
		}
		if w.mails("ada", "deleted") != 1 {
			t.Fatalf("%d final messages, want 1", w.mails("ada", "deleted"))
		}
		if r := w.run(t, false); r != (stale.Result{}) {
			t.Fatalf("second run after the deletion: %+v, want nothing", r)
		}
		if w.mails("ada", "deleted") != 1 {
			t.Fatal("the final message was sent twice")
		}
	})
}

// TestStale_ASignInDuringTheGraceSavesTheAccount: signing in after the
// warning clears it, so the grace period passing deletes nothing.
func TestStale_ASignInDuringTheGraceSavesTheAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil, stale.DeleteAfterWarning(staleGrace))
		ada := w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		w.run(t, false)
		e.clock.Advance(staleGrace / 2)
		w.signIn(t, "ada")
		e.clock.Advance(staleGrace)
		if r := w.run(t, false); r.Deleted != 0 || r.Warned != 0 || !w.exists(t, ada) {
			t.Fatalf("signed in during the grace: %+v exists %v", r, w.exists(t, ada))
		}
	})
}

// TestStale_ExemptNoChannelAndFailures: a protected account, an account with
// nobody to warn and an exemption check that fails are each left alone and
// counted, and the other accounts are still handled.
func TestStale_ExemptNoChannelAndFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var vip, broken string
		w := newStaleWorld(t, e, nil, stale.DeleteAfterWarning(staleGrace), stale.Exempt(func(_ context.Context, id string) (bool, error) {
			if id == broken {
				return false, errors.New("directory down")
			}
			return id == vip, nil
		}))
		vip, broken = w.user(t, "vip"), w.user(t, "broken")
		w.user(t, "plain")
		ghost, err := w.a.CreateUser(context.Background(), auth.NewUser{Name: "ghost"}) // no identity: nobody to mail
		if err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(staleAfter + oneDay)
		r := w.run(t, false)
		if r.Warned != 1 || r.Exempt != 1 || r.Failed != 1 || r.NoChannel != 1 {
			t.Fatalf("run = %+v, want 1 warned, 1 exempt, 1 failed, 1 no channel", r)
		}
		e.clock.Advance(staleGrace + oneDay)
		r = w.run(t, false)
		if r.Deleted != 1 || !w.exists(t, vip) || !w.exists(t, broken) || !w.exists(t, ghost.ID) {
			t.Fatalf("deletion run = %+v: only the warned, unprotected account may go", r)
		}
	})
}

// TestStale_AnAccountProtectedAfterItsWarningIsNotDeleted: the exemption is
// asked again at deletion, so an account that became protected (promoted to
// admin) between the warning and the deadline survives.
func TestStale_AnAccountProtectedAfterItsWarningIsNotDeleted(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		protected := false
		w := newStaleWorld(t, e, nil, stale.DeleteAfterWarning(staleGrace), stale.Exempt(func(context.Context, string) (bool, error) { return protected, nil }))
		ada := w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		if r := w.run(t, false); r.Warned != 1 {
			t.Fatalf("warning run: %+v", r)
		}
		protected = true
		e.clock.Advance(staleGrace + oneDay)
		if r := w.run(t, false); r.Deleted != 0 || r.Exempt != 1 || !w.exists(t, ada) {
			t.Fatalf("protected at the deadline: %+v exists %v", r, w.exists(t, ada))
		}
	})
}

// TestStale_AnExemptionCheckThatFailsAtDeletionLeavesTheAccount: the check is
// asked again at the deadline, and an account it cannot judge is kept and
// counted as failed, to be retried by the next run.
func TestStale_AnExemptionCheckThatFailsAtDeletionLeavesTheAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		down := false
		w := newStaleWorld(t, e, nil, stale.DeleteAfterWarning(staleGrace), stale.Exempt(func(context.Context, string) (bool, error) {
			if down {
				return false, errors.New("directory down")
			}
			return false, nil
		}))
		ada := w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		w.run(t, false)
		e.clock.Advance(staleGrace + oneDay)
		down = true
		if r := w.run(t, false); r.Failed != 1 || r.Deleted != 0 || !w.exists(t, ada) {
			t.Fatalf("exemption check down at the deadline: %+v", r)
		}
		down = false
		if r := w.run(t, false); r.Deleted != 1 || w.exists(t, ada) {
			t.Fatalf("retry once it is back: %+v", r)
		}
	})
}

// TestStale_BatchSizeCapsDeletionsToo: a run deletes at most BatchSize
// accounts, and the next carries on.
func TestStale_BatchSizeCapsDeletionsToo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil, stale.DeleteAfterWarning(staleGrace), stale.BatchSize(1))
		for _, n := range []string{"d1", "d2", "d3"} {
			w.user(t, n)
		}
		e.clock.Advance(staleAfter + oneDay)
		for range 3 {
			w.run(t, false)
		}
		e.clock.Advance(staleGrace + oneDay)
		var got []int64
		for range 4 {
			got = append(got, w.run(t, false).Deleted)
		}
		if got[0] != 1 || got[1] != 1 || got[2] != 1 || got[3] != 0 {
			t.Fatalf("deleted per run = %v, want [1 1 1 0]", got)
		}
	})
}

// TestStale_WithStatelessSessionsOnlyTheRecordedSignInsCount: a deployment
// that keeps no session list cannot see a session in use, so the plugin judges
// by the sign-ins it recorded, and still runs.
func TestStale_WithStatelessSessionsOnlyTheRecordedSignInsCount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		stateless := []auth.Option{auth.WithSecret([]byte(strings.Repeat("k", auth.MinSecretSize))), auth.WithStatelessSessions()}
		w := newStaleWorld(t, e, stateless)
		w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		if r := w.run(t, false); r.Warned != 1 || r.Failed != 0 {
			t.Fatalf("stateless run: %+v", r)
		}
	})
}

// TestStale_DryRunCountsAndChangesNothing: the same counters as a real run,
// no mail, no mark, no deletion.
func TestStale_DryRunCountsAndChangesNothing(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil, stale.DeleteAfterWarning(staleGrace))
		ada := w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		dry := w.run(t, true)
		if dry.Warned != 1 || w.mails("ada", "inactive") != 0 {
			t.Fatalf("dry warning run: %+v, mails %d", dry, w.mails("ada", "inactive"))
		}
		if real := w.run(t, false); real != dry {
			t.Fatalf("real %+v differs from dry %+v", real, dry)
		}
		e.clock.Advance(staleGrace + oneDay)
		dry = w.run(t, true)
		if dry.Deleted != 1 || !w.exists(t, ada) || w.mails("ada", "deleted") != 0 {
			t.Fatalf("dry deletion run: %+v exists %v", dry, w.exists(t, ada))
		}
		if real := w.run(t, false); real != dry || w.exists(t, ada) {
			t.Fatalf("real %+v differs from dry %+v", real, dry)
		}
	})
}

// TestStale_BatchSizeCapsEachRun: a run warns at most BatchSize accounts, so a
// first run on an old install cannot mail the whole table; the next run
// carries on until all are done.
func TestStale_BatchSizeCapsEachRun(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil, stale.BatchSize(2))
		for _, n := range []string{"a1", "a2", "a3", "a4", "a5"} {
			w.user(t, n)
		}
		e.clock.Advance(staleAfter + oneDay)
		var got []int64
		for range 4 {
			got = append(got, w.run(t, false).Warned)
		}
		if got[0] != 2 || got[1] != 2 || got[2] != 1 || got[3] != 0 {
			t.Fatalf("warned per run = %v, want [2 2 1 0]", got)
		}
	})
}

// TestStale_SinceKeepsOldAccountsOutOfTheFirstRun: with Since set to the
// install time, accounts that never recorded a sign-in count from then, not
// from when they were created.
func TestStale_SinceKeepsOldAccountsOutOfTheFirstRun(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		first := newStaleWorld(t, e, nil)
		first.user(t, "old")
		created := e.clock.Now()
		e.clock.Advance(5 * staleAfter)
		installed := e.clock.Now()
		w := newStaleWorld(t, e, nil, stale.Since(installed))
		if r := w.run(t, false); r != (stale.Result{}) {
			t.Fatalf("on install day: %+v, want nothing", r)
		}
		e.clock.Advance(staleAfter - oneDay)
		if r := w.run(t, false); r.Warned != 0 {
			t.Fatalf("a day before the period from install: %+v", r)
		}
		e.clock.Advance(2 * oneDay)
		if r := w.run(t, false); r.Warned != 1 {
			t.Fatalf("a day after: %+v, want the old account warned", r)
		}
		// The warning counts the quiet from the install, not from sign-up.
		body := ""
		for _, m := range e.mail.To(w.a, "old@example.com") {
			if strings.Contains(m.Subject, "inactive") {
				body = m.Text
			}
		}
		if !strings.Contains(body, installed.UTC().Format("2 January 2006")) || strings.Contains(body, created.UTC().Format("2 January 2006")) {
			t.Fatalf("warning body counts from the wrong day (installed %v, created %v):\n%s", installed, created, body)
		}
	})
}

// TestStale_AccountsWithNobodyToWarnDoNotUseUpTheBatch: an account with no
// recovery channel is skipped without counting toward BatchSize, so it cannot
// starve the accounts that can be warned.
func TestStale_AccountsWithNobodyToWarnDoNotUseUpTheBatch(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil, stale.BatchSize(1))
		w.user(t, "ada")
		// Many, because the order is by random id: were they counted, ada would
		// be reached only if she sorted before all of them.
		for i := range 30 {
			if _, err := w.a.CreateUser(context.Background(), auth.NewUser{Name: "ghost" + strconv.Itoa(i)}); err != nil {
				t.Fatal(err)
			}
		}
		e.clock.Advance(staleAfter + oneDay)
		if r := w.run(t, false); r.Warned != 1 || w.mails("ada", "inactive") != 1 {
			t.Fatalf("run = %+v, want ada warned whatever the ghosts' order", r)
		}
	})
}

// TestStale_AnImpersonationIsNotTheUsersActivity: an admin signing in as the
// user does not make a dormant account look alive.
func TestStale_AnImpersonationIsNotTheUsersActivity(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil)
		ada := w.user(t, "ada")
		e.clock.Advance(staleAfter - oneDay)
		if _, _, err := w.a.CreateImpersonationSession(context.Background(), ada, "admin_1", auth.Client{}, time.Minute); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(2 * oneDay)
		if r := w.run(t, false); r.Warned != 1 {
			t.Fatalf("after an impersonation: %+v, want the account still counted as dormant", r)
		}
	})
}

// longSessions keeps a session alive for months of use, so the tests can have
// a user who stays signed in without ever signing in again.
var longSessions = auth.WithSession(auth.SessionConfig{IdleTimeout: 60 * oneDay, MaxLifetime: 1000 * oneDay, RefreshAfter: time.Minute})

// TestStale_ALongLivedSessionCountsAsActivity: a user kept signed in by a
// session still in use is not inactive though they have not signed in.
func TestStale_ALongLivedSessionCountsAsActivity(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, []auth.Option{longSessions})
		w.user(t, "ada")
		token := w.signInToken(t, "ada")
		for range 3 {
			e.clock.Advance(20 * oneDay)
			if _, _, _, err := w.a.ResolveSession(context.Background(), token); err != nil {
				t.Fatalf("the session died: %v", err)
			}
		}
		if r := w.run(t, false); r.Warned != 0 || r.Active != 1 {
			t.Fatalf("a session in use: %+v, want it skipped as active", r)
		}
	})
}

// TestStale_AWarnedUserFoundInUseIsClearedNotDeleted: a user warned while quiet
// who then starts using a session they already had (no new sign-in, so the
// warning is not cleared by the sign-in hook) is not deleted when the grace
// ends; the warning is forgotten, and they are judged afresh from then.
func TestStale_AWarnedUserFoundInUseIsClearedNotDeleted(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, []auth.Option{longSessions}, stale.DeleteAfterWarning(staleGrace))
		ada := w.user(t, "ada")
		token := w.signInToken(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		if r := w.run(t, false); r.Warned != 1 {
			t.Fatalf("quiet for the period: %+v", r)
		}
		e.clock.Advance(staleGrace / 2)
		if _, _, _, err := w.a.ResolveSession(context.Background(), token); err != nil {
			t.Fatalf("the session died: %v", err)
		}
		e.clock.Advance(staleGrace)
		r := w.run(t, false)
		if r.Deleted != 0 || r.Cleared != 1 || !w.exists(t, ada) {
			t.Fatalf("grace over, user in use: %+v exists %v, want cleared and kept", r, w.exists(t, ada))
		}
		// Judged afresh: quiet for the whole period again, they are warned again.
		e.clock.Advance(staleAfter + oneDay)
		if r := w.run(t, false); r.Warned != 1 || r.Deleted != 0 {
			t.Fatalf("quiet again: %+v, want a second warning and no deletion on the old one", r)
		}
	})
}

// signInToken signs name in and returns the session token.
func (w *staleWorld) signInToken(t *testing.T, name string) auth.Token {
	t.Helper()
	r, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: name + "@example.com", Password: password.Secret(secret)})
	if err != nil {
		t.Fatal(err)
	}
	return r.Token
}

// TestStale_MaintainReportsUnderThePluginsName: auth.Maintain runs the plugin
// and names its counters "stale.<counter>".
func TestStale_MaintainReportsUnderThePluginsName(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil)
		w.user(t, "ada")
		e.clock.Advance(staleAfter + oneDay)
		got, err := w.a.Maintain(context.Background(), auth.MaintainOptions{})
		if err != nil || got["stale.warned"] != 1 {
			t.Fatalf("Maintain = %v, %v", got, err)
		}
		for _, k := range []string{"stale.deleted", "stale.cleared", "stale.active", "stale.exempt", "stale.no_channel", "stale.failed"} {
			if _, ok := got[k]; !ok {
				t.Errorf("Maintain lacks the counter %s: %v", k, got)
			}
		}
	})
}

// TestStale_NewRefusesWhatCannotWork: deletion without the outbox, and option
// values that would warn people on holiday or delete before they could read.
func TestStale_NewRefusesWhatCannotWork(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), stale.New(stale.DeleteAfterWarning(staleGrace)))); !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), "WithDeliveryOutbox") {
			t.Fatalf("deletion without the outbox: %v", err)
		}
		for name, opt := range map[string]stale.Option{
			"InactiveAfter":       stale.InactiveAfter(time.Hour),
			"DeleteAfterWarning":  stale.DeleteAfterWarning(time.Hour),
			"BatchSize":           stale.BatchSize(0),
			"BatchSize too large": stale.BatchSize(stale.MaxBatchSize + 1),
			"Exempt":              stale.Exempt(nil),
		} {
			err := stale.New(opt).OptionErr()
			if err == nil || !strings.Contains(err.Error(), "stale."+strings.Fields(name)[0]) {
				t.Errorf("%s: OptionErr = %v", name, err)
			}
		}
	})
}

// TestStale_APageOfUnwarnableAccountsStillReadsTheNext: with a batch of one
// and only accounts nobody can be mailed at, every page is full and warns
// nobody, so the run must page on by id to the end and warn no one. The
// ghosts test above reaches the second page only when the warnable account
// does not sort first, which random ids leave to chance; with no warnable
// account the paging is certain.
func TestStale_APageOfUnwarnableAccountsStillReadsTheNext(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newStaleWorld(t, e, nil, stale.BatchSize(1))
		for i := range 3 {
			if _, err := w.a.CreateUser(context.Background(), auth.NewUser{Name: "ghost" + strconv.Itoa(i)}); err != nil {
				t.Fatal(err)
			}
		}
		e.clock.Advance(staleAfter + oneDay)
		if r := w.run(t, false); r.Warned != 0 {
			t.Fatalf("run = %+v, want nobody warned", r)
		}
	})
}
