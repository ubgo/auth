package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// auditWorld is adminWorld with the audit plugin registered.
type auditWorld struct {
	*adminWorld
	au *audit.Plugin
}

func newAuditWorld(t *testing.T, e *env, opts ...audit.Option) *auditWorld {
	t.Helper()
	w := &adminWorld{em: e.emailPlugin(), pw: e.passwordPlugin(), ad: admin.New()}
	au := audit.New(opts...)
	w.a = e.newAuth(t, nil, w.em, w.pw, w.ad, au)
	w.boss = signUpVerified(t, e, w.a, w.pw, w.em)
	if err := w.ad.Grant(context.Background(), w.boss.User.ID); err != nil {
		t.Fatal(err)
	}
	w.bob = must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
	w.bossCtx = func() context.Context { return request(w.a, w.boss.Token) }
	return &auditWorld{adminWorld: w, au: au}
}

// find returns the newest event for op with the given outcome that about
// accepts (nil accepts any), or fails. The env clock stands still, so events
// of one test share an instant and "newest" alone would be a coin toss.
func (w *auditWorld) find(t *testing.T, op auth.EndpointID, ok bool, about func(audit.Event) bool) audit.Event {
	t.Helper()
	pg := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Op: op}))
	for _, e := range pg.Events {
		if e.OK == ok && (about == nil || about(e)) {
			return e
		}
	}
	t.Fatalf("no %s event with ok=%v; have %+v", op, ok, pg.Events)
	return audit.Event{}
}

// TestAudit_RecordsSignInsFailuresAndAdminActions: a successful sign-in names
// the user it signed in, a failed one its code and the identifier typed, an
// admin action its actor and subject, an impersonated call its impersonator,
// and a sign-out its session; queries are not recorded by default.
func TestAudit_RecordsSignInsFailuresAndAdminActions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e)
		in := w.find(t, password.EndpointSignUp, true, func(e audit.Event) bool { return e.Identifier == "bob@example.com" })
		if in.ActorID != w.bob.User.ID || in.Identifier != "bob@example.com" || in.Transport != auth.TransportHTTP || in.IP != "203.0.113.7" || in.Plugin != password.PluginName {
			t.Fatalf("sign-up event = %+v", in)
		}
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: " BOB@example.com", Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		failed := w.find(t, password.EndpointSignIn, false, func(e audit.Event) bool { return e.Identifier == "bob@example.com" })
		if failed.Code != password.ErrInvalidCredentials.Code || failed.ActorID != "" || failed.Identifier != "bob@example.com" {
			t.Fatalf("failed sign-in event = %+v", failed)
		}
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "nobody@example.com", Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatal(err)
		}
		if unknown := w.find(t, password.EndpointSignIn, false, func(e audit.Event) bool { return e.Identifier == "nobody@example.com" }); unknown.ActorID != "" || unknown.Code != password.ErrInvalidCredentials.Code {
			t.Fatalf("unknown account event = %+v", unknown)
		}

		if err := w.ad.Ban(w.bossCtx(), w.bob.User.ID, "spam"); err != nil {
			t.Fatal(err)
		}
		ban := w.find(t, admin.EndpointBan, true, nil)
		if ban.ActorID != w.boss.User.ID || ban.SubjectID != w.bob.User.ID || ban.SessionID == "" {
			t.Fatalf("ban event = %+v", ban)
		}
		// The banned user's refused sign-in is a failure with the ban's code.
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); !errors.Is(err, admin.ErrBanned) {
			t.Fatal(err)
		}
		if banned := w.find(t, password.EndpointSignIn, false, func(e audit.Event) bool { return e.Code == admin.ErrBanned.Code }); banned.Identifier != "bob@example.com" || banned.ActorID != "" {
			t.Fatalf("banned sign-in event = %+v", banned)
		}
		if err := w.ad.Unban(w.bossCtx(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}

		as := must[admin.ImpersonateResult](t)(w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}))
		// Impersonating rotated the admin's token; the old one is dead.
		w.boss.Token = as.AdminToken
		imp := w.find(t, admin.EndpointImpersonate, true, func(e audit.Event) bool { return e.SubjectID == w.bob.User.ID })
		if imp.ActorID != w.boss.User.ID || imp.SubjectID != w.bob.User.ID {
			t.Fatalf("impersonate event = %+v", imp)
		}
		// A call made while impersonating records the admin behind it.
		name := "Robert"
		op, _ := w.a.Operation(auth.EndpointProfile)
		if _, err := op.Invoke(request(w.a, as.Token), func(dst any) error { *dst.(*auth.ProfileRequest) = auth.ProfileRequest{Name: &name}; return nil }); err != nil {
			t.Fatal(err)
		}
		if prof := w.find(t, auth.EndpointProfile, true, nil); prof.ActorID != w.bob.User.ID || prof.ImpersonatorID != w.boss.User.ID {
			t.Fatalf("impersonated profile event = %+v", prof)
		}

		// Queries are not recorded by default.
		if _, err := w.ad.Users(w.bossCtx(), admin.UsersRequest{}); err != nil {
			t.Fatal(err)
		}
		if pg := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Op: admin.EndpointUsers, UserID: w.boss.User.ID})); pg.Total != 0 {
			t.Fatalf("a query was recorded: %+v", pg)
		}

		// "Everything about bob" matches him as actor and as subject; the admin
		// route serves it to admins only, with the audit plugin's paging.
		about := must[audit.Page](t)(w.ad.Audit(w.bossCtx(), audit.Query{UserID: w.bob.User.ID, Limit: 2}))
		if about.Total < 4 || len(about.Events) != 2 || about.Limit != 2 || about.Page != 1 {
			t.Fatalf("about bob = %+v", about)
		}
		for _, ev := range about.Events {
			if ev.ActorID != w.bob.User.ID && ev.SubjectID != w.bob.User.ID {
				t.Fatalf("event not about bob: %+v", ev)
			}
		}
		// Bob's own session ended with the ban; the impersonation session is
		// a user session too, and is refused the same way.
		if _, err := w.ad.Audit(request(w.a, as.Token), audit.Query{}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin reading the log: %v", err)
		}
		// Sign-out records the session that ended.
		so, _ := w.a.Operation(auth.EndpointSignOut)
		if _, err := so.Invoke(request(w.a, as.Token), func(any) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if out := w.find(t, auth.EndpointSignOut, true, nil); out.SessionID == "" || out.ActorID != w.bob.User.ID {
			t.Fatalf("sign-out event = %+v", out)
		}
	})
}

// TestAudit_SweepRetentionQueriesOptionAndSkip: Sweep deletes events older
// than the retention and nothing newer; Queries records reads; Skip drops an
// operation.
func TestAudit_SweepRetentionQueriesOptionAndSkip(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e, audit.Retention(time.Hour), audit.Queries(), audit.Skip(admin.EndpointBan))
		// Counted per user: the table is shared between tests on Postgres and
		// MySQL, so a global count would include other tests' rows.
		before := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{UserID: w.boss.User.ID})).Total
		if before == 0 {
			t.Fatal("nothing recorded")
		}
		if err := w.ad.Ban(w.bossCtx(), w.bob.User.ID, "spam"); err != nil {
			t.Fatal(err)
		}
		if pg := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Op: admin.EndpointBan, UserID: w.bob.User.ID})); pg.Total != 0 {
			t.Fatalf("a skipped operation was recorded: %+v", pg)
		}
		e.clock.Advance(2 * time.Hour)
		if _, err := w.ad.Users(w.bossCtx(), admin.UsersRequest{}); err != nil {
			t.Fatal(err)
		}
		if pg := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Op: admin.EndpointUsers, UserID: w.boss.User.ID})); pg.Total != 1 {
			t.Fatalf("with Queries a read must be recorded: %+v", pg)
		}
		res := must[auth.SweepResult](t)(w.a.Sweep(context.Background(), auth.DefaultSweepRetention))
		if res[audit.PluginName] < before {
			t.Fatalf("swept %d, want at least %d: %+v", res[audit.PluginName], before, res)
		}
		// Only the read made after the clock moved survives.
		if after := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{UserID: w.boss.User.ID})); after.Total != 1 || after.Events[0].Op != admin.EndpointUsers {
			t.Fatalf("after sweep = %+v", after)
		}
		if bob := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{UserID: w.bob.User.ID})); bob.Total != 0 {
			t.Fatalf("bob's rows after sweep = %+v", bob)
		}
	})
}

// TestAudit_SinkReplacesTheTableAndItsRefusalRefusesTheOperation: with To,
// events reach the sink and no table exists; a sink that cannot record a
// success refuses the operation, so no sign-in happens unrecorded; a sink that
// fails on a failure only logs.
func TestAudit_SinkReplacesTheTableAndItsRefusalRefusesTheOperation(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var got []audit.Event
		fail := false
		sinkErr := errors.New("siem down")
		sink := audit.SinkFunc(func(_ context.Context, ev audit.Event) error {
			if fail {
				return sinkErr
			}
			got = append(got, ev)
			return nil
		})
		w := newAuditWorld(t, e, audit.To(sink))
		if len(got) == 0 || got[len(got)-1].Op != password.EndpointSignUp || got[len(got)-1].ID == "" {
			t.Fatalf("sink got %+v", got)
		}
		fail = true
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); !errors.Is(err, sinkErr) {
			t.Fatalf("a sink refusal must refuse the sign-in: %v", err)
		}
		// Nothing was granted: the failed sign-in opened no session.
		if n := must[[]auth.Session](t)(w.a.Sessions(context.Background(), w.bob.User.ID)); len(n) != 1 {
			t.Fatalf("sessions after a refused recording = %d", len(n))
		}
		// A failed operation whose recording also fails only logs.
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("the operation's own error must win: %v", err)
		}
		// A sink with no read side refuses reads rather than claim the log
		// is empty (audit.Querier serves them; TestAuditSeams_*).
		if _, err := w.au.Events(context.Background(), audit.Query{}); !errors.Is(err, audit.ErrNoQueryBackend) {
			t.Fatalf("Events with a write-only sink = %v", err)
		}
	})
}

// TestAudit_EveryDatabaseFailureSurfaces: recording a success, reading the
// log and sweeping it surface every database failure.
func TestAudit_EveryDatabaseFailureSurfaces(t *testing.T) {
	cases := map[string]func(t *testing.T, w *auditWorld) func(context.Context) error{
		"record-on-ban": func(_ *testing.T, w *auditWorld) func(context.Context) error {
			return func(context.Context) error { return w.ad.Ban(w.bossCtx(), w.bob.User.ID, "spam") }
		},
		"events": func(_ *testing.T, w *auditWorld) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := w.au.Events(ctx, audit.Query{UserID: w.bob.User.ID})
				return err
			}
		},
		"admin-audit": func(_ *testing.T, w *auditWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.ad.Audit(w.bossCtx(), audit.Query{}); return err }
		},
		"sweep": func(_ *testing.T, w *auditWorld) func(context.Context) error {
			return func(ctx context.Context) error { _, err := w.au.Sweep(ctx, time.Time{}); return err }
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error { return op(t, newAuditWorld(t, e.env)) })
		})
	}
}

// TestAudit_FailedSignInRowIsTheSameForKnownAndUnknownAccounts: a refused
// sign-in writes one row through one code path whether or not the account
// exists, so neither the row's presence nor its shape reveals the account;
// only the identifier typed differs. A refusal before the input was decoded
// (a signed-out call to a SignedIn mutation) writes nothing.
func TestAudit_FailedSignInRowIsTheSameForKnownAndUnknownAccounts(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e)
		// Addresses unique to this run: the table is shared between tests on
		// Postgres and MySQL.
		nobody := "nobody-" + w.bob.User.ID + "@example.com"
		var rows []audit.Event
		for _, id := range []string{"bob@example.com", nobody} {
			if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: id, Password: "wrong"}); !errors.Is(err, password.ErrInvalidCredentials) {
				t.Fatal(err)
			}
			pg := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Op: password.EndpointSignIn, Identifier: id, Limit: 1}))
			if len(pg.Events) != 1 {
				t.Fatalf("%s: events = %+v", id, pg.Events)
			}
			rows = append(rows, pg.Events[0])
		}
		known, unknown := rows[0], rows[1]
		known.ID, known.At, known.Identifier = "", time.Time{}, ""
		unknown.ID, unknown.At, unknown.Identifier = "", time.Time{}, ""
		if known != unknown || known.Code != password.ErrInvalidCredentials.Code || known.ActorID != "" || known.SubjectID != "" {
			t.Fatalf("known = %+v, unknown = %+v", known, unknown)
		}
		before := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{})).Total
		if _, err := w.ad.Impersonate(anon(w.a), admin.ImpersonateRequest{UserID: w.bob.User.ID}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatal(err)
		}
		if after := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{})).Total; after != before {
			t.Fatalf("a pre-decode refusal was recorded: %d -> %d", before, after)
		}
	})
}

// TestAudit_RecordingFailureNeverChangesTheAnswer: when the audit insert for
// a refused sign-in fails, the sign-in's own error still reaches the caller
// and the recording failure is only logged; with every other database call
// failing in turn, the answer is either the sign-in's own error or that
// database error, never a success.
func TestAudit_RecordingFailureNeverChangesTheAnswer(t *testing.T) {
	swallowedByAudit := 0
	for k := 1; k <= maxFaultSteps; k++ {
		e := newFaultEnv(t)
		w := newAuditWorld(t, e.env)
		e.f.arm(k)
		_, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: "wrong"})
		reached := e.f.disarm()
		if err == nil {
			t.Fatalf("step %d: a wrong password signed in", k)
		}
		if !reached {
			break
		}
		if errors.Is(err, password.ErrInvalidCredentials) {
			// The failure hit the audit insert (or a call after the
			// verdict): the verdict stood, and the row is missing.
			if pg := must[audit.Page](t)(w.au.Events(context.Background(), audit.Query{Op: password.EndpointSignIn})); pg.Total == 0 {
				swallowedByAudit++
			}
		}
	}
	if swallowedByAudit == 0 {
		t.Fatal("no run faulted the audit insert; the test proves nothing")
	}
}

// TestAudit_IDFailureRefusesTheOperation: when no id can be made for the
// event of a success, the operation is refused (a success is recorded in its
// own transaction, or not at all).
func TestAudit_IDFailureRefusesTheOperation(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{factorsFailIDs(audit.IDPrefixEvent)}, em, pw, audit.New())
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "erin@example.com", Password: secret, Name: "Erin"}); !errors.Is(err, errFactorsIDs) {
			t.Fatalf("sign-up with no event id: %v", err)
		}
		if _, err := a.FindIdentity(context.Background(), email.KindEmail, "erin@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("the refused sign-up must leave no user: %v", err)
		}
	})
}
