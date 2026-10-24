package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/password"
)

// recordOnlyLog is an audit backend of the app's own, not the audit plugin,
// with only the write side the admin plugin looks for (admin.EventRecorder).
type recordOnlyLog struct{ recorded []audit.Event }

func (*recordOnlyLog) Name() string { return "applog" }

func (l *recordOnlyLog) Record(_ context.Context, e audit.Event) error {
	l.recorded = append(l.recorded, e)
	return nil
}

// fullLog adds the read side (admin.EventQuerier).
type fullLog struct {
	recordOnlyLog
	got audit.Query
	err error
}

func (l *fullLog) Events(_ context.Context, q audit.Query) (audit.Page, error) {
	l.got = q
	return audit.Page{Events: l.recorded, Total: int64(len(l.recorded))}, l.err
}

// adminWithLog wires admin with log in place of the audit plugin and returns
// the world.
func adminWithLog(t *testing.T, e *env, log auth.Plugin) *adminWorld {
	t.Helper()
	w := &adminWorld{em: e.emailPlugin(), pw: e.passwordPlugin(), ad: admin.New()}
	w.a = e.newAuth(t, nil, w.em, w.pw, w.ad, log)
	w.boss = signUpVerified(t, e, w.a, w.pw, w.em)
	if err := w.ad.Grant(context.Background(), w.boss.User.ID); err != nil {
		t.Fatal(err)
	}
	w.bob = must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
	w.bossCtx = func() context.Context { return request(w.a, w.boss.Token) }
	return w
}

// TestAuditSeams_AdminUsesAnyAuditLog: the admin plugin records a Go-side
// ban to, and serves its audit route from, an audit log that is not the audit
// plugin, found by method set, and the log's read error is the route's error.
func TestAuditSeams_AdminUsesAnyAuditLog(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		log := &fullLog{}
		w := adminWithLog(t, e, log)
		if err := w.ad.BanFor(context.Background(), w.bob.User.ID, "fraud", time.Time{}); err != nil {
			t.Fatal(err)
		}
		if len(log.recorded) != 1 || log.recorded[0].Op != admin.EndpointBan || log.recorded[0].SubjectID != w.bob.User.ID {
			t.Fatalf("recorded %+v", log.recorded)
		}
		pg := must[audit.Page](t)(w.ad.Audit(w.bossCtx(), audit.Query{UserID: w.bob.User.ID}))
		if log.got.UserID != w.bob.User.ID || pg.Total != 1 || pg.Events[0].SubjectID != w.bob.User.ID {
			t.Fatalf("audit route = %+v, querier got %+v", pg, log.got)
		}
		log.err = errors.New("log down")
		if _, err := w.ad.Audit(w.bossCtx(), audit.Query{}); !errors.Is(err, log.err) {
			t.Fatalf("the log's error must surface: %v", err)
		}
	})
}

// TestAuditSeams_AdminLogWithoutReadSide: a log with only the write side
// still records a Go-side ban, and the audit route stays ErrNoAuditPlugin.
func TestAuditSeams_AdminLogWithoutReadSide(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		writeOnly := &recordOnlyLog{}
		w := adminWithLog(t, e, writeOnly)
		if err := w.ad.BanFor(context.Background(), w.bob.User.ID, "fraud", time.Time{}); err != nil || len(writeOnly.recorded) != 1 {
			t.Fatalf("a write-only log must still record: %v %+v", err, writeOnly.recorded)
		}
		if _, err := w.ad.Audit(w.bossCtx(), audit.Query{}); !errors.Is(err, admin.ErrNoAuditPlugin) {
			t.Fatalf("a log with no read side must leave the route refused: %v", err)
		}
	})
}

// TestAuditSeams_WriteOnlySinkRefusesEveryRead: with a sink that cannot
// answer queries, the admin route and my-events answer ErrNoQueryBackend
// instead of an empty history.
func TestAuditSeams_WriteOnlySinkRefusesEveryRead(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e, audit.To(audit.SinkFunc(func(context.Context, audit.Event) error { return nil })))
		if _, err := w.ad.Audit(w.bossCtx(), audit.Query{}); !errors.Is(err, audit.ErrNoQueryBackend) {
			t.Fatalf("admin audit = %v", err)
		}
		if _, err := w.au.MyEvents(request(w.a, w.bob.Token), audit.MyQuery{}); !errors.Is(err, audit.ErrNoQueryBackend) {
			t.Fatalf("my-events = %v", err)
		}
	})
}

// acmeSignIn is a third-party sign-in plugin: one operation, and the event
// type it declares for it (audit.EventTyper), with no import of audit's types.
type acmeSignIn struct{ op *auth.Op[struct{}, auth.Done] }

func newAcmeSignIn() *acmeSignIn {
	return &acmeSignIn{op: auth.Define(auth.OpInfo{ID: "acme.sign-in", Kind: auth.Mutation, Require: auth.Public, Path: "/acme/sign-in"},
		func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil })}
}

func (*acmeSignIn) Name() string                   { return "acme" }
func (*acmeSignIn) SignsIn() bool                  { return true }
func (a *acmeSignIn) Operations() []auth.Operation { return []auth.Operation{a.op} }
func (*acmeSignIn) AuditEventTypes() map[auth.EndpointID]string {
	return map[auth.EndpointID]string{"acme.sign-in": string(audit.TypeUserSignedIn)}
}

// TestAuditSeams_ThirdPartySignInIsUserSignedIn: a third-party plugin's
// sign-in operation is recorded through the pipeline and found by a query
// for user_signed_in, beside the built-in password sign-ins.
func TestAuditSeams_ThirdPartySignInIsUserSignedIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		acme := newAcmeSignIn()
		au := audit.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), acme, au)
		must[auth.Done](t)(acme.op.Call(anon(a), struct{}{}))
		pg := must[audit.Page](t)(au.Events(context.Background(), audit.Query{Type: audit.TypeUserSignedIn}))
		if pg.Total != 1 || pg.Events[0].Op != "acme.sign-in" || pg.Events[0].Type != audit.TypeUserSignedIn {
			t.Fatalf("sign-ins = %+v", pg)
		}
	})
}
