package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/lastlogin"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
)

// lastMethod reads the recorded method of a user.
func lastMethod(t *testing.T, ll *lastlogin.Plugin, userID string) lastlogin.LastLoginColumns {
	t.Helper()
	return must[lastlogin.LastLoginColumns](t)(ll.Of(context.Background(), userID))
}

// TestLastLogin_RecordsTheMethodOfEverySignIn: a password sign-up and
// sign-in, a magic link and an emailed code each record their plugin's name
// and the time; a session made outside an operation records nothing.
func TestLastLogin_RecordsTheMethodOfEverySignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ml, ll := e.emailPlugin(email.SignInWithCode()), e.passwordPlugin(), magiclink.New(), lastlogin.New()
		a := e.newAuth(t, nil, em, pw, ml, ll)
		up := signUpVerified(t, e, a, pw, em)
		uid := up.User.ID
		if got := lastMethod(t, ll, uid); got.LastLoginMethod != password.PluginName || got.LastLoginAt == nil || !got.LastLoginAt.Equal(e.clock.Now()) {
			t.Fatalf("after sign-up = %+v", got)
		}
		e.clock.Advance(time.Hour)
		if err := ml.Send(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		if _, err := ml.SignIn(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		if got := lastMethod(t, ll, uid); got.LastLoginMethod != magiclink.PluginName || !got.LastLoginAt.Equal(e.clock.Now()) {
			t.Fatalf("after a magic link = %+v", got)
		}
		e.clock.Advance(time.Hour)
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		if _, err := em.SignInCode(anon(a), alice, lastMailCode(t, e, a, alice)); err != nil {
			t.Fatal(err)
		}
		if got := lastMethod(t, ll, uid); got.LastLoginMethod != email.PluginName {
			t.Fatalf("after an email code = %+v", got)
		}
		e.clock.Advance(time.Hour)
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		if got := lastMethod(t, ll, uid); got.LastLoginMethod != password.PluginName || !got.LastLoginAt.Equal(e.clock.Now()) {
			t.Fatalf("after a password sign-in = %+v", got)
		}
		// A session created from Go, outside any operation, is not a sign-in
		// the user made.
		before := lastMethod(t, ll, uid)
		e.clock.Advance(time.Hour)
		if _, _, err := a.CreateSession(context.Background(), uid, auth.Client{}); err != nil {
			t.Fatal(err)
		}
		if got := lastMethod(t, ll, uid); got.LastLoginMethod != before.LastLoginMethod || !got.LastLoginAt.Equal(*before.LastLoginAt) {
			t.Fatalf("a Go-made session changed the record: %+v, was %+v", got, before)
		}
		// A user who never signed in since the column existed reads empty.
		other, _ := identUser(t, a, identBob)
		if got := lastMethod(t, ll, other); got.LastLoginMethod != "" || got.LastLoginAt != nil {
			t.Fatalf("a user with no sign-in = %+v", got)
		}
	})
}

// TestLastLogin_PendingKeepsTheFirstFactorAndImpersonationIsSkipped: a
// sign-in that ends in a pending second-factor session records its method,
// the promotion does not overwrite it, and an impersonation records nothing.
func TestLastLogin_PendingKeepsTheFirstFactorAndImpersonationIsSkipped(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ll, promote := e.emailPlugin(), e.passwordPlugin(), lastlogin.New(), corePromoteOp()
		a := e.newAuth(t, nil, em, pw, ll, &coreStub{name: coreStubName, ops: []auth.Operation{promote}}, alwaysSecond{})
		up, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret})
		if err != nil || !up.SecondFactorRequired {
			t.Fatalf("sign-up under a second factor = %+v %v", up, err)
		}
		if got := lastMethod(t, ll, up.User.ID); got.LastLoginMethod != password.PluginName {
			t.Fatalf("a pending session must record the first factor: %+v", got)
		}
		e.clock.Advance(time.Minute)
		if _, err := promote.Call(request(a, up.Token), struct{}{}); err != nil {
			t.Fatal(err)
		}
		if got := lastMethod(t, ll, up.User.ID); got.LastLoginMethod != password.PluginName || got.LastLoginAt.Equal(e.clock.Now()) {
			t.Fatalf("the promotion must not overwrite the record: %+v", got)
		}
		adminID, _ := identUser(t, a, identBob)
		e.clock.Advance(time.Minute)
		if _, _, err := a.CreateImpersonationSession(context.Background(), up.User.ID, adminID, auth.Client{}, time.Hour); err != nil {
			t.Fatal(err)
		}
		if got := lastMethod(t, ll, up.User.ID); got.LastLoginAt.Equal(e.clock.Now()) {
			t.Fatalf("an impersonation must record nothing: %+v", got)
		}
	})
}

// TestLastLogin_Resolver: WithResolver names the method itself, and "" records
// nothing; a resolver error-free path with the default resolver reads the
// plugin from the operation id.
func TestLastLogin_Resolver(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ll := lastlogin.New(lastlogin.WithResolver(func(_ context.Context, op auth.OpInfo, s auth.Session) string {
			if op.ID == password.EndpointSignUp {
				return ""
			}
			return "custom:" + string(op.ID) + ":" + s.UserAgent
		}))
		a := e.newAuth(t, nil, em, pw, ll)
		up := signUpVerified(t, e, a, pw, em)
		if got := lastMethod(t, ll, up.User.ID); got.LastLoginMethod != "" {
			t.Fatalf("a resolver answering \"\" must record nothing: %+v", got)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		if got := lastMethod(t, ll, up.User.ID); got.LastLoginMethod != "custom:password.sign-in:test" {
			t.Fatalf("custom resolver = %+v", got)
		}
	})
	if got := lastlogin.DefaultResolver(context.Background(), auth.OpInfo{ID: "oauth.callback"}, auth.Session{}); got != "oauth" {
		t.Fatalf("DefaultResolver = %q", got)
	}
	if got := lastlogin.DefaultResolver(context.Background(), auth.OpInfo{ID: "noplugin"}, auth.Session{}); got != "noplugin" {
		t.Fatalf("DefaultResolver without a dot = %q", got)
	}
	if _, err := lastlogin.New().Of(context.Background(), "usr_x"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Of unwired = %v", err)
	}
}

// TestIdentFaults_LastLogin: the record on a sign-in surfaces every database
// failure.
func TestIdentFaults_LastLogin(t *testing.T) {
	identRun(t, []identSweep{
		{"password sign-in records the method", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, ll := e.emailPlugin(), e.passwordPlugin(), lastlogin.New()
			a := e.newAuth(t, nil, em, pw, ll)
			signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error {
				_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
				return err
			}
		}},
		{"of", func(t *testing.T, e *faultEnv) func(context.Context) error {
			ll := lastlogin.New()
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ll)
			uid, _ := identUser(t, a, alice)
			return func(ctx context.Context) error { _, err := ll.Of(ctx, uid); return err }
		}},
	})
}
