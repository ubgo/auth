package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
)

// adminWorld is an admin (boss) and an ordinary user (bob), signed up and
// wired with the password and email plugins, for the round-2 admin tests.
type adminWorld struct {
	a        *auth.Auth
	em       *email.Plugin
	pw       *password.Plugin
	ad       *admin.Plugin
	boss     password.SignInResult
	bob      password.SignInResult
	bossCtx  func() context.Context
	bossMail string
}

func newAdminWorld(t *testing.T, e *env, adminOpts []admin.Option, emailOpts ...email.Option) *adminWorld {
	t.Helper()
	w := &adminWorld{em: e.emailPlugin(emailOpts...), pw: e.passwordPlugin(), ad: admin.New(adminOpts...)}
	w.a = e.newAuth(t, nil, w.em, w.pw, w.ad)
	w.boss = signUpVerified(t, e, w.a, w.pw, w.em)
	w.bossMail = alice
	if err := w.ad.Grant(context.Background(), w.boss.User.ID); err != nil {
		t.Fatal(err)
	}
	w.bob = must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
	if _, err := w.em.Verify(anon(w.a), e.mail.LastToken(t, w.a, "bob@example.com")); err != nil {
		t.Fatal(err)
	}
	w.bossCtx = func() context.Context { return request(w.a, w.boss.Token) }
	return w
}

// TestAdmin_BannedUserIsRefusedAtSignInOnEveryMethod: a banned user who
// proves the credential is told so, with the app's message, by the password
// and the code sign-in alike; a stranger without the credential gets the
// ordinary wrong-credential answer, so the ban reveals nothing to them.
func TestAdmin_BannedUserIsRefusedAtSignInOnEveryMethod(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		msg := func(_ context.Context, b admin.Ban) string { return "Banned: " + b.Reason }
		w := newAdminWorld(t, e, []admin.Option{admin.BannedMessage(msg)}, email.SignInWithCode())
		if err := w.ad.Ban(w.bossCtx(), w.bob.User.ID, "chargeback"); err != nil {
			t.Fatal(err)
		}
		_, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret})
		var ae *auth.Error
		if !errors.Is(err, admin.ErrBanned) || !errors.As(err, &ae) || ae.Message != "Banned: chargeback" {
			t.Fatalf("banned password sign-in = %v (%+v)", err, ae)
		}
		// Without the password the answer is the same as for any account.
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: "not it"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password for a banned user: %v, must not reveal the ban", err)
		}
		if err := w.em.SendCode(anon(w.a), "bob@example.com"); err != nil {
			t.Fatal(err)
		}
		w.a.WaitDeliveries()
		if _, err := w.em.SignInCode(anon(w.a), "bob@example.com", lastMailCode(t, e, w.a, "bob@example.com")); !errors.Is(err, admin.ErrBanned) {
			t.Fatalf("banned code sign-in = %v", err)
		}
		// Lifting the ban lets the same credential in again.
		if err := w.ad.Unban(w.bossCtx(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); err != nil {
			t.Fatalf("after unban: %v", err)
		}
		// A temporary ban stops refusing once it passes.
		if _, err := w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}); err != nil {
			t.Fatal(err)
		}
	})
}

// TestAdmin_BannedMessageDefaultsAndTemporaryBanLifts: no BannedMessage, or
// one that answers "", reads DefaultBannedMessage; a ban with minutes stops
// refusing sign-in the moment it passes.
func TestAdmin_BannedMessageDefaultsAndTemporaryBanLifts(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, []admin.Option{admin.BannedMessage(func(context.Context, admin.Ban) string { return "" })})
		op, _ := w.a.Operation(admin.EndpointBan)
		if _, err := op.Invoke(w.bossCtx(), func(dst any) error {
			*dst.(*admin.BanRequest) = admin.BanRequest{UserID: w.bob.User.ID, Minutes: 30}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		_, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret})
		var ae *auth.Error
		if !errors.As(err, &ae) || ae.Code != admin.ErrBanned.Code || ae.Message != admin.DefaultBannedMessage {
			t.Fatalf("empty message must fall back: %v (%+v)", err, ae)
		}
		e.clock.Advance(31 * time.Minute)
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); err != nil {
			t.Fatalf("after the ban expired: %v", err)
		}
	})
}

// TestAdmin_CreateUserSetPasswordSetEmail: an admin creates a user who can
// sign in at once, sets another user's password (ending their sessions) and
// gives a user a new primary address, all through the owning plugins' rules.
func TestAdmin_CreateUserSetPasswordSetEmail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		if _, err := w.ad.CreateUser(request(w.a, w.bob.Token), admin.CreateUserRequest{Email: "carol@example.com"}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin create: %v", err)
		}
		if _, err := w.ad.CreateUser(w.bossCtx(), admin.CreateUserRequest{Name: "Carol"}); !errors.Is(err, admin.ErrEmailRequired) {
			t.Fatalf("create without an address: %v", err)
		}
		if _, err := w.ad.CreateUser(w.bossCtx(), admin.CreateUserRequest{Name: "Carol", Email: "carol@example.com", Password: "short"}); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("a weak password must be refused by the password plugin: %v", err)
		}
		// The refused password left no user and no address behind.
		if _, err := w.a.FindIdentity(context.Background(), email.KindEmail, "carol@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("after a refused create: %v", err)
		}
		carol := must[auth.UserView](t)(w.ad.CreateUser(w.bossCtx(), admin.CreateUserRequest{Name: "Carol", Email: " Carol@Example.com ", Verified: true, Password: secret}))
		if carol.Name != "Carol" {
			t.Fatalf("created = %+v", carol)
		}
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "carol@example.com", Password: secret}); err != nil {
			t.Fatalf("the created user signs in: %v", err)
		}
		idn := must[auth.Identity](t)(w.a.FindIdentity(context.Background(), email.KindEmail, "carol@example.com", true))
		if idn.UserID != carol.ID || !idn.IsPrimary {
			t.Fatalf("created address = %+v", idn)
		}
		// Taken addresses stay taken.
		if _, err := w.ad.CreateUser(w.bossCtx(), admin.CreateUserRequest{Email: "bob@example.com", Verified: true}); !errors.Is(err, auth.ErrIdentityTaken) {
			t.Fatalf("creating with another user's address: %v", err)
		}

		// Set password: bob's session ends, the new password works, an admin
		// is protected.
		if err := w.ad.SetUserPassword(w.bossCtx(), w.bob.User.ID, "a brand new passphrase"); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := w.a.ResolveSession(context.Background(), w.bob.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("bob's session after set-password: %v", err)
		}
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: "a brand new passphrase"}); err != nil {
			t.Fatalf("new password: %v", err)
		}
		if err := w.ad.SetUserPassword(w.bossCtx(), w.boss.User.ID, "a brand new passphrase"); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("setting an admin's password: %v", err)
		}
		if err := w.ad.SetUserPassword(w.bossCtx(), "usr_nobody", "a brand new passphrase"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown target: %v", err)
		}

		// Set email: a verified address becomes primary at once.
		if err := w.ad.SetUserEmail(w.bossCtx(), admin.SetEmailRequest{UserID: w.bob.User.ID, Email: "robert@example.com", Verified: true}); err != nil {
			t.Fatal(err)
		}
		d := must[admin.UserDetail](t)(w.ad.User(w.bossCtx(), w.bob.User.ID))
		primary := ""
		for _, i := range d.Identities {
			if i.Primary {
				primary = i.Value
			}
		}
		if primary != "robert@example.com" {
			t.Fatalf("identities after set-email = %+v", d.Identities)
		}
		if err := w.ad.SetUserEmail(w.bossCtx(), admin.SetEmailRequest{UserID: w.boss.User.ID, Email: "x@example.com"}); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("setting an admin's address: %v", err)
		}
	})
}

// TestAdmin_WithoutPasswordOrEmailPluginTheOperationsSaySo: the admin plugin
// works without the password and email plugins; the operations that need
// them answer with a code rather than a nil-pointer panic.
func TestAdmin_WithoutPasswordOrEmailPluginTheOperationsSaySo(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph, ad := e.phonePlugin(phone.Login(), phone.SignInWithCode()), admin.New()
		a := e.newAuth(t, nil, ph, ad)
		const number = "+14155550123"
		if err := ph.SendCode(anon(a), number); err != nil {
			t.Fatal(err)
		}
		in := must[phone.SignInResult](t)(ph.SignIn(anon(a), number, e.sms.LastCode(t, a, number)))
		if err := ad.Grant(context.Background(), in.User.ID); err != nil {
			t.Fatal(err)
		}
		ctx := request(a, in.Token)
		if _, err := ad.CreateUser(ctx, admin.CreateUserRequest{Email: "x@example.com"}); !errors.Is(err, admin.ErrNoEmailPlugin) {
			t.Fatalf("create-user without email plugin: %v", err)
		}
		if err := ad.SetUserEmail(ctx, admin.SetEmailRequest{UserID: in.User.ID, Email: "x@example.com"}); !errors.Is(err, admin.ErrNoEmailPlugin) {
			t.Fatalf("set-email without email plugin: %v", err)
		}
		if err := ad.SetUserPassword(ctx, in.User.ID, "a brand new passphrase"); !errors.Is(err, admin.ErrNoPasswordPlugin) {
			t.Fatalf("set-password without password plugin: %v", err)
		}
		if _, err := ad.Audit(ctx, audit.Query{}); !errors.Is(err, admin.ErrNoAuditPlugin) {
			t.Fatalf("audit without audit plugin: %v", err)
		}
		// With an email plugin but no password plugin, a create that names a
		// password is refused before any user is made.
		// An address unique to this run: the database is shared between tests
		// on Postgres and MySQL, and a sign-in code for an address another
		// test left unverified is deliberately never mailed.
		em, ad2 := e.emailPlugin(email.SignUpWithCode()), admin.New()
		a2 := e.newAuth(t, nil, em, ad2)
		danaMail := "dana-" + in.User.ID + "@example.com"
		if err := em.SendCode(anon(a2), danaMail); err != nil {
			t.Fatal(err)
		}
		a2.WaitDeliveries()
		dana := must[email.CodeSignInResult](t)(em.SignInCode(anon(a2), danaMail, lastMailCode(t, e, a2, danaMail)))
		if err := ad2.Grant(context.Background(), dana.User.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := ad2.CreateUser(request(a2, dana.Token), admin.CreateUserRequest{Email: "x@example.com", Password: secret}); !errors.Is(err, admin.ErrNoPasswordPlugin) {
			t.Fatalf("create-user with a password and no password plugin: %v", err)
		}
		if _, err := a2.FindIdentity(context.Background(), email.KindEmail, "x@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("a refused create must leave no user: %v", err)
		}
	})
}

// TestAdmin_Round2EveryDatabaseFailureSurfaces: the new operations, and a
// sign-in (which now reads the ban state), surface every database failure.
func TestAdmin_Round2EveryDatabaseFailureSurfaces(t *testing.T) {
	cases := map[string]func(t *testing.T, w *adminWorld) func(context.Context) error{
		"create-user": func(_ *testing.T, w *adminWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.ad.CreateUser(w.bossCtx(), admin.CreateUserRequest{Name: "Carol", Email: "carol@example.com", Verified: true, Password: secret})
				return err
			}
		},
		"set-password": func(_ *testing.T, w *adminWorld) func(context.Context) error {
			return func(context.Context) error {
				return w.ad.SetUserPassword(w.bossCtx(), w.bob.User.ID, "a brand new passphrase")
			}
		},
		"set-email": func(_ *testing.T, w *adminWorld) func(context.Context) error {
			return func(context.Context) error {
				return w.ad.SetUserEmail(w.bossCtx(), admin.SetEmailRequest{UserID: w.bob.User.ID, Email: "robert@example.com", Verified: true})
			}
		},
		// The ban check adds a read to every sign-in; a failure of that read
		// must fail the sign-in, never let it through.
		"sign-in-with-ban-check": func(_ *testing.T, w *adminWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret})
				return err
			}
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				return op(t, newAdminWorld(t, e.env, nil))
			})
		})
	}
	// Stopping with the flow value resolves the admin's session, which can
	// fail too; its setup impersonates first, with faults off.
	t.Run("stop-impersonating-restore", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := newAdminWorld(t, e.env, nil)
			as := must[admin.ImpersonateResult](t)(w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}))
			return func(context.Context) error {
				_, err := w.ad.StopImpersonating(withFlow(w.a, as.Token, as.AdminToken))
				return err
			}
		})
	})
}

// TestAdmin_BanRefusalKeepsTheMessageOutOfTheCode: the error a client sees
// has the stable code and the configured text, and nothing else.
func TestAdmin_BanRefusalKeepsTheMessageOutOfTheCode(t *testing.T) {
	if admin.ErrBanned.Error() != "admin.banned" || !strings.Contains(admin.DefaultBannedMessage, "banned") {
		t.Fatalf("%q %q", admin.ErrBanned.Error(), admin.DefaultBannedMessage)
	}
}

// TestAdmin_StopImpersonatingRestoresTheAdmin: impersonating rotates the
// admin's token (the old one dies) and hands the new one back as the flow
// binding; stopping with that flow value re-issues the admin's session,
// which is the same session as before, so it is not fresh; stopping without
// the flow value, or with a flow value that is not the admin's, signs out.
func TestAdmin_StopImpersonatingRestoresTheAdmin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAdminWorld(t, e, nil)
		adminSession := must[[]auth.Session](t)(w.a.Sessions(context.Background(), w.boss.User.ID))
		if len(adminSession) != 1 {
			t.Fatalf("sessions = %d", len(adminSession))
		}
		as := must[admin.ImpersonateResult](t)(w.ad.Impersonate(w.bossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}))
		if as.AdminToken == "" || as.AdminToken == w.boss.Token {
			t.Fatalf("admin token = %q", as.AdminToken)
		}
		// The old admin token is dead; the new one is the same session.
		if _, _, _, err := w.a.ResolveSession(context.Background(), w.boss.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("old admin token: %v", err)
		}
		s, u, _, err := w.a.ResolveSession(context.Background(), as.AdminToken)
		if err != nil || u.ID != w.boss.User.ID || s.ID != adminSession[0].ID || !s.CreatedAt.Equal(adminSession[0].CreatedAt) {
			t.Fatalf("rotated admin session = %+v %+v %v", s, u, err)
		}
		// Stop with the flow value: restored, as an issue-session effect.
		ctx := withFlow(w.a, as.Token, as.AdminToken)
		r := must[admin.StopResult](t)(w.ad.StopImpersonating(ctx))
		if !r.OK || !r.Restored {
			t.Fatalf("stop = %+v", r)
		}
		issued, cleared := false, false
		for _, ef := range auth.RequestEffects(ctx) {
			switch ef.Kind {
			case auth.EffectIssueSession:
				issued = ef.Token == as.AdminToken && ef.UserID == w.boss.User.ID
			case auth.EffectClearSession:
				cleared = true
			case auth.EffectBindFlow:
				if ef.Token != "" {
					t.Fatalf("the flow binding must be cleared, got %+v", ef)
				}
			}
		}
		if !issued || cleared {
			t.Fatalf("effects = %+v", auth.RequestEffects(ctx))
		}
		// Not fresh: the restored session is the original one.
		e.clock.Advance(auth.DefaultFreshWindow + time.Minute)
		if err := w.ad.Ban(request(w.a, as.AdminToken), w.bob.User.ID, "spam"); !errors.Is(err, auth.ErrFreshSessionRequired) {
			t.Fatalf("a restored session must not be fresh: %v", err)
		}

		// Without the flow value, or with someone else's token in it, the
		// client is signed out.
		w.boss.Token = as.AdminToken
		as2 := must[admin.ImpersonateResult](t)(w.ad.Impersonate(request(w.a, mustSignIn(t, w)), admin.ImpersonateRequest{UserID: w.bob.User.ID}))
		ctx = request(w.a, as2.Token)
		if r := must[admin.StopResult](t)(w.ad.StopImpersonating(ctx)); !r.OK || r.Restored {
			t.Fatalf("stop without flow = %+v", r)
		}
		bobTok := mustSignInAs(t, w, "bob@example.com")
		as3 := must[admin.ImpersonateResult](t)(w.ad.Impersonate(request(w.a, mustSignIn(t, w)), admin.ImpersonateRequest{UserID: w.bob.User.ID}))
		ctx = withFlow(w.a, as3.Token, bobTok)
		if r := must[admin.StopResult](t)(w.ad.StopImpersonating(ctx)); !r.OK || r.Restored {
			t.Fatalf("stop with a stranger's token in the flow = %+v", r)
		}
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectIssueSession {
				t.Fatalf("a stranger's token must not be issued: %+v", ef)
			}
		}
	})
}

// withFlow is request with a flow binding, as a browser that received a
// BindFlow effect sends it back.
func withFlow(a *auth.Auth, tok, flow auth.Token) context.Context {
	req := auth.Request{
		Transport:  auth.TransportHTTP,
		Client:     auth.Client{IP: "203.0.113.7", UserAgent: "test", Origin: testBaseURL},
		Credential: auth.CredentialCookie, Token: tok, Flow: flow,
	}
	return a.WithRequest(context.Background(), req)
}

// mustSignIn signs the admin in afresh and returns the new token.
func mustSignIn(t *testing.T, w *adminWorld) auth.Token {
	t.Helper()
	return mustSignInAs(t, w, w.bossMail)
}

func mustSignInAs(t *testing.T, w *adminWorld, address string) auth.Token {
	t.Helper()
	return must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: address, Password: secret})).Token
}
