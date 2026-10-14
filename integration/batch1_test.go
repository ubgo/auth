package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// batch1Call sends one request to web with tok as a bearer token ("" for an
// anonymous caller) and returns the status and the body.
func batch1Call(t *testing.T, web *app, method string, tok auth.Token, path string, body any) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, web.srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+string(tok))
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, string(b)
}

// batch1Code is the code of an error body ({"error": {"code": …}}).
func batch1Code(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Error auth.ErrorInfo `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("error body %q: %v", body, err)
	}
	return e.Error.Code
}

// TestBatch1_AdminTwoFactor: an admin sees another user's factor, pauses
// it (sign-in stops asking, the factor and codes stay, sessions stay),
// switches it back on (sessions end, the old recovery codes work again) and
// resets it (the user enrols again). A caller without the permission is
// refused before the target is looked up, so an unknown id reads the same as
// a real one; an admin target cannot be paused or reset; every route is
// recorded by the audit log.
func TestBatch1_AdminTwoFactor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf, au, ad := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(), audit.New(), admin.New()
		a := e.newAuth(t, nil, em, pw, tf, au, ad)
		f := factorsEnroll(t, e, a, pw, em, tf)
		boss := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "boss@example.com", Password: secret, Name: "Boss"}))
		if err := ad.Grant(context.Background(), boss.User.ID); err != nil {
			t.Fatal(err)
		}
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
		as := func() context.Context { return request(a, boss.Token) }
		aliceID := f.up.User.ID

		// Without the permission every route is ErrForbidden, for a real
		// user and an unknown id alike.
		for _, id := range []string{aliceID, "usr_nobody"} {
			if _, err := ad.TwoFactor(request(a, bob.Token), id); !errors.Is(err, admin.ErrForbidden) {
				t.Fatalf("non-admin two-factor %s: %v", id, err)
			}
			for name, op := range map[string]func(context.Context, string) error{"disable": ad.DisableTwoFactor, "enable": ad.EnableTwoFactor, "reset": ad.ResetTwoFactor} {
				if err := op(request(a, bob.Token), id); !errors.Is(err, admin.ErrForbidden) {
					t.Fatalf("non-admin %s %s: %v", name, id, err)
				}
			}
		}
		if _, err := ad.TwoFactor(as(), "usr_nobody"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		if got := must[admin.TwoFactorResult](t)(ad.TwoFactor(as(), bob.User.ID)); got != (admin.TwoFactorResult{}) {
			t.Fatalf("bob = %+v, want not enrolled", got)
		}
		if got := must[admin.TwoFactorResult](t)(ad.TwoFactor(as(), aliceID)); got != (admin.TwoFactorResult{Enrolled: true, Enabled: true, Method: string(twofactor.MethodTOTP)}) {
			t.Fatalf("aliceID = %+v", got)
		}
		if err := ad.DisableTwoFactor(as(), bob.User.ID); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("pausing a user with no factor: %v", err)
		}

		// Pause: sign-in stops asking, her session survives, she sees it off.
		if err := ad.DisableTwoFactor(as(), aliceID); err != nil {
			t.Fatal(err)
		}
		if got := must[admin.TwoFactorResult](t)(ad.TwoFactor(as(), aliceID)); got.Enabled || !got.Enrolled {
			t.Fatalf("paused = %+v", got)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), f.up.Token); err != nil {
			t.Fatalf("a pause ended her session: %v", err)
		}
		if st := must[twofactor.Status](t)(tf.Status(request(a, f.up.Token))); st.Enabled {
			t.Fatalf("her status while paused = %+v", st)
		}
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if in.SecondFactorRequired {
			t.Fatal("a paused factor was asked for")
		}
		if err := ad.DisableTwoFactor(as(), aliceID); err != nil {
			t.Fatalf("pausing twice: %v", err)
		}

		// Back on: every session ends, and the recovery codes kept through
		// the pause still work.
		if err := ad.EnableTwoFactor(as(), aliceID); err != nil {
			t.Fatal(err)
		}
		for _, tok := range []auth.Token{f.up.Token, in.Token} {
			if _, _, _, err := a.ResolveSession(context.Background(), tok); !errors.Is(err, auth.ErrSignedOut) {
				t.Fatalf("a session made during the pause survived enable: %v", err)
			}
		}
		pending := factorsPending(t, a, pw)
		if err := tf.Verify(request(a, pending), f.codes[0]); err != nil {
			t.Fatalf("a recovery code kept through the pause: %v", err)
		}
		live := must[[]auth.Session](t)(a.Sessions(context.Background(), aliceID))
		if err := ad.EnableTwoFactor(as(), aliceID); err != nil {
			t.Fatalf("enabling twice: %v", err)
		}
		if after := must[[]auth.Session](t)(a.Sessions(context.Background(), aliceID)); len(live) == 0 || len(after) != len(live) {
			t.Fatalf("enabling an enabled factor changed her sessions: %d before, %d after", len(live), len(after))
		}

		// An admin target cannot be paused or reset over the route.
		if err := ad.DisableTwoFactor(as(), boss.User.ID); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("pausing an admin: %v", err)
		}
		if err := ad.ResetTwoFactor(as(), boss.User.ID); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("resetting an admin: %v", err)
		}

		// Reset: no factor, sign-in not asked, a second reset says so.
		if err := ad.ResetTwoFactor(as(), aliceID); err != nil {
			t.Fatal(err)
		}
		if got := must[admin.TwoFactorResult](t)(ad.TwoFactor(as(), aliceID)); got != (admin.TwoFactorResult{}) {
			t.Fatalf("after reset = %+v", got)
		}
		if in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})); in.SecondFactorRequired {
			t.Fatal("a reset factor was asked for")
		}
		if err := ad.ResetTwoFactor(as(), aliceID); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("second reset: %v", err)
		}

		// The audit log holds each route, about aliceID, by the admin.
		for _, op := range []auth.EndpointID{admin.EndpointDisableTwoFactor, admin.EndpointEnableTwoFactor, admin.EndpointResetTwoFactor} {
			page := must[audit.Page](t)(au.Events(context.Background(), audit.Query{Op: op}))
			if !slices.ContainsFunc(page.Events, func(ev audit.Event) bool { return ev.OK && ev.SubjectID == aliceID && ev.ActorID == boss.User.ID }) {
				t.Fatalf("%s events = %+v", op, page.Events)
			}
		}

		// From Go, an admin can be reset, and the reset is recorded with no
		// actor.
		bctx := request(a, boss.Token)
		benr := must[twofactor.EnrollResult](t)(tf.Enroll(bctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(bctx, totpAt(t, benr.Secret, e.clock.Now())))
		if err := ad.ResetTwoFactorFor(context.Background(), boss.User.ID); err != nil {
			t.Fatal(err)
		}
		if err := ad.ResetTwoFactorFor(context.Background(), "usr_nobody"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("Go reset of an unknown user: %v", err)
		}
		page := must[audit.Page](t)(au.Events(context.Background(), audit.Query{UserID: boss.User.ID, Op: admin.EndpointResetTwoFactor}))
		if !slices.ContainsFunc(page.Events, func(ev audit.Event) bool { return ev.OK && ev.ActorID == "" && ev.SubjectID == boss.User.ID }) {
			t.Fatalf("Go reset events = %+v", page.Events)
		}
	})
}

// TestBatch1_AdminTwoFactorAuthorizer: the routes ask the Authorizer for
// two-factor permissions, so a support role may read a factor and nothing
// more; DefaultRoles grants the admin role all four.
func TestBatch1_AdminTwoFactorAuthorizer(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		support := admin.AuthorizerFunc(func(_ context.Context, req admin.AccessRequest) (bool, error) {
			return admin.Grants(admin.Permissions{admin.ResourceTwoFactor: {admin.ActionGet}}, req.Permissions, req.Connector), nil
		})
		em, pw, tf, ad := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(), admin.New(admin.WithAuthorizer(support))
		a := e.newAuth(t, nil, em, pw, tf, ad)
		f := factorsEnroll(t, e, a, pw, em, tf)
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
		if got := must[admin.TwoFactorResult](t)(ad.TwoFactor(request(a, bob.Token), f.up.User.ID)); !got.Enabled {
			t.Fatalf("support read = %+v", got)
		}
		if err := ad.ResetTwoFactor(request(a, bob.Token), f.up.User.ID); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("support reset: %v", err)
		}
		granted := admin.DefaultRoles()[admin.RoleAdmin][admin.ResourceTwoFactor]
		for _, act := range []string{admin.ActionGet, admin.ActionDisable, admin.ActionEnable, admin.ActionReset} {
			if !slices.Contains(granted, act) {
				t.Fatalf("the admin role lacks two-factor:%s (%v)", act, granted)
			}
		}
		if len(admin.DefaultRoles()[admin.RoleUser]) != 0 {
			t.Fatal("the user role must grant nothing")
		}
	})
}

// TestBatch1_AdminTwoFactorWithoutThePlugin: with no second-factor plugin
// the routes answer ErrNoTwoFactorPlugin to an admin and ErrForbidden to
// anyone else, in that order, and over HTTP an anonymous caller gets 401
// and a signed-in non-admin 403 on every route.
func TestBatch1_AdminTwoFactorWithoutThePlugin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ad := e.emailPlugin(), e.passwordPlugin(), admin.New()
		a := e.newAuth(t, nil, em, pw, ad)
		boss := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "boss@example.com", Password: secret}))
		if err := ad.Grant(context.Background(), boss.User.ID); err != nil {
			t.Fatal(err)
		}
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := ad.TwoFactor(request(a, boss.Token), bob.User.ID); !errors.Is(err, admin.ErrNoTwoFactorPlugin) {
			t.Fatalf("admin without the plugin: %v", err)
		}
		if err := ad.ResetTwoFactorFor(context.Background(), bob.User.ID); !errors.Is(err, admin.ErrNoTwoFactorPlugin) {
			t.Fatalf("Go reset without the plugin: %v", err)
		}
		if _, err := ad.TwoFactor(request(a, bob.Token), boss.User.ID); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin without the plugin: %v", err)
		}

		web := newApp(t, a)
		routes := []struct {
			method, path string
		}{
			{http.MethodGet, "/auth/admin/two-factor?userId=" + bob.User.ID},
			{http.MethodPost, "/auth/admin/disable-two-factor"},
			{http.MethodPost, "/auth/admin/enable-two-factor"},
			{http.MethodPost, "/auth/admin/reset-two-factor"},
		}
		body := map[string]string{"userId": boss.User.ID}
		for _, r := range routes {
			var b any
			if r.method == http.MethodPost {
				b = body
			}
			if code, out := batch1Call(t, web, r.method, "", r.path, b); code != http.StatusUnauthorized {
				t.Fatalf("anonymous %s %s: %d %s", r.method, r.path, code, out)
			}
			if code, out := batch1Call(t, web, r.method, bob.Token, r.path, b); code != http.StatusForbidden || batch1Code(t, out) != admin.ErrForbidden.Code {
				t.Fatalf("non-admin %s %s: %d %s", r.method, r.path, code, out)
			}
		}
		code, out := batch1Call(t, web, http.MethodGet, boss.Token, "/auth/admin/two-factor?userId="+bob.User.ID, nil)
		if code != http.StatusConflict || batch1Code(t, out) != admin.ErrNoTwoFactorPlugin.Code {
			t.Fatalf("admin over HTTP without the plugin: %d %s", code, out)
		}
	})
}

// TestBatch1_AdminTwoFactorOverHTTP: the four routes as a signed-in admin.
func TestBatch1_AdminTwoFactorOverHTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf, ad := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(), admin.New()
		a := e.newAuth(t, nil, em, pw, tf, ad)
		f := factorsEnroll(t, e, a, pw, em, tf)
		boss := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "boss@example.com", Password: secret}))
		if err := ad.Grant(context.Background(), boss.User.ID); err != nil {
			t.Fatal(err)
		}
		web := newApp(t, a)
		state := func() admin.TwoFactorResult {
			t.Helper()
			code, out := batch1Call(t, web, http.MethodGet, boss.Token, "/auth/admin/two-factor?userId="+f.up.User.ID, nil)
			var r admin.TwoFactorResult
			if code != http.StatusOK || json.Unmarshal([]byte(out), &r) != nil {
				t.Fatalf("two-factor: %d %s", code, out)
			}
			return r
		}
		if got := state(); !got.Enabled || got.Method != string(twofactor.MethodTOTP) {
			t.Fatalf("before = %+v", got)
		}
		body := map[string]string{"userId": f.up.User.ID}
		for path, want := range map[string]admin.TwoFactorResult{
			"/auth/admin/disable-two-factor": {Enrolled: true, Method: string(twofactor.MethodTOTP)},
		} {
			if code, out := batch1Call(t, web, http.MethodPost, boss.Token, path, body); code != http.StatusOK {
				t.Fatalf("%s: %d %s", path, code, out)
			}
			if got := state(); got != want {
				t.Fatalf("after %s = %+v, want %+v", path, got, want)
			}
		}
		if code, out := batch1Call(t, web, http.MethodPost, boss.Token, "/auth/admin/enable-two-factor", body); code != http.StatusOK || !state().Enabled {
			t.Fatalf("enable: %d %s", code, out)
		}
		if code, out := batch1Call(t, web, http.MethodPost, boss.Token, "/auth/admin/reset-two-factor", body); code != http.StatusOK || state().Enrolled {
			t.Fatalf("reset: %d %s", code, out)
		}
		code, out := batch1Call(t, web, http.MethodPost, boss.Token, "/auth/admin/reset-two-factor", body)
		if code != http.StatusConflict || batch1Code(t, out) != twofactor.ErrNotEnrolled.Code {
			t.Fatalf("second reset: %d %s", code, out)
		}
	})
}

// batch1Logs collects log records, for a test that checks the operator saw
// a line.
type batch1Logs struct{ buf bytes.Buffer }

func (l *batch1Logs) logger() *slog.Logger { return slog.New(slog.NewTextHandler(&l.buf, nil)) }

// TestBatch1_VerifyWithAnUnreadableSecret: a TOTP secret that will not
// open answers twofactor.secret_unreadable with 503 instead of a bare 500,
// keeps the cause for errors.Is, logs it for the operator, never counts as a
// wrong code (so the factor does not lock), and leaves recovery codes
// working.
func TestBatch1_VerifyWithAnUnreadableSecret(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		kms, logs := newPrefixSealer(t), &batch1Logs{}
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), twofactor.New(twofactor.WithSealer(kms))
		a := e.newAuth(t, []auth.Option{auth.WithLogger(logs.logger())}, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		pending := factorsPending(t, a, pw)

		kms.failOpen.Store(true)
		for range twofactor.MaxFailures + 1 {
			err := tf.Verify(request(a, pending), totpAt(t, f.secret, e.clock.Now()))
			if !errors.Is(err, twofactor.ErrSecretUnreadable) || !errors.Is(err, errKMSDown) {
				t.Fatalf("verify with the key service down: %v", err)
			}
			if info := auth.ErrorOf(err); info.Status != http.StatusServiceUnavailable || info.Code != twofactor.ErrSecretUnreadable.Code {
				t.Fatalf("answer = %+v", info)
			}
		}
		if !strings.Contains(logs.buf.String(), "does not open") || !strings.Contains(logs.buf.String(), f.up.User.ID) {
			t.Fatalf("no operator log line: %q", logs.buf.String())
		}

		// Over HTTP: the pending sign-in's verify answers 503 with the code.
		web := newApp(t, a)
		res := web.post(t, "/auth/password/sign-in", map[string]string{"identifier": alice, "password": secret})
		if res.StatusCode != http.StatusOK {
			t.Fatalf("sign-in: %d %s", res.StatusCode, readAll(t, res))
		}
		res = web.post(t, "/auth/twofactor/verify", map[string]string{"code": totpAt(t, f.secret, e.clock.Now())})
		if body := readAll(t, res); res.StatusCode != http.StatusServiceUnavailable || batch1Code(t, body) != twofactor.ErrSecretUnreadable.Code || strings.Contains(body, errKMSDown.Error()) {
			t.Fatalf("verify over HTTP: %d %s", res.StatusCode, body)
		}

		// A recovery code is checked by hash and still passes.
		if err := tf.Verify(request(a, pending), f.codes[0]); err != nil {
			t.Fatalf("recovery code with the key service down: %v", err)
		}
		// None of the failures counted: with the key back, a code passes.
		kms.failOpen.Store(false)
		e.clock.Advance(twofactor.Step)
		if err := tf.Verify(request(a, factorsPending(t, a, pw)), totpAt(t, f.secret, e.clock.Now())); err != nil {
			t.Fatalf("after the outage: %v (an unreadable secret must not lock the factor)", err)
		}
	})
}

// TestBatch1_ViewRecoveryCodesInIssueOrder: view-recovery-codes shows the
// unused codes in the order confirm handed them out, after a code is used
// and after a new set, not in the order of their random ids.
func TestBatch1_ViewRecoveryCodesInIssueOrder(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted))
		a := e.newAuth(t, []auth.Option{auth.WithSecret(parityAppSecret)}, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		ctx := request(a, f.up.Token)
		view := func() []string {
			t.Helper()
			return must[twofactor.RecoveryCodes](t)(tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{Password: secret})).Codes
		}
		if got := view(); !slices.Equal(got, f.codes) {
			t.Fatalf("view = %v, want the issue order %v", got, f.codes)
		}
		if err := tf.Verify(request(a, factorsPending(t, a, pw)), f.codes[3]); err != nil {
			t.Fatal(err)
		}
		if got, want := view(), slices.Delete(slices.Clone(f.codes), 3, 4); !slices.Equal(got, want) {
			t.Fatalf("after use = %v, want %v", got, want)
		}
		fresh := must[twofactor.RecoveryCodes](t)(tf.RegenerateRecoveryCodesWith(ctx, twofactor.CodeRequest{Code: f.codes[0]}))
		if got := view(); !slices.Equal(got, fresh.Codes) {
			t.Fatalf("after a new set = %v, want %v", got, fresh.Codes)
		}
	})
}

// TestBatch1_EmailAllowDomains: AllowDomains lets in exactly the listed
// domains (and subdomains of a "*." entry) at sign-up, add and change, with
// the one enumeration-safe answer; an account made before the list still
// signs in, because sign-in runs no address check; a list naming no domain
// fails auth.New.
func TestBatch1_EmailAllowDomains(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		before := e.passwordPlugin()
		a0 := e.newAuth(t, nil, e.emailPlugin(), before)
		if _, err := before.SignUp(anon(a0), password.SignUpRequest{Identifier: "old@elsewhere.example", Password: secret}); err != nil {
			t.Fatal(err)
		}

		// A list naming no domain fails auth.New, naming the option.
		if _, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(email.AllowDomains("acme.example", "@")), e.passwordPlugin())); !errors.Is(err, email.ErrBadDomainList) || !strings.Contains(err.Error(), "email.AllowDomains") {
			t.Fatalf("auth.New with a bad allow-list = %v, want email.ErrBadDomainList", err)
		}

		em, pw := e.emailPlugin(email.AllowDomains("acme.example", "*.uni.example"), email.Multiple()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		for _, addr := range []string{"new@elsewhere.example", "new@eu.acme.example", "new@uni.example", "new@notacme.example"} {
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: addr, Password: secret}); !errors.Is(err, email.ErrAddressRejected) {
				t.Fatalf("sign up %s: %v, want ErrAddressRejected", addr, err)
			}
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "old@elsewhere.example", Password: secret}); err != nil {
			t.Fatalf("an account from before the list cannot sign in: %v", err)
		}
		up := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "pat@acme.example", Password: secret}))
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "sam@cs.uni.example", Password: secret}); err != nil {
			t.Fatalf("a subdomain of a wildcard entry: %v", err)
		}
		if err := em.Add(request(a, up.Token), "pat@elsewhere.example"); !errors.Is(err, email.ErrAddressRejected) {
			t.Fatalf("add: %v", err)
		}
		if err := em.Change(request(a, up.Token), "pat@elsewhere.example"); !errors.Is(err, email.ErrAddressRejected) {
			t.Fatalf("change: %v", err)
		}
		if n := len(e.mail.To(a, "pat@elsewhere.example")); n != 0 {
			t.Fatalf("%d mails went to a refused address", n)
		}

		// Over HTTP the refusal is the same body for an address that exists
		// elsewhere and one that exists nowhere.
		web := newApp(t, a)
		var bodies []string
		for _, addr := range []string{"old@elsewhere.example", "nobody@elsewhere.example"} {
			code, out := batch1Call(t, web, http.MethodPost, "", "/auth/password/sign-up", map[string]string{"identifier": addr, "password": secret})
			if code != http.StatusBadRequest || batch1Code(t, out) != email.ErrAddressRejected.Code {
				t.Fatalf("sign-up %s over HTTP: %d %s", addr, code, out)
			}
			bodies = append(bodies, out)
		}
		if bodies[0] != bodies[1] {
			t.Fatalf("the refusal differs by account: %q vs %q", bodies[0], bodies[1])
		}
	})
}

// TestBatch1_PausedFactorCanBeReplaced: a factor an admin paused reads as
// off to its user, who may enrol a new one; a factor that is on still
// refuses enroll with ErrAlreadyEnabled. From Go the pause and enable need a
// confirmed factor.
func TestBatch1_PausedFactorCanBeReplaced(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		ctx := request(a, f.up.Token)
		if _, err := tf.Enroll(ctx); !errors.Is(err, twofactor.ErrAlreadyEnabled) {
			t.Fatalf("enroll over a factor that is on: %v", err)
		}
		if err := tf.DisableFor(context.Background(), f.up.User.ID); err != nil {
			t.Fatal(err)
		}
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if enr.Secret == f.secret {
			t.Fatal("enroll over a paused factor kept the old secret")
		}
		// Until confirmed, the new enrolment is no factor at all.
		if method, on, err := tf.FactorOf(context.Background(), f.up.User.ID); err != nil || method != "" || on {
			t.Fatalf("unconfirmed replacement = %q %v %v", method, on, err)
		}
		if err := tf.EnableFor(context.Background(), f.up.User.ID); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("enable with only an unconfirmed enrolment: %v", err)
		}
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		if method, on, err := tf.FactorOf(context.Background(), f.up.User.ID); err != nil || method != string(twofactor.MethodTOTP) || !on {
			t.Fatalf("confirmed replacement = %q %v %v", method, on, err)
		}
		if err := tf.DisableFor(context.Background(), "usr_nobody"); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("pause of a user with no factor: %v", err)
		}
	})
}

// batch1FaultWorld is alice with a confirmed factor, an admin, the admin
// plugin and no audit log, on a fault-injecting database.
type batch1FaultWorld struct {
	a     *auth.Auth
	tf    *twofactor.Plugin
	ad    *admin.Plugin
	alice factorsTOTP
	boss  password.SignInResult
}

func batch1Faults(t *testing.T, e *faultEnv) batch1FaultWorld {
	t.Helper()
	em, pw, tf, ad := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(), admin.New()
	a := e.newAuth(t, nil, em, pw, tf, ad)
	w := batch1FaultWorld{a: a, tf: tf, ad: ad, alice: factorsEnroll(t, e.env, a, pw, em, tf)}
	w.boss = must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "boss@example.com", Password: secret}))
	if err := ad.Grant(context.Background(), w.boss.User.ID); err != nil {
		t.Fatal(err)
	}
	return w
}

// TestBatch1_AdminTwoFactorFaults: every database failure in the four
// admin routes, the Go reset and the plugin calls under them reaches the
// caller; none reads as a success or an empty answer.
func TestBatch1_AdminTwoFactorFaults(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := batch1Faults(t, e)
			return func(context.Context) error {
				_, err := w.ad.TwoFactor(request(w.a, w.boss.Token), w.alice.up.User.ID)
				return err
			}
		})
	})
	t.Run("pause", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := batch1Faults(t, e)
			return func(context.Context) error {
				return w.ad.DisableTwoFactor(request(w.a, w.boss.Token), w.alice.up.User.ID)
			}
		})
	})
	t.Run("enable a paused factor", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := batch1Faults(t, e)
			if err := w.tf.DisableFor(context.Background(), w.alice.up.User.ID); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				return w.ad.EnableTwoFactor(request(w.a, w.boss.Token), w.alice.up.User.ID)
			}
		})
	})
	t.Run("reset", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := batch1Faults(t, e)
			return func(context.Context) error {
				return w.ad.ResetTwoFactor(request(w.a, w.boss.Token), w.alice.up.User.ID)
			}
		})
	})
	t.Run("Go reset without an audit log", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := batch1Faults(t, e)
			return func(ctx context.Context) error { return w.ad.ResetTwoFactorFor(ctx, w.alice.up.User.ID) }
		})
	})
	t.Run("enroll over a paused factor", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			w := batch1Faults(t, e)
			if err := w.tf.DisableFor(context.Background(), w.alice.up.User.ID); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				_, err := w.tf.Enroll(request(w.a, w.alice.up.Token))
				return err
			}
		})
	})
}
