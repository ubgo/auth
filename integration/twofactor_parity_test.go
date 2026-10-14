package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// The better-auth parity features of the two-factor plugin: a per-enrolment
// issuer, SkipVerificationOnEnable, totp-uri behind the password and a fresh
// sign-in, verify without a session plus the step-up check, encrypted
// recovery codes that can be viewed again, and RequirePassword.

// The password plugin is the PasswordChecker the two-factor plugin finds at
// Init; this fails to compile the day its method set drifts.
var _ twofactor.PasswordChecker = (*password.Plugin)(nil)

// parityAppSecret is the app secret StoreEncrypted derives its key from.
var parityAppSecret = []byte(strings.Repeat("a", auth.MinSecretSize))

// TestTwoFactorParity_IssuerPerEnrolment: an issuer named at enroll replaces
// the plugin's in the URI and is kept with the factor, so totp-uri shows it
// again; a bad one is refused before anything is written.
func TestTwoFactorParity_IssuerPerEnrolment(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.Issuer("Acme"), twofactor.ReadableTOTPURI())
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if _, err := tf.EnrollWith(ctx, twofactor.EnrollRequest{Issuer: "Acme:Beta"}); !errors.Is(err, twofactor.ErrIssuerInvalid) {
			t.Fatalf("colon issuer: %v, want ErrIssuerInvalid", err)
		}
		if _, err := tf.TOTPURI(ctx, twofactor.PasswordRequest{Password: secret}); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("refused issuer must write nothing: %v", err)
		}
		enr := must[twofactor.EnrollResult](t)(tf.EnrollWith(ctx, twofactor.EnrollRequest{Issuer: " Beta "}))
		if got := uriIssuer(t, enr.URL); got != "Beta" {
			t.Fatalf("enroll issuer = %q, want Beta", got)
		}
		uri := must[twofactor.TOTPURIResult](t)(tf.TOTPURI(ctx, twofactor.PasswordRequest{Password: secret}))
		if uri.URL != enr.URL {
			t.Fatalf("totp-uri = %s, want the enrolment's %s", uri.URL, enr.URL)
		}
		// Without an issuer, the plugin's applies again.
		must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		uri = must[twofactor.TOTPURIResult](t)(tf.TOTPURI(ctx, twofactor.PasswordRequest{Password: secret}))
		if got := uriIssuer(t, uri.URL); got != "Acme" {
			t.Fatalf("default issuer = %q, want Acme", got)
		}
	})
}

func uriIssuer(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("issuer")
}

// TestTwoFactorParity_SkipVerificationOnEnable: enroll turns the factor on at
// once with the recovery codes, signs out the other sessions, and the next
// sign-in is pending; a delivered factor sends nothing at enroll but still
// needs a verified identity.
func TestTwoFactorParity_SkipVerificationOnEnable(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.SkipVerificationOnEnable(), twofactor.DeliveredCodes())
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		other := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if !enr.Enabled || len(enr.RecoveryCodes) != twofactor.DefaultRecoveryCodes || enr.Secret == "" {
			t.Fatalf("enroll = %+v, want enabled with codes", enr)
		}
		if st := must[twofactor.Status](t)(tf.Status(ctx)); !st.Enabled || st.Method != twofactor.MethodTOTP {
			t.Fatalf("status = %+v, want on", st)
		}
		if _, err := tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, twofactor.ErrAlreadyEnabled) {
			t.Fatalf("confirm after skip: %v, want ErrAlreadyEnabled", err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), other.Token); err == nil {
			t.Fatal("turning the factor on must sign out the other sessions")
		}
		pending := factorsPending(t, a, pw)
		must[auth.Done](t)(auth.Done{OK: true}, tf.Verify(request(a, pending), enr.RecoveryCodes[0]))

		// A delivered factor: nothing is mailed at enroll, the factor is on.
		must[auth.Done](t)(auth.Done{OK: true}, tf.Disable(request(a, factorsFull(t, a, pw, tf, enr.RecoveryCodes[1])), enr.RecoveryCodes[2]))
		sent := len(e.mail.To(a, alice))
		fresh := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		del := must[twofactor.EnrollResult](t)(tf.EnrollWith(request(a, fresh.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}))
		if !del.Enabled || del.Method != twofactor.MethodDelivered || len(del.RecoveryCodes) == 0 {
			t.Fatalf("delivered enroll = %+v", del)
		}
		if got := len(e.mail.To(a, alice)); got != sent {
			t.Fatalf("mails = %d, want %d: skip sends no first code", got, sent)
		}
		// A user with nowhere to send a code cannot enrol the delivered method.
		_, bare := factorsSession(t, a, "Bo")
		if _, err := tf.EnrollWith(request(a, bare), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}); !errors.Is(err, twofactor.ErrNoChannel) {
			t.Fatalf("no channel: %v, want ErrNoChannel", err)
		}
		if st := must[twofactor.Status](t)(tf.Status(request(a, bare))); st.Enabled {
			t.Fatal("a refused enroll must leave the factor off")
		}
	})
}

// factorsFull signs alice in and passes the factor with code, returning the
// full session's token.
func factorsFull(t *testing.T, a *auth.Auth, pw *password.Plugin, tf *twofactor.Plugin, code string) auth.Token {
	t.Helper()
	pending := factorsPending(t, a, pw)
	ctx := request(a, pending)
	if err := tf.Verify(ctx, code); err != nil {
		t.Fatal(err)
	}
	return issuedToken(t, a, ctx)
}

// issuedToken is the session token the call in ctx handed the client.
func issuedToken(t *testing.T, a *auth.Auth, ctx context.Context) auth.Token {
	t.Helper()
	for _, eff := range auth.RequestEffects(ctx) {
		if eff.Kind == auth.EffectIssueSession {
			return eff.Token
		}
	}
	t.Fatal("no session issued")
	return ""
}

// TestTwoFactorParity_TOTPURI: the URI comes back only with the password of a
// user who has one and only on a fresh session; a passwordless user passes
// on the fresh session; a delivered factor has none; the route exists only
// with the option.
func TestTwoFactorParity_TOTPURI(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.ReadableTOTPURI(), twofactor.DeliveredCodes())
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		ctx := request(a, f.up.Token)
		for _, bad := range []auth.Token{"", "wrong horse battery"} {
			if _, err := tf.TOTPURI(ctx, twofactor.PasswordRequest{Password: bad}); !errors.Is(err, password.ErrInvalidCredentials) {
				t.Fatalf("password %q: %v, want ErrInvalidCredentials", bad, err)
			}
		}
		uri := must[twofactor.TOTPURIResult](t)(tf.TOTPURI(ctx, twofactor.PasswordRequest{Password: secret}))
		u, err := url.Parse(uri.URL)
		if err != nil || u.Query().Get("secret") != f.secret {
			t.Fatalf("uri = %s, %v; want the enrolled secret", uri.URL, err)
		}
		e.clock.Advance(a.Config().FreshWindow + 1)
		if _, err := tf.TOTPURI(request(a, f.up.Token), twofactor.PasswordRequest{Password: secret}); !errors.Is(err, auth.ErrFreshSessionRequired) {
			t.Fatalf("stale session: %v, want ErrFreshSessionRequired", err)
		}

		// A passwordless user: the fresh session is the proof.
		_, bare := factorsSession(t, a, "Bo")
		bctx := request(a, bare)
		if _, err := tf.TOTPURI(bctx, twofactor.PasswordRequest{}); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("not enrolled: %v", err)
		}
		benr := must[twofactor.EnrollResult](t)(tf.Enroll(bctx))
		if got := must[twofactor.TOTPURIResult](t)(tf.TOTPURI(bctx, twofactor.PasswordRequest{})); got.URL != benr.URL {
			t.Fatalf("passwordless uri = %s, want %s", got.URL, benr.URL)
		}
		cy, coded := factorsSession(t, a, "Cy")
		must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: cy.ID, Kind: email.KindEmail, Raw: "cy@example.com", Verified: true, Primary: true}))
		must[twofactor.EnrollResult](t)(tf.EnrollWith(request(a, coded), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}))
		if _, err := tf.TOTPURI(request(a, coded), twofactor.PasswordRequest{}); !errors.Is(err, twofactor.ErrNotTOTP) {
			t.Fatalf("delivered: %v, want ErrNotTOTP", err)
		}

		// Without the option there is no route, from Go or over HTTP.
		plain := factorsTwoFactor()
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), plain)
		if _, err := plain.TOTPURI(request(b, bare), twofactor.PasswordRequest{}); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatalf("without the option: %v, want ErrOperationNotWired", err)
		}
		web := newApp(t, b)
		if res := web.post(t, "/auth/twofactor/totp-uri", map[string]string{}); res.StatusCode != http.StatusNotFound {
			t.Fatalf("POST totp-uri without the option: %d, want 404", res.StatusCode)
		}
	})
}

// TestTwoFactorParity_TOTPURIOverHTTP: the route answers better-auth's field
// name, with the password in the POST body.
func TestTwoFactorParity_TOTPURIOverHTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.ReadableTOTPURI()))
		web := newApp(t, a)
		if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": "bob@example.com", "password": secret, "name": "Bob"}); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d %s", res.StatusCode, readAll(t, res))
		}
		res := web.post(t, "/auth/twofactor/enroll", map[string]string{"issuer": "Beta"})
		var enr twofactor.EnrollResult
		if err := json.Unmarshal([]byte(readAll(t, res)), &enr); err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("enroll: %d %v", res.StatusCode, err)
		}
		if res := web.post(t, "/auth/twofactor/totp-uri", map[string]string{"password": "nope"}); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d %s", res.StatusCode, readAll(t, res))
		}
		res = web.post(t, "/auth/twofactor/totp-uri", map[string]string{"password": secret})
		var body map[string]string
		if err := json.Unmarshal([]byte(readAll(t, res)), &body); err != nil || res.StatusCode != http.StatusOK || body["totpURI"] != enr.URL {
			t.Fatalf("totp-uri: %d %v %v, want %s", res.StatusCode, body, err, enr.URL)
		}
	})
}

// TestTwoFactorParity_DisableSessionAndCheck: verify with disableSession
// spends the code and leaves the session pending; check is the signed-in
// step-up with the same lockout; trust and disableSession together are
// refused.
func TestTwoFactorParity_DisableSessionAndCheck(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(0))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		pctx := request(a, pending)
		code := totpAt(t, f.secret, e.clock.Now())
		if err := tf.VerifyWith(pctx, twofactor.CodeRequest{Code: code, DisableSession: true, TrustDevice: true}); !errors.Is(err, twofactor.ErrTrustNeedsSession) {
			t.Fatalf("trust without a session: %v, want ErrTrustNeedsSession", err)
		}
		if err := tf.VerifyWith(pctx, twofactor.CodeRequest{Code: code, DisableSession: true}); err != nil {
			t.Fatal(err)
		}
		if effs := auth.RequestEffects(pctx); slices.ContainsFunc(effs, func(eff auth.Effect) bool { return eff.Kind == auth.EffectIssueSession }) {
			t.Fatal("disableSession must issue no session")
		}
		// Still pending: a signed-in operation does not see it, and the code
		// is spent.
		if err := tf.CheckCode(request(a, pending), code); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("check on the pending session: %v, want ErrSignedOut", err)
		}
		if err := tf.Verify(request(a, pending), code); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("spent code: %v, want ErrCodeInvalid", err)
		}
		e.clock.Advance(twofactor.Step)
		full := factorsFull(t, a, pw, tf, totpAt(t, f.secret, e.clock.Now()))

		// The step-up check on the full session: a recovery code works once,
		// a current code works, and wrong codes lock like verify's.
		fctx := request(a, full)
		must[auth.Done](t)(auth.Done{OK: true}, tf.CheckCode(fctx, f.codes[0]))
		if err := tf.CheckCode(fctx, f.codes[0]); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("used recovery code: %v", err)
		}
		e.clock.Advance(twofactor.Step)
		must[auth.Done](t)(auth.Done{OK: true}, tf.CheckCode(fctx, totpAt(t, f.secret, e.clock.Now())))
		if effs := auth.RequestEffects(fctx); slices.ContainsFunc(effs, func(eff auth.Effect) bool { return eff.Kind == auth.EffectIssueSession }) {
			t.Fatal("check must issue no session")
		}
		e.clock.Advance(twofactor.Step)
		for range twofactor.MaxFailures - 1 {
			if err := tf.CheckCode(fctx, "000000x"); !errors.Is(err, twofactor.ErrCodeInvalid) {
				t.Fatalf("wrong code: %v", err)
			}
		}
		if err := tf.CheckCode(fctx, factorsWrongCode(t, e, f.secret)); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("last wrong code: %v", err)
		}
		if err := tf.CheckCode(fctx, totpAt(t, f.secret, e.clock.Now())); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("after %d failures: %v, want ErrLocked", twofactor.MaxFailures, err)
		}
		if err := tf.Verify(request(a, factorsPending(t, a, pw)), totpAt(t, f.secret, e.clock.Now())); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("the check's lock is the account's: %v", err)
		}
	})
}

// TestTwoFactorParity_ViewRecoveryCodes: under StoreEncrypted the unused
// codes are shown again; a used one drops out; a new set replaces them;
// codes made under hashed storage cannot be shown; viewing needs a fresh
// sign-in and, with RequirePassword, the password.
func TestTwoFactorParity_ViewRecoveryCodes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted), twofactor.RequirePassword())
		a := e.newAuth(t, []auth.Option{auth.WithSecret(parityAppSecret)}, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if _, err := tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{Password: secret}); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("not enrolled: %v", err)
		}
		enr := must[twofactor.EnrollResult](t)(tf.EnrollWith(ctx, twofactor.EnrollRequest{Password: secret}))
		if _, err := tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{Password: secret}); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("unconfirmed: %v", err)
		}
		codes := must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		if _, err := tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("no password: %v", err)
		}
		got := must[twofactor.RecoveryCodes](t)(tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{Password: secret}))
		if !sameCodes(got.Codes, codes.Codes) {
			t.Fatalf("view = %v, want %v", got.Codes, codes.Codes)
		}
		// Stored sealed, never as typed.
		var sealed string
		q := "SELECT " + twofactor.ColRecoverySealed + " FROM " + tbl(twofactor.TableNameRecovery) + " WHERE " + twofactor.ColRecoveryUser + " = " + e.d.Placeholder(1) + " AND " + twofactor.ColRecoverySealed + " <> ''"
		if err := e.db.QueryRow(q, up.User.ID).Scan(&sealed); err != nil || slices.ContainsFunc(codes.Codes, func(c string) bool { return strings.Contains(sealed, c) }) {
			t.Fatalf("sealed = %q, %v", sealed, err)
		}
		// A used code drops out of the list and its sealed copy is cleared.
		e.clock.Advance(twofactor.Step)
		must[auth.Done](t)(auth.Done{OK: true}, tf.Verify(request(a, factorsPending(t, a, pw)), codes.Codes[0]))
		got = must[twofactor.RecoveryCodes](t)(tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{Password: secret}))
		if !sameCodes(got.Codes, codes.Codes[1:]) {
			t.Fatalf("after use = %v, want %v", got.Codes, codes.Codes[1:])
		}
		var empty int
		cq := "SELECT COUNT(*) FROM " + tbl(twofactor.TableNameRecovery) + " WHERE " + twofactor.ColRecoveryUser + " = " + e.d.Placeholder(1) + " AND " + twofactor.ColRecoveryUsed + " IS NOT NULL AND " + twofactor.ColRecoverySealed + " = ''"
		if err := e.db.QueryRow(cq, up.User.ID).Scan(&empty); err != nil || empty != 1 {
			t.Fatalf("used codes with the sealed copy cleared = %d, %v; want 1", empty, err)
		}
		// A new set replaces the old one in the view.
		fresh := must[twofactor.RecoveryCodes](t)(tf.RegenerateRecoveryCodesWith(ctx, twofactor.CodeRequest{Code: codes.Codes[1], Password: secret}))
		got = must[twofactor.RecoveryCodes](t)(tf.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{Password: secret}))
		if !sameCodes(got.Codes, fresh.Codes) {
			t.Fatalf("after regenerate = %v, want %v", got.Codes, fresh.Codes)
		}
		e.clock.Advance(a.Config().FreshWindow + 1)
		if _, err := tf.ViewRecoveryCodes(request(a, up.Token), twofactor.PasswordRequest{Password: secret}); !errors.Is(err, auth.ErrFreshSessionRequired) {
			t.Fatalf("stale session: %v", err)
		}

		// Codes made under hashed storage: the view says so instead of
		// showing nothing.
		hashed := factorsTwoFactor()
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hashed)
		_, bob := factorsSession(t, b, "Bob")
		benr := must[twofactor.EnrollResult](t)(hashed.Enroll(request(b, bob)))
		must[twofactor.RecoveryCodes](t)(hashed.Confirm(request(b, bob), totpAt(t, benr.Secret, e.clock.Now())))
		enc := factorsTwoFactor(twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted))
		c := e.newAuth(t, []auth.Option{auth.WithSecret(parityAppSecret)}, e.emailPlugin(), e.passwordPlugin(), enc)
		if _, err := enc.ViewRecoveryCodes(request(c, bob), twofactor.PasswordRequest{}); !errors.Is(err, twofactor.ErrRecoveryCodesHidden) {
			t.Fatalf("hashed codes: %v, want ErrRecoveryCodesHidden", err)
		}
	})
}

func sameCodes(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// TestTwoFactorParity_RequirePassword: enroll, disable and recovery-codes
// ask for the password of a user who has one; a passwordless user passes on
// the fresh session; the default asks nothing.
func TestTwoFactorParity_RequirePassword(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.RequirePassword())
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if _, err := tf.Enroll(ctx); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("enroll without the password: %v", err)
		}
		enr := must[twofactor.EnrollResult](t)(tf.EnrollWith(ctx, twofactor.EnrollRequest{Password: secret}))
		codes := must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		if _, err := tf.RegenerateRecoveryCodes(ctx, codes.Codes[0]); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("regenerate without the password: %v", err)
		}
		// The password is checked first, so the refused call spent no code.
		if err := tf.Disable(ctx, codes.Codes[0]); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("disable without the password: %v", err)
		}
		must[auth.Done](t)(auth.Done{OK: true}, tf.DisableWith(ctx, twofactor.CodeRequest{Code: codes.Codes[0], Password: secret}))

		_, bare := factorsSession(t, a, "Bo")
		must[twofactor.EnrollResult](t)(tf.Enroll(request(a, bare)))
	})
}

// The fault sweeps: every database call of each new path surfaces its
// failure.

func TestTwoFactorParity_SkipEnrollFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.SkipVerificationOnEnable(), twofactor.DeliveredCodes(), twofactor.RequirePassword())
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e.env, a, pw, em)
		return func(context.Context) error {
			_, err := tf.EnrollWith(request(a, up.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered, Password: secret})
			return err
		}
	})
}

func TestTwoFactorParity_TOTPURIFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.ReadableTOTPURI())
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e.env, a, pw, em, tf)
		return func(context.Context) error {
			_, err := tf.TOTPURI(request(a, f.up.Token), twofactor.PasswordRequest{Password: secret})
			return err
		}
	})
}

func TestTwoFactorParity_CheckFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e.env, a, pw, em, tf)
		return func(context.Context) error { return tf.CheckCode(request(a, f.up.Token), f.codes[0]) }
	})
}

func TestTwoFactorParity_VerifyNoSessionFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e.env, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		return func(context.Context) error {
			return tf.VerifyWith(request(a, pending), twofactor.CodeRequest{Code: totpAt(t, f.secret, e.clock.Now()), DisableSession: true})
		}
	})
}

func TestTwoFactorParity_ViewFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted), twofactor.RequirePassword())
		a := e.newAuth(t, []auth.Option{auth.WithSecret(parityAppSecret)}, em, pw, tf)
		up := signUpVerified(t, e.env, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.EnrollWith(ctx, twofactor.EnrollRequest{Password: secret}))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		return func(context.Context) error {
			_, err := tf.ViewRecoveryCodes(request(a, up.Token), twofactor.PasswordRequest{Password: secret})
			return err
		}
	})
}

// TestTwoFactorParity_ReadBackWithAnotherKey: totp-uri and
// view-recovery-codes report a sealed value that does not open (the key or
// the secret changed) as an error, never as an empty answer.
func TestTwoFactorParity_ReadBackWithAnotherKey(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.ReadableTOTPURI(), twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted))
		a := e.newAuth(t, []auth.Option{auth.WithSecret(parityAppSecret)}, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		other := twofactor.New(twofactor.WithEncryptionKey([]byte(strings.Repeat("o", auth.SealKeySize))), twofactor.ReadableTOTPURI(), twofactor.RecoveryCodeStorage(twofactor.StoreEncrypted))
		b := e.newAuth(t, []auth.Option{auth.WithSecret([]byte(strings.Repeat("b", auth.MinSecretSize)))}, e.emailPlugin(), e.passwordPlugin(), other)
		ctx := request(b, f.up.Token)
		if _, err := other.TOTPURI(ctx, twofactor.PasswordRequest{Password: secret}); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("totp-uri with another key: %v, want ErrSealedCorrupt", err)
		}
		if _, err := other.ViewRecoveryCodes(ctx, twofactor.PasswordRequest{Password: secret}); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("view with another secret: %v, want ErrSealedCorrupt", err)
		}
	})
}
