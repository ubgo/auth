package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// TestFactors_TwoFactorStatus: status is "off" before enrol and before
// confirm, names the method once confirmed, answers a pending sign-in (the
// page learns which form to show without probing send) and describes the
// configuration so a settings page knows what it may offer.
func TestFactors_TwoFactorStatus(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes(), twofactor.TrustDevices(0))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		// The methods this configuration offers: no security_key, which
		// exists only with WithSecurityKeys.
		want := twofactor.Status{Methods: []twofactor.Method{twofactor.MethodTOTP, twofactor.MethodDelivered}, TrustDevices: true}
		if got := must[twofactor.Status](t)(tf.Status(ctx)); !statusEqual(got, want) {
			t.Fatalf("before enrol = %+v, want %+v", got, want)
		}
		must[twofactor.EnrollResult](t)(tf.EnrollWith(ctx, twofactor.EnrollRequest{Method: twofactor.MethodDelivered}))
		if got := must[twofactor.Status](t)(tf.Status(ctx)); !statusEqual(got, want) {
			t.Fatalf("enrolled, not confirmed = %+v, want off", got)
		}
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, factorsMailedCode(t, e, a, alice)))
		want.Enabled, want.Method = true, twofactor.MethodDelivered
		if got := must[twofactor.Status](t)(tf.Status(ctx)); !statusEqual(got, want) {
			t.Fatalf("confirmed = %+v, want %+v", got, want)
		}
		pending := factorsPending(t, a, pw)
		if got := must[twofactor.Status](t)(tf.Status(request(a, pending))); !statusEqual(got, want) {
			t.Fatalf("on the pending session = %+v, want %+v", got, want)
		}
		// Over HTTP the pending cookie reads it too, and a plain configuration
		// offers TOTP only, with no device trust.
		plain := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor())
		web := newApp(t, plain)
		if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": "bob@example.com", "password": secret, "name": "Bob"}); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d %s", res.StatusCode, readAll(t, res))
		}
		var st twofactor.Status
		res := web.get(t, "/auth/twofactor/status")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET status: %d %s", res.StatusCode, readAll(t, res))
		}
		if err := json.NewDecoder(res.Body).Decode(&st); err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if !statusEqual(st, twofactor.Status{Methods: []twofactor.Method{twofactor.MethodTOTP}}) {
			t.Fatalf("plain status = %+v", st)
		}
		web.post(t, "/auth/sign-out", nil)
		if res := web.get(t, "/auth/twofactor/status"); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status signed out: %d, want 401", res.StatusCode)
		}
	})
}

func statusEqual(a, b twofactor.Status) bool {
	if a.Enabled != b.Enabled || a.Method != b.Method || a.TrustDevices != b.TrustDevices || len(a.Methods) != len(b.Methods) {
		return false
	}
	for i := range a.Methods {
		if a.Methods[i] != b.Methods[i] {
			return false
		}
	}
	return true
}

// TestFactors_TwoFactorStatusFaults: a failed read is an error, never "off".
func TestFactors_TwoFactorStatusFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e.env, a, pw, em)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(request(a, up.Token)))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(request(a, up.Token), totpAt(t, enr.Secret, e.clock.Now())))
		return func(context.Context) error {
			_, err := tf.Status(request(a, up.Token))
			return err
		}
	})
}

// TestIdent_ImageOnCodeSignUp: the picture given with a sign-in code is the
// new account's picture, and is ignored for an account that exists.
func TestIdent_ImageOnCodeSignUp(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.SignUpWithCode())
		a := e.newAuth(t, nil, em)
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		in, err := em.SignInCodeWith(anon(a), email.CodeRequest{Email: alice, Code: lastMailCode(t, e, a, alice), Name: "Alice", Image: "https://img.example/alice.png"})
		if err != nil || !in.Created || in.User.Name != "Alice" || in.User.Image != "https://img.example/alice.png" {
			t.Fatalf("code sign-up with a picture = %+v %v", in, err)
		}
		if err := em.SendCode(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		in, err = em.SignInCodeWith(anon(a), email.CodeRequest{Email: alice, Code: lastMailCode(t, e, a, alice), Image: "https://img.example/mallory.png"})
		if err != nil || in.Created || in.User.Image != "https://img.example/alice.png" {
			t.Fatalf("code sign-in with a picture for an existing user = %+v %v", in, err)
		}
	})
}

// importedUser is a user with a verified address and no password, as an
// import creates one before giving it a credential.
func importedUser(t *testing.T, a *auth.Auth, address string) auth.User {
	t.Helper()
	ctx := context.Background()
	u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Imported"}))
	must[auth.Identity](t)(a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: address, Verified: true, Primary: true}))
	return u
}

// TestFactors_PasswordImportHash: an imported bcrypt hash signs the user in
// with the old password and is re-hashed; the refusals are an unrecognized
// format, a user with a password already, and an unknown user, each before
// any row is written.
func TestFactors_PasswordImportHash(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.AcceptLegacyHashes(password.Bcrypt()))
		a := e.newAuth(t, nil, em, pw)
		u := importedUser(t, a, alice)
		ctx := context.Background()
		if err := pw.ImportHash(ctx, u.ID, "pbkdf2_sha256$1$salt$key"); !errors.Is(err, password.ErrHashUnrecognized) {
			t.Fatalf("a format no verifier knows: %v, want ErrHashUnrecognized", err)
		}
		if err := pw.ImportHash(ctx, u.ID, ""); !errors.Is(err, password.ErrHashUnrecognized) {
			t.Fatalf("empty hash: %v", err)
		}
		if err := pw.ImportHash(ctx, "usr_nobody", bcryptOfImported); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		if has := must[bool](t)(pw.HasPassword(ctx, u.ID)); has {
			t.Fatal("a refused import wrote a row")
		}
		if err := pw.ImportHash(ctx, u.ID, bcryptOfImported); err != nil {
			t.Fatal(err)
		}
		if err := pw.ImportHash(ctx, u.ID, bcryptOfImported); !errors.Is(err, password.ErrHasPassword) {
			t.Fatalf("import over a password: %v, want ErrHasPassword", err)
		}
		if h := factorsStoredHash(t, e, u.ID); h != bcryptOfImported {
			t.Fatalf("stored = %s, want the hash as given", h)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password against the import: %v", err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: imported}); err != nil {
			t.Fatalf("sign-in with the imported password: %v", err)
		}
		if h := factorsStoredHash(t, e, u.ID); !strings.HasPrefix(h, "$argon2id$") {
			t.Fatalf("hash after sign-in = %s, want argon2id", h)
		}
		// The Hasher's own format imports too (a dump from another instance).
		v := importedUser(t, a, "vera@example.com")
		own := factorsStoredHash(t, e, u.ID)
		if err := pw.ImportHash(ctx, v.ID, own); err != nil {
			t.Fatal(err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "vera@example.com", Password: imported}); err != nil {
			t.Fatalf("sign-in with an imported argon2id hash: %v", err)
		}
	})
}

func TestFactors_PasswordImportHashFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		pw := e.passwordPlugin(password.AcceptLegacyHashes(password.Bcrypt()))
		a := e.newAuth(t, nil, e.emailPlugin(), pw)
		u := importedUser(t, a, alice)
		return func(ctx context.Context) error { return pw.ImportHash(ctx, u.ID, bcryptOfImported) }
	})
}

// importedSecret is a 160-bit TOTP secret as another system stores it.
const importedSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"

// TestFactors_TwoFactorImportTOTP: an imported secret makes the next sign-in
// pending and the user's existing app code passes it; status says totp; no
// recovery codes exist until the user regenerates. Refusals: a bad secret, a
// user already enrolled, an unknown user, a plugin without TOTP.
func TestFactors_TwoFactorImportTOTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := context.Background()
		for _, bad := range []string{"", "not base32!", "JBSWY3DP", "JBSWY3DPEHPK3PX"} {
			if err := tf.ImportTOTP(ctx, up.User.ID, bad); !errors.Is(err, twofactor.ErrSecretInvalid) {
				t.Fatalf("secret %q: %v, want ErrSecretInvalid", bad, err)
			}
		}
		if err := tf.ImportTOTP(ctx, "usr_nobody", importedSecret); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		if st := must[twofactor.Status](t)(tf.Status(request(a, up.Token))); st.Enabled {
			t.Fatal("a refused import enrolled the user")
		}
		// Lower case, grouped and padded forms of the same secret all import.
		if err := tf.ImportTOTP(ctx, up.User.ID, "jbsw y3dp-ehpk 3pxp jbsw y3dp ehpk 3pxp=="); err != nil {
			t.Fatal(err)
		}
		if err := tf.ImportTOTP(ctx, up.User.ID, importedSecret); !errors.Is(err, twofactor.ErrAlreadyEnabled) {
			t.Fatalf("import over a factor: %v, want ErrAlreadyEnabled", err)
		}
		st := must[twofactor.Status](t)(tf.Status(request(a, up.Token)))
		if !st.Enabled || st.Method != twofactor.MethodTOTP {
			t.Fatalf("status after import = %+v", st)
		}
		pending := factorsPending(t, a, pw)
		if err := tf.Verify(request(a, pending), factorsWrongCode(t, e, importedSecret)); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("wrong code: %v", err)
		}
		verifyCtx := request(a, pending)
		if err := tf.Verify(verifyCtx, totpAt(t, importedSecret, e.clock.Now())); err != nil {
			t.Fatalf("the existing app's code: %v", err)
		}
		// Verify promotes the pending session to a full one under a new token.
		var full auth.Token
		for _, ef := range auth.RequestEffects(verifyCtx) {
			if ef.Kind == auth.EffectIssueSession {
				full = ef.Token
			}
		}
		if full == "" || full == pending {
			t.Fatal("verify must issue a new token")
		}
		// No recovery codes were made; the user regenerates a set with the
		// next app code (the one that passed is spent).
		if err := tf.Verify(request(a, factorsPending(t, a, pw)), "JRRP-QJEK-IWB7-PPLL"); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("a recovery code that cannot exist: %v", err)
		}
		e.clock.Advance(twofactor.Step)
		codes := must[twofactor.RecoveryCodes](t)(tf.RegenerateRecoveryCodes(request(a, full), totpAt(t, importedSecret, e.clock.Now())))
		if len(codes.Codes) != twofactor.DefaultRecoveryCodes {
			t.Fatalf("regenerate after import = %v", codes.Codes)
		}
		// Without TOTP there is nothing to import into.
		codesOnly := factorsTwoFactor(twofactor.DeliveredCodes(), twofactor.WithoutTOTP())
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), codesOnly)
		if err := codesOnly.ImportTOTP(ctx, importedUser(t, b, "vera@example.com").ID, importedSecret); !errors.Is(err, twofactor.ErrMethodInvalid) {
			t.Fatalf("import WithoutTOTP: %v, want ErrMethodInvalid", err)
		}
	})
}

func TestFactors_TwoFactorImportTOTPFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e.env, a, pw, em)
		return func(ctx context.Context) error { return tf.ImportTOTP(ctx, up.User.ID, importedSecret) }
	})
}

// TestAdmin_BanFor: a Go-only ban ends the user's sessions and refuses the
// next sign-in; a zero until is permanent and a set until lifts; an admin and
// an unknown user are refused; the audit plugin records it with no actor.
func TestAdmin_BanFor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := newAuditWorld(t, e)
		ctx := context.Background()
		if err := w.ad.BanFor(ctx, w.boss.User.ID, "no", time.Time{}); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("banning an admin: %v", err)
		}
		if err := w.ad.BanFor(ctx, "usr_nobody", "no", time.Time{}); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
		until := e.clock.Now().Add(time.Hour)
		if err := w.ad.BanFor(ctx, w.bob.User.ID, "imported ban", until); err != nil {
			t.Fatal(err)
		}
		if _, err := w.a.Session(request(w.a, w.bob.Token)); err == nil {
			t.Fatal("the ban must end the user's sessions")
		}
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); !errors.Is(err, admin.ErrBanned) {
			t.Fatalf("sign-in while banned: %v", err)
		}
		if d := must[admin.UserDetail](t)(w.ad.User(w.bossCtx(), w.bob.User.ID)); d.BanReason != "imported ban" {
			t.Fatalf("ban reason = %q", d.BanReason)
		}
		pg := must[audit.Page](t)(w.au.Events(ctx, audit.Query{Op: admin.EndpointBan, UserID: w.bob.User.ID}))
		if pg.Total != 1 || pg.Events[0].ActorID != "" || pg.Events[0].SubjectID != w.bob.User.ID || !pg.Events[0].OK || pg.Events[0].Transport != auth.TransportGo {
			t.Fatalf("audit = %+v", pg.Events)
		}
		e.clock.Advance(time.Hour + time.Second)
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); err != nil {
			t.Fatalf("after until: %v", err)
		}
		if err := w.ad.BanFor(ctx, w.bob.User.ID, "", time.Time{}); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(1000 * time.Hour)
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); !errors.Is(err, admin.ErrBanned) {
			t.Fatalf("a permanent ban lifted: %v", err)
		}
	})
}

// TestAdmin_BanForFaults sweeps the ban without an audit plugin, which is the
// other branch: nothing to record, the ban alone.
func TestAdmin_BanForFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		w := newAdminWorld(t, e.env, nil)
		return func(ctx context.Context) error { return w.ad.BanFor(ctx, w.bob.User.ID, "x", time.Time{}) }
	})
}
