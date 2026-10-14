package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

// Round 2 of the better-auth comparison, factors area: foreign password
// hashes, trusted devices, delivered second-factor codes, passkey-first
// registration.

// factorsOverwriteHash puts a hash the plugin did not make into
// auth_password, standing in for a row imported from another stack. Tests may
// write what plugins may not.
func factorsOverwriteHash(t *testing.T, e *env, userID, hash string) {
	t.Helper()
	q := "UPDATE " + tbl(password.TableNamePassword) + " SET " + password.ColHash + " = " + e.d.Placeholder(1) + " WHERE " + password.ColUserID + " = " + e.d.Placeholder(2)
	if _, err := e.db.Exec(q, hash, userID); err != nil {
		t.Fatal(err)
	}
}

// Hashes of the suite's passwords as other stacks store them, generated once
// with golang.org/x/crypto (bcrypt cost 4; Django's PBKDF2-SHA256 with 1000
// iterations and the salt "salt"). Fixed strings rather than computed here,
// so this module needs no direct dependency on x/crypto, and so the test
// proves the formats as they arrive from an import, not as this code writes
// them.
const (
	bcryptOfSecret   = "$2a$04$orXCA9fHdXUOIRkhe8MoXOZd5Ne4R7HQtp3acBbs3HW2CkpHcSs5O"
	bcryptOfImported = "$2a$04$xN3/uPFBYU1N.1Fl2a1xb.7kmRMS/iDm2BsmB.roxIok1byFBCDoe"
	djangoOfSecret   = "pbkdf2_sha256$1000$salt$hHq2CwjSpsUCltVF/ZDe25M5jA5hBHN9+inXRaOGbjU="
	imported         = "imported passphrase"
)

// TestFactors_PasswordLegacyHashSignsInAndIsRehashed: an imported bcrypt
// hash signs the user in with AcceptLegacyHashes(Bcrypt()), is replaced by an
// argon2id hash in the same sign-in, the wrong password is still refused, and
// a password change verifies the imported hash as the current password.
func TestFactors_PasswordLegacyHashSignsInAndIsRehashed(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.AcceptLegacyHashes(password.Bcrypt(), password.Scrypt(password.BetterAuthScrypt)))
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		factorsOverwriteHash(t, e, up.User.ID, bcryptOfImported)

		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("old password against the imported hash: %v, want ErrInvalidCredentials", err)
		}
		if h := factorsStoredHash(t, e, up.User.ID); !strings.HasPrefix(h, "$2a$") {
			t.Fatalf("a refused sign-in replaced the hash: %s", h)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: imported}); err != nil {
			t.Fatalf("sign-in with the imported hash: %v", err)
		}
		if h := factorsStoredHash(t, e, up.User.ID); !strings.HasPrefix(h, "$argon2id$") {
			t.Fatalf("hash after sign-in = %s, want argon2id", h)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: imported}); err != nil {
			t.Fatalf("sign-in after the re-hash: %v", err)
		}

		// Change with a legacy current password: the imported hash is the
		// one checked, and the new password is stored with argon2id.
		factorsOverwriteHash(t, e, up.User.ID, bcryptOfImported)
		res := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: imported}))
		factorsOverwriteHash(t, e, up.User.ID, bcryptOfImported)
		if err := pw.Change(request(a, res.Token), password.ChangeRequest{Current: imported, New: "a brand new passphrase"}); err != nil {
			t.Fatalf("change with a legacy current password: %v", err)
		}
		if h := factorsStoredHash(t, e, up.User.ID); !strings.HasPrefix(h, "$argon2id$") {
			t.Fatalf("hash after change = %s, want argon2id", h)
		}
	})
}

// TestFactors_PasswordUnrecognizedHashIsAServerError: a stored string no
// configured verifier recognizes is reported as a failure, not as wrong
// credentials, and not as a match. Without AcceptLegacyHashes a bcrypt row is
// exactly that.
func TestFactors_PasswordUnrecognizedHashIsAServerError(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		factorsOverwriteHash(t, e, up.User.ID, bcryptOfSecret)
		_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
		if err == nil || errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("sign-in over an unrecognized hash: %v, want a server error", err)
		}
	})
}

// countingHasher wraps Argon2id and records every hash it makes, so a test
// can see that WithHasher is the algorithm sign-up and re-hash use.
type countingHasher struct {
	password.Argon2id
	hashes int
}

func (c *countingHasher) Hash(pw password.Secret) (string, error) {
	c.hashes++
	return c.Argon2id.Hash(pw)
}

// TestFactors_PasswordWithHasher: a custom Hasher makes the dummy at start-up,
// the sign-up hash, and the re-hash after a legacy match.
func TestFactors_PasswordWithHasher(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ch := &countingHasher{Argon2id: password.Argon2id{Params: fastArgon2}}
		em := e.emailPlugin()
		pw := password.New(password.WithHasher(ch), password.AcceptLegacyHashes(password.DjangoPBKDF2()))
		a := e.newAuth(t, nil, em, pw)
		if ch.hashes != 1 {
			t.Fatalf("hashes after auth.New = %d, want 1 (the dummy)", ch.hashes)
		}
		up := signUpVerified(t, e, a, pw, em)
		if ch.hashes != 2 {
			t.Fatalf("hashes after sign-up = %d, want 2", ch.hashes)
		}
		factorsOverwriteHash(t, e, up.User.ID, djangoOfSecret)
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("sign-in over a Django hash: %v", err)
		}
		if ch.hashes != 3 {
			t.Fatalf("hashes after the legacy sign-in = %d, want 3 (the re-hash)", ch.hashes)
		}
	})
}

// TestFactors_PasswordLegacyFaults: the sign-in that verifies a legacy hash
// and re-hashes it surfaces every database failure.
func TestFactors_PasswordLegacyFaults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.AcceptLegacyHashes(password.Bcrypt()))
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e.env, a, pw, em)
		factorsOverwriteHash(t, e.env, up.User.ID, bcryptOfSecret)
		return func(context.Context) error {
			_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
			return err
		}
	})
}

// ---------------------------------------------------------------- twofactor: delivered codes

// factorsMailedCode returns the one-time code in the newest mail to addr.
func factorsMailedCode(t *testing.T, e *env, a *auth.Auth, addr string) string {
	t.Helper()
	list := e.mail.To(a, addr)
	if len(list) == 0 {
		t.Fatal("no mail")
	}
	m := regexp.MustCompile(`\b[0-9]{` + strconv.Itoa(auth.DefaultCodeLength) + `}\b`).FindString(list[len(list)-1].Text)
	if m == "" {
		t.Fatalf("no code in %q", list[len(list)-1].Text)
	}
	return m
}

// factorsWrongDigits is a code of the core's length that is not code.
func factorsWrongDigits(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

// TestFactors_TwoFactorDeliveredCodes: a user enrols the mailed-code method,
// confirms with the mailed code, and at sign-in asks for a code and verifies
// it. A code works once, a wrong code counts towards the lockout, the lock
// stops send too, and a recovery code still works.
func TestFactors_TwoFactorDeliveredCodes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes())
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		enr := must[twofactor.EnrollResult](t)(tf.EnrollWith(ctx, twofactor.EnrollRequest{Method: twofactor.MethodDelivered}))
		if enr.Method != twofactor.MethodDelivered || enr.Secret != "" || enr.URL != "" {
			t.Fatalf("enroll = %+v, want the code method and no secret", enr)
		}
		list := e.mail.To(a, alice)
		if last := list[len(list)-1]; last.Subject != "Your sign-in code" || !strings.Contains(last.Text, "expires in 5 minutes") {
			t.Fatalf("mail = %+v", last)
		}
		first := factorsMailedCode(t, e, a, alice)
		if _, err := tf.Confirm(ctx, factorsWrongDigits(first)); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("confirm with a wrong code: %v", err)
		}
		codes := must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, first))
		if len(codes.Codes) != twofactor.DefaultRecoveryCodes {
			t.Fatalf("recovery codes = %v", codes.Codes)
		}
		if _, err := tf.Confirm(ctx, first); !errors.Is(err, twofactor.ErrAlreadyEnabled) {
			t.Fatalf("confirm twice: %v", err)
		}

		// Sign-in is pending; the client asks for a code, then verifies it.
		pending := factorsPending(t, a, pw)
		before := len(e.mail.To(a, alice))
		if err := tf.Verify(request(a, pending), first); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("the enrolment code after confirm: %v, want ErrCodeInvalid (spent)", err)
		}
		if err := tf.Send(request(a, pending)); err != nil {
			t.Fatalf("send: %v", err)
		}
		if n := len(e.mail.To(a, alice)); n != before+1 {
			t.Fatalf("mails after send = %d, want %d", n, before+1)
		}
		code := factorsMailedCode(t, e, a, alice)
		verifyCtx := request(a, pending)
		if err := tf.Verify(verifyCtx, code); err != nil {
			t.Fatalf("verify: %v", err)
		}
		promoted := false
		for _, ef := range auth.RequestEffects(verifyCtx) {
			promoted = promoted || (ef.Kind == auth.EffectIssueSession && ef.Token != pending)
		}
		if !promoted {
			t.Fatal("verify must promote the pending session")
		}
		if err := tf.Verify(request(a, pending), code); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("verify on the spent pending session: %v", err)
		}

		// A recovery code still signs in without any mail.
		second := factorsPending(t, a, pw)
		if err := tf.Verify(request(a, second), codes.Codes[0]); err != nil {
			t.Fatalf("recovery code: %v", err)
		}

		// Wrong codes lock the factor; a locked factor refuses send and the
		// right code alike.
		third := factorsPending(t, a, pw)
		if err := tf.Send(request(a, third)); err != nil {
			t.Fatal(err)
		}
		right := factorsMailedCode(t, e, a, alice)
		for range twofactor.MaxFailures {
			if err := tf.Verify(request(a, third), factorsWrongDigits(right)); !errors.Is(err, twofactor.ErrCodeInvalid) {
				t.Fatalf("wrong code: %v", err)
			}
		}
		if err := tf.Verify(request(a, third), right); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("right code while locked: %v, want ErrLocked", err)
		}
		if err := tf.Send(request(a, third)); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("send while locked: %v, want ErrLocked", err)
		}
	})
}

// TestFactors_TwoFactorDeliveredCodeRefusals: the method exists only with
// DeliveredCodes, TOTP only without WithoutTOTP, a plugin with neither is
// refused at start-up, a user with no verified channel cannot enrol codes,
// and send for an authenticator-app user has nothing to send.
func TestFactors_TwoFactorDeliveredCodeRefusals(t *testing.T) {
	e := newEnv(t, auth.EngineSQLite, nil, sqlb.SQLiteDialect{})
	if _, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.WithoutTOTP()))); !errors.Is(err, twofactor.ErrNoMethod) {
		t.Fatalf("WithoutTOTP alone: %v, want ErrNoMethod", err)
	}
	if _, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes(), twofactor.CodeTTL(0)))); !errors.Is(err, twofactor.ErrBadCodeTTL) {
		t.Fatalf("CodeTTL(0): %v, want ErrBadCodeTTL", err)
	}
	if got := factorsTwoFactor(twofactor.DeliveredCodes(), twofactor.WithoutTOTP()).Methods(); len(got) != 1 || got[0] != twofactor.MethodDelivered {
		t.Fatalf("Methods = %v", got)
	}
	ops := factorsTwoFactor().Operations()
	for _, op := range ops {
		if op.Info().ID == twofactor.EndpointSend {
			t.Fatal("send must not exist without DeliveredCodes")
		}
	}
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if _, err := tf.EnrollWith(ctx, twofactor.EnrollRequest{Method: twofactor.MethodDelivered}); !errors.Is(err, twofactor.ErrMethodInvalid) {
			t.Fatalf("code method without DeliveredCodes: %v", err)
		}
		if _, err := tf.EnrollWith(ctx, twofactor.EnrollRequest{Method: "sms"}); !errors.Is(err, twofactor.ErrMethodInvalid) {
			t.Fatalf("unknown method: %v", err)
		}
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		e.clock.Advance(twofactor.Step)
		pending := factorsPending(t, a, pw)
		// Send is not wired here, so the Go call reports that; with the method
		// on but a TOTP user it is ErrNotCodeMethod (next instance).
		if err := tf.Send(request(a, pending)); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatalf("send without DeliveredCodes: %v, want ErrOperationNotWired", err)
		}

		em2, pw2, tf2 := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes(), twofactor.WithoutTOTP())
		a2 := e.newAuth(t, nil, em2, pw2, tf2)
		pending2 := factorsPending(t, a2, pw2)
		if err := tf2.Send(request(a2, pending2)); !errors.Is(err, twofactor.ErrNotCodeMethod) {
			t.Fatalf("send for a TOTP user: %v, want ErrNotCodeMethod", err)
		}
		if _, err := tf2.EnrollWith(request(a2, must[password.SignInResult](t)(pw2.SignIn(anon(a2), password.SignInRequest{Identifier: alice, Password: secret})).Token), twofactor.EnrollRequest{}); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("enroll on a pending session: %v", err)
		}

		// A user whose only address is unverified has nowhere to receive a
		// code: sign up as bob without verifying.
		bob := must[password.SignInResult](t)(pw2.SignUp(anon(a2), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := tf2.EnrollWith(request(a2, bob.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}); !errors.Is(err, twofactor.ErrNoChannel) {
			t.Fatalf("code method with no verified channel: %v, want ErrNoChannel", err)
		}
		if _, err := tf2.Enroll(request(a2, bob.Token)); !errors.Is(err, twofactor.ErrMethodInvalid) {
			t.Fatalf("TOTP with WithoutTOTP: %v, want ErrMethodInvalid", err)
		}
	})
}

// TestFactors_TwoFactorDeliveredCodeFaults: enrol, send, confirm and verify of
// the code method surface every database failure.
func TestFactors_TwoFactorDeliveredCodeFaults(t *testing.T) {
	setup := func(t *testing.T, e *faultEnv) (*auth.Auth, *password.Plugin, *email.Plugin, *twofactor.Plugin, password.SignInResult) {
		t.Helper()
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes())
		a := e.newAuth(t, nil, em, pw, tf)
		return a, pw, em, tf, signUpVerified(t, e.env, a, pw, em)
	}
	enrolled := func(t *testing.T, e *faultEnv) (*auth.Auth, *password.Plugin, *twofactor.Plugin, password.SignInResult) {
		t.Helper()
		a, pw, _, tf, up := setup(t, e)
		if _, err := tf.EnrollWith(request(a, up.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}); err != nil {
			t.Fatal(err)
		}
		if _, err := tf.Confirm(request(a, up.Token), factorsMailedCode(t, e.env, a, alice)); err != nil {
			t.Fatal(err)
		}
		return a, pw, tf, up
	}
	t.Run("enroll", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _, _, tf, up := setup(t, e)
			return func(context.Context) error {
				_, err := tf.EnrollWith(request(a, up.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered})
				return err
			}
		})
	})
	t.Run("confirm", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _, _, tf, up := setup(t, e)
			if _, err := tf.EnrollWith(request(a, up.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}); err != nil {
				t.Fatal(err)
			}
			code := factorsMailedCode(t, e.env, a, alice)
			return func(context.Context) error {
				_, err := tf.Confirm(request(a, up.Token), code)
				return err
			}
		})
	})
	t.Run("send", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, tf, _ := enrolled(t, e)
			pending := factorsPending(t, a, pw)
			return func(context.Context) error { return tf.Send(request(a, pending)) }
		})
	})
	t.Run("verify", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, tf, _ := enrolled(t, e)
			pending := factorsPending(t, a, pw)
			if err := tf.Send(request(a, pending)); err != nil {
				t.Fatal(err)
			}
			code := factorsMailedCode(t, e.env, a, alice)
			return func(context.Context) error { return tf.Verify(request(a, pending), code) }
		})
	})
}

// ---------------------------------------------------------------- twofactor: trusted devices

// factorsDeviceRequest is request with a trusted-device token on it, as a browser
// that holds the device cookie sends it.
func factorsDeviceRequest(a *auth.Auth, tok, device auth.Token) context.Context {
	req := auth.Request{
		Transport: auth.TransportHTTP,
		Client:    auth.Client{IP: "203.0.113.7", UserAgent: "Firefox on a laptop", Origin: testBaseURL},
		Device:    device,
	}
	if tok != "" {
		req.Credential, req.Token = auth.CredentialCookie, tok
	}
	return a.WithRequest(context.Background(), req)
}

// rememberedDevice returns the device token the verify in ctx asked the
// transport to remember, "" when it asked for none, and whether an effect to
// forget the device was recorded.
func rememberedDevice(ctx context.Context) (tok auth.Token, expires time.Time, forget bool) {
	for _, ef := range auth.RequestEffects(ctx) {
		if ef.Kind != auth.EffectRememberDevice {
			continue
		}
		if ef.Token == "" {
			forget = true
		} else {
			tok, expires = ef.Token, ef.ExpiresAt
		}
	}
	return tok, expires, forget
}

// factorsDeviceRows counts userID's trusted-device rows.
func factorsDeviceRows(t *testing.T, e *env, userID string) int {
	t.Helper()
	var n int
	q := "SELECT COUNT(*) FROM " + tbl(twofactor.TableNameDevice) + " WHERE " + twofactor.ColDeviceUser + " = " + e.d.Placeholder(1)
	if err := e.db.QueryRow(q, userID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestFactors_TwoFactorTrustedDevices: a verify that asks to trust the device
// hands the transport a token; a sign-in carrying it skips the second factor
// for this user only, until the age passes; the device is listed, marked
// current, and revocable; forgetting the current one tells the transport to
// drop its token.
func TestFactors_TwoFactorTrustedDevices(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(0))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)

		pending := factorsPending(t, a, pw)
		verifyCtx := request(a, pending)
		if err := tf.VerifyWith(verifyCtx, twofactor.CodeRequest{Code: totpAt(t, f.secret, e.clock.Now()), TrustDevice: true}); err != nil {
			t.Fatalf("verify with trust: %v", err)
		}
		device, expires, _ := rememberedDevice(verifyCtx)
		if device == "" {
			t.Fatal("verify with TrustDevice must record an EffectRememberDevice with a token")
		}
		if want := e.clock.Now().Add(twofactor.DefaultTrustedDeviceAge); !expires.Equal(want) {
			t.Fatalf("device expires %v, want %v (the default age)", expires, want)
		}
		if n := factorsDeviceRows(t, e, f.up.User.ID); n != 1 {
			t.Fatalf("device rows = %d", n)
		}

		// The next sign-in from that device is a full session: no second step.
		in := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret}))
		if in.SecondFactorRequired {
			t.Fatal("a trusted device must skip the second factor")
		}
		if _, _, _, err := a.ResolveSession(context.Background(), in.Token); err != nil {
			t.Fatalf("the session from a trusted device must be full: %v", err)
		}
		// A made-up token, and a token of another user, skip nothing.
		if in := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", auth.NewToken()), password.SignInRequest{Identifier: alice, Password: secret})); !in.SecondFactorRequired {
			t.Fatal("an unknown device token must not skip the second factor")
		}
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, "bob@example.com")); err != nil {
			t.Fatal(err)
		}
		bobCtx := request(a, bob.Token)
		benr := must[twofactor.EnrollResult](t)(tf.Enroll(bobCtx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(bobCtx, totpAt(t, benr.Secret, e.clock.Now())))
		if in := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: "bob@example.com", Password: secret})); !in.SecondFactorRequired {
			t.Fatal("alice's device token must not skip bob's second factor")
		}

		// The list shows the device, marked current when the request holds its token.
		list := must[[]twofactor.TrustedDevice](t)(tf.Devices(factorsDeviceRequest(a, in.Token, device)))
		// The user agent is the verifying request's ("test"), not the lister's.
		if len(list) != 1 || !list[0].Current || list[0].UserAgent != "test" || list[0].LastUsed == nil || !list[0].ExpiresAt.Equal(expires) {
			t.Fatalf("devices = %+v", list)
		}
		if plain := must[[]twofactor.TrustedDevice](t)(tf.Devices(request(a, in.Token))); len(plain) != 1 || plain[0].Current {
			t.Fatalf("devices without the token = %+v; none is current", plain)
		}

		// Forgetting the current device revokes it and drops the cookie.
		forgetCtx := factorsDeviceRequest(a, in.Token, device)
		if err := tf.ForgetDevice(forgetCtx, twofactor.ForgetDeviceRequest{ID: "tfd_nobody"}); !errors.Is(err, twofactor.ErrDeviceNotFound) {
			t.Fatalf("forget an unknown id: %v", err)
		}
		if err := tf.ForgetDevice(forgetCtx, twofactor.ForgetDeviceRequest{ID: list[0].ID}); err != nil {
			t.Fatalf("forget: %v", err)
		}
		if _, _, forget := rememberedDevice(forgetCtx); !forget {
			t.Fatal("forgetting the current device must tell the transport to drop the token")
		}
		if in := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret})); !in.SecondFactorRequired {
			t.Fatal("a forgotten device must ask for the second factor again")
		}

		// Trust again, then let the age pass: the row no longer counts, and
		// sweep removes it.
		pending = factorsPending(t, a, pw)
		verifyCtx = request(a, pending)
		e.clock.Advance(twofactor.Step)
		if err := tf.VerifyWith(verifyCtx, twofactor.CodeRequest{Code: totpAt(t, f.secret, e.clock.Now()), TrustDevice: true}); err != nil {
			t.Fatal(err)
		}
		device, _, _ = rememberedDevice(verifyCtx)
		e.clock.Advance(twofactor.DefaultTrustedDeviceAge + time.Second)
		if in := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret})); !in.SecondFactorRequired {
			t.Fatal("an expired device must ask for the second factor")
		}
		res := must[auth.SweepResult](t)(a.Sweep(context.Background(), 0))
		if res[twofactor.PluginName] != 1 || factorsDeviceRows(t, e, f.up.User.ID) != 0 {
			t.Fatalf("sweep = %v, rows left = %d", res, factorsDeviceRows(t, e, f.up.User.ID))
		}
	})
}

// TestFactors_TwoFactorTrustedDevicesEnd: trusted devices end with the factor
// (disable), with a password change or reset (CredentialChanged), and with
// "forget all"; and a verify asking for trust is refused when the plugin was
// built without TrustDevices.
func TestFactors_TwoFactorTrustedDevicesEnd(t *testing.T) {
	trust := func(t *testing.T, e *env, a *auth.Auth, pw *password.Plugin, tf *twofactor.Plugin, secretB32 string) auth.Token {
		t.Helper()
		// Each round signs in several times; move past the per-account
		// sign-in window so the rate rule does not fire.
		e.clock.Advance(16 * time.Minute)
		pending := factorsPending(t, a, pw)
		ctx := request(a, pending)
		e.clock.Advance(twofactor.Step)
		if err := tf.VerifyWith(ctx, twofactor.CodeRequest{Code: totpAt(t, secretB32, e.clock.Now()), TrustDevice: true}); err != nil {
			t.Fatal(err)
		}
		device, _, _ := rememberedDevice(ctx)
		return device
	}
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(time.Hour))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		uid := f.up.User.ID

		// Password change clears the devices.
		device := trust(t, e, a, pw, tf, f.secret)
		full := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret}))
		if err := pw.Change(request(a, full.Token), password.ChangeRequest{Current: secret, New: "a brand new passphrase"}); err != nil {
			t.Fatal(err)
		}
		if n := factorsDeviceRows(t, e, uid); n != 0 {
			t.Fatalf("devices after a password change = %d, want 0", n)
		}
		if err := pw.SetPassword(context.Background(), uid, secret); err != nil {
			t.Fatal(err)
		}

		// Password reset clears them too.
		trust(t, e, a, pw, tf, f.secret)
		must[password.ForgotResult](t)(pw.Forgot(anon(a), alice))
		if err := pw.Reset(anon(a), password.ResetRequest{Token: e.mail.LastToken(t, a, alice).Wire(), Password: secret}); err != nil {
			t.Fatal(err)
		}
		if n := factorsDeviceRows(t, e, uid); n != 0 {
			t.Fatalf("devices after a password reset = %d, want 0", n)
		}

		// Forget all, from the current device, drops the token too.
		device = trust(t, e, a, pw, tf, f.secret)
		trust(t, e, a, pw, tf, f.secret)
		full = must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret}))
		allCtx := factorsDeviceRequest(a, full.Token, device)
		if err := tf.ForgetDevice(allCtx, twofactor.ForgetDeviceRequest{All: true}); err != nil {
			t.Fatal(err)
		}
		if _, _, forget := rememberedDevice(allCtx); !forget || factorsDeviceRows(t, e, uid) != 0 {
			t.Fatalf("forget all: drop effect %v, rows %d", forget, factorsDeviceRows(t, e, uid))
		}

		// Disable clears them, and drops the token of the device it ran from.
		device = trust(t, e, a, pw, tf, f.secret)
		full = must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret}))
		disableCtx := factorsDeviceRequest(a, full.Token, device)
		e.clock.Advance(twofactor.Step)
		if err := tf.Disable(disableCtx, totpAt(t, f.secret, e.clock.Now())); err != nil {
			t.Fatal(err)
		}
		if _, _, forget := rememberedDevice(disableCtx); !forget || factorsDeviceRows(t, e, uid) != 0 {
			t.Fatalf("disable: drop effect %v, rows %d", forget, factorsDeviceRows(t, e, uid))
		}

		// Without TrustDevices the request is refused, and the device
		// operations are not wired.
		em2, pw2, tf2 := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a2 := e.newAuth(t, nil, em2, pw2, tf2)
		ctx2 := request(a2, must[password.SignInResult](t)(pw2.SignIn(anon(a2), password.SignInRequest{Identifier: alice, Password: secret})).Token)
		enr := must[twofactor.EnrollResult](t)(tf2.Enroll(ctx2))
		must[twofactor.RecoveryCodes](t)(tf2.Confirm(ctx2, totpAt(t, enr.Secret, e.clock.Now())))
		e.clock.Advance(twofactor.Step)
		pending := factorsPending(t, a2, pw2)
		if err := tf2.VerifyWith(request(a2, pending), twofactor.CodeRequest{Code: totpAt(t, enr.Secret, e.clock.Now()), TrustDevice: true}); !errors.Is(err, twofactor.ErrTrustDisabled) {
			t.Fatalf("trust without TrustDevices: %v, want ErrTrustDisabled", err)
		}
		if err := tf2.Verify(request(a2, pending), totpAt(t, enr.Secret, e.clock.Now())); err != nil {
			t.Fatalf("the refused request must not have spent the code: %v", err)
		}
		if _, err := tf2.Devices(request(a2, pending)); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatalf("devices without TrustDevices: %v", err)
		}
	})
	e := newEnv(t, auth.EngineSQLite, nil, sqlb.SQLiteDialect{})
	if _, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(twofactor.MaxTrustedDeviceAge+time.Hour)))); !errors.Is(err, twofactor.ErrBadTrustAge) {
		t.Fatalf("TrustDevices over the maximum: %v, want ErrBadTrustAge", err)
	}
}

// TestFactors_TwoFactorTrustedDeviceFaults: verify with trust, a sign-in that
// consults the device table, forget and the credential-change fan-out
// surface every database failure.
func TestFactors_TwoFactorTrustedDeviceFaults(t *testing.T) {
	trusted := func(t *testing.T, e *faultEnv) (*auth.Auth, *password.Plugin, *twofactor.Plugin, factorsTOTP, auth.Token) {
		t.Helper()
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(0))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e.env, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		ctx := request(a, pending)
		if err := tf.VerifyWith(ctx, twofactor.CodeRequest{Code: totpAt(t, f.secret, e.clock.Now()), TrustDevice: true}); err != nil {
			t.Fatal(err)
		}
		device, _, _ := rememberedDevice(ctx)
		e.clock.Advance(twofactor.Step)
		return a, pw, tf, f, device
	}
	t.Run("verify with trust", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(0))
			a := e.newAuth(t, nil, em, pw, tf)
			f := factorsEnroll(t, e.env, a, pw, em, tf)
			pending := factorsPending(t, a, pw)
			code := totpAt(t, f.secret, e.clock.Now())
			return func(context.Context) error {
				return tf.VerifyWith(request(a, pending), twofactor.CodeRequest{Code: code, TrustDevice: true})
			}
		})
	})
	t.Run("sign-in from a trusted device", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, _, _, device := trusted(t, e)
			return func(context.Context) error {
				_, err := pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret})
				return err
			}
		})
	})
	t.Run("forget", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, tf, _, device := trusted(t, e)
			full := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret}))
			list := must[[]twofactor.TrustedDevice](t)(tf.Devices(request(a, full.Token)))
			return func(context.Context) error {
				return tf.ForgetDevice(factorsDeviceRequest(a, full.Token, device), twofactor.ForgetDeviceRequest{ID: list[0].ID})
			}
		})
	})
	t.Run("password change clears devices", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, _, _, device := trusted(t, e)
			full := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret}))
			return func(context.Context) error {
				return pw.Change(request(a, full.Token), password.ChangeRequest{Current: secret, New: "a brand new passphrase"})
			}
		})
	})
}

// ---------------------------------------------------------------- passkey: sign-up and extensions

// withExtensionResults puts client extension results into an authenticator
// answer, as a browser does when the options asked for extensions.
func withExtensionResults(t *testing.T, credential json.RawMessage, results map[string]any) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(credential, &m); err != nil {
		t.Fatal(err)
	}
	m["clientExtensionResults"] = results
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// optionsExtensions reads the extensions the begin options carry.
func optionsExtensions(t *testing.T, options json.RawMessage) map[string]any {
	t.Helper()
	var o struct {
		PublicKey struct {
			Extensions map[string]any `json:"extensions"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	return o.PublicKey.Extensions
}

// TestFactors_PasskeySignUp: an account is created from a passkey with no
// session and no password; the authenticator's user handle is the new user's
// id, so a discoverable login finds the account; the identifier follows
// password sign-up's rules (unverified row, owner told of a taken value,
// RequireVerified kinds issue no session); and the ceremony is single use.
func TestFactors_PasskeySignUp(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pk := e.emailPlugin(), passkey.New(passkey.WithSignUp())
		a := e.newAuth(t, nil, em, pk)
		dev := newAuthenticator(t)

		if _, err := pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: "not an address", Name: "Alice"}); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("sign-up with a value no kind accepts: %v, want ErrIdentifierInvalid", err)
		}
		begin := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Alice"}))
		finishCtx := anon(a)
		res, err := pk.SignUpFinish(finishCtx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options), Name: "Laptop"})
		if err != nil {
			t.Fatalf("sign-up finish: %v", err)
		}
		if res.User.Name != "Alice" || res.Passkey.Name != "Laptop" || res.Token == "" || res.VerificationRequired {
			t.Fatalf("sign-up result = %+v", res)
		}
		if _, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
			t.Fatalf("a ceremony used twice: %v", err)
		}
		ids := must[[]auth.Identity](t)(a.Identities(context.Background(), res.User.ID))
		if len(ids) != 1 || ids[0].Value != alice || ids[0].Verified() {
			t.Fatalf("identities = %+v; want one unverified address", ids)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), res.Token); err != nil {
			t.Fatalf("the sign-up session must be full: %v", err)
		}

		// The passkey signs the new user in: the handle is the user id.
		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		in, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, res.User.ID)})
		if err != nil || in.User.ID != res.User.ID {
			t.Fatalf("passkey sign-in after sign-up: %+v %v", in, err)
		}

		// Alice verifies; a stranger signing up with her address gets a
		// separate account and she is told, as with password sign-up.
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		before := len(e.mail.To(a, alice))
		dev2 := newAuthenticator(t)
		begin2 := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Mallory"}))
		res2, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: begin2.Ceremony, Credential: dev2.register(t, begin2.Options)})
		if err != nil || res2.User.ID == res.User.ID {
			t.Fatalf("sign-up over a taken address: %+v %v", res2, err)
		}
		told := false
		for _, m := range e.mail.To(a, alice)[before:] {
			told = told || strings.Contains(m.Subject, "tried to sign up")
		}
		if !told {
			t.Fatal("the owner of the address must be told of the sign-up attempt")
		}

		// Without WithSignUp the operations do not exist.
		em3, pw3, pk3 := e.emailPlugin(), e.passwordPlugin(), passkey.New()
		a3 := e.newAuth(t, nil, em3, pw3, pk3)
		if _, err := pk3.SignUpBegin(anon(a3), passkey.SignUpBeginRequest{Identifier: "carol@example.com"}); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatalf("sign-up without WithSignUp: %v, want ErrOperationNotWired", err)
		}
	})
	if _, err := auth.New(auth.WithBaseURL(testBaseURL), auth.WithPlugins(passkey.New(passkey.WithSignUp()))); !errors.Is(err, passkey.ErrSignUpNeedsKind) {
		t.Fatalf("WithSignUp with no identifier plugin: %v, want ErrSignUpNeedsKind", err)
	}
}

// TestFactors_PasskeySignUpRequireVerified: with an identifier kind that
// requires verification, sign-up creates the account and the passkey but no
// session; after verifying the address the passkey signs in.
func TestFactors_PasskeySignUpRequireVerified(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pk := e.emailPlugin(email.RequireVerified()), passkey.New(passkey.WithSignUp())
		a := e.newAuth(t, nil, em, pk)
		dev := newAuthenticator(t)
		begin := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Alice"}))
		finishCtx := anon(a)
		res := must[passkey.SignUpResult](t)(pk.SignUpFinish(finishCtx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}))
		if !res.VerificationRequired || res.Token != "" || len(auth.RequestEffects(finishCtx)) != 0 {
			t.Fatalf("result = %+v, effects = %v; want verification required and no session", res, auth.RequestEffects(finishCtx))
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if in, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, res.User.ID)}); err != nil || in.User.ID != res.User.ID {
			t.Fatalf("sign-in after verifying: %+v %v", in, err)
		}
	})
}

// TestFactors_PasskeyExtensions: configured registration and authentication
// extensions reach the browser's options, and the browser's results come
// back in the finish results, unread.
func TestFactors_PasskeyExtensions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, nil,
			passkey.RegistrationExtensions(passkey.Extensions{"credProps": true}),
			passkey.AuthenticationExtensions(passkey.Extensions{"largeBlob": map[string]any{"read": true}}))
		ctx := request(a, up.Token)
		dev := newAuthenticator(t)

		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		if ext := optionsExtensions(t, begin.Options); ext["credProps"] != true {
			t.Fatalf("registration options extensions = %v", ext)
		}
		cred := withExtensionResults(t, dev.register(t, begin.Options), map[string]any{"credProps": map[string]any{"rk": true}})
		added := must[passkey.Passkey](t)(pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: cred, Name: "Laptop"}))
		if string(added.Extensions) != `{"credProps":{"rk":true}}` {
			t.Fatalf("Passkey.Extensions = %s", added.Extensions)
		}
		list := must[[]passkey.Passkey](t)(pk.List(ctx))
		if len(list) != 1 || list[0].Extensions != nil {
			t.Fatalf("the list must not carry extension results: %+v", list)
		}

		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if ext := optionsExtensions(t, lb.Options); ext["largeBlob"] == nil {
			t.Fatalf("assertion options extensions = %v", ext)
		}
		assertion := withExtensionResults(t, dev.assert(t, lb.Options, up.User.ID), map[string]any{"largeBlob": map[string]any{"blob": "AQID"}})
		in := must[passkey.SignInResult](t)(pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: assertion}))
		if string(in.Extensions) != `{"largeBlob":{"blob":"AQID"}}` {
			t.Fatalf("SignInResult.Extensions = %s", in.Extensions)
		}

		// Without results the fields are absent, not "{}" or "null".
		lb = must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		plain := must[passkey.SignInResult](t)(pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, up.User.ID)}))
		if plain.Extensions != nil {
			t.Fatalf("Extensions without results = %s", plain.Extensions)
		}
		if b, _ := json.Marshal(plain); strings.Contains(string(b), "extensions") {
			t.Fatalf("empty extensions must be omitted: %s", b)
		}
	})
}

// TestFactors_PasskeySignUpFaults: both halves of the sign-up ceremony
// surface every database failure.
func TestFactors_PasskeySignUpFaults(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			pk := passkey.New(passkey.WithSignUp())
			a := e.newAuth(t, nil, e.emailPlugin(), pk)
			return func(context.Context) error {
				_, err := pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Alice"})
				return err
			}
		})
	})
	t.Run("finish", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			pk := passkey.New(passkey.WithSignUp())
			a := e.newAuth(t, nil, e.emailPlugin(), pk)
			begin := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, Name: "Alice"}))
			cred := newAuthenticator(t).register(t, begin.Options)
			return func(context.Context) error {
				_, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: cred, Name: "Laptop"})
				return err
			}
		})
	})
}

// ---------------------------------------------------------------- password: reset by code, username at sign-up

// TestFactors_PasswordResetByCode: under ResetByCode, forgot mails a code
// instead of a link, reset-code with the identifier, the code and a new
// password sets it, signs out every session and spends the code; an unknown
// identifier, a wrong code and a spent code all answer auth.code_invalid; a
// weak new password does not spend the code; the link route does not exist
// and no base URL is needed.
func TestFactors_PasswordResetByCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.ResetByCode())
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		if err := pw.Reset(anon(a), password.ResetRequest{Token: "x", Password: secret}); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatalf("link reset under ResetByCode: %v, want ErrOperationNotWired", err)
		}
		must[password.ForgotResult](t)(pw.Forgot(anon(a), alice))
		list := e.mail.To(a, alice)
		last := list[len(list)-1]
		if strings.Contains(last.Text, "http") {
			t.Fatalf("forgot under ResetByCode sent a link: %q", last.Text)
		}
		code := factorsMailedCode(t, e, a, alice)

		const fresh = "a brand new passphrase"
		if err := pw.ResetWithCode(anon(a), password.ResetCodeRequest{Identifier: "nobody@example.com", Code: code, Password: fresh}); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("unknown identifier: %v, want ErrCodeInvalid", err)
		}
		if err := pw.ResetWithCode(anon(a), password.ResetCodeRequest{Identifier: alice, Code: factorsWrongDigits(code), Password: fresh}); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("wrong code: %v, want ErrCodeInvalid", err)
		}
		if err := pw.ResetWithCode(anon(a), password.ResetCodeRequest{Identifier: alice, Code: code, Password: "short"}); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("weak password: %v, want ErrTooShort", err)
		}
		resetCtx := anon(a)
		if err := pw.ResetWithCode(resetCtx, password.ResetCodeRequest{Identifier: alice, Code: code, Password: fresh}); err != nil {
			t.Fatalf("reset with code: %v", err)
		}
		cleared := false
		for _, ef := range auth.RequestEffects(resetCtx) {
			cleared = cleared || ef.Kind == auth.EffectClearSession
		}
		if !cleared {
			t.Fatal("reset must clear the session cookie")
		}
		if _, _, _, err := a.ResolveSession(context.Background(), up.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the old session after a reset: %v", err)
		}
		if err := pw.ResetWithCode(anon(a), password.ResetCodeRequest{Identifier: alice, Code: code, Password: fresh}); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("spent code: %v, want ErrCodeInvalid", err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: fresh}); err != nil {
			t.Fatalf("sign-in with the new password: %v", err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("sign-in with the old password: %v", err)
		}
	})
	// No base URL is needed for a code; the link form still needs one.
	// (The phone plugin, because the email plugin needs a base URL for its
	// own links either way.)
	e := newEnv(t, auth.EngineSQLite, nil, sqlb.SQLiteDialect{})
	if _, err := auth.New(auth.WithPlugins(e.phonePlugin(phone.Login(), phone.Recover()), e.passwordPlugin(password.ResetByCode()))); err != nil {
		t.Fatalf("ResetByCode without a base URL: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(e.phonePlugin(phone.Login(), phone.Recover()), e.passwordPlugin())); !errors.Is(err, password.ErrNoResetLinks) {
		t.Fatalf("links without a base URL: %v, want ErrNoResetLinks", err)
	}
	rules := map[auth.RateKey]bool{}
	for _, r := range e.passwordPlugin(password.ResetByCode()).RateLimits() {
		if r.Match == password.EndpointResetCode {
			rules[r.Key] = true
		}
	}
	if !rules[auth.ByIP] || !rules[auth.ByIdentifier] {
		t.Fatalf("reset-code rate rules = %v, want per IP and per identifier", rules)
	}
}

// TestFactors_PasswordResetByCodeSMS: with a phone as the recovery identity,
// the code goes out as a text.
func TestFactors_PasswordResetByCodeSMS(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph, pw := e.phonePlugin(phone.Login(), phone.Recover()), e.passwordPlugin(password.ResetByCode())
		a := e.newAuth(t, nil, ph, pw)
		const number = "+15550100123"
		up := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: number, Password: secret}))
		if err := ph.Verify(request(a, up.Token), number, e.sms.LastCode(t, a, number)); err != nil {
			t.Fatalf("verify the number: %v", err)
		}
		before := e.sms.Count(a, number)
		must[password.ForgotResult](t)(pw.Forgot(anon(a), number))
		if n := e.sms.Count(a, number); n != before+1 {
			t.Fatalf("texts after forgot = %d, want %d", n, before+1)
		}
		if err := pw.ResetWithCode(anon(a), password.ResetCodeRequest{Identifier: number, Code: e.sms.LastCode(t, a, number), Password: "a brand new passphrase"}); err != nil {
			t.Fatalf("reset with the texted code: %v", err)
		}
	})
}

// TestFactors_PasswordSignUpWithUsername: a sign-up body may claim a handle
// in the same transaction; a taken or reserved handle fails the whole
// sign-up and leaves no account; without the username plugin the field is
// refused.
func TestFactors_PasswordSignUpWithUsername(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, un := e.emailPlugin(), e.passwordPlugin(), username.New(username.Login(), username.Reserved("admin"))
		a := e.newAuth(t, nil, em, pw, un)
		res := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: aliceRaw, Password: secret, Username: "Alice_1"}))
		ids := must[[]auth.Identity](t)(a.Identities(context.Background(), res.User.ID))
		handles := 0
		for _, id := range ids {
			if id.Kind == username.KindUsername {
				handles++
			}
		}
		if handles != 1 {
			t.Fatalf("identities after sign-up with a username = %+v; want one handle", ids)
		}
		// The handle signs in.
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "alice_1", Password: secret}); err != nil {
			t.Fatalf("sign-in by handle: %v", err)
		}
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Username: "alice_1"}); !errors.Is(err, auth.ErrIdentityTaken) {
			t.Fatalf("taken handle: %v, want ErrIdentityTaken", err)
		}
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Username: "admin"}); !errors.Is(err, username.ErrReserved) {
			t.Fatalf("reserved handle: %v, want ErrReserved", err)
		}
		// Neither failed sign-up left an account behind.
		if _, err := a.FindIdentity(context.Background(), email.KindEmail, "bob@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("a failed sign-up left an identity: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: aliceRaw, Password: secret, Username: "alice"}); !errors.Is(err, password.ErrNoUsernames) {
			t.Fatalf("username without the plugin: %v, want ErrNoUsernames", err)
		}
	})
}

// TestFactors_PasswordResetByCodeFaults: forgot by code, reset-code and a
// sign-up that claims a handle surface every database failure.
func TestFactors_PasswordResetByCodeFaults(t *testing.T) {
	t.Run("forgot", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin(password.ResetByCode())
			a := e.newAuth(t, nil, em, pw)
			signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error {
				_, err := pw.Forgot(anon(a), alice)
				return err
			}
		})
	})
	t.Run("reset-code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin(password.ResetByCode())
			a := e.newAuth(t, nil, em, pw)
			signUpVerified(t, e.env, a, pw, em)
			must[password.ForgotResult](t)(pw.Forgot(anon(a), alice))
			code := factorsMailedCode(t, e.env, a, alice)
			return func(context.Context) error {
				return pw.ResetWithCode(anon(a), password.ResetCodeRequest{Identifier: alice, Code: code, Password: "a brand new passphrase"})
			}
		})
	})
	t.Run("sign-up with username", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, un := e.emailPlugin(), e.passwordPlugin(), username.New(username.Login())
			a := e.newAuth(t, nil, em, pw, un)
			return func(context.Context) error {
				_, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: aliceRaw, Password: secret, Username: "alice_1"})
				return err
			}
		})
	})
}

// ---------------------------------------------------------------- round-2 coverage of the refusal paths

// flakyHasher is Argon2id that fails on demand, so the hasher error paths of
// sign-up, re-hash, reset and change can be reached.
type flakyHasher struct {
	password.Argon2id
	fail bool
}

var errHSMDown = errors.New("hsm unreachable")

func (f *flakyHasher) Hash(pw password.Secret) (string, error) {
	if f.fail {
		return "", errHSMDown
	}
	return f.Argon2id.Hash(pw)
}

// TestFactors_PasswordHasherFailures: a Hasher that cannot hash fails
// sign-up, the re-hash at sign-in, reset and change with its own error, and
// stores nothing.
func TestFactors_PasswordHasherFailures(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		fh := &flakyHasher{Argon2id: password.Argon2id{Params: fastArgon2}}
		em := e.emailPlugin()
		pw := password.New(password.WithHasher(fh), password.AcceptLegacyHashes(password.Bcrypt()))
		a := e.newAuth(t, nil, em, pw)
		fh.fail = true
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: aliceRaw, Password: secret}); !errors.Is(err, errHSMDown) {
			t.Fatalf("sign-up with a failing hasher: %v", err)
		}
		fh.fail = false
		up := signUpVerified(t, e, a, pw, em)

		factorsOverwriteHash(t, e, up.User.ID, bcryptOfSecret)
		fh.fail = true
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, errHSMDown) {
			t.Fatalf("re-hash with a failing hasher: %v", err)
		}
		if h := factorsStoredHash(t, e, up.User.ID); h != bcryptOfSecret {
			t.Fatalf("a failed re-hash changed the row: %s", h)
		}
		if err := pw.Change(request(a, up.Token), password.ChangeRequest{Current: secret, New: "a brand new passphrase"}); !errors.Is(err, errHSMDown) {
			t.Fatalf("change with a failing hasher: %v", err)
		}
		must[password.ForgotResult](t)(pw.Forgot(anon(a), alice))
		if err := pw.Reset(anon(a), password.ResetRequest{Token: e.mail.LastToken(t, a, alice).Wire(), Password: "a brand new passphrase"}); !errors.Is(err, errHSMDown) {
			t.Fatalf("reset with a failing hasher: %v", err)
		}
	})
}

// TestFactors_PasskeySignUpRefusals: the sign-up ceremony refuses an unknown
// attachment before it starts, an answer that does not parse, an answer to
// another ceremony's challenge, and stored ceremony data that does not decode.
func TestFactors_PasskeySignUpRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pk := e.emailPlugin(), passkey.New(passkey.WithSignUp())
		a := e.newAuth(t, nil, em, pk)
		dev := newAuthenticator(t)
		if _, err := pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, AuthenticatorAttachment: "usb"}); !errors.Is(err, passkey.ErrAttachmentInvalid) {
			t.Fatalf("unknown attachment: %v, want ErrAttachmentInvalid", err)
		}
		begin := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: aliceRaw, AuthenticatorAttachment: passkey.AttachmentPlatform}))
		if _, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: json.RawMessage(`{"not":"a credential"}`)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("unparsable answer: %v, want ErrPasskeyInvalid", err)
		}
		other := must[passkey.BeginResult](t)(pk.SignUpBegin(anon(a), passkey.SignUpBeginRequest{Identifier: "bob@example.com"}))
		if _, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: other.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("answer to another ceremony's challenge: %v, want ErrPasskeyInvalid", err)
		}
		if _, err := a.FindIdentity(context.Background(), email.KindEmail, "bob@example.com", false); !errors.Is(err, auth.ErrIdentityNotFound) {
			t.Fatalf("a refused sign-up created an identity: %v", err)
		}
		tok, err := a.IssueVerification(context.Background(), passkey.PurposeSignUp, "usr_x", time.Minute, "not json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pk.SignUpFinish(anon(a), passkey.FinishRequest{Ceremony: tok.Reveal(), Credential: dev.register(t, begin.Options)}); err == nil || !strings.Contains(err.Error(), "ceremony data") {
			t.Fatalf("corrupt ceremony data: %v", err)
		}
	})
}

// TestFactors_TwoFactorDeliveredCodeChannel: with a handle (no delivery) and
// an address on the account, the code goes to the address; the handle's
// kind is skipped rather than failing the send.
func TestFactors_TwoFactorDeliveredCodeChannel(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		un, em, pw, tf := username.New(username.Login()), e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes())
		a := e.newAuth(t, nil, un, em, pw, tf)
		a.WaitDeliveries()
		up := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: aliceRaw, Password: secret, Username: "alice_1"}))
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		ids := must[[]auth.Identity](t)(a.Identities(context.Background(), up.User.ID))
		if len(ids) != 2 {
			t.Fatalf("identities = %+v, want a handle and an address", ids)
		}
		before := len(e.mail.To(a, alice))
		if _, err := tf.EnrollWith(request(a, up.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}); err != nil {
			t.Fatalf("enrol with a handle and an address: %v", err)
		}
		if n := len(e.mail.To(a, alice)); n != before+1 {
			t.Fatalf("mails = %d, want %d: the code must go to the address", n, before+1)
		}
	})
}

// TestFactors_Round2MoreFaults: the password reset that clears trusted
// devices, and forget-all, surface every database failure.
func TestFactors_Round2MoreFaults(t *testing.T) {
	t.Run("reset clears devices", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(0))
			a := e.newAuth(t, nil, em, pw, tf)
			f := factorsEnroll(t, e.env, a, pw, em, tf)
			pending := factorsPending(t, a, pw)
			if err := tf.VerifyWith(request(a, pending), twofactor.CodeRequest{Code: totpAt(t, f.secret, e.clock.Now()), TrustDevice: true}); err != nil {
				t.Fatal(err)
			}
			must[password.ForgotResult](t)(pw.Forgot(anon(a), alice))
			tok := e.mail.LastToken(t, a, alice)
			return func(context.Context) error {
				return pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: "a brand new passphrase"})
			}
		})
	})
	t.Run("forget all", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(0))
			a := e.newAuth(t, nil, em, pw, tf)
			f := factorsEnroll(t, e.env, a, pw, em, tf)
			pending := factorsPending(t, a, pw)
			ctx := request(a, pending)
			if err := tf.VerifyWith(ctx, twofactor.CodeRequest{Code: totpAt(t, f.secret, e.clock.Now()), TrustDevice: true}); err != nil {
				t.Fatal(err)
			}
			device, _, _ := rememberedDevice(ctx)
			e.clock.Advance(16 * time.Minute)
			full := must[password.SignInResult](t)(pw.SignIn(factorsDeviceRequest(a, "", device), password.SignInRequest{Identifier: alice, Password: secret}))
			return func(context.Context) error {
				return tf.ForgetDevice(factorsDeviceRequest(a, full.Token, device), twofactor.ForgetDeviceRequest{All: true})
			}
		})
	})
}

// ---------------------------------------------------------------- trusted devices over HTTP

// deviceCookie returns the browser's trusted-device cookie value, or "".
func deviceCookie(web *app) string {
	u, _ := url.Parse(web.srv.URL)
	for _, c := range web.jar.Cookies(https(u)) {
		if c.Name == authhttp.DeviceCookieName {
			return c.Value
		}
	}
	return ""
}

// TestFactors_TwoFactorTrustedDeviceHTTP: over authhttp, verify with
// trustDevice sets the device cookie apart from the session cookie; it
// survives sign-out; the next sign-in from that browser is a full session;
// forgetting every device deletes the cookie and the step is back.
func TestFactors_TwoFactorTrustedDeviceHTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.TrustDevices(0))
		a := e.newAuth(t, nil, em, pw, tf)
		web := newApp(t, a)
		decode := func(res *http.Response, into any) {
			t.Helper()
			if err := json.NewDecoder(res.Body).Decode(into); err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
		}
		if res := web.post(t, "/auth/password/sign-up", map[string]string{"identifier": alice, "password": secret, "name": "Alice"}); res.StatusCode != http.StatusOK {
			t.Fatalf("sign-up: %d %s", res.StatusCode, readAll(t, res))
		}
		var enr twofactor.EnrollResult
		decode(web.post(t, "/auth/twofactor/enroll", nil), &enr)
		if res := web.post(t, "/auth/twofactor/confirm", map[string]string{"code": totpAt(t, enr.Secret, e.clock.Now())}); res.StatusCode != http.StatusOK {
			t.Fatalf("confirm: %d %s", res.StatusCode, readAll(t, res))
		}
		web.post(t, "/auth/sign-out", nil)

		var in password.SignInResult
		decode(web.post(t, "/auth/password/sign-in", map[string]string{"identifier": alice, "password": secret}), &in)
		if !in.SecondFactorRequired {
			t.Fatal("sign-in must be pending")
		}
		e.clock.Advance(twofactor.Step)
		if res := web.post(t, "/auth/twofactor/verify", map[string]any{"code": totpAt(t, enr.Secret, e.clock.Now()), "trustDevice": true}); res.StatusCode != http.StatusOK {
			t.Fatalf("verify with trust: %d %s", res.StatusCode, readAll(t, res))
		}
		device := deviceCookie(web)
		if device == "" {
			t.Fatalf("verify with trustDevice must set %s", authhttp.DeviceCookieName)
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("/app/me after verify: %d", res.StatusCode)
		}
		web.post(t, "/auth/sign-out", nil)
		if deviceCookie(web) != device {
			t.Fatal("sign-out must leave the device cookie in place")
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("/app/me after sign-out: %d", res.StatusCode)
		}

		// The next sign-in from this browser skips the step.
		e.clock.Advance(16 * time.Minute)
		decode(web.post(t, "/auth/password/sign-in", map[string]string{"identifier": alice, "password": secret}), &in)
		if in.SecondFactorRequired {
			t.Fatal("a trusted browser must not get the second step")
		}
		if res := web.get(t, "/app/me"); res.StatusCode != http.StatusOK {
			t.Fatalf("/app/me from a trusted browser: %d", res.StatusCode)
		}
		var list twofactor.DevicesResult
		decode(web.get(t, "/auth/twofactor/devices"), &list)
		if len(list.Devices) != 1 || !list.Devices[0].Current {
			t.Fatalf("devices = %+v", list.Devices)
		}
		if res := web.post(t, "/auth/twofactor/devices/forget", map[string]any{"all": true}); res.StatusCode != http.StatusOK {
			t.Fatalf("forget all: %d %s", res.StatusCode, readAll(t, res))
		}
		if deviceCookie(web) != "" {
			t.Fatal("forgetting the current device must delete the cookie")
		}
		web.post(t, "/auth/sign-out", nil)
		e.clock.Advance(16 * time.Minute)
		decode(web.post(t, "/auth/password/sign-in", map[string]string{"identifier": alice, "password": secret}), &in)
		if !in.SecondFactorRequired {
			t.Fatal("after forgetting the device the step must be back")
		}
	})
}

// TestFactors_TwoFactorDeliveredCodeSignedInSend: a signed-in user with a
// delivered-code factor asks for a code before disable or new recovery codes;
// send before confirm has no confirmed factor to send for.
func TestFactors_TwoFactorDeliveredCodeSignedInSend(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes())
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if err := tf.Send(ctx); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("send before enrol: %v, want ErrNotEnrolled", err)
		}
		must[twofactor.EnrollResult](t)(tf.EnrollWith(ctx, twofactor.EnrollRequest{Method: twofactor.MethodDelivered}))
		if err := tf.Send(ctx); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("send before confirm: %v, want ErrNotEnrolled", err)
		}
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, factorsMailedCode(t, e, a, alice)))
		if err := tf.Send(ctx); err != nil {
			t.Fatalf("send on a signed-in session: %v", err)
		}
		codes := must[twofactor.RecoveryCodes](t)(tf.RegenerateRecoveryCodes(ctx, factorsMailedCode(t, e, a, alice)))
		if len(codes.Codes) != twofactor.DefaultRecoveryCodes {
			t.Fatalf("regenerate with a sent code: %v", codes.Codes)
		}
		if err := tf.Send(ctx); err != nil {
			t.Fatal(err)
		}
		if err := tf.Disable(ctx, factorsMailedCode(t, e, a, alice)); err != nil {
			t.Fatalf("disable with a sent code: %v", err)
		}
	})
}

// TestFactors_TwoFactorDeliveredCodeSkipsAnUndeliverableFirstIdentity: when
// a verified identity no plugin can deliver to (a claimed handle) sorts ahead
// of the addresses, the code goes on to the next identity instead of failing.
// The handle is verified and primary; the first address is made non-primary
// by promoting a second one, so the order sendCode walks is handle, second
// address, first address.
func TestFactors_TwoFactorDeliveredCodeSkipsAnUndeliverableFirstIdentity(t *testing.T) {
	const second = "alice.second@example.com"
	eachEngine(t, func(t *testing.T, e *env) {
		un, em, pw, tf := username.New(username.Login()), e.emailPlugin(email.Multiple()), e.passwordPlugin(), factorsTwoFactor(twofactor.DeliveredCodes())
		a := e.newAuth(t, nil, un, em, pw, tf)
		up := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: aliceRaw, Password: secret, Username: "alice_1"}))
		a.WaitDeliveries()
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Minute)
		if err := em.Add(request(a, up.Token), second); err != nil {
			t.Fatal(err)
		}
		a.WaitDeliveries()
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, second)); err != nil {
			t.Fatal(err)
		}
		var secondID string
		for _, x := range must[[]auth.Identity](t)(a.Identities(context.Background(), up.User.ID)) {
			if x.Kind == email.KindEmail && x.Value == second {
				secondID = x.ID
			}
		}
		if _, err := a.SetPrimaryIdentity(context.Background(), up.User.ID, secondID); err != nil {
			t.Fatal(err)
		}
		before, beforeFirst := len(e.mail.To(a, second)), len(e.mail.To(a, alice))
		if _, err := tf.EnrollWith(request(a, up.Token), twofactor.EnrollRequest{Method: twofactor.MethodDelivered}); err != nil {
			t.Fatalf("enrol with a handle sorted first: %v", err)
		}
		a.WaitDeliveries()
		if n := len(e.mail.To(a, second)); n != before+1 {
			t.Fatalf("mails to the primary address = %d, want %d: the code must skip the handle", n, before+1)
		}
		if n := len(e.mail.To(a, alice)); n != beforeFirst {
			t.Fatalf("mails to the non-primary address = %d, want %d", n, beforeFirst)
		}
	})
}
