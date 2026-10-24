package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
)

// totpAt is an independent RFC 6238 implementation, so the test does not
// check the plugin against itself.
func totpAt(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

var twoFactorKey = []byte(strings.Repeat("k", auth.SealKeySize))

func TestTwoFactor_EnrollSignInVerifyRecover(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		// The label callback reaches the core, so it can read the address the
		// plugin itself knows nothing about.
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey), twofactor.Issuer("Acme"),
			twofactor.AccountLabel(func(ctx context.Context, a *auth.Auth, u auth.User) string {
				ids, err := a.Identities(ctx, u.ID)
				if err != nil {
					t.Errorf("identities in the label callback: %v", err)
					return ""
				}
				for _, id := range ids {
					if id.Kind == email.KindEmail {
						return id.Value
					}
				}
				return ""
			}))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)

		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if !strings.HasPrefix(enr.URL, "otpauth://totp/Acme:"+alice+"?") {
			t.Fatalf("url = %s", enr.URL)
		}
		wrong := "000000"
		if totpAt(t, enr.Secret, e.clock.Now()) == wrong {
			wrong = "111111"
		}
		if _, err := tf.Confirm(ctx, wrong); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("confirm with a wrong code: %v", err)
		}
		codes := must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
		if len(codes.Codes) != twofactor.DefaultRecoveryCodes {
			t.Fatalf("recovery codes = %v", codes.Codes)
		}

		// Sign-in now yields a pending session: it signs nobody in.
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if !in.SecondFactorRequired {
			t.Fatal("sign-in must report the second factor")
		}
		pendingCtx := request(a, in.Token)
		if err := a.Resolve(pendingCtx); err != nil {
			t.Fatal(err)
		}
		if _, ok := auth.CurrentUser(pendingCtx); ok {
			t.Fatal("a pending session must not be a signed-in user")
		}
		if _, _, _, err := a.ResolveSession(context.Background(), in.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("ResolveSession on a pending token: %v", err)
		}
		if _, err := tf.Enroll(request(a, in.Token)); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a signed-in operation on a pending session: %v", err)
		}

		// The code used to confirm cannot be replayed in the same step.
		replay := totpAt(t, enr.Secret, e.clock.Now())
		if err := tf.Verify(request(a, in.Token), replay); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("replayed code: %v", err)
		}
		e.clock.Advance(twofactor.Step)
		verifyCtx := request(a, in.Token)
		if err := tf.Verify(verifyCtx, totpAt(t, enr.Secret, e.clock.Now())); err != nil {
			t.Fatalf("verify: %v", err)
		}
		var full auth.Token
		for _, ef := range auth.RequestEffects(verifyCtx) {
			if ef.Kind == auth.EffectIssueSession {
				full = ef.Token
			}
		}
		if full == "" || full == in.Token {
			t.Fatal("verify must issue a new token")
		}
		if _, _, _, err := a.ResolveSession(context.Background(), full); err != nil {
			t.Fatalf("promoted session: %v", err)
		}
		if n := sessionRows(t, e, a, in.Token); n != 0 {
			t.Fatalf("the pending session still has %d row(s)", n)
		}

		// A recovery code works once, dashes or not.
		second := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		rc := codes.Codes[0]
		if err := tf.Verify(request(a, second.Token), strings.ToLower(strings.ReplaceAll(rc, "-", ""))); err != nil {
			t.Fatalf("recovery code: %v", err)
		}
		third := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if err := tf.Verify(request(a, third.Token), rc); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("recovery code used twice: %v", err)
		}

		// Five wrong codes lock the factor, even for the right code.
		for range twofactor.MaxFailures {
			_ = tf.Verify(request(a, third.Token), "123456")
		}
		e.clock.Advance(twofactor.Step)
		if err := tf.Verify(request(a, third.Token), totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("after %d failures: %v, want ErrLocked", twofactor.MaxFailures, err)
		}
	})
}

// sessionRows counts session rows with tok's hash, pending or not.
func sessionRows(t *testing.T, e *env, a *auth.Auth, tok auth.Token) int {
	t.Helper()
	var n int64
	q, err := a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(auth.TableSession).
		Where(sqlb.Eq(auth.SessionTokenHash, auth.HashToken(tok))).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlb.One(context.Background(), e.db, q); err != nil {
		t.Fatal(err)
	}
	return int(n)
}
