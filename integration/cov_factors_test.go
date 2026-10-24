package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

// This file covers the password, two-factor and passkey plugins past their
// happy paths: every refusal a client can cause, every configuration option,
// and, through sweepFaults, every database failure each operation can meet.

// ---------------------------------------------------------------- helpers

// factorsBadge is an identifier kind that can be verified and can sign in but
// whose plugin cannot deliver messages: the shape of a custom kind (an
// employee badge, say) that an app verifies out of band.
const factorsBadge = "badge"

// factorsBadgePrefix marks the values factorsBadgeKind accepts, so email
// addresses fall through to the email plugin.
const factorsBadgePrefix = "badge-"

type factorsBadgeKind struct{}

func (factorsBadgeKind) Name() string { return "badges" }

func (factorsBadgeKind) Identifiers() []auth.IdentifierKind {
	return []auth.IdentifierKind{{
		Name: factorsBadge, Unique: true, UniqueOnlyVerified: true, CanLogin: true, Verifiable: true,
		Normalize: func(raw string) (string, error) {
			v := strings.ToLower(strings.TrimSpace(raw))
			if !strings.HasPrefix(v, factorsBadgePrefix) {
				return "", auth.ErrIdentifierInvalid
			}
			return v, nil
		},
	}}
}

// factorsLog is a slog destination a test reads back.
type factorsLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *factorsLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *factorsLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *factorsLog) option() auth.Option {
	return auth.WithLogger(slog.New(slog.NewTextHandler(l, nil)))
}

// factorsFailIDs fails id generation for one prefix only, so a single
// plugin's NewID call fails while everything before it succeeds.
func factorsFailIDs(prefix string) auth.Option {
	return auth.WithIDs(func(p string) (string, error) {
		if p == prefix {
			return "", errFactorsIDs
		}
		return auth.NewID(p)
	})
}

var errFactorsIDs = errors.New("integration: id generator down")

// factorsTOTP is alice with a confirmed TOTP factor.
type factorsTOTP struct {
	up     password.SignInResult
	secret string
	codes  []string
}

// factorsEnroll signs alice up, verifies her address and turns TOTP on, then
// moves the clock one step so the confirm code is not the current one.
func factorsEnroll(t *testing.T, e *env, a *auth.Auth, pw *password.Plugin, em *email.Plugin, tf *twofactor.Plugin) factorsTOTP {
	t.Helper()
	up := signUpVerified(t, e, a, pw, em)
	ctx := request(a, up.Token)
	enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
	codes := must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))
	e.clock.Advance(twofactor.Step)
	return factorsTOTP{up: up, secret: enr.Secret, codes: codes.Codes}
}

// factorsPending signs alice in with her password and returns the pending
// session token the second factor must promote.
func factorsPending(t *testing.T, a *auth.Auth, pw *password.Plugin) auth.Token {
	t.Helper()
	in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
	if !in.SecondFactorRequired {
		t.Fatal("sign-in must be pending with a factor on")
	}
	return in.Token
}

// factorsWrongCode is a six-digit code that is not the current one.
func factorsWrongCode(t *testing.T, e *env, totpSecret string) string {
	t.Helper()
	for _, c := range []string{"000000", "111111"} {
		if c != totpAt(t, totpSecret, e.clock.Now()) {
			return c
		}
	}
	return "222222"
}

// factorsSession is a fresh session for a new user with no identifier.
func factorsSession(t *testing.T, a *auth.Auth, name string) (auth.User, auth.Token) {
	t.Helper()
	u := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{Name: name}))
	_, tok, err := a.CreateSession(context.Background(), u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return u, tok
}

// factorsRegister adds dev as a passkey of the session's user.
func factorsRegister(t *testing.T, pk *passkey.Plugin, ctx context.Context, dev *authenticator, name string) passkey.Passkey {
	t.Helper()
	begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
	return must[passkey.Passkey](t)(pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options), Name: name}))
}

// factorsStoredHash reads userID's password hash straight from the table.
func factorsStoredHash(t *testing.T, e *env, userID string) string {
	t.Helper()
	var h string
	q := "SELECT " + password.ColHash + " FROM " + tbl(password.TableNamePassword) + " WHERE " + password.ColUserID + " = " + e.d.Placeholder(1)
	if err := e.db.QueryRow(q, userID).Scan(&h); err != nil {
		t.Fatal(err)
	}
	return h
}

// ---------------------------------------------------------------- password

func TestFactors_PasswordSignUpRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: "short"}); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("short password: %v, want ErrTooShort", err)
		}
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "not an address", Password: secret}); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("identifier no kind accepts: %v, want ErrIdentifierInvalid", err)
		}
		if n := len(e.mail.To(a, alice)); n != 0 {
			t.Fatalf("a refused sign-up sent %d mail(s)", n)
		}
	})
}

// TestFactors_PasswordSignUpTakenValueOfUndeliverableKind pins a fix: when the
// verified owner's kind has no plugin that can deliver, sign-up used to fail
// with ErrNoDeliverer for a taken value and succeed for a free one, which told
// any caller which values have accounts. It now answers the same either way.
func TestFactors_PasswordSignUpTakenValueOfUndeliverableKind(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, factorsBadgeKind{}, em, pw)
		ctx := context.Background()
		owner := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: "Owner"}))
		if _, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: owner.ID, Kind: factorsBadge, Raw: "badge-42", Verified: true}); err != nil {
			t.Fatal(err)
		}
		taken, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "badge-42", Password: secret})
		if err != nil {
			t.Fatalf("sign-up with a taken badge: %v; must look like a free one", err)
		}
		free, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "badge-43", Password: secret})
		if err != nil {
			t.Fatalf("sign-up with a free badge: %v", err)
		}
		if taken.User.ID == owner.ID || taken.Token == "" || free.Token == "" {
			t.Fatalf("taken = %+v, free = %+v; both must be new accounts with sessions", taken, free)
		}
	})
}

func TestFactors_PasswordSignInRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.MaxLength(32))
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		// Longer than the maximum is refused before hashing, with the same
		// answer as a wrong password.
		long := password.Secret(strings.Repeat("x", 33))
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: long}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("over-long password: %v, want ErrInvalidCredentials", err)
		}
		// A corrupt stored hash is an error, never a match.
		q := "UPDATE " + tbl(password.TableNamePassword) + " SET " + password.ColHash + " = " + e.d.Placeholder(1) + " WHERE " + password.ColUserID + " = " + e.d.Placeholder(2)
		if _, err := e.db.Exec(q, "not a phc string", up.User.ID); err != nil {
			t.Fatal(err)
		}
		_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
		if err == nil || errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("corrupt hash: %v, want a server error", err)
		}
		// Change and verify check the current password against the same corrupt hash.
		if err := pw.Change(request(a, up.Token), password.ChangeRequest{Current: secret, New: "next passphrase"}); err == nil || errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("change over a corrupt hash: %v, want a server error", err)
		}
		if err := pw.Verify(request(a, up.Token), secret); err == nil || errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("verify over a corrupt hash: %v, want a server error", err)
		}
	})
}

// TestFactors_PasswordRehashesOnNewCost: a hash made with other parameters is
// replaced at the next successful sign-in, and the password still works.
func TestFactors_PasswordRehashesOnNewCost(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		if h := factorsStoredHash(t, e, up.User.ID); !strings.Contains(h, "m=64,t=1,p=1$") {
			t.Fatalf("first hash = %s", h)
		}
		stronger := password.Argon2Params{Memory: 128, Time: 2, Threads: 1}
		pw2 := password.New(password.Argon2(stronger))
		a2 := e.newAuth(t, nil, e.emailPlugin(), pw2)
		if _, err := pw2.SignIn(anon(a2), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("sign-in under the new cost: %v", err)
		}
		if h := factorsStoredHash(t, e, up.User.ID); !strings.Contains(h, "m=128,t=2,p=1$") {
			t.Fatalf("hash after sign-in = %s, want the new parameters", h)
		}
		if _, err := pw2.SignIn(anon(a2), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("sign-in with the re-hashed password: %v", err)
		}
	})
}

func TestFactors_PasswordHasPassword(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		if has, err := pw.HasPassword(context.Background(), up.User.ID); err != nil || !has {
			t.Fatalf("user with a password: %v, %v", has, err)
		}
		other, tok := factorsSession(t, a, "Social")
		if has, err := pw.HasPassword(context.Background(), other.ID); err != nil || has {
			t.Fatalf("user without a password: %v, %v", has, err)
		}
		// Change sets the first password without a current one.
		if err := pw.Change(request(a, tok), password.ChangeRequest{New: "first passphrase"}); err != nil {
			t.Fatalf("first password: %v", err)
		}
		if has, _ := pw.HasPassword(context.Background(), other.ID); !has {
			t.Fatal("change must create the password")
		}
	})
}

// TestFactors_PasswordResetOptions: ResetLinks decides the link in the mail and
// ResetTTL how long it works.
func TestFactors_PasswordResetOptions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		pw := e.passwordPlugin(password.ResetTTL(time.Minute), password.ResetLinks(func(tok auth.Token) string {
			return "myapp://reset?token=" + tok.Reveal()
		}))
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		if _, err := pw.Forgot(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		mails := e.mail.To(a, alice)
		if last := mails[len(mails)-1]; !strings.Contains(last.Text, "myapp://reset?token=") {
			t.Fatalf("reset mail does not carry the app's link: %s", last.Text)
		}
		tok := e.mail.LastToken(t, a, alice)
		e.clock.Advance(time.Minute + time.Second)
		if err := pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: "a brand new passphrase"}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("reset after ResetTTL: %v, want ErrTokenInvalid", err)
		}
	})
}

// TestFactors_PasswordNewPasswordRules: reset and change apply the same rules
// as sign-up, before spending the token or checking the current password.
func TestFactors_PasswordNewPasswordRules(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		if _, err := pw.Forgot(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		tok := e.mail.LastToken(t, a, alice)
		if err := pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: "short"}); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("reset to a short password: %v", err)
		}
		// The refused reset did not spend the token.
		if err := pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: "a brand new passphrase"}); err != nil {
			t.Fatalf("reset after a refused one: %v", err)
		}
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "a brand new passphrase"}))
		if err := pw.Change(request(a, in.Token), password.ChangeRequest{Current: "a brand new passphrase", New: "short"}); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("change to a short password: %v", err)
		}
	})
}

// TestFactors_PasswordForgotWithoutAVerifiedChannel: an account whose address
// is unverified gets no link, and the answer is the usual one.
func TestFactors_PasswordForgotWithoutAVerifiedChannel(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		before := len(e.mail.To(a, alice))
		res, err := pw.Forgot(anon(a), alice)
		if err != nil || res.Status != password.ForgotStatus {
			t.Fatalf("forgot = %+v, %v", res, err)
		}
		if after := len(e.mail.To(a, alice)); after != before {
			t.Fatalf("a reset link went to an unverified address (%d mails, was %d)", after, before)
		}
	})
}

func TestFactors_PasswordFaults(t *testing.T) {
	signedUp := func(t *testing.T, e *faultEnv, opts ...password.Option) (*auth.Auth, *password.Plugin, password.SignInResult) {
		t.Helper()
		em, pw := e.emailPlugin(), e.passwordPlugin(opts...)
		a := e.newAuth(t, nil, em, pw)
		return a, pw, signUpVerified(t, e.env, a, pw, em)
	}
	t.Run("sign-up over a verified owner", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, _ := signedUp(t, e)
			return func(context.Context) error {
				_, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: "another passphrase"})
				return err
			}
		})
	})
	t.Run("sign-in that re-hashes", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			signedUp(t, e)
			pw2 := password.New(password.Argon2(password.Argon2Params{Memory: 128, Time: 1, Threads: 1}))
			a2 := e.newAuth(t, nil, e.emailPlugin(), pw2)
			return func(context.Context) error {
				_, err := pw2.SignIn(anon(a2), password.SignInRequest{Identifier: alice, Password: secret})
				return err
			}
		})
	})
	t.Run("forgot", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, _ := signedUp(t, e)
			return func(context.Context) error {
				_, err := pw.Forgot(anon(a), alice)
				return err
			}
		})
	})
	t.Run("reset", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, _ := signedUp(t, e)
			if _, err := pw.Forgot(anon(a), alice); err != nil {
				t.Fatal(err)
			}
			tok := e.mail.LastToken(t, a, alice)
			return func(context.Context) error {
				return pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: "a brand new passphrase"})
			}
		})
	})
	t.Run("change", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, up := signedUp(t, e)
			return func(context.Context) error {
				return pw.Change(request(a, up.Token), password.ChangeRequest{Current: secret, New: "next passphrase"})
			}
		})
	})
	t.Run("has password", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			_, pw, up := signedUp(t, e)
			return func(ctx context.Context) error {
				_, err := pw.HasPassword(ctx, up.User.ID)
				return err
			}
		})
	})
}

// ---------------------------------------------------------------- two-factor

func factorsTwoFactor(opts ...twofactor.Option) *twofactor.Plugin {
	return twofactor.New(append([]twofactor.Option{twofactor.WithEncryptionKey(twoFactorKey)}, opts...)...)
}

func TestFactors_TwoFactorStateRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if _, err := tf.Confirm(ctx, "123456"); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("confirm before enroll: %v, want ErrNotEnrolled", err)
		}
		if err := tf.Disable(ctx, "123456"); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("disable with nothing enrolled: %v, want ErrNotEnrolled", err)
		}
		first := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if err := tf.Disable(ctx, "123456"); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("disable an unconfirmed factor: %v, want ErrNotEnrolled", err)
		}
		// A second enroll replaces the unconfirmed secret: the first one's
		// codes no longer confirm.
		second := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if second.Secret == first.Secret {
			t.Fatal("re-enroll must mint a new secret")
		}
		if _, err := tf.Confirm(ctx, totpAt(t, first.Secret, e.clock.Now())); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("confirm with the replaced secret: %v", err)
		}
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, second.Secret, e.clock.Now())))
		if _, err := tf.Confirm(ctx, totpAt(t, second.Secret, e.clock.Now())); !errors.Is(err, twofactor.ErrAlreadyEnabled) {
			t.Fatalf("confirm twice: %v, want ErrAlreadyEnabled", err)
		}
		if _, err := tf.Enroll(ctx); !errors.Is(err, twofactor.ErrAlreadyEnabled) {
			t.Fatalf("enroll with a factor on: %v, want ErrAlreadyEnabled", err)
		}
	})
}

// TestFactors_TwoFactorDisable: a wrong code keeps the factor; the right one
// turns it off, and sign-in is then a full session again.
func TestFactors_TwoFactorDisable(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		ctx := request(a, f.up.Token)
		if err := tf.Disable(ctx, factorsWrongCode(t, e, f.secret)); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("disable with a wrong code: %v", err)
		}
		if on, err := tf.SecondFactorRequired(context.Background(), f.up.User.ID); err != nil || !on {
			t.Fatalf("after a refused disable: %v, %v", on, err)
		}
		if err := tf.Disable(ctx, totpAt(t, f.secret, e.clock.Now())); err != nil {
			t.Fatalf("disable: %v", err)
		}
		if on, err := tf.SecondFactorRequired(context.Background(), f.up.User.ID); err != nil || on {
			t.Fatalf("after disable: %v, %v", on, err)
		}
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if in.SecondFactorRequired {
			t.Fatal("sign-in after disable must be a full session")
		}
		// The recovery codes went with the factor.
		if err := tf.Disable(ctx, f.codes[0]); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("recovery code after disable: %v", err)
		}
	})
}

// TestFactors_TwoFactorLockCoversRecoveryCodes: the lock refuses recovery
// codes too, or they would be the way around it.
func TestFactors_TwoFactorLockCoversRecoveryCodes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		// Wrong recovery codes count as failures like wrong TOTP codes.
		for range twofactor.MaxFailures {
			if err := tf.Verify(request(a, pending), "AAAA-BBBB-CCCC-DDDD"); !errors.Is(err, twofactor.ErrCodeInvalid) {
				t.Fatalf("wrong recovery code: %v", err)
			}
		}
		if err := tf.Verify(request(a, pending), f.codes[0]); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("recovery code while locked: %v, want ErrLocked", err)
		}
		// The pending session outlived by the lock is gone; a new sign-in
		// gets a new one, and the recovery code now works.
		e.clock.Advance(twofactor.LockDuration + time.Second)
		pending = factorsPending(t, a, pw)
		if err := tf.Verify(request(a, pending), f.codes[0]); err != nil {
			t.Fatalf("recovery code after the lock: %v", err)
		}
	})
}

// TestFactors_TwoFactorLostKey: with the encryption key replaced, a TOTP code
// cannot be checked, and a recovery code is the way in, as the option's doc
// promises.
func TestFactors_TwoFactorLostKey(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)

		pw2 := e.passwordPlugin()
		tf2 := twofactor.New(twofactor.WithEncryptionKey([]byte(strings.Repeat("n", auth.SealKeySize))))
		a2 := e.newAuth(t, nil, e.emailPlugin(), pw2, tf2)
		pending := factorsPending(t, a2, pw2)
		if err := tf2.Verify(request(a2, pending), totpAt(t, f.secret, e.clock.Now())); !errors.Is(err, auth.ErrSealedCorrupt) {
			t.Fatalf("TOTP under a new key: %v, want ErrSealedCorrupt", err)
		}
		if err := tf2.Verify(request(a2, pending), f.codes[0]); err != nil {
			t.Fatalf("recovery code under a new key: %v", err)
		}
	})
}

func TestFactors_TwoFactorRecoveryCodeCount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor(twofactor.RecoveryCodeCount(3))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		if len(f.codes) != 3 {
			t.Fatalf("codes = %v, want 3", f.codes)
		}
		for _, c := range f.codes {
			if len(c) != len("XXXX-XXXX-XXXX-XXXX") {
				t.Fatalf("code %q is not four groups of four", c)
			}
		}
	})
}

func TestFactors_TwoFactorRecoveryCodeIDFailure(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, []auth.Option{factorsFailIDs("tfr")}, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if _, err := tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, errFactorsIDs) {
			t.Fatalf("confirm with ids failing: %v", err)
		}
		// The failed confirm rolled back: the factor is not on.
		if on, err := tf.SecondFactorRequired(context.Background(), up.User.ID); err != nil || on {
			t.Fatalf("after a failed confirm: %v, %v", on, err)
		}
	})
}

// TestFactors_TwoFactorFailureCountErrorIsLogged: the failure counter writes
// after the transaction; when that write fails it is logged, and the answer
// to the client is still ErrCodeInvalid.
func TestFactors_TwoFactorFailureCountErrorIsLogged(t *testing.T) {
	const logged = "twofactor: count failed attempt"
	seen := false
	for k := 1; k <= maxFaultSteps; k++ {
		e := newFaultEnv(t)
		log := &factorsLog{}
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, []auth.Option{log.option()}, em, pw, tf)
		f := factorsEnroll(t, e.env, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		wrong := factorsWrongCode(t, e.env, f.secret)
		e.f.arm(k)
		err := tf.Verify(request(a, pending), wrong)
		if !e.f.disarm() {
			break
		}
		if err == nil {
			t.Fatalf("fault at call %d: a wrong code was accepted", k)
		}
		if strings.Contains(log.String(), logged) {
			seen = true
			if !errors.Is(err, twofactor.ErrCodeInvalid) {
				t.Fatalf("a failed count changed the answer: %v", err)
			}
		}
	}
	if !seen {
		t.Fatal("no fault reached the failure counter")
	}
}

func TestFactors_TwoFactorFaults(t *testing.T) {
	setup := func(t *testing.T, e *faultEnv) (*auth.Auth, *password.Plugin, *email.Plugin, *twofactor.Plugin) {
		t.Helper()
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		return e.newAuth(t, nil, em, pw, tf), pw, em, tf
	}
	t.Run("enroll", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, em, tf := setup(t, e)
			up := signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error {
				_, err := tf.Enroll(request(a, up.Token))
				return err
			}
		})
	})
	t.Run("confirm", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, em, tf := setup(t, e)
			up := signUpVerified(t, e.env, a, pw, em)
			enr := must[twofactor.EnrollResult](t)(tf.Enroll(request(a, up.Token)))
			code := totpAt(t, enr.Secret, e.clock.Now())
			return func(context.Context) error {
				_, err := tf.Confirm(request(a, up.Token), code)
				return err
			}
		})
	})
	t.Run("disable", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, em, tf := setup(t, e)
			f := factorsEnroll(t, e.env, a, pw, em, tf)
			code := totpAt(t, f.secret, e.clock.Now())
			return func(context.Context) error { return tf.Disable(request(a, f.up.Token), code) }
		})
	})
	t.Run("verify totp", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, em, tf := setup(t, e)
			f := factorsEnroll(t, e.env, a, pw, em, tf)
			pending := factorsPending(t, a, pw)
			code := totpAt(t, f.secret, e.clock.Now())
			return func(context.Context) error { return tf.Verify(request(a, pending), code) }
		})
	})
	t.Run("verify recovery code", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pw, em, tf := setup(t, e)
			f := factorsEnroll(t, e.env, a, pw, em, tf)
			pending := factorsPending(t, a, pw)
			return func(context.Context) error { return tf.Verify(request(a, pending), f.codes[0]) }
		})
	})
}

// ---------------------------------------------------------------- passkey

// factorsPasskeyAuth wires email, password and passkey, and returns alice's
// fresh session.
func factorsPasskeyAuth(t *testing.T, e *env, opts []auth.Option, pkOpts ...passkey.Option) (*auth.Auth, *passkey.Plugin, password.SignInResult) {
	t.Helper()
	em, pw, pk := e.emailPlugin(), e.passwordPlugin(), passkey.New(pkOpts...)
	a := e.newAuth(t, opts, em, pw, pk)
	return a, pk, signUpVerified(t, e, a, pw, em)
}

func TestFactors_PasskeyCeremonyRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, nil, passkey.WithCeremonyTTL(time.Minute))
		ctx := request(a, up.Token)
		dev := newAuthenticator(t)

		// A ceremony begun by one user cannot be finished by another.
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		_, otherTok := factorsSession(t, a, "Mallory")
		if _, err := pk.RegisterFinish(request(a, otherTok), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
			t.Fatalf("another user's ceremony: %v, want ErrCeremonyInvalid", err)
		}
		// A credential that does not parse.
		begin = must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: []byte(`{"id":1}`)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("unparseable registration: %v, want ErrPasskeyInvalid", err)
		}
		// An answer made for another origin.
		begin = must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		phish := newAuthenticator(t)
		phish.origin = "https://evil.example"
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: phish.register(t, begin.Options)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("registration for another origin: %v, want ErrPasskeyInvalid", err)
		}
		// An expired ceremony.
		begin = must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		e.clock.Advance(time.Minute + time.Second)
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
			t.Fatalf("ceremony past its TTL: %v, want ErrCeremonyInvalid", err)
		}
		if list := must[[]passkey.Passkey](t)(pk.List(request(a, up.Token))); len(list) != 0 {
			t.Fatalf("refused ceremonies stored %d passkey(s)", len(list))
		}
	})
}

func TestFactors_PasskeyLoginRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, nil)
		dev := newAuthenticator(t)
		factorsRegister(t, pk, request(a, up.Token), dev, "Laptop")

		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: []byte(`not json`)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("unparseable assertion: %v, want ErrPasskeyInvalid", err)
		}
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: "no-such-ceremony", Credential: dev.assert(t, lb.Options, up.User.ID)}); !errors.Is(err, passkey.ErrCeremonyInvalid) {
			t.Fatalf("unknown ceremony: %v, want ErrCeremonyInvalid", err)
		}
		// A user handle naming nobody.
		lb = must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, "usr_nobody")}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("unknown user handle: %v, want ErrPasskeyInvalid", err)
		}
		// Ceremony data that does not decode is an error, not a sign-in.
		tok, err := a.IssueVerification(context.Background(), passkey.PurposeLogin, "", time.Minute, "not json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: tok.Reveal(), Credential: dev.assert(t, lb.Options, up.User.ID)}); err == nil || !strings.Contains(err.Error(), "ceremony data") {
			t.Fatalf("corrupt ceremony data: %v", err)
		}
	})
}

// TestFactors_PasskeyTwoDevices: signing in with the second of two passkeys
// updates that passkey only; removing one of two works; an id that is not the
// user's is ErrNotFound.
func TestFactors_PasskeyTwoDevices(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, nil)
		ctx := request(a, up.Token)
		laptop, phone := newAuthenticator(t), newAuthenticator(t)
		first := factorsRegister(t, pk, ctx, laptop, "Laptop")
		e.clock.Advance(time.Second)
		second := factorsRegister(t, pk, ctx, phone, "Phone")

		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		in, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: phone.assert(t, lb.Options, up.User.ID)})
		if err != nil {
			t.Fatalf("sign-in with the second passkey: %v", err)
		}
		list := must[[]passkey.Passkey](t)(pk.List(request(a, in.Token)))
		if len(list) != 2 || list[0].ID != first.ID || list[0].LastUsedAt != nil || list[1].ID != second.ID || list[1].LastUsedAt == nil {
			t.Fatalf("list = %+v; only the phone was used", list)
		}
		if err := pk.Remove(ctx, "pky_not_mine"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("remove an unknown id: %v, want ErrNotFound", err)
		}
		_, otherTok := factorsSession(t, a, "Mallory")
		if err := pk.Remove(request(a, otherTok), first.ID); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("remove another user's passkey: %v, want ErrNotFound", err)
		}
		if err := pk.Remove(ctx, second.ID); err != nil {
			t.Fatalf("remove one of two: %v", err)
		}
		if list := must[[]passkey.Passkey](t)(pk.List(ctx)); len(list) != 1 || list[0].ID != first.ID {
			t.Fatalf("after remove: %+v", list)
		}
	})
}

// TestFactors_PasskeyCredentialOfAnotherUser: one authenticator credential
// cannot be registered to a second account.
func TestFactors_PasskeyCredentialOfAnotherUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, nil)
		dev := newAuthenticator(t)
		factorsRegister(t, pk, request(a, up.Token), dev, "Laptop")
		_, otherTok := factorsSession(t, a, "Pat")
		ctx := request(a, otherTok)
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, passkey.ErrPasskeyInvalid) {
			t.Fatalf("a credential already registered elsewhere: %v, want ErrPasskeyInvalid", err)
		}
	})
}

func TestFactors_PasskeyIDFailure(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, []auth.Option{factorsFailIDs("pky")})
		ctx := request(a, up.Token)
		dev := newAuthenticator(t)
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); !errors.Is(err, errFactorsIDs) {
			t.Fatalf("register with ids failing: %v", err)
		}
	})
}

// TestFactors_PasskeyCorruptStoredCredential: a stored credential that does
// not decode fails the ceremony with an error naming the row, rather than
// being skipped (which would let the same authenticator register twice).
// SQLite only: the MySQL column is JSON and refuses the corrupt value.
func TestFactors_PasskeyCorruptStoredCredential(t *testing.T) {
	db, d := openSQLite(t)
	e := newEnv(t, auth.EngineSQLite, db, d)
	a, pk, up := factorsPasskeyAuth(t, e, nil)
	ctx := request(a, up.Token)
	added := factorsRegister(t, pk, ctx, newAuthenticator(t), "Laptop")
	if _, err := db.Exec("UPDATE "+tbl(passkey.TableNamePasskey)+" SET "+passkey.ColCredential+" = '{broken' WHERE "+passkey.ColID+" = ?", added.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pk.RegisterBegin(ctx); err == nil || !strings.Contains(err.Error(), "stored credential "+added.ID) {
		t.Fatalf("register over a corrupt row: %v", err)
	}
	if _, err := pk.List(ctx); err == nil || !strings.Contains(err.Error(), "stored credential "+added.ID) {
		t.Fatalf("list over a corrupt row: %v", err)
	}
}

// TestFactors_PasskeyLoginBeginRateLimited: login-begin writes a ceremony row
// per call, so one IP gets a bounded number a minute; another IP is not
// affected.
func TestFactors_PasskeyLoginBeginRateLimited(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pk := passkey.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), pk)
		// factorsLoginBeginCeiling bounds the loop: far above any sane limit,
		// so a missing rule fails the test instead of hanging it.
		const factorsLoginBeginCeiling = 1000
		var last error
		calls := 0
		for last == nil && calls < factorsLoginBeginCeiling {
			_, last = pk.LoginBegin(anon(a))
			calls++
		}
		if !errors.Is(last, auth.ErrRateLimited) || calls < 2 {
			t.Fatalf("after %d calls: %v, want ErrRateLimited once the limit is used up", calls, last)
		}
		other := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "198.51.100.9", Origin: testBaseURL}})
		if _, err := pk.LoginBegin(other); err != nil {
			t.Fatalf("another IP: %v", err)
		}
		e.clock.Advance(time.Minute)
		if _, err := pk.LoginBegin(anon(a)); err != nil {
			t.Fatalf("after the window: %v", err)
		}
	})
}

// factorsUserEntity reads the user entity of registration options.
func factorsUserEntity(t *testing.T, options []byte) (name, displayName string) {
	t.Helper()
	var o struct {
		PublicKey struct {
			User struct {
				Name        string `json:"name"`
				DisplayName string `json:"displayName"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &o); err != nil {
		t.Fatal(err)
	}
	return o.PublicKey.User.Name, o.PublicKey.User.DisplayName
}

// TestFactors_PasskeyAccountName: AccountName's callback reaches the core and
// names the account the device stores; without it the name is the user id.
func TestFactors_PasskeyAccountName(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		primaryEmail := func(ctx context.Context, a *auth.Auth, u auth.User) string {
			ids, err := a.Identities(ctx, u.ID)
			if err != nil {
				t.Errorf("identities in the name callback: %v", err)
				return ""
			}
			for _, id := range ids {
				if id.Kind == email.KindEmail {
					return id.Value
				}
			}
			return ""
		}
		a, pk, up := factorsPasskeyAuth(t, e, nil, passkey.AccountName(primaryEmail))
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(request(a, up.Token)))
		if name, display := factorsUserEntity(t, begin.Options); name != alice || display != "Alice" {
			t.Fatalf("user entity = %q / %q, want %q / Alice", name, display, alice)
		}

		db, d := openSQLite(t)
		e2 := newEnv(t, auth.EngineSQLite, db, d)
		a2, pk2, up2 := factorsPasskeyAuth(t, e2, nil)
		begin = must[passkey.BeginResult](t)(pk2.RegisterBegin(request(a2, up2.Token)))
		if name, _ := factorsUserEntity(t, begin.Options); name != up2.User.ID {
			t.Fatalf("default account name = %q, want the user id", name)
		}
	})
}

func TestFactors_PasskeyFaults(t *testing.T) {
	type fixture struct {
		a   *auth.Auth
		pk  *passkey.Plugin
		up  password.SignInResult
		dev *authenticator
	}
	registered := func(t *testing.T, e *faultEnv) fixture {
		t.Helper()
		a, pk, up := factorsPasskeyAuth(t, e.env, nil)
		dev := newAuthenticator(t)
		factorsRegister(t, pk, request(a, up.Token), dev, "Laptop")
		return fixture{a: a, pk: pk, up: up, dev: dev}
	}
	t.Run("register begin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			f := registered(t, e)
			return func(context.Context) error {
				_, err := f.pk.RegisterBegin(request(f.a, f.up.Token))
				return err
			}
		})
	})
	t.Run("register finish", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pk, up := factorsPasskeyAuth(t, e.env, nil)
			ctx := request(a, up.Token)
			begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
			cred := newAuthenticator(t).register(t, begin.Options)
			return func(context.Context) error {
				_, err := pk.RegisterFinish(request(a, up.Token), passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: cred})
				return err
			}
		})
	})
	t.Run("login begin", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			f := registered(t, e)
			return func(context.Context) error {
				_, err := f.pk.LoginBegin(anon(f.a))
				return err
			}
		})
	})
	t.Run("login finish", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			f := registered(t, e)
			lb := must[passkey.BeginResult](t)(f.pk.LoginBegin(anon(f.a)))
			cred := f.dev.assert(t, lb.Options, f.up.User.ID)
			return func(context.Context) error {
				_, err := f.pk.LoginFinish(anon(f.a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: cred})
				// A database failure must surface as itself. Reported as
				// ErrPasskeyInvalid it blames the user's passkey, so that
				// answer counts as swallowed here and the sweep flags it.
				if errors.Is(err, passkey.ErrPasskeyInvalid) {
					return nil
				}
				return err
			}
		})
	})
	t.Run("list", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			f := registered(t, e)
			return func(context.Context) error {
				_, err := f.pk.List(request(f.a, f.up.Token))
				return err
			}
		})
	})
	t.Run("remove", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			f := registered(t, e)
			list := must[[]passkey.Passkey](t)(f.pk.List(request(f.a, f.up.Token)))
			return func(context.Context) error { return f.pk.Remove(request(f.a, f.up.Token), list[0].ID) }
		})
	})
}

// ---------------------------------------------------------------- round-1 switches

// factorsTOTPAt is totpAt for a plugin configured with other digits or period.
func factorsTOTPAt(t *testing.T, secretB32 string, at time.Time, digits int, period time.Duration) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/int64(period/time.Second)))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%mod)
}

// TestFactors_PasswordSignUpImageAndRemember: the picture lands on the user
// and remember:false makes the sign-up session transient.
func TestFactors_PasswordSignUpImageAndRemember(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		no := false
		ctx := anon(a)
		up, err := pw.SignUp(ctx, password.SignUpRequest{Identifier: alice, Password: secret, Name: "Alice", Image: "https://img.example/alice.png", Remember: &no})
		if err != nil {
			t.Fatal(err)
		}
		if up.User.Image != "https://img.example/alice.png" {
			t.Fatalf("image = %q", up.User.Image)
		}
		u := must[auth.User](t)(a.User(context.Background(), up.User.ID))
		if u.Image != "https://img.example/alice.png" {
			t.Fatalf("stored image = %q", u.Image)
		}
		transient := false
		for _, ef := range auth.RequestEffects(ctx) {
			if ef.Kind == auth.EffectIssueSession {
				transient = ef.Transient
			}
		}
		if !transient {
			t.Fatal("remember:false at sign-up must issue a transient session (no expiry on the cookie)")
		}
	})
}

// TestFactors_PasswordWithoutSignUp: the operation does not exist, so the Go
// call and the route are refused as unknown, and sign-in still works for an
// account created another way.
func TestFactors_PasswordWithoutSignUp(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.WithoutSignUp())
		a := e.newAuth(t, nil, em, pw)
		if _, ok := a.Operation(password.EndpointSignUp); ok {
			t.Fatal("sign-up must not be registered")
		}
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); !errors.Is(err, auth.ErrOperationNotWired) {
			t.Fatalf("Go sign-up with WithoutSignUp: %v, want ErrOperationNotWired", err)
		}
		u := must[auth.User](t)(a.CreateUser(context.Background(), auth.NewUser{Name: "Alice"}))
		if _, err := a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: u.ID, Kind: email.KindEmail, Raw: alice, Verified: true}); err != nil {
			t.Fatal(err)
		}
		if err := pw.SetPassword(context.Background(), u.ID, secret); err != nil {
			t.Fatal(err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("sign-in: %v", err)
		}
	})
}

// TestFactors_PasswordSignUpWithoutSession: the account exists, no session
// was issued, and the password signs in.
func TestFactors_PasswordSignUpWithoutSession(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin(password.SignUpWithoutSession())
		a := e.newAuth(t, nil, em, pw)
		ctx := anon(a)
		up := must[password.SignInResult](t)(pw.SignUp(ctx, password.SignUpRequest{Identifier: alice, Password: secret}))
		if up.Token != "" || up.VerificationRequired || len(auth.RequestEffects(ctx)) != 0 {
			t.Fatalf("sign-up = %+v, effects %d; want no session", up, len(auth.RequestEffects(ctx)))
		}
		if has, err := pw.HasPassword(context.Background(), up.User.ID); err != nil || !has {
			t.Fatalf("HasPassword = %v, %v", has, err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("sign-in after sign-up: %v", err)
		}
	})
}

// TestFactors_PasswordVerify: the signed-in user's own password, right, wrong,
// over-long, and for a user without one; always the sign-in answer.
func TestFactors_PasswordVerify(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if err := pw.Verify(ctx, secret); err != nil {
			t.Fatalf("right password: %v", err)
		}
		if err := pw.Verify(ctx, "not the password"); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password: %v", err)
		}
		if err := pw.Verify(ctx, password.Secret(strings.Repeat("x", password.DefaultMaxLength+1))); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("over-long password: %v", err)
		}
		if err := pw.Verify(anon(a), secret); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("signed out: %v", err)
		}
		_, tok := factorsSession(t, a, "Social")
		if err := pw.Verify(request(a, tok), secret); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("user without a password: %v", err)
		}
	})
}

// TestFactors_PasswordSetPassword: server code sets a first password, replaces
// one, applies the rules, spends reset links, signs out every session, and
// refuses an unknown user.
func TestFactors_PasswordSetPassword(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		ctx := context.Background()
		up := signUpVerified(t, e, a, pw, em)
		if _, err := pw.Forgot(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		pending := e.mail.LastToken(t, a, alice)
		if err := pw.SetPassword(ctx, up.User.ID, "short"); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("rules at SetPassword: %v", err)
		}
		if err := pw.SetPassword(ctx, up.User.ID, "support set this one"); err != nil {
			t.Fatalf("replace: %v", err)
		}
		if _, _, _, err := a.ResolveSession(ctx, up.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("session after SetPassword: %v, want signed out", err)
		}
		if err := pw.Reset(anon(a), password.ResetRequest{Token: pending.Wire(), Password: "undo the change!"}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("reset link from before SetPassword: %v", err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "support set this one"}); err != nil {
			t.Fatalf("sign-in with the set password: %v", err)
		}
		social, _ := factorsSession(t, a, "Social")
		if err := pw.SetPassword(ctx, social.ID, "a first passphrase"); err != nil {
			t.Fatalf("first password: %v", err)
		}
		if has, _ := pw.HasPassword(ctx, social.ID); !has {
			t.Fatal("SetPassword must create the row")
		}
		if err := pw.SetPassword(ctx, "usr_nobody", "a first passphrase"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("unknown user: %v", err)
		}
	})
}

func TestFactors_PasswordSwitchFaults(t *testing.T) {
	t.Run("verify", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			a := e.newAuth(t, nil, em, pw)
			up := signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error { return pw.Verify(request(a, up.Token), secret) }
		})
	})
	t.Run("set password", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			a := e.newAuth(t, nil, em, pw)
			up := signUpVerified(t, e.env, a, pw, em)
			return func(ctx context.Context) error { return pw.SetPassword(ctx, up.User.ID, "support set this one") }
		})
	})
}

// TestFactors_TwoFactorDigitsAndPeriod: eight-digit codes every minute, and a
// six-digit code is then taken for a recovery code and refused.
func TestFactors_TwoFactorDigitsAndPeriod(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.WithDigits(twofactor.LongDigits), twofactor.WithPeriod(time.Minute))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if !strings.Contains(enr.URL, "digits=8") || !strings.Contains(enr.URL, "period=60") {
			t.Fatalf("url = %s", enr.URL)
		}
		if _, err := tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("a six-digit code with Digits(8): %v", err)
		}
		if _, err := tf.Confirm(ctx, factorsTOTPAt(t, enr.Secret, e.clock.Now(), twofactor.LongDigits, time.Minute)); err != nil {
			t.Fatalf("confirm with an eight-digit code: %v", err)
		}
		e.clock.Advance(time.Minute)
		pending := factorsPending(t, a, pw)
		if err := tf.Verify(request(a, pending), factorsTOTPAt(t, enr.Secret, e.clock.Now(), twofactor.LongDigits, time.Minute)); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
}

// TestFactors_TwoFactorRecoveryCodeOptions: a shorter length, an app
// generator, and regeneration that kills the old set.
func TestFactors_TwoFactorRecoveryCodeOptions(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.RecoveryCodeLength(twofactor.MinRecoveryCodeLength), twofactor.RecoveryCodeCount(2))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		if len(f.codes) != 2 || len(f.codes[0]) != len("XXXX-XXXX") {
			t.Fatalf("codes = %v", f.codes)
		}
		ctx := request(a, f.up.Token)
		if _, err := tf.RegenerateRecoveryCodes(ctx, "000000"); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("regenerate with a wrong code: %v", err)
		}
		fresh := must[twofactor.RecoveryCodes](t)(tf.RegenerateRecoveryCodes(ctx, totpAt(t, f.secret, e.clock.Now())))
		if len(fresh.Codes) != 2 || fresh.Codes[0] == f.codes[0] {
			t.Fatalf("regenerated = %v", fresh.Codes)
		}
		pending := factorsPending(t, a, pw)
		if err := tf.Verify(request(a, pending), f.codes[0]); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("old recovery code after regenerate: %v", err)
		}
		if err := tf.Verify(request(a, pending), fresh.Codes[1]); err != nil {
			t.Fatalf("new recovery code: %v", err)
		}

	})
}

// TestFactors_TwoFactorRecoveryCodeGenerator: the app's codes are handed out
// as given and accepted however the user types them.
func TestFactors_TwoFactorRecoveryCodeGenerator(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.RecoveryCodeGenerator(func() []string { return []string{"apple tree", "blue sky"} }))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		if len(f.codes) != 2 || f.codes[0] != "apple tree" || f.codes[1] != "blue sky" {
			t.Fatalf("codes = %v", f.codes)
		}
		pending := factorsPending(t, a, pw)
		if err := tf.Verify(request(a, pending), " Apple-Tree "); err != nil {
			t.Fatalf("a generator code typed loosely: %v", err)
		}
		pending = factorsPending(t, a, pw)
		if err := tf.Verify(request(a, pending), "apple tree"); !errors.Is(err, twofactor.ErrCodeInvalid) {
			t.Fatalf("a generator code used twice: %v", err)
		}
	})
}

// TestFactors_TwoFactorLockoutOption: two wrong codes lock for one minute.
func TestFactors_TwoFactorLockoutOption(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.Lockout(2, time.Minute))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		wrong := factorsWrongCode(t, e, f.secret)
		for range 2 {
			if err := tf.Verify(request(a, pending), wrong); !errors.Is(err, twofactor.ErrCodeInvalid) {
				t.Fatalf("wrong code: %v", err)
			}
		}
		if err := tf.Verify(request(a, pending), totpAt(t, f.secret, e.clock.Now())); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("after 2 failures with Lockout(2, 1m): %v, want ErrLocked", err)
		}
		e.clock.Advance(time.Minute + time.Second)
		if err := tf.Verify(request(a, pending), totpAt(t, f.secret, e.clock.Now())); err != nil {
			t.Fatalf("after the one-minute lock: %v", err)
		}
	})
}

// TestFactors_TwoFactorVerifyRateLimited: the per-IP rule on verify trips
// before the lockout would, from one address.
func TestFactors_TwoFactorVerifyRateLimited(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		// A generous lockout, so the rate rule is what answers.
		tf := factorsTwoFactor(twofactor.Lockout(1000, time.Minute))
		a := e.newAuth(t, nil, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		wrong := factorsWrongCode(t, e, f.secret)
		const ceiling = 1000
		var last error
		calls := 0
		for calls < ceiling {
			last = tf.Verify(request(a, pending), wrong)
			calls++
			if !errors.Is(last, twofactor.ErrCodeInvalid) {
				break
			}
		}
		if !errors.Is(last, auth.ErrRateLimited) {
			t.Fatalf("after %d verifies from one IP: %v, want ErrRateLimited", calls, last)
		}
	})
}

// TestFactors_PasskeyListDetailsAndRename: the list carries the authenticator
// details from the stored credential; rename relabels only the user's own.
func TestFactors_PasskeyListDetailsAndRename(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, nil)
		ctx := request(a, up.Token)
		added := factorsRegister(t, pk, ctx, newAuthenticator(t), "Laptop")
		list := must[[]passkey.Passkey](t)(pk.List(ctx))
		if len(list) != 1 || list[0].AAGUID != "" || list[0].BackedUp || len(list[0].Transports) != 1 || list[0].Transports[0] != "internal" {
			t.Fatalf("list = %+v; the software authenticator sends a zero AAGUID, no backup flag and transport internal", list)
		}
		if err := pk.Rename(ctx, added.ID, strings.Repeat("n", 70)); err != nil {
			t.Fatalf("rename: %v", err)
		}
		if list = must[[]passkey.Passkey](t)(pk.List(ctx)); list[0].Name != strings.Repeat("n", 64) {
			t.Fatalf("renamed to %q, want 64 characters", list[0].Name)
		}
		if err := pk.Rename(ctx, "pky_nothing", "x"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("rename unknown: %v", err)
		}
		_, otherTok := factorsSession(t, a, "Mallory")
		if err := pk.Rename(request(a, otherTok), added.ID, "mine now"); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("rename another user's passkey: %v", err)
		}
	})
}

// TestFactors_PasskeyAttachment: the attachment reaches the browser options;
// anything but the two WebAuthn values is refused.
func TestFactors_PasskeyAttachment(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a, pk, up := factorsPasskeyAuth(t, e, nil)
		ctx := request(a, up.Token)
		begin := must[passkey.BeginResult](t)(pk.RegisterBeginWith(ctx, passkey.RegisterBeginRequest{AuthenticatorAttachment: passkey.AttachmentPlatform}))
		var o struct {
			PublicKey struct {
				Selection struct {
					Attachment string `json:"authenticatorAttachment"`
					UV         string `json:"userVerification"`
				} `json:"authenticatorSelection"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(begin.Options, &o); err != nil || o.PublicKey.Selection.Attachment != "platform" || o.PublicKey.Selection.UV != "required" {
			t.Fatalf("options = %s (%v); want attachment platform and user verification still required", begin.Options, err)
		}
		plain := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		o.PublicKey.Selection.Attachment = ""
		if err := json.Unmarshal(plain.Options, &o); err != nil || o.PublicKey.Selection.Attachment != "" {
			t.Fatalf("default options carry an attachment: %s", plain.Options)
		}
		if _, err := pk.RegisterBeginWith(ctx, passkey.RegisterBeginRequest{AuthenticatorAttachment: "usb"}); !errors.Is(err, passkey.ErrAttachmentInvalid) {
			t.Fatalf("bad attachment: %v", err)
		}
	})
}

func TestFactors_SwitchFaults(t *testing.T) {
	t.Run("twofactor recovery-codes", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
			a := e.newAuth(t, nil, em, pw, tf)
			f := factorsEnroll(t, e.env, a, pw, em, tf)
			code := totpAt(t, f.secret, e.clock.Now())
			return func(context.Context) error {
				_, err := tf.RegenerateRecoveryCodes(request(a, f.up.Token), code)
				return err
			}
		})
	})
	t.Run("passkey rename", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, pk, up := factorsPasskeyAuth(t, e.env, nil)
			added := factorsRegister(t, pk, request(a, up.Token), newAuthenticator(t), "Laptop")
			return func(context.Context) error { return pk.Rename(request(a, up.Token), added.ID, "Desk") }
		})
	})
}

// TestFactors_PasswordSignInUnverifiedSendsNothingByDefault: the right
// password on an unverified address is refused as before, and without a
// resend option on the identifier plugin no second verification mail goes out.
func TestFactors_PasswordSignInUnverifiedSendsNothingByDefault(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.RequireVerified()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		before := len(e.mail.To(a, alice))
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, auth.ErrNotVerified) {
			t.Fatalf("sign-in before verify: %v", err)
		}
		if after := len(e.mail.To(a, alice)); after != before {
			t.Fatalf("a refused sign-in sent %d extra mail(s) with no resend option", after-before)
		}
	})
}

// TestFactors_TwoFactorBadGeneratorFailsConfirm: a generator that hands back
// a duplicate fails the confirm with ErrBadRecoveryCodes, and the factor stays
// off because the transaction rolled back.
func TestFactors_TwoFactorBadGeneratorFailsConfirm(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := factorsTwoFactor(twofactor.RecoveryCodeGenerator(func() []string { return []string{"same", "SAME"} }))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		if _, err := tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, twofactor.ErrBadRecoveryCodes) {
			t.Fatalf("confirm with a bad generator: %v", err)
		}
		if on, err := tf.SecondFactorRequired(context.Background(), up.User.ID); err != nil || on {
			t.Fatalf("after a failed confirm: %v, %v", on, err)
		}
	})
}

// TestFactors_TwoFactorPendingSessionTTL: the pending session dies after the
// configured time, so the code step cannot be finished later.
func TestFactors_TwoFactorPendingSessionTTL(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, tf := e.emailPlugin(), e.passwordPlugin(), factorsTwoFactor()
		a := e.newAuth(t, []auth.Option{auth.WithPendingSessionTTL(time.Minute)}, em, pw, tf)
		f := factorsEnroll(t, e, a, pw, em, tf)
		pending := factorsPending(t, a, pw)
		e.clock.Advance(time.Minute + time.Second)
		if err := tf.Verify(request(a, pending), totpAt(t, f.secret, e.clock.Now())); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("verify after the pending TTL: %v, want ErrSignedOut", err)
		}
	})
}

// TestFactors_PasswordSignInUnverifiedResends: with the identifier plugin's
// resend option on, the right password on an unverified address is still
// refused, and a fresh verification mail goes out.
func TestFactors_PasswordSignInUnverifiedResends(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.RequireVerified(), email.ResendOnSignIn()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		before := len(e.mail.To(a, alice))
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, auth.ErrNotVerified) {
			t.Fatalf("sign-in before verify: %v", err)
		}
		if after := len(e.mail.To(a, alice)); after != before+1 {
			t.Fatalf("mails after a refused sign-in: %d, want %d (one more verification)", after, before+1)
		}
		// A wrong password sends nothing: only the owner of the password
		// gets the mail, so a stranger cannot spam the address.
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "wrong password!"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password: %v", err)
		}
		if after := len(e.mail.To(a, alice)); after != before+1 {
			t.Fatalf("a wrong password sent mail: %d, want %d", after, before+1)
		}
	})
}

// TestFactors_PasswordResendFaults: a database failure while re-sending the
// verification after a refused sign-in is logged and never changes the
// answer, which stays ErrNotVerified. Calls 5 to 9 are the resend itself
// (spending the earlier verify links, the email plugin's token row, the
// check that no other account verified the address, and delivery, run after
// the sign-in's transaction ended): swallowing those is the documented
// behaviour, since the client's answer must not depend on whether a mail went
// out.
func TestFactors_PasswordResendFaults(t *testing.T) {
	const resendFirstCall, resendLastCall = 5, 9
	swallowOK := make([]int, 0, resendLastCall-resendFirstCall+1)
	for k := resendFirstCall; k <= resendLastCall; k++ {
		swallowOK = append(swallowOK, k)
	}
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em, pw := e.emailPlugin(email.RequireVerified(), email.ResendOnSignIn()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		return func(context.Context) error {
			_, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
			if errors.Is(err, auth.ErrNotVerified) {
				// The expected refusal: success for this sweep, so a fault
				// that changed the answer would show as an error here.
				return nil
			}
			if err == nil {
				return errors.New("an unverified sign-in succeeded")
			}
			return err
		}
	}, swallowOK...)
}
