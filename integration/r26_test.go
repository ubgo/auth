package integration

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
)

// Round 26, end to end on every engine: the phone plugin is
// enumeration-safe the way the email plugin is (TestR24).

// noticePrefix starts the phone plugin's default duplicate sign-up text.
const noticePrefix = "Someone tried to sign up"

// TestR26_PhoneTakenNumberGetsNoCode: adding, resending for or changing to a
// number another account has verified answers the requester exactly as a
// free number does, and the number gets the duplicate sign-up notice instead
// of a code that could only answer auth.identity_taken; so verify and
// confirm-change can only answer auth.code_invalid. With a Verifier the
// provider is never asked to text the number. A free number still gets its
// code.
func TestR26_PhoneTakenNumberGetsNoCode(t *testing.T) {
	const taken, free = "+15550100260", "+15550100261"
	for _, mode := range []struct {
		name string
		v    *fakeVerifier
	}{{"own codes", nil}, {"verifier", &fakeVerifier{code: "424242"}}} {
		t.Run(mode.name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				opts := []phone.Option{phone.Login(), phone.Multiple()}
				if mode.v != nil {
					mode.v.sent = nil
					opts = append(opts, phone.WithVerifier(mode.v))
				}
				ph := e.phonePlugin(opts...)
				a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph)
				ali, _ := identUser(t, a, alice)
				must[auth.Identity](t)(a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: ali, Kind: phone.KindPhone, Raw: taken, Verified: true, Primary: true}))
				bob, bobTok := identUser(t, a, identBob)
				// guess is a code nobody was sent: the fake provider accepts
				// only 424242, and the plugin's own code reached no one.
				const guess = "000000"
				verifierSends := func() int {
					a.WaitDeliveries()
					if mode.v == nil {
						return 0
					}
					mode.v.mu.Lock()
					defer mode.v.mu.Unlock()
					return len(mode.v.sent)
				}
				notice := func(step string, before, sends int) {
					t.Helper()
					a.WaitDeliveries()
					e.sms.mu.Lock()
					got := append([]string(nil), e.sms.sent[taken]...)
					e.sms.mu.Unlock()
					if len(got) != before+1 || !strings.HasPrefix(got[len(got)-1], noticePrefix) {
						t.Fatalf("%s: texts to the taken number %q, want only the sign-up notice", step, got[before:])
					}
					if n := verifierSends(); n != sends {
						t.Fatalf("%s: the provider was asked to text %d times, want %d", step, n, sends)
					}
				}

				before, sends := e.sms.Count(a, taken), verifierSends()
				if err := ph.Add(request(a, bobTok), taken); err != nil {
					t.Fatalf("add a taken number: %v", err)
				}
				notice("add", before, sends)
				if err := ph.Verify(request(a, bobTok), taken, guess); !errors.Is(err, auth.ErrCodeInvalid) {
					t.Fatalf("verify a taken number = %v, want code_invalid", err)
				}

				before = e.sms.Count(a, taken)
				if err := ph.Resend(request(a, bobTok), taken); err != nil {
					t.Fatalf("resend for a taken number: %v", err)
				}
				notice("resend", before, sends)

				before = e.sms.Count(a, taken)
				if err := ph.Change(request(a, bobTok), taken); err != nil {
					t.Fatalf("change to a taken number: %v", err)
				}
				notice("change", before, sends)
				if _, err := ph.ConfirmChange(request(a, bobTok), taken, guess); !errors.Is(err, auth.ErrCodeInvalid) {
					t.Fatalf("confirm a taken number = %v, want code_invalid", err)
				}
				if ids := phoneOf(t, a, bob); len(ids) != 1 || ids[0].Verified() {
					t.Fatalf("bob's rows after the refused steps: %+v", ids)
				}

				// The inverse: a free number gets its code, from the plugin or
				// from the provider.
				if err := ph.Add(request(a, bobTok), free); err != nil {
					t.Fatal(err)
				}
				if mode.v == nil {
					code := e.sms.LastCode(t, a, free)
					if err := ph.Verify(request(a, bobTok), free, code); err != nil {
						t.Fatalf("verify a free number: %v", err)
					}
				} else if n := verifierSends(); n != sends+1 {
					t.Fatalf("a free number: the provider was asked %d times, want %d", n, sends+1)
				}
			})
		})
	}
}

// TestR26_CodeSignInFieldsRefusedBeforeTheCode: a sign-up field sent both
// at the top level of the body and under "fields", and an undeclared field,
// are auth.field_invalid on the phone and the email code sign-in, before
// the code is looked at (the codes here were never sent).
func TestR26_CodeSignInFieldsRefusedBeforeTheCode(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
		em := e.emailPlugin(email.SignUpWithCode())
		a := e.newAuth(t, r21FieldsOpts(), ph, em)
		both := `{"plan":"team","fields":{"plan":"free"},"code":"000000",`

		var pin phone.SignInRequest
		if err := json.Unmarshal([]byte(both+`"phone":"+15550100262"}`), &pin); err != nil {
			t.Fatal(err)
		}
		if _, err := ph.SignInWith(anon(a), pin); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("phone, a field sent both ways = %v", err)
		}

		var ein email.CodeRequest
		if err := json.Unmarshal([]byte(both+`"email":"fields@example.com"}`), &ein); err != nil {
			t.Fatal(err)
		}
		if _, err := em.SignInCodeWith(anon(a), ein); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("email, a field sent both ways = %v", err)
		}
		bad := email.CodeRequest{Email: "fields@example.com", Code: "000000", Fields: r21Fields(t, map[string]any{"role": "admin"})}
		if _, err := em.SignInCodeWith(anon(a), bad); !errors.Is(err, auth.ErrFieldInvalid) {
			t.Fatalf("email, an undeclared field = %v", err)
		}
	})
}

// TestR26_FaultsPhoneMultipleAndCodeSignUpFields: every database failure on
// the Multiple() paths of the phone plugin and on the sign-up fields write
// of both code sign-ins fails the operation instead of reporting success for
// work not done.
func TestR26_FaultsPhoneMultipleAndCodeSignUpFields(t *testing.T) {
	multi := func(t *testing.T, e *faultEnv) (*auth.Auth, *phone.Plugin, auth.Token) {
		ph := e.phonePlugin(phone.Login(), phone.Multiple())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph)
		_, tok := identUser(t, a, alice)
		withVerifiedNumber(t, e.env, a, ph, tok, phoneOld)
		return a, ph, tok
	}
	identRun(t, []identSweep{
		{"verify a second number", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph, tok := multi(t, e)
			if err := ph.Add(request(a, tok), phoneNew); err != nil {
				t.Fatal(err)
			}
			code := e.sms.LastCode(t, a, phoneNew)
			return func(context.Context) error { return ph.Verify(request(a, tok), phoneNew, code) }
		}},
		{"remove the primary of two", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph, tok := multi(t, e)
			withVerifiedNumber(t, e.env, a, ph, tok, phoneNew)
			return func(context.Context) error { return ph.Remove(request(a, tok), phoneOld) }
		}},
		{"list", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph, tok := multi(t, e)
			return func(context.Context) error { _, err := ph.List(request(a, tok)); return err }
		}},
		{"make primary", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph, tok := multi(t, e)
			withVerifiedNumber(t, e.env, a, ph, tok, phoneNew)
			return func(context.Context) error { return ph.MakePrimary(request(a, tok), phoneNew) }
		}},
		{"phone code sign-up with fields", func(t *testing.T, e *faultEnv) func(context.Context) error {
			ph := e.phonePlugin(phone.Login(), phone.SignInWithCode())
			a := e.newAuth(t, r21FieldsOpts(), ph)
			if err := ph.SendCode(anon(a), phoneNew); err != nil {
				t.Fatal(err)
			}
			in := phone.SignInRequest{Phone: phoneNew, Code: e.sms.LastCode(t, a, phoneNew), Fields: r21Fields(t, map[string]any{r21ColPlan: "team"})}
			return func(context.Context) error { _, err := ph.SignInWith(anon(a), in); return err }
		}},
		{"email code sign-up with fields", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em := e.emailPlugin(email.SignUpWithCode())
			a := e.newAuth(t, r21FieldsOpts(), em)
			const addr = "codefields@example.com"
			if err := em.SendCode(anon(a), addr); err != nil {
				t.Fatal(err)
			}
			a.WaitDeliveries()
			in := email.CodeRequest{Email: addr, Code: lastMailCode(t, e.env, a, addr), Fields: r21Fields(t, map[string]any{r21ColSeats: 3})}
			return func(context.Context) error { _, err := em.SignInCodeWith(anon(a), in); return err }
		}},
	})
}

// r26Period is the ExpireAfter period of the change-expired tests.
const r26Period = 24 * time.Hour

// r26Fresh is a new password every policy in these tests accepts.
const r26Fresh = "a fresh passphrase now"

// TestR26_ChangeExpiredRefusals: change-expired refuses a current password
// longer than MaxLength as a wrong one (no hash is spent on it), a new
// password the length policy refuses, and, under RequireVerified, the right
// expired password of an unverified address.
func TestR26_ChangeExpiredRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.RequireVerified()), e.passwordPlugin(password.ExpireAfter(r26Period), password.MaxLength(64))
		a := e.newAuth(t, nil, em, pw)
		must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}))
		e.clock.Advance(r26Period + time.Hour)
		ce := func(cur, next string) error {
			_, err := pw.ChangeExpired(anon(a), password.ChangeExpiredRequest{Identifier: alice, Current: password.Secret(cur), New: password.Secret(next)})
			return err
		}
		if err := ce(strings.Repeat("x", 65), r26Fresh); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("a current password over MaxLength: %v, want ErrInvalidCredentials", err)
		}
		if err := ce(secret, "short"); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("a too-short new password: %v, want ErrTooShort", err)
		}
		if err := ce(secret, r26Fresh); !errors.Is(err, auth.ErrNotVerified) {
			t.Fatalf("an unverified address: %v, want ErrNotVerified", err)
		}
	})
}

// TestR26_FaultsPasswordHistoryAndExpiry: every database failure on a
// change, a reset and a change-expired under History, and on a
// change-expired without it, fails the operation.
func TestR26_FaultsPasswordHistoryAndExpiry(t *testing.T) {
	wire := func(t *testing.T, e *faultEnv, opts ...password.Option) (*auth.Auth, *email.Plugin, *password.Plugin, password.SignInResult) {
		em, pw := e.emailPlugin(), e.passwordPlugin(opts...)
		a := e.newAuth(t, nil, em, pw)
		return a, em, pw, signUpVerified(t, e.env, a, pw, em)
	}
	expired := func(t *testing.T, e *faultEnv, opts ...password.Option) func(context.Context) error {
		a, _, pw, _ := wire(t, e, append([]password.Option{password.ExpireAfter(r26Period)}, opts...)...)
		e.clock.Advance(r26Period + time.Hour)
		return func(context.Context) error {
			_, err := pw.ChangeExpired(anon(a), password.ChangeExpiredRequest{Identifier: alice, Current: password.Secret(secret), New: password.Secret(r26Fresh)})
			return err
		}
	}
	identRun(t, []identSweep{
		{"change under History", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, _, pw, up := wire(t, e, password.History(3))
			ctx := request(a, up.Token)
			if err := pw.Change(ctx, password.ChangeRequest{Current: password.Secret(secret), New: password.Secret("second passphrase here")}); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error {
				return pw.Change(ctx, password.ChangeRequest{Current: password.Secret("second passphrase here"), New: password.Secret(r26Fresh)})
			}
		}},
		{"change-expired under History", func(t *testing.T, e *faultEnv) func(context.Context) error {
			return expired(t, e, password.History(3))
		}},
		{"change-expired", func(t *testing.T, e *faultEnv) func(context.Context) error {
			return expired(t, e)
		}},
	})
}

// TestR26_FaultsSignUpAndReusedCodes: every database failure on a password
// sign-up that writes sign-up fields, on one whose address another account
// has verified (the owner's notice is queued in the same transaction), and
// on a second code send under ReuseCodeOnResend fails the operation.
func TestR26_FaultsSignUpAndReusedCodes(t *testing.T) {
	identRun(t, []identSweep{
		{"password sign-up with fields", func(t *testing.T, e *faultEnv) func(context.Context) error {
			pw := e.passwordPlugin()
			a := e.newAuth(t, r21FieldsOpts(), e.emailPlugin(), pw)
			in := password.SignUpRequest{Identifier: alice, Password: secret, Fields: r21Fields(t, map[string]any{r21ColPlan: "team"})}
			return func(context.Context) error { _, err := pw.SignUp(anon(a), in); return err }
		}},
		{"password sign-up with a taken address", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em, pw := e.emailPlugin(), e.passwordPlugin()
			a := e.newAuth(t, nil, em, pw)
			signUpVerified(t, e.env, a, pw, em)
			return func(context.Context) error {
				_, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret})
				return err
			}
		}},
		{"second code send under ReuseCodeOnResend", func(t *testing.T, e *faultEnv) func(context.Context) error {
			em := e.emailPlugin(email.SignUpWithCode(), email.ReuseCodeOnResend())
			a := e.newAuth(t, []auth.Option{auth.WithSecret(r21Secret)}, em)
			const addr = "reuse@example.com"
			if err := em.SendCode(anon(a), addr); err != nil {
				t.Fatal(err)
			}
			a.WaitDeliveries()
			return func(context.Context) error { return em.SendCode(anon(a), addr) }
		}},
	})
}
