package integration

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
)

// Numbers the round-2 phone tests use.
const (
	phoneOld = "+15550100200"
	phoneNew = "+15550100201"
)

// phoneOf returns the user's phone identities, for asserting the state after
// a change in one line.
func phoneOf(t *testing.T, a *auth.Auth, userID string) []auth.Identity {
	t.Helper()
	var out []auth.Identity
	for _, idn := range must[[]auth.Identity](t)(a.Identities(context.Background(), userID)) {
		if idn.Kind == phone.KindPhone {
			out = append(out, idn)
		}
	}
	return out
}

// withVerifiedNumber gives the user of tok the number, verified.
func withVerifiedNumber(t *testing.T, e *env, a *auth.Auth, ph *phone.Plugin, tok auth.Token, number string) {
	t.Helper()
	if err := ph.Add(request(a, tok), number); err != nil {
		t.Fatal(err)
	}
	if err := ph.Verify(request(a, tok), number, e.sms.LastCode(t, a, number)); err != nil {
		t.Fatal(err)
	}
}

// TestPhone_ChangeReplacesTheNumberInOneStep: a code to the new number, then
// one confirm that makes it the verified primary and removes the old one; in
// between the old number keeps working, and nothing exists for the new one.
func TestPhone_ChangeReplacesTheNumberInOneStep(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph)
		uid, tok := identUser(t, a, alice)
		withVerifiedNumber(t, e, a, ph, tok, phoneOld)

		if err := ph.Change(request(a, tok), phoneNew); err != nil {
			t.Fatal(err)
		}
		if ids := phoneOf(t, a, uid); len(ids) != 1 || ids[0].Value != phoneOld {
			t.Fatalf("after change, before confirm: %+v", ids)
		}
		code := e.sms.LastCode(t, a, phoneNew)
		if _, err := ph.ConfirmChange(request(a, tok), phoneNew, "000000"); !errors.Is(err, phone.ErrCodeInvalid) && code != "000000" {
			t.Fatalf("a wrong code = %v", err)
		}
		if _, err := ph.ConfirmChange(request(a, tok), phoneOld, code); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("the right code for another number = %v", err)
		}
		res, err := ph.ConfirmChange(request(a, tok), phoneNew, code)
		if err != nil || res.Phone != phoneNew {
			t.Fatalf("confirm = %+v %v", res, err)
		}
		ids := phoneOf(t, a, uid)
		if len(ids) != 1 || ids[0].Value != phoneNew || !ids[0].Verified() || !ids[0].IsPrimary {
			t.Fatalf("after confirm: %+v", ids)
		}
		if _, err := ph.ConfirmChange(request(a, tok), phoneNew, code); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("a code used twice = %v", err)
		}
		if _, err := ph.ConfirmChange(request(a, tok), "not a number", code); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("a malformed number = %v", err)
		}
		if err := ph.Change(request(a, tok), "not a number"); !errors.Is(err, auth.ErrIdentifierInvalid) {
			t.Fatalf("change to a malformed number = %v", err)
		}
		// Change needs a fresh sign-in; confirm needs only a session.
		e.clock.Advance(auth.DefaultFreshWindow + time.Second)
		if err := ph.Change(request(a, tok), phoneOld); !errors.Is(err, auth.ErrFreshSessionRequired) {
			t.Fatalf("change on a stale session = %v", err)
		}
	})
}

// TestPhone_ChangeEdgeCases: a user with no number sets one; a number the
// user already holds unverified is verified in place, not duplicated; a
// number another account verified after the code was sent is refused at
// confirm.
func TestPhone_ChangeEdgeCases(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ph := e.phonePlugin(phone.Login())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph)
		uid, tok := identUser(t, a, alice)
		if err := ph.Change(request(a, tok), phoneNew); err != nil {
			t.Fatal(err)
		}
		if _, err := ph.ConfirmChange(request(a, tok), phoneNew, e.sms.LastCode(t, a, phoneNew)); err != nil {
			t.Fatal(err)
		}
		if ids := phoneOf(t, a, uid); len(ids) != 1 || !ids[0].Verified() {
			t.Fatalf("first number by change: %+v", ids)
		}

		other, otherTok := identUser(t, a, identBob)
		if err := ph.Add(request(a, otherTok), phoneOld); err != nil {
			t.Fatal(err)
		}
		if err := ph.Change(request(a, otherTok), phoneOld); err != nil {
			t.Fatal(err)
		}
		if _, err := ph.ConfirmChange(request(a, otherTok), phoneOld, e.sms.LastCode(t, a, phoneOld)); err != nil {
			t.Fatal(err)
		}
		if ids := phoneOf(t, a, other); len(ids) != 1 || !ids[0].Verified() || !ids[0].IsPrimary {
			t.Fatalf("own unverified number confirmed: %+v", ids)
		}
		// The race: Bob is texted a code for a free number, then Alice
		// verifies that number first. Bob's confirm is refused. (A number
		// already taken when Bob asks gets no code at all: TestR26.)
		const raced = "+15550100202"
		if err := ph.Change(request(a, otherTok), raced); err != nil {
			t.Fatal(err)
		}
		bobCode := e.sms.LastCode(t, a, raced)
		if err := ph.Change(request(a, tok), raced); err != nil {
			t.Fatal(err)
		}
		if _, err := ph.ConfirmChange(request(a, tok), raced, e.sms.LastCode(t, a, raced)); err != nil {
			t.Fatal(err)
		}
		if _, err := ph.ConfirmChange(request(a, otherTok), raced, bobCode); !errors.Is(err, auth.ErrIdentityTaken) {
			t.Fatalf("confirm to a number taken meanwhile = %v", err)
		}
		if ids := phoneOf(t, a, other); len(ids) != 1 || ids[0].Value != phoneOld {
			t.Fatalf("a refused confirm must change nothing: %+v", ids)
		}
	})
}

// fakeVerifier is a provider's verification service: it records every Send
// and accepts one code.
type fakeVerifier struct {
	mu    sync.Mutex
	sent  []string
	code  string
	fail  error
	calls int
}

func (v *fakeVerifier) Send(_ context.Context, number string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sent = append(v.sent, number)
	return nil
}

func (v *fakeVerifier) Check(_ context.Context, _, code string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.fail != nil {
		return v.fail
	}
	if code != v.code {
		return phone.ErrCodeInvalid
	}
	return nil
}

func (v *fakeVerifier) sends(a *auth.Auth) []string {
	a.WaitDeliveries()
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.sent...)
}

// TestPhone_Verifier: with a Verifier the provider makes and checks every
// code: no text goes through the SMSSender for a code, the provider's Send
// runs after commit, its verdict decides verify, sign-in and change, and a
// provider failure fails the operation instead of refusing the user.
func TestPhone_Verifier(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		v := &fakeVerifier{code: "424242"}
		ph := e.phonePlugin(phone.Login(), phone.SignInWithCode(), phone.WithVerifier(v))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph)
		uid, tok := identUser(t, a, alice)

		if err := ph.Add(request(a, tok), phoneOld); err != nil {
			t.Fatal(err)
		}
		if got := v.sends(a); len(got) != 1 || got[0] != phoneOld {
			t.Fatalf("provider sends = %v", got)
		}
		if n := e.sms.Count(a, phoneOld); n != 0 {
			t.Fatalf("%d texts went through the SMSSender for a provider code", n)
		}
		if err := ph.Verify(request(a, tok), phoneOld, "111111"); !errors.Is(err, phone.ErrCodeInvalid) {
			t.Fatalf("a code the provider refuses = %v", err)
		}
		if err := ph.Verify(request(a, tok), phoneOld, "424242"); err != nil {
			t.Fatal(err)
		}
		if ids := phoneOf(t, a, uid); len(ids) != 1 || !ids[0].Verified() {
			t.Fatalf("after provider verify: %+v", ids)
		}

		// Sign-in by code, for an unknown number: the provider sends, the
		// provider checks, the account is created.
		if err := ph.SendCode(anon(a), phoneNew); err != nil {
			t.Fatal(err)
		}
		if got := v.sends(a); len(got) != 2 || got[1] != phoneNew {
			t.Fatalf("provider sends = %v", got)
		}
		in, err := ph.SignIn(anon(a), phoneNew, "424242")
		if err != nil || !in.Created {
			t.Fatalf("sign-in through the provider = %+v %v", in, err)
		}
		// Change through the provider.
		if err := ph.Change(request(a, tok), "+15550100202"); err != nil {
			t.Fatal(err)
		}
		if _, err := ph.ConfirmChange(request(a, tok), "+15550100202", "424242"); err != nil {
			t.Fatal(err)
		}
		if ids := phoneOf(t, a, uid); len(ids) != 1 || ids[0].Value != "+15550100202" {
			t.Fatalf("after provider change: %+v", ids)
		}
		// A provider outage is an error, not a wrong code.
		v.fail = errors.New("provider: timeout")
		if _, err := ph.SignIn(anon(a), phoneNew, "424242"); !errors.Is(err, v.fail) {
			t.Fatalf("provider failure = %v", err)
		}
		// Messages that are not codes still go through the SMSSender.
		v.fail = nil
		if err := a.Deliver(context.Background(), auth.Identity{Kind: phone.KindPhone, Value: phoneOld}, auth.Message{Purpose: auth.PurposeReset, Link: "https://x/reset"}); err != nil {
			t.Fatal(err)
		}
		if n := e.sms.Count(a, phoneOld); n != 1 {
			t.Fatalf("%d texts for a reset link", n)
		}
	})
}

// TestIdentFaults_PhoneRound2: change and confirm-change, with and without a
// provider, surface every database failure.
func TestIdentFaults_PhoneRound2(t *testing.T) {
	wire := func(t *testing.T, e *faultEnv, opts ...phone.Option) (*auth.Auth, *phone.Plugin) {
		ph := e.phonePlugin(append([]phone.Option{phone.Login()}, opts...)...)
		return e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), ph), ph
	}
	identRun(t, []identSweep{
		{"change", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := wire(t, e)
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { return ph.Change(request(a, tok), phoneNew) }
		}},
		{"confirm change replacing a number", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := wire(t, e)
			_, tok := identUser(t, a, alice)
			withVerifiedNumber(t, e.env, a, ph, tok, phoneOld)
			if err := ph.Change(request(a, tok), phoneNew); err != nil {
				t.Fatal(err)
			}
			code := e.sms.LastCode(t, a, phoneNew)
			return func(context.Context) error { _, err := ph.ConfirmChange(request(a, tok), phoneNew, code); return err }
		}},
		{"confirm change of an own unverified number", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := wire(t, e)
			_, tok := identUser(t, a, alice)
			if err := ph.Add(request(a, tok), phoneOld); err != nil {
				t.Fatal(err)
			}
			// Add and Change both text phoneOld in the background; the Add
			// text must land first, or LastCode reads its (replaced) code.
			a.WaitDeliveries()
			if err := ph.Change(request(a, tok), phoneOld); err != nil {
				t.Fatal(err)
			}
			code := e.sms.LastCode(t, a, phoneOld)
			return func(context.Context) error { _, err := ph.ConfirmChange(request(a, tok), phoneOld, code); return err }
		}},
		{"verify through a provider", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := wire(t, e, phone.WithVerifier(&fakeVerifier{code: "424242"}))
			_, tok := identUser(t, a, alice)
			if err := ph.Add(request(a, tok), phoneOld); err != nil {
				t.Fatal(err)
			}
			return func(context.Context) error { return ph.Verify(request(a, tok), phoneOld, "424242") }
		}},
		{"sign in through a provider", func(t *testing.T, e *faultEnv) func(context.Context) error {
			a, ph := wire(t, e, phone.SignInWithCode(), phone.WithVerifier(&fakeVerifier{code: "424242"}))
			return func(context.Context) error { _, err := ph.SignIn(anon(a), phoneNew, "424242"); return err }
		}},
	})
}
