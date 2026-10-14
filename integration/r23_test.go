package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/terms"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

// Round 23 on real databases: verify links revoked by a resend, the
// username available route's own limit, the support desk's two-factor reset
// and unlock, several phone numbers per account, and the terms history.

// TestR23_EmailResendRevokesEarlierLink: a resent verify link is the only
// one that works; the link from the sign-up mail is spent by the resend.
func TestR23_EmailResendRevokesEarlierLink(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		a.WaitDeliveries()
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatal(err)
		}
		first := e.mail.LastToken(t, a, alice)
		must0(t, em.Resend(anon(a), alice))
		second := e.mail.LastToken(t, a, alice)
		if first == second {
			t.Fatal("the resend mailed the same link")
		}
		if _, err := em.Verify(anon(a), first); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("the earlier link still verifies: %v", err)
		}
		if _, err := em.Verify(anon(a), second); err != nil {
			t.Fatalf("the newest link: %v", err)
		}
	})
}

// TestR23_UsernameAvailableHasItsOwnLimit: the available route stops one
// client after its limit, counted apart from the set route, and lets it in
// again once the window has passed.
func TestR23_UsernameAvailableHasItsOwnLimit(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const limit = 3
		un := username.New(username.WithAvailableLimit(limit, time.Minute))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), un)
		for i := range limit {
			if ok, err := un.Available(anon(a), "ada"); err != nil || !ok {
				t.Fatalf("call %d: %v, %v", i+1, ok, err)
			}
		}
		if _, err := un.Available(anon(a), "ada"); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("call %d: %v, want ErrRateLimited", limit+1, err)
		}
		e.clock.Advance(time.Minute)
		if _, err := un.Available(anon(a), "ada"); err != nil {
			t.Fatalf("after the window: %v", err)
		}
	})
}

// TestR23_TwoFactorUnlockAndReset: Unlock lets a locked user in with the
// right code before the lock expires; Reset turns the factor off so the
// next sign-in asks for the password only, and enrolment starts over. Both
// say ErrNotEnrolled for a user with no factor.
func TestR23_TwoFactorUnlockAndReset(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		a := e.newAuth(t, nil, em, pw, tf)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if err := tf.Unlock(context.Background(), up.User.ID); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("Unlock with no factor: %v", err)
		}
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))

		signIn := func() password.SignInResult {
			t.Helper()
			return must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		}
		pending := signIn()
		wrong := "000000"
		for range twofactor.MaxFailures {
			e.clock.Advance(twofactor.Step)
			if totpAt(t, enr.Secret, e.clock.Now()) == wrong {
				wrong = "111111"
			}
			_ = tf.Verify(request(a, pending.Token), wrong)
		}
		e.clock.Advance(twofactor.Step)
		if err := tf.Verify(request(a, pending.Token), totpAt(t, enr.Secret, e.clock.Now())); !errors.Is(err, twofactor.ErrLocked) {
			t.Fatalf("locked: %v", err)
		}
		must0(t, tf.Unlock(context.Background(), up.User.ID))
		e.clock.Advance(twofactor.Step)
		if err := tf.Verify(request(a, pending.Token), totpAt(t, enr.Secret, e.clock.Now())); err != nil {
			t.Fatalf("after Unlock: %v", err)
		}

		must0(t, tf.Reset(context.Background(), up.User.ID))
		if in := signIn(); in.SecondFactorRequired {
			t.Fatal("sign-in after Reset still asks for the second factor")
		}
		var cols twofactor.TwoFactorColumns
		must0(t, a.LoadUserColumns(context.Background(), up.User.ID, twofactor.Bindings(&cols)...))
		if cols.TwoFactorEnabled {
			t.Fatal("two_factor_enabled still set after Reset")
		}
		var recovery int
		must0(t, e.db.QueryRow("SELECT COUNT(*) FROM "+tbl(twofactor.TableNameRecovery)+" WHERE "+twofactor.ColRecoveryUser+" = "+e.d.Placeholder(1), up.User.ID).Scan(&recovery))
		if recovery != 0 {
			t.Fatalf("%d recovery code(s) left after Reset", recovery)
		}
		if err := tf.Reset(context.Background(), up.User.ID); !errors.Is(err, twofactor.ErrNotEnrolled) {
			t.Fatalf("Reset twice: %v", err)
		}
		fresh := signIn()
		must[twofactor.EnrollResult](t)(tf.Enroll(request(a, fresh.Token)))
	})
}

// TestR23_PhoneMultiple: under Multiple a user adds a second number, the
// first verified stays primary, make-primary moves it, a confirmed change
// keeps the old numbers, and removing the primary promotes another verified
// one. Without Multiple a second number is still ErrHasNumber.
func TestR23_PhoneMultiple(t *testing.T) {
	const one, two, three = "+14155550101", "+14155550102", "+14155550103"
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		ph := e.phonePlugin(phone.Multiple())
		a := e.newAuth(t, nil, em, pw, ph)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		addVerified := func(n string) {
			t.Helper()
			must0(t, ph.Add(ctx, n))
			must0(t, ph.Verify(ctx, n, e.sms.LastCode(t, a, n)))
		}
		primary := func() string {
			t.Helper()
			for _, n := range must[[]phone.Number](t)(ph.List(ctx)) {
				if n.Primary {
					return n.Phone
				}
			}
			return ""
		}
		addVerified(one)
		addVerified(two)
		must0(t, ph.Add(ctx, two)) // adding one the user has is a no-op
		if list := must[[]phone.Number](t)(ph.List(ctx)); len(list) != 2 || !list[0].Verified || !list[1].Verified {
			t.Fatalf("list = %+v", list)
		}
		if p := primary(); p != one {
			t.Fatalf("primary = %q, want the first verified %q", p, one)
		}
		must0(t, ph.MakePrimary(ctx, two))
		if p := primary(); p != two {
			t.Fatalf("primary after MakePrimary = %q", p)
		}
		must0(t, ph.Change(ctx, three))
		must[phone.ChangeResult](t)(ph.ConfirmChange(ctx, three, e.sms.LastCode(t, a, three)))
		if list := must[[]phone.Number](t)(ph.List(ctx)); len(list) != 3 || primary() != three {
			t.Fatalf("after change: %+v", list)
		}
		must0(t, ph.Remove(ctx, three))
		if p := primary(); p == "" || p == three {
			t.Fatalf("primary after removing it = %q", p)
		}

		// Without Multiple, on the same database, the one-number rule stands.
		single := e.phonePlugin()
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), single)
		if err := single.Add(request(b, up.Token), "+14155550104"); !errors.Is(err, phone.ErrHasNumber) {
			t.Fatalf("a second number without Multiple: %v", err)
		}
	})
}

// TestR23_TermsHistory: every acceptance is kept, oldest first; accepting
// the version already accepted adds nothing; the migration copies an
// acceptance made before the table existed; DeleteUser removes the rows.
func TestR23_TermsHistory(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		v1 := terms.New(terms.Current("v1"))
		a := e.newAuth(t, nil, em, pw, v1)
		up := signUpVerified(t, e, a, pw, em)
		ctx := request(a, up.Token)
		if h := must[[]terms.Acceptance](t)(v1.History(context.Background(), up.User.ID)); len(h) != 0 {
			t.Fatalf("history before accepting = %+v", h)
		}
		must0(t, v1.Accept(ctx, "v1"))
		at1 := e.clock.Now()
		e.clock.Advance(time.Minute)
		must0(t, v1.Accept(ctx, "v1"))
		if h := must[[]terms.Acceptance](t)(v1.History(context.Background(), up.User.ID)); len(h) != 1 || h[0].Version != "v1" || !h[0].AcceptedAt.Equal(at1) {
			t.Fatalf("history after accepting v1 twice = %+v", h)
		}

		// The same database, the terms bumped to v2.
		v2 := terms.New(terms.Current("v2"))
		b := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), v2)
		must0(t, v2.Accept(request(b, up.Token), "v2"))
		h := must[[]terms.Acceptance](t)(v2.History(context.Background(), up.User.ID))
		if len(h) != 2 || h[0].Version != "v1" || h[1].Version != "v2" || !h[1].AcceptedAt.Equal(e.clock.Now()) {
			t.Fatalf("history after v2 = %+v", h)
		}

		// A deployment that had the plugin before the table: drop the table
		// and its ledger row, migrate again, and the latest acceptance is
		// copied from auth_user.
		_, err := e.db.Exec("DROP TABLE " + tbl(terms.TableNameAcceptance))
		must0(t, err)
		_, err = e.db.Exec("DELETE FROM " + tbl(auth.TableNameMigrations) + " WHERE owner = 'terms' AND name = '0001_terms_acceptance'")
		must0(t, err)
		_, err = b.Migrate(context.Background())
		must0(t, err)
		h = must[[]terms.Acceptance](t)(v2.History(context.Background(), up.User.ID))
		if len(h) != 1 || h[0].Version != "v2" || !h[0].AcceptedAt.Equal(e.clock.Now()) {
			t.Fatalf("history after the backfill = %+v", h)
		}

		must0(t, b.DeleteUser(context.Background(), up.User.ID))
		if h := must[[]terms.Acceptance](t)(v2.History(context.Background(), up.User.ID)); len(h) != 0 {
			t.Fatalf("history after DeleteUser = %+v", h)
		}
	})
}
