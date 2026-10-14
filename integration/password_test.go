package integration

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	alice    = "alice@example.com"
	aliceRaw = "  Alice@Example.COM "
	secret   = "correct horse battery"
)

// signUpVerified creates alice with a verified email and returns her session.
func signUpVerified(t *testing.T, e *env, a *auth.Auth, pw *password.Plugin, em *email.Plugin) password.SignInResult {
	t.Helper()
	// Mail goes out in the background, so a link from an earlier sign-up to
	// the same address (a squatter's, say) can land after this one's and be
	// taken for it. Settle earlier deliveries first: this sign-up's link is
	// then the newest in the mailbox.
	a.WaitDeliveries()
	res, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: aliceRaw, Password: secret, Name: "Alice"})
	if err != nil {
		t.Fatalf("sign up: %v", err)
	}
	if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

func TestPassword_SignUpVerifySignIn(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)
		if up.Token == "" {
			t.Fatal("sign-up without RequireVerified must start a session")
		}

		in, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "ALICE@example.com", Password: secret})
		if err != nil {
			t.Fatalf("sign in: %v", err)
		}
		ctx := request(a, in.Token)
		if err := a.Resolve(ctx); err != nil {
			t.Fatal(err)
		}
		u, ok := auth.CurrentUser(ctx)
		if !ok || u.ID != in.User.ID || u.Name != "Alice" {
			t.Fatalf("current user = %+v, %v", u, ok)
		}

		var cols email.EmailColumns
		if err := a.LoadUserColumns(context.Background(), u.ID, email.Bindings(&cols)...); err != nil {
			t.Fatal(err)
		}
		if cols.PrimaryEmail == nil || *cols.PrimaryEmail != alice || cols.EmailVerifiedAt == nil {
			t.Fatalf("user row copy of the primary address = %+v", cols)
		}
	})
}

// TestPassword_SignInIsEnumerationSafe: an unknown account and a wrong
// password give the same error.
func TestPassword_SignInIsEnumerationSafe(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		_, wrong := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "not the password"})
		_, unknown := pw.SignIn(anon(a), password.SignInRequest{Identifier: "nobody@example.com", Password: secret})
		if !errors.Is(wrong, password.ErrInvalidCredentials) || !errors.Is(unknown, password.ErrInvalidCredentials) {
			t.Fatalf("wrong = %v, unknown = %v; both must be ErrInvalidCredentials", wrong, unknown)
		}
	})
}

func TestPassword_RequireVerified(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.RequireVerified()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret})
		if err != nil {
			t.Fatal(err)
		}
		if !up.VerificationRequired || up.Token != "" {
			t.Fatalf("sign-up = %+v, want no session and VerificationRequired", up)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); !errors.Is(err, auth.ErrNotVerified) {
			t.Fatalf("sign-in before verify: %v, want ErrNotVerified", err)
		}
		// Only a caller who knows the password learns it is unverified.
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "wrong password!"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("wrong password before verify: %v", err)
		}
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("sign-in after verify: %v", err)
		}
	})
}

// TestPassword_SquatterCannotTakeTheAddress is the pre-account-takeover case:
// someone signs up first with an address they do not own. The real owner can
// still sign up and verify, and every sign-in by that address then reaches the
// owner, never the squatter.
func TestPassword_SquatterCannotTakeTheAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		squat, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: "squatter password"})
		if err != nil {
			t.Fatal(err)
		}
		owner := signUpVerified(t, e, a, pw, em)
		if owner.User.ID == squat.User.ID {
			t.Fatal("the owner's sign-up must be a separate account")
		}
		in, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret})
		if err != nil || in.User.ID != owner.User.ID {
			t.Fatalf("sign-in reached %v (%v), want the verified owner %s", in.User.ID, err, owner.User.ID)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: "squatter password"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("the squatter's password must not work once the owner verified: %v", err)
		}
	})
}

func TestPassword_SignUpWithTakenAddressTellsTheOwner(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: "another password"}); err != nil {
			t.Fatalf("sign-up must look the same for a taken address: %v", err)
		}
		// Delivery runs in the background, so the order of mail is not fixed;
		// the notice must be among what the address received.
		told := false
		for _, m := range e.mail.To(a, alice) {
			told = told || m.Subject == "Someone tried to sign up with your address"
		}
		if !told {
			t.Fatalf("owner was not told; mail: %+v", e.mail.To(a, alice))
		}
	})
}

func TestPassword_ForgotAndReset(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		up := signUpVerified(t, e, a, pw, em)

		unknown, err := pw.Forgot(anon(a), "nobody@example.com")
		if err != nil {
			t.Fatal(err)
		}
		known, err := pw.Forgot(anon(a), alice)
		if err != nil {
			t.Fatal(err)
		}
		if unknown != known || known.Status != password.ForgotStatus {
			t.Fatalf("forgot answered %+v and %+v; must be identical", unknown, known)
		}
		if len(e.mail.To(a, "nobody@example.com")) != 0 {
			t.Fatal("mail sent for an unknown address")
		}
		tok := e.mail.LastToken(t, a, alice)

		const next = "a brand new passphrase"
		if err := pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: next}); err != nil {
			t.Fatalf("reset: %v", err)
		}
		if err := pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: "third passphrase!"}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("second use of a reset token: %v, want ErrTokenInvalid", err)
		}
		// The reset signed out the session from sign-up.
		if _, _, _, err := a.ResolveSession(context.Background(), up.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("old session after reset: %v, want ErrSignedOut", err)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: next}); err != nil {
			t.Fatalf("sign-in with the new password: %v", err)
		}
	})
}

func TestPassword_ResetTokenExpires(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		if _, err := pw.Forgot(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		tok := e.mail.LastToken(t, a, alice)
		e.clock.Advance(password.DefaultResetTTL + time.Second)
		if err := pw.Reset(anon(a), password.ResetRequest{Token: tok.Wire(), Password: "a brand new passphrase"}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("expired reset token: %v", err)
		}
	})
}

// TestVerification_ConcurrentUseSucceedsOnce spends one token from many
// goroutines; the database, not Go, decides the single winner.
func TestVerification_ConcurrentUseSucceedsOnce(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		ctx := context.Background()
		tok, err := a.IssueVerification(ctx, "test.race", "subject", time.Hour, "")
		if err != nil {
			t.Fatal(err)
		}
		const racers = 8
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := a.ConsumeVerification(ctx, "test.race", tok); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d goroutines spent one token, want exactly 1", wins)
		}
	})
}

func TestPassword_ChangeNeedsFreshSessionAndSignsOutOthers(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		one := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		two := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: alice, Password: secret}))
		if _, err := pw.Forgot(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		pending := e.mail.LastToken(t, a, alice)

		if err := pw.Change(request(a, one.Token), password.ChangeRequest{Current: "wrong password!", New: "next passphrase"}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("change with a wrong current password: %v", err)
		}
		if err := pw.Change(request(a, one.Token), password.ChangeRequest{Current: secret, New: "next passphrase"}); err != nil {
			t.Fatalf("change: %v", err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), two.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("other session after change: %v, want signed out", err)
		}
		if err := pw.Reset(anon(a), password.ResetRequest{Token: pending.Wire(), Password: "undo the change!"}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a reset link from before the change still works: %v", err)
		}
		if _, _, _, err := a.ResolveSession(context.Background(), one.Token); err != nil {
			t.Fatalf("the session that changed it must stay: %v", err)
		}
		e.clock.Advance(auth.DefaultFreshWindow + time.Minute)
		if err := pw.Change(request(a, one.Token), password.ChangeRequest{Current: "next passphrase", New: "third passphrase"}); !errors.Is(err, auth.ErrFreshSessionRequired) {
			t.Fatalf("change on an old session: %v, want ErrFreshSessionRequired", err)
		}
	})
}

func TestPassword_RateLimitPerAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		signUpVerified(t, e, a, pw, em)
		var last error
		for i := range 6 {
			ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: "198.51.100." + string(rune('1'+i))}})
			_, last = pw.SignIn(ctx, password.SignInRequest{Identifier: alice, Password: "wrong password!"})
		}
		if !errors.Is(last, auth.ErrRateLimited) {
			t.Fatalf("6th attempt from 6 IPs: %v, want ErrRateLimited", last)
		}
		if d, ok := auth.RetryAfter(last); !ok || d <= 0 {
			t.Fatalf("RetryAfter = %v, %v", d, ok)
		}
	})
}

// TestPassword_UnknownAccountCostsAHash times sign-in with a real argon2 cost:
// an unknown identifier must take about as long as a wrong password, because
// it runs the same hash against the dummy. If the check were skipped, the
// unknown case would answer in a fraction of a millisecond against tens.
// SQLite only: it measures the library, not a network round trip.
//
//ds:def id=testpassword-unknownaccountcostsahash-qbmfb3b2
func TestPassword_UnknownAccountCostsAHash(t *testing.T) {
	db, d := openSQLite(t)
	e := newEnv(t, auth.EngineSQLite, db, d)
	em := e.emailPlugin()
	pw := password.New(password.Argon2(password.Argon2Params{Memory: 16 * 1024, Time: 2, Threads: 1}))
	a := e.newAuth(t, nil, em, pw)
	if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret}); err != nil {
		t.Fatal(err)
	}
	// Samples alternate between the two cases, so a burst of load from the
	// rest of the machine lands on both medians instead of only on the half
	// that happened to run during it.
	const runs = 9
	knownRuns, unknownRuns := make([]time.Duration, runs), make([]time.Duration, runs)
	timeSignIn := func(identifier string) time.Duration {
		start := time.Now()
		_, _ = pw.SignIn(anon(a), password.SignInRequest{Identifier: identifier, Password: "wrong password!"})
		return time.Since(start)
	}
	for i := range runs {
		knownRuns[i] = timeSignIn(alice)
		unknownRuns[i] = timeSignIn("nobody@example.com")
	}
	slices.Sort(knownRuns)
	slices.Sort(unknownRuns)
	known, unknown := knownRuns[runs/2], unknownRuns[runs/2]
	if unknown < known/2 {
		t.Fatalf("unknown account answered in %v, a wrong password in %v: the hash is being skipped", unknown, known)
	}
}
