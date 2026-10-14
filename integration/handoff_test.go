package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/handoff"
)

// alwaysSecond is a SecondFactor plugin that requires a second factor of
// every user, so CreateSession makes pending sessions; a hand-off must not.
type alwaysSecond struct{}

func (alwaysSecond) Name() string { return "alwayssecond" }
func (alwaysSecond) SecondFactorRequired(context.Context, string) (bool, error) {
	return true, nil
}

// TestHandoff_ExchangeStartsANewSessionOnce: a token minted by a session is
// exchanged once for a new session of the same user; a second exchange, an
// expired token and a token of a session that has since ended are refused
// alike.
func TestHandoff_ExchangeStartsANewSessionOnce(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
		uid, web := identUser(t, a, alice)

		gen, err := hp.Generate(request(a, web))
		if err != nil || gen.Token == "" || !gen.ExpiresAt.Equal(e.clock.Now().Add(handoff.DefaultTTL)) {
			t.Fatalf("generate = %+v %v", gen, err)
		}
		app, err := hp.Verify(anon(a), auth.Token(gen.Token))
		if err != nil || app.User.ID != uid || app.Token == "" || app.Token == web {
			t.Fatalf("verify = %+v %v", app, err)
		}
		if !identSignedIn(t, a, app.Token) || !identSignedIn(t, a, web) {
			t.Fatal("both the source and the new session must work")
		}
		if _, err := hp.Verify(anon(a), auth.Token(gen.Token)); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a token used twice: %v", err)
		}
		if _, err := hp.Verify(anon(a), "not-a-token"); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a made-up token: %v", err)
		}

		late := must[handoff.GenerateResult](t)(hp.Generate(request(a, web)))
		e.clock.Advance(handoff.DefaultTTL + time.Second)
		if _, err := hp.Verify(anon(a), auth.Token(late.Token)); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("an expired token: %v", err)
		}

		// The source session ends: its tokens die with it.
		orphan := must[handoff.GenerateResult](t)(hp.Generate(request(a, web)))
		if err := a.SignOut(request(a, web)); err != nil {
			t.Fatal(err)
		}
		if _, err := hp.Verify(anon(a), auth.Token(orphan.Token)); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a token of an ended session: %v", err)
		}
		// Signed out, nobody can mint one.
		if _, err := hp.Generate(request(a, web)); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("generate signed out: %v", err)
		}
	})
}

// TestHandoff_NewSessionIsFullAndUserMayBeGone: the exchange skips the second
// factor, which the source session already passed; and a user deleted after
// minting gets the same answer as a spent token.
func TestHandoff_NewSessionIsFullAndUserMayBeGone(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp, alwaysSecond{})
		uid, _ := identUser(t, a, alice)
		// identUser's own session is pending under alwaysSecond; a full one
		// is what a real sign-in ends with after the second step.
		full, tok, err := a.CreateMultiFactorSession(context.Background(), uid, auth.Client{})
		if err != nil || full.SecondFactorPending {
			t.Fatal(err)
		}
		gen := must[handoff.GenerateResult](t)(hp.Generate(request(a, tok)))
		res, err := hp.Verify(anon(a), auth.Token(gen.Token))
		if err != nil {
			t.Fatal(err)
		}
		if !identSignedIn(t, a, res.Token) {
			t.Fatal("the handed-off session must be full, not pending")
		}
		gone := must[handoff.GenerateResult](t)(hp.Generate(request(a, tok)))
		if err := a.DeleteUser(context.Background(), uid); err != nil {
			t.Fatal(err)
		}
		if _, err := hp.Verify(anon(a), auth.Token(gone.Token)); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a token of a deleted user: %v", err)
		}
	})
}

// TestHandoff_ImpersonationRefused: an admin acting as a user cannot hand
// that session off.
func TestHandoff_ImpersonationRefused(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
		uid, _ := identUser(t, a, alice)
		adminID, _ := identUser(t, a, identBob)
		_, as, err := a.CreateImpersonationSession(context.Background(), uid, adminID, auth.Client{}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hp.Generate(request(a, as)); !errors.Is(err, auth.ErrImpersonationRefused) {
			t.Fatalf("generate while impersonating: %v", err)
		}
	})
}

// TestHandoff_ServerOnly: the route answers unknown while the Go method still
// works.
func TestHandoff_ServerOnly(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New(handoff.ServerOnly())
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
		_, tok := identUser(t, a, alice)
		op, ok := a.Operation(handoff.EndpointGenerate)
		if !ok {
			t.Fatal("generate must stay registered under ServerOnly, for the Go call")
		}
		if _, err := op.Invoke(request(a, tok), func(any) error { return nil }); !errors.Is(err, auth.ErrUnknownOperation) {
			t.Fatalf("generate over a transport under ServerOnly: %v", err)
		}
		gen, err := hp.Generate(request(a, tok))
		if err != nil || gen.Token == "" {
			t.Fatalf("generate from Go under ServerOnly = %+v %v", gen, err)
		}
		if _, err := hp.Verify(anon(a), auth.Token(gen.Token)); err != nil {
			t.Fatal(err)
		}
	})
}

// TestHandoff_Stateless: with no session store the source cannot be checked,
// so the exchange relies on the token's own short life; a user deleted after
// minting still gets the spent-token answer, since no cascade ended the
// token's source here.
func TestHandoff_Stateless(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New()
		a := e.newAuth(t, []auth.Option{auth.WithStatelessSessions(sessKey)}, e.emailPlugin(), e.passwordPlugin(), hp)
		uid, tok := identUser(t, a, alice)
		gen := must[handoff.GenerateResult](t)(hp.Generate(request(a, tok)))
		res, err := hp.Verify(anon(a), auth.Token(gen.Token))
		if err != nil || res.User.ID != uid || !identSignedIn(t, a, res.Token) {
			t.Fatalf("stateless exchange = %+v %v", res, err)
		}
		gone := must[handoff.GenerateResult](t)(hp.Generate(request(a, tok)))
		if err := a.DeleteUser(context.Background(), uid); err != nil {
			t.Fatal(err)
		}
		if _, err := hp.Verify(anon(a), auth.Token(gone.Token)); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a token of a deleted user, stateless: %v", err)
		}
	})
}

// TestIdentFaults_Handoff: minting and exchanging surface every database
// failure.
func TestIdentFaults_Handoff(t *testing.T) {
	identRun(t, []identSweep{
		{"generate", func(t *testing.T, e *faultEnv) func(context.Context) error {
			hp := handoff.New()
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
			_, tok := identUser(t, a, alice)
			return func(context.Context) error { _, err := hp.Generate(request(a, tok)); return err }
		}},
		{"verify", func(t *testing.T, e *faultEnv) func(context.Context) error {
			hp := handoff.New()
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
			_, tok := identUser(t, a, alice)
			gen := must[handoff.GenerateResult](t)(hp.Generate(request(a, tok)))
			return func(context.Context) error { _, err := hp.Verify(anon(a), auth.Token(gen.Token)); return err }
		}},
		{"verify bound", func(t *testing.T, e *faultEnv) func(context.Context) error {
			hp := handoff.New()
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
			_, tok := identUser(t, a, alice)
			verifier, challenge, err := handoff.NewVerifier()
			if err != nil {
				t.Fatal(err)
			}
			gen := must[handoff.GenerateResult](t)(hp.GenerateWith(request(a, tok), handoff.GenerateRequest{Challenge: challenge}))
			return func(context.Context) error {
				_, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: verifier})
				return err
			}
		}},
	})
}

// TestHandoff_ChallengeBindsTheToken: a token minted with a challenge is
// spent only with its verifier; a wrong verifier, no verifier, or a verifier
// for an unbound token answer like a bad token and leave the token unspent
// (the operation's transaction rolls back), so a client that caught the
// token on a shared channel can neither use nor burn it, and the holder of
// the verifier still exchanges it. A malformed challenge or verifier is a
// request error that touches no token.
func TestHandoff_ChallengeBindsTheToken(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
		uid, web := identUser(t, a, alice)
		verifier, challenge, err := handoff.NewVerifier()
		if err != nil || len(verifier) != handoff.MinVerifierLen || challenge != handoff.ChallengeOf(verifier) {
			t.Fatalf("NewVerifier = %q %q %v", verifier, challenge, err)
		}

		gen := must[handoff.GenerateResult](t)(hp.GenerateWith(request(a, web), handoff.GenerateRequest{Challenge: challenge}))
		// Without the verifier, and with a wrong one of the right shape:
		// refused, and the token stays unspent.
		other, _, err := handoff.NewVerifier()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := hp.Verify(anon(a), auth.Token(gen.Token)); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a bound token with no verifier: %v", err)
		}
		if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: other}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a wrong verifier: %v", err)
		}
		// With the verifier: the hand-off, once.
		res, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: verifier})
		if err != nil || res.User.ID != uid || !identSignedIn(t, a, res.Token) {
			t.Fatalf("bound exchange = %+v %v", res, err)
		}
		if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: verifier}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a bound token used twice: %v", err)
		}
		// A verifier for an unbound token: refused.
		plain := must[handoff.GenerateResult](t)(hp.Generate(request(a, web)))
		if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(plain.Token), Verifier: verifier}); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("an unbound token with a verifier: %v", err)
		}
		// Shape errors touch no token.
		for _, bad := range []string{"short", challenge + "=", "not base64url!" + challenge[14:]} {
			if _, err := hp.GenerateWith(request(a, web), handoff.GenerateRequest{Challenge: bad}); !errors.Is(err, handoff.ErrChallengeInvalid) {
				t.Fatalf("challenge %q: %v", bad, err)
			}
		}
		gen = must[handoff.GenerateResult](t)(hp.GenerateWith(request(a, web), handoff.GenerateRequest{Challenge: challenge}))
		for _, bad := range []string{"short", verifier[:handoff.MinVerifierLen-1], verifier + "!", verifier + verifier + verifier} {
			if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: bad}); !errors.Is(err, handoff.ErrVerifierInvalid) {
				t.Fatalf("verifier %q: %v", bad, err)
			}
		}
		if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: verifier}); err != nil {
			t.Fatalf("the token survives malformed verifiers: %v", err)
		}
	})
}

// TestHandoff_VerifyIsRateLimited: because a refused exchange leaves a bound
// token unspent, guesses at its verifier are bounded per token (five a
// minute) and exchanges per IP (ten a minute); the right verifier still works
// once the window passes, and an unbound token's exchange counts too.
func TestHandoff_VerifyIsRateLimited(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		hp := handoff.New()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), hp)
		_, web := identUser(t, a, alice)
		verifier, challenge, err := handoff.NewVerifier()
		if err != nil {
			t.Fatal(err)
		}
		wrong, _, err := handoff.NewVerifier()
		if err != nil {
			t.Fatal(err)
		}
		gen := must[handoff.GenerateResult](t)(hp.GenerateWith(request(a, web), handoff.GenerateRequest{Challenge: challenge}))
		for i := 0; i < 5; i++ {
			if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: wrong}); !errors.Is(err, auth.ErrTokenInvalid) {
				t.Fatalf("guess %d: %v", i+1, err)
			}
		}
		if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: verifier}); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("the sixth exchange of one token in a minute: %v, want ErrRateLimited", err)
		}
		// Another token from the same IP is still allowed until the IP's ten.
		other := must[handoff.GenerateResult](t)(hp.Generate(request(a, web)))
		for i := 0; i < 4; i++ {
			if _, err := hp.Verify(anon(a), "not-a-token"); !errors.Is(err, auth.ErrTokenInvalid) {
				t.Fatalf("made-up token %d: %v", i+1, err)
			}
		}
		if _, err := hp.Verify(anon(a), auth.Token(other.Token)); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("the eleventh exchange from one IP in a minute: %v, want ErrRateLimited", err)
		}
		e.clock.Advance(time.Minute + time.Second)
		if _, err := hp.VerifyWith(anon(a), handoff.VerifyRequest{Token: auth.WireToken(gen.Token), Verifier: verifier}); err != nil {
			t.Fatalf("the right verifier after the window: %v", err)
		}
		if _, err := hp.Verify(anon(a), auth.Token(other.Token)); err != nil {
			t.Fatalf("the unbound token after the window: %v", err)
		}
	})
}
