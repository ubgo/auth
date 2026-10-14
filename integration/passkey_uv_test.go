package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/twofactor"
)

// recordSignIn is a SecondFactorForSignIn plugin that asks for nothing and
// keeps the last SignInAttempt it saw.
type recordSignIn struct{ last *auth.SignInAttempt }

func (recordSignIn) Name() string { return "recordsignin" }

func (r recordSignIn) SecondFactorRequiredForSignIn(_ context.Context, in auth.SignInAttempt) (bool, error) {
	*r.last = in
	return false, nil
}

// TestPasskey_UnverifiedSignInIsOneFactorForTwoFactor: under twofactor's
// DefaultPolicy, a passkey sign-in whose authenticator did not verify the
// user proves possession only, so a user with a confirmed factor gets a
// pending session; a user-verified passkey is two factors and gets a full
// one, as in better-auth. The attempt the policy sees carries SingleFactor
// for the first and not for the second.
func TestPasskey_UnverifiedSignInIsOneFactorForTwoFactor(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var seen auth.SignInAttempt
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		pk := passkey.New(passkey.AuthenticatorSelection(passkey.Selection{ResidentKey: passkey.RequirementPreferred, UserVerification: passkey.RequirementPreferred}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), recordSignIn{last: &seen}, tf, pk)
		uid, _ := identUser(t, a, alice)
		dev := newAuthenticator(t)
		registerPasskey(t, a, pk, uid, dev)

		_, tok, err := a.CreateMultiFactorSession(anon(a), uid, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		ctx := request(a, tok)
		enr := must[twofactor.EnrollResult](t)(tf.Enroll(ctx))
		must[twofactor.RecoveryCodes](t)(tf.Confirm(ctx, totpAt(t, enr.Secret, e.clock.Now())))

		dev.noUV = true
		lb := must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		in, err := pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, uid)})
		if err != nil || !in.SecondFactorRequired {
			t.Fatalf("an unverified passkey sign-in with two-factor on = %+v %v, want a pending session", in, err)
		}
		if _, _, _, err := a.ResolveSession(anon(a), in.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("the pending session signed somebody in: %v", err)
		}
		if !seen.SingleFactor || seen.Method != "passkey" {
			t.Fatalf("attempt = %+v, want a single-factor passkey sign-in", seen)
		}

		dev.noUV = false
		seen = auth.SignInAttempt{}
		lb = must[passkey.BeginResult](t)(pk.LoginBegin(anon(a)))
		in, err = pk.LoginFinish(anon(a), passkey.FinishRequest{Ceremony: lb.Ceremony, Credential: dev.assert(t, lb.Options, uid)})
		if err != nil || in.SecondFactorRequired {
			t.Fatalf("a verified passkey sign-in = %+v %v, want a full session", in, err)
		}
		if _, _, _, err := a.ResolveSession(anon(a), in.Token); err != nil {
			t.Fatalf("the verified sign-in must be full: %v", err)
		}
		if seen != (auth.SignInAttempt{}) {
			t.Fatalf("a multi-factor session asked the second-factor plugins: %+v", seen)
		}
	})
}
