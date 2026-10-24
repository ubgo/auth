package integration

import (
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/sso"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/auth/plugin/username"
)

// enrollFactor turns on an authenticator-app factor for the user signed in
// with tok.
func enrollFactor(t *testing.T, e *env, a *auth.Auth, tf *twofactor.Plugin, tok auth.Token) {
	t.Helper()
	enr := must[twofactor.EnrollResult](t)(tf.Enroll(request(a, tok)))
	must[twofactor.RecoveryCodes](t)(tf.Confirm(request(a, tok), totpAt(t, enr.Secret, e.clock.Now())))
}

// TestTwoFactorDefault_AsksAfterEveryCredentialSignIn: under the default
// policy a password sign-in by email and by username, and the
// expired-password change that signs in, are pending for a user with a
// factor. Every id in CredentialSignIns names a real operation.
func TestTwoFactorDefault_AsksAfterEveryCredentialSignIn(t *testing.T) {
	const handle = "alice_w"
	const period = 24 * time.Hour
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, un := e.emailPlugin(), e.passwordPlugin(password.ExpireAfter(period)), username.New(username.Login())
		tf := twofactor.New(twofactor.WithEncryptionKey(twoFactorKey))
		a := e.newAuth(t, nil, em, pw, un, tf)
		for _, id := range twofactor.CredentialSignIns {
			if _, ok := a.Operation(id); !ok {
				t.Errorf("CredentialSignIns names %q, which no operation has", id)
			}
		}
		up := signUpVerified(t, e, a, pw, em)
		if _, err := un.Set(request(a, up.Token), handle); err != nil {
			t.Fatalf("set username: %v", err)
		}
		enrollFactor(t, e, a, tf, up.Token)
		for _, id := range []string{alice, handle} {
			in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: id, Password: secret}))
			if !in.SecondFactorRequired {
				t.Errorf("password sign-in by %q is not pending", id)
			}
		}
		e.clock.Advance(period)
		res := must[password.SignInResult](t)(pw.ChangeExpired(anon(a), password.ChangeExpiredRequest{Identifier: alice, Current: secret, New: "a fresh passphrase now"}))
		if !res.SecondFactorRequired {
			t.Fatal("the expired-password change signed in past the factor")
		}
	})
}

// TestTwoFactorDefault_SkipsAfterSSO: an SSO sign-in of a user with a
// factor is not pending under the default, and is under
// AskEverySignIn.
func TestTwoFactorDefault_SkipsAfterSSO(t *testing.T) {
	for name, c := range map[string]struct {
		opts []twofactor.Option
		want bool
	}{
		"default":        {nil, false},
		"AskEverySignIn": {[]twofactor.Option{twofactor.WithPolicy(twofactor.AskEverySignIn)}, true},
	} {
		t.Run(name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				tf := twofactor.New(append([]twofactor.Option{twofactor.WithEncryptionKey(twoFactorKey)}, c.opts...)...)
				w := c2BuildWith(t, e, nil, []auth.Plugin{tf})
				w.register(t, w.oidcRequest(c2OIDC))
				first, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
				if err != nil {
					t.Fatal(err)
				}
				enrollFactor(t, e, w.a, tf, first.Token)
				again, err := w.oidcSignIn(t, sso.SignInRequest{ProviderID: c2OIDC})
				if err != nil {
					t.Fatal(err)
				}
				if again.SecondFactorRequired != c.want {
					t.Fatalf("SSO sign-in pending = %v, want %v", again.SecondFactorRequired, c.want)
				}
			})
		})
	}
}
