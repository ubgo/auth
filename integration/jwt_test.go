package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/password"
)

func TestJWT_IssueFromSessionAndVerifyElsewhere(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		em, pw, ad := e.emailPlugin(), e.passwordPlugin(), admin.New()
		jw := jwt.New(jwt.WithSigningKey(key), jwt.Audience("orders-api"), jwt.Claims(func(_ context.Context, u auth.User) map[string]any {
			return map[string]any{"name": u.Name}
		}))
		a := e.newAuth(t, nil, em, pw, ad, jw)
		up := signUpVerified(t, e, a, pw, em)

		res := must[jwt.TokenResult](t)(jw.Token(request(a, up.Token)))
		// The receiving service knows only the published keys.
		v := jwt.Verifier{Keys: jwt.KeysFromJWKS(jw.PublicKeys()), Issuer: testBaseURL, Audience: "orders-api", Now: e.clock.Now}
		c, err := v.Verify(res.Token)
		if err != nil || c.Subject != up.User.ID || c.Actor != "" || string(c.Extra["name"]) != `"Alice"` {
			t.Fatalf("verified = %+v %v", c, err)
		}
		if _, err := jw.Token(anon(a)); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("a token without a session: %v", err)
		}

		// An impersonation session's token names the admin in "act".
		if err := ad.Grant(context.Background(), up.User.ID); err != nil {
			t.Fatal(err)
		}
		bob := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: secret}))
		as := must[admin.ImpersonateResult](t)(ad.Impersonate(request(a, up.Token), admin.ImpersonateRequest{UserID: bob.User.ID}))
		imp := must[jwt.TokenResult](t)(jw.Token(request(a, as.Token)))
		c, err = v.Verify(imp.Token)
		if err != nil || c.Subject != bob.User.ID || c.Actor != up.User.ID {
			t.Fatalf("impersonation token = %+v %v", c, err)
		}
	})
}
