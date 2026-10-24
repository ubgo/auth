package integration

import (
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
)

func TestMagicLink_SignsInTheVerifiedOwnerOnly(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, ml := e.emailPlugin(), e.passwordPlugin(), magiclink.New()
		a := e.newAuth(t, nil, em, pw, ml)
		owner := signUpVerified(t, e, a, pw, em)

		// Unknown address, no SignUp: same answer, nothing sent.
		if err := ml.Send(anon(a), "nobody@example.com"); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, "nobody@example.com")); n != 0 {
			t.Fatalf("%d mails to an unknown address", n)
		}
		// An unverified row does not receive a link either.
		must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: "unverified@example.com", Password: secret}))
		before := len(e.mail.To(a, "unverified@example.com"))
		if err := ml.Send(anon(a), "unverified@example.com"); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, "unverified@example.com")); n != before {
			t.Fatal("a link went to an address nobody verified")
		}

		if err := ml.Send(anon(a), " ALICE@example.com "); err != nil {
			t.Fatal(err)
		}
		tok := e.mail.LastToken(t, a, alice)
		in, err := ml.SignIn(anon(a), tok)
		if err != nil || in.User.ID != owner.User.ID || in.Created {
			t.Fatalf("sign-in = %+v %v", in, err)
		}
		if _, err := ml.SignIn(anon(a), tok); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a link used twice: %v", err)
		}
		if err := ml.Send(anon(a), alice); err != nil {
			t.Fatal(err)
		}
		late := e.mail.LastToken(t, a, alice)
		e.clock.Advance(magiclink.DefaultTTL + time.Second)
		if _, err := ml.SignIn(anon(a), late); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("an expired link: %v", err)
		}
	})
}

func TestMagicLink_SignUpCreatesAVerifiedAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ml := e.emailPlugin(), magiclink.New(magiclink.SignUp())
		a := e.newAuth(t, nil, em, ml)
		if err := ml.Send(anon(a), "new@example.com"); err != nil {
			t.Fatal(err)
		}
		in, err := ml.SignIn(anon(a), e.mail.LastToken(t, a, "new@example.com"))
		if err != nil || !in.Created || in.Token == "" {
			t.Fatalf("sign-up by link = %+v %v", in, err)
		}
		if _, err := a.FindIdentity(anon(a), "email", "new@example.com", true); err != nil {
			t.Fatalf("the clicked address must be verified: %v", err)
		}
	})
}

// TestMagicLink_BoundToItsTenant: with addresses unique per tenant, a link
// sent in one tenant signs in that tenant's user, and is refused in another.
func TestMagicLink_BoundToItsTenant(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, ml := e.emailPlugin(email.ScopedByTenant()), magiclink.New(magiclink.SignUp())
		a := e.newAuth(t, nil, em, ml)
		acme := auth.WithScope(anon(a), "acme")
		if err := ml.Send(acme, alice); err != nil {
			t.Fatal(err)
		}
		tok := e.mail.LastToken(t, a, alice)
		if _, err := ml.SignIn(auth.WithScope(anon(a), "globex"), tok); !errors.Is(err, auth.ErrTokenInvalid) {
			t.Fatalf("a link clicked in another tenant: %v", err)
		}
		if err := ml.Send(acme, alice); err != nil {
			t.Fatal(err)
		}
		in, err := ml.SignIn(anon(a), e.mail.LastToken(t, a, alice)) // no tenant on the click
		if err != nil || !in.Created {
			t.Fatalf("click without a tenant: %+v %v", in, err)
		}
		if _, err := a.FindIdentity(acme, email.KindEmail, alice, true); err != nil {
			t.Fatalf("the account must be in acme: %v", err)
		}
	})
}
