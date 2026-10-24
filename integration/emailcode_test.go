package integration

import (
	"errors"
	"regexp"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

var mailCode = regexp.MustCompile(`\b(\d{6})\b`)

// lastMailCode returns the newest six-digit code mailed to addr.
func lastMailCode(t *testing.T, e *env, a *auth.Auth, addr string) string {
	t.Helper()
	list := e.mail.To(a, addr)
	for i := len(list) - 1; i >= 0; i-- {
		if m := mailCode.FindStringSubmatch(list[i].Text); m != nil {
			return m[1]
		}
	}
	t.Fatalf("no code mailed to %s", addr)
	return ""
}

func TestEmailCode_SignInOwnerOnlyAndSingleUse(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(email.SignInWithCode()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)
		owner := signUpVerified(t, e, a, pw, em)

		if err := em.SendCode(anon(a), "nobody@example.com"); err != nil {
			t.Fatal(err)
		}
		if n := len(e.mail.To(a, "nobody@example.com")); n != 0 {
			t.Fatalf("%d mails to an unknown address without SignUpWithCode", n)
		}
		if err := em.SendCode(anon(a), "Alice@Example.com"); err != nil {
			t.Fatal(err)
		}
		code := lastMailCode(t, e, a, alice)
		in, err := em.SignInCode(anon(a), alice, code)
		if err != nil || in.User.ID != owner.User.ID || in.Created {
			t.Fatalf("code sign-in = %+v %v", in, err)
		}
		if _, err := em.SignInCode(anon(a), alice, code); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a code used twice: %v", err)
		}
		// A code sent in one tenant does not work in another.
		if err := em.SendCode(auth.WithScope(anon(a), "acme"), alice); err != nil {
			t.Fatal(err)
		}
		if _, err := em.SignInCode(auth.WithScope(anon(a), "globex"), alice, lastMailCode(t, e, a, alice)); !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("a code from another tenant: %v", err)
		}
	})
}

func TestEmailCode_SignUp(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.SignUpWithCode())
		a := e.newAuth(t, nil, em)
		if err := em.SendCode(anon(a), "new@example.com"); err != nil {
			t.Fatal(err)
		}
		in, err := em.SignInCode(anon(a), "new@example.com", lastMailCode(t, e, a, "new@example.com"))
		if err != nil || !in.Created || in.Token == "" {
			t.Fatalf("sign-up by code = %+v %v", in, err)
		}
	})
}
