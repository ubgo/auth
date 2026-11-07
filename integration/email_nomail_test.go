package integration

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// TestEmailNoMail: an app that only stores addresses it verified itself
// runs the email plugin with NoMail and no mailer. SetFor stores a verified
// address as primary and copies it to auth_user; an unverified one is stored
// without a verify link and stays unverified; list reads both back, and the
// routes that would mail are not served.
func TestEmailNoMail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := email.New(email.Login(), email.Multiple(), email.NoMail())
		a := e.newAuth(t, nil, em, e.passwordPlugin(password.WithoutRecovery()))
		ctx := context.Background()
		u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{}))
		_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
		if err != nil {
			t.Fatal(err)
		}
		if err := em.SetFor(ctx, u.ID, "ada@example.test", true); err != nil {
			t.Fatal(err)
		}
		if err := em.SetFor(ctx, u.ID, "work@example.test", false); err != nil {
			t.Fatalf("an unverified address under NoMail: %v", err)
		}
		if got := identAddresses(t, em, a, tok); got != "ada@example.test[v][p] work@example.test" {
			t.Fatalf("addresses = %s", got)
		}
		if got := identPrimaryColumn(t, a, u.ID); got != "ada@example.test" {
			t.Fatalf("auth_user primary = %q", got)
		}
		// No verify link was made for the unverified address, so no
		// delivery was attempted and none failed behind the call.
		a.WaitDeliveries()
		if n := r20VerificationRows(t, a); n != 0 {
			t.Fatalf("%d verification rows under NoMail", n)
		}
		for _, id := range []auth.EndpointID{"email.add", "email.resend", "email.change", "email.verify"} {
			if _, ok := a.Operation(id); ok {
				t.Errorf("%s is served under NoMail", id)
			}
		}
	})
}
