package integration

import (
	"testing"

	"github.com/ubgo/auth/plugin/email"
)

// Addresses for the no-address ReplaceUnverified flow.
const (
	r6First  = "first@example.com"
	r6Second = "second@example.com"
)

// TestEmailReplaceUnverified_UserWithNoAddress: under ReplaceUnverified a
// user who has no address yet gets the changed-to address created with
// nothing to delete (the core keeps an unverified address off the primary
// flag, whatever the request asks); a second change then replaces that one
// unverified address at once. Pins replaceAtOnce's "nothing to replace"
// branch and replacedAddress's empty-list answer.
func TestEmailReplaceUnverified_UserWithNoAddress(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.ReplaceUnverified())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, "")
		if err := em.Change(request(a, tok), r6First); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != r6First {
			t.Fatalf("addresses after the first change = %q, want the new address, unverified and not primary", got)
		}
		if err := em.Change(request(a, tok), r6Second); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != r6Second {
			t.Fatalf("addresses after the second change = %q, want the only address replaced", got)
		}
		if got := r5Subjects(e, a, r6First); got != r5SubjectVerify {
			t.Fatalf("mail to the replaced address = %q, want only its verification", got)
		}
	})
}
