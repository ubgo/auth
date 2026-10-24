package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// Round 5 of the feature work, the core's last rows: the one-step
// address change while nothing is verified, on a real database.

// r5Typo is the address a user mistyped at sign-up; r5Fixed is the one they
// meant; r5Bob is another account's verified address.
const (
	r5Typo  = "alice@exmaple.com"
	r5Fixed = "alice@example.com"
	r5Bob   = "bob@example.com"
)

// Subjects the default templates give the mails these tests look for.
const (
	r5SubjectVerify  = "Verify your email address"
	r5SubjectAttempt = "Someone tried to sign up with your address"
)

// r5Subjects lists the subjects of every mail sent to addr, in order.
func r5Subjects(e *env, a *auth.Auth, addr string) string {
	a.WaitDeliveries()
	var out []string
	for _, m := range e.mail.To(a, addr) {
		out = append(out, m.Subject)
	}
	return strings.Join(out, ",")
}

func TestEmailReplaceUnverified_ReplacesAtOnceWhileNothingIsVerified(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.ReplaceUnverified())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), r5Typo); err != nil {
			t.Fatal(err)
		}
		if err := em.Change(request(a, tok), r5Fixed); err != nil {
			t.Fatal(err)
		}
		// The typo is gone, the new address is the user's only one, still
		// unverified, and the verification went to it; the typo got nothing
		// (no undo: an unverified address has nobody to warn).
		if got := identAddresses(t, em, a, tok); got != r5Fixed {
			t.Fatalf("addresses after the change = %q", got)
		}
		if got := r5Subjects(e, a, r5Fixed); got != r5SubjectVerify {
			t.Fatalf("mail to the new address = %q", got)
		}
		if got := r5Subjects(e, a, r5Typo); got != r5SubjectVerify {
			t.Fatalf("mail to the typo = %q, want only the sign-up verification", got)
		}
		// Verifying the new address makes it the verified primary, the usual
		// first-address rule.
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, r5Fixed)); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != r5Fixed+"[v][p]" {
			t.Fatalf("addresses after verifying = %q", got)
		}
		// From now on a change is the two-step one: nothing changes until the
		// confirm link is used, and the undo goes to the old address.
		if err := em.Change(request(a, tok), "alice@work.example"); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != r5Fixed+"[v][p]" {
			t.Fatalf("a verified address was replaced at once: %q", got)
		}
		if _, err := em.ConfirmChange(anon(a), e.mail.LastToken(t, a, "alice@work.example")); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(r5Subjects(e, a, r5Fixed), "changed") {
			t.Fatalf("the old verified address got no undo mail: %q", r5Subjects(e, a, r5Fixed))
		}
	})
}

// TestEmailReplaceUnverified_IsEnumerationSafe: a change to another account's
// verified address answers like a change to a free one, changes nothing, and
// tells that account's owner, as a duplicate sign-up does; a change to the
// address the user already has re-sends the verification and adds no row.
func TestEmailReplaceUnverified_IsEnumerationSafe(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.ReplaceUnverified())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		identUser(t, a, r5Bob)
		_, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), r5Typo); err != nil {
			t.Fatal(err)
		}
		if err := em.Change(request(a, tok), r5Bob); err != nil {
			t.Fatalf("a change to a taken address must answer OK, got %v", err)
		}
		if got := identAddresses(t, em, a, tok); got != r5Typo {
			t.Fatalf("a taken address changed the account: %q", got)
		}
		if got := r5Subjects(e, a, r5Bob); got != r5SubjectAttempt {
			t.Fatalf("mail to the owner = %q", got)
		}
		// The same address again: one more verification, still one row.
		if err := em.Change(request(a, tok), strings.ToUpper(r5Typo)); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != r5Typo {
			t.Fatalf("addresses = %q", got)
		}
		if got := r5Subjects(e, a, r5Typo); got != r5SubjectVerify+","+r5SubjectVerify {
			t.Fatalf("mail to the typo = %q", got)
		}
	})
}

// TestEmailReplaceUnverified_OffByDefault: without the option a user with an
// unverified address still gets the confirm step, so nothing changes until
// the link is used.
func TestEmailReplaceUnverified_OffByDefault(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin()
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), r5Typo); err != nil {
			t.Fatal(err)
		}
		if err := em.Change(request(a, tok), r5Fixed); err != nil {
			t.Fatal(err)
		}
		if got := identAddresses(t, em, a, tok); got != r5Typo {
			t.Fatalf("addresses = %q, want the typo until the confirm link is used", got)
		}
	})
}

func TestEmailReplaceUnverified_Faults(t *testing.T) {
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		em := e.emailPlugin(email.ReplaceUnverified())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), r5Typo); err != nil {
			t.Fatal(err)
		}
		return func(context.Context) error { return em.Change(request(a, tok), r5Fixed) }
	})
}

// TestEmailReplaceUnverified_UnderMultipleReplacesOnlyOneAddress: with
// several addresses allowed, a change replaces the address it names (the
// primary one, or the oldest when none is primary) and leaves the user's
// other unverified addresses alone, since those were added on purpose.
func TestEmailReplaceUnverified_UnderMultipleReplacesOnlyOneAddress(t *testing.T) {
	const second = "alice.second@example.org"
	eachEngine(t, func(t *testing.T, e *env) {
		em := e.emailPlugin(email.ReplaceUnverified(), email.Multiple())
		a := e.newAuth(t, nil, em, e.passwordPlugin())
		_, tok := identUser(t, a, "")
		if err := em.Add(request(a, tok), r5Typo); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(time.Minute)
		if err := em.Add(request(a, tok), second); err != nil {
			t.Fatal(err)
		}
		if err := em.Change(request(a, tok), r5Fixed); err != nil {
			t.Fatal(err)
		}
		if got, want := identAddresses(t, em, a, tok), second+" "+r5Fixed; got != want {
			t.Fatalf("addresses after the change = %q, want %q: only the oldest address is replaced", got, want)
		}
	})
}
