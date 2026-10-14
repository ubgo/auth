package integration

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/password"
)

// p3DNS answers RequireMX: "mail.example" has a mail server, every other
// name does not exist.
type p3DNS struct{}

func (p3DNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if name == "mail.example" {
		return []*net.MX{{Host: "mx.mail.example.", Pref: 10}}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (p3DNS) LookupHost(_ context.Context, host string) ([]string, error) {
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// TestP3_EmailAddressChecks: CheckAddresses refuses a new address at sign-up,
// add and change (before the confirm mail is sent), while an account created
// before the check was switched on still signs in, because sign-in never runs
// the checks.
func TestP3_EmailAddressChecks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		// The account exists before the blocklist does.
		before := e.passwordPlugin()
		a0 := e.newAuth(t, nil, e.emailPlugin(), before)
		if _, err := before.SignUp(anon(a0), password.SignUpRequest{Identifier: "old@mailinator.com", Password: secret}); err != nil {
			t.Fatal(err)
		}

		checks := email.CheckAddresses(email.BlockDomains("mailinator.com"), email.RequireMX(p3DNS{}, 0))
		em, pw := e.emailPlugin(checks, email.Multiple()), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw)

		for _, addr := range []string{"new@mailinator.com", "new@sub.mailinator.com", "new@nowhere.example"} {
			if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: addr, Password: secret}); !errors.Is(err, email.ErrAddressRejected) {
				t.Fatalf("sign up %s: %v, want ErrAddressRejected", addr, err)
			}
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "old@mailinator.com", Password: secret}); err != nil {
			t.Fatalf("an existing account on a blocked domain cannot sign in: %v", err)
		}

		up, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "ok@mail.example", Password: secret})
		if err != nil {
			t.Fatalf("sign up on a domain with MX: %v", err)
		}
		if err := em.Add(request(a, up.Token), "x@mailinator.com"); !errors.Is(err, email.ErrAddressRejected) {
			t.Fatalf("add: %v, want ErrAddressRejected", err)
		}
		if err := em.Change(request(a, up.Token), "y@mailinator.com"); !errors.Is(err, email.ErrAddressRejected) {
			t.Fatalf("change: %v, want ErrAddressRejected", err)
		}
		if n := len(e.mail.To(a, "y@mailinator.com")); n != 0 {
			t.Fatalf("%d confirm mails went to a refused address", n)
		}
		if err := em.Add(request(a, up.Token), "z@mail.example"); err != nil {
			t.Fatalf("add an allowed address: %v", err)
		}
	})
}

// TestP3_AuditRecordsOAuthLinks: with no wiring beyond the two plugins, an
// explicit link flow and the implicit link by a verified email each record
// account_linked (read from oauth.AnnotationAction) for the linked user; a sign-up through a provider does not, and a link rolled
// back by a later hook records nothing.
func TestP3_AuditRecordsOAuthLinks(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		alpha := &tokensProvider{name: "alpha", profile: oauth.Profile{Subject: "a-1", Name: "Carol"}}
		beta := &tokensProvider{name: "beta", profile: oauth.Profile{Subject: "b-1"}}
		gamma := &tokensProvider{name: "gamma", profile: oauth.Profile{Subject: "g-1", Email: alice, EmailVerified: true}}
		au := audit.New()
		refuse := false
		oa := oauth.New(oauth.WithProviders(alpha, beta, gamma),
			oauth.OnResolved(func(context.Context, *auth.Call, oauth.ResolvedEvent) error {
				if refuse {
					return errors.New("refused by the app")
				}
				return nil
			}))
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), oa, au)
		links := func() []audit.Event {
			t.Helper()
			return must[audit.Page](t)(au.Events(context.Background(), audit.Query{Type: audit.TypeAccountLinked})).Events
		}

		carol, first := tokensSignIn(t, a, "alpha")
		if n := len(links()); n != 0 {
			t.Fatalf("a sign-up recorded %d links", n)
		}
		// The callback is a Query, recorded without audit.Queries() because
		// it resolved a user.
		signIns := must[audit.Page](t)(au.Events(context.Background(), audit.Query{Type: audit.TypeUserSignedIn})).Events
		if len(signIns) != 1 || signIns[0].Op != oauth.CallbackEndpoint("alpha") || signIns[0].ActorID != first.User.ID {
			t.Fatalf("callback events = %+v", signIns)
		}
		tokensLink(t, carol, "beta")
		got := links()
		if len(got) != 1 || got[0].Op != audit.LinkedOp("beta") || got[0].ActorID != first.User.ID || got[0].Type != audit.TypeAccountLinked || got[0].SessionID == "" {
			t.Fatalf("explicit link events = %+v", got)
		}

		tokensVerifiedAlice(t, a)
		e.clock.Advance(time.Second) // newest first is then by time, not the id tiebreak
		_, viaEmail := tokensSignIn(t, a, "gamma")
		got = links()
		if len(got) != 2 || got[0].Op != audit.LinkedOp("gamma") || got[0].ActorID != viaEmail.User.ID {
			t.Fatalf("implicit link events = %+v", got)
		}

		refuse = true
		beta.profile = oauth.Profile{Subject: "b-2"}
		again := &tokensBrowser{a: a, session: carol.session}
		tokensMust(t, again.start("beta", oauth.StartRequest{Link: oauth.LinkFlag}))
		if _, err := again.finish("beta"); err == nil {
			t.Fatal("the refusing hook did not fail the link")
		}
		if n := len(links()); n != 2 {
			t.Fatalf("a rolled-back link left %d link events, want 2", n)
		}
	})
}
