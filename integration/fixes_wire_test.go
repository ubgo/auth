package integration

import (
	"net/http"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
	"github.com/ubgo/auth/plugin/invite"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/referral"
)

// redactedJSON is what an auth.Token answers in JSON; a token a response
// hands to the caller must never read as this.
const redactedJSON = "[redacted]"

// wirePlugins is an app with the plugins whose answers carry tokens and
// whose lists take ?limit= and ?offset=.
func wirePlugins(e *authtest.Env) []auth.Plugin {
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(e.Mail)),
		password.New(password.Argon2(fastArgon2)),
		invite.New(),
		referral.New(),
		emailchallenge.New(),
	}
}

// TestHTTP_ResponseTokensAreUsable: the token invite.create and
// emailchallenge.start hand to the caller arrives as itself, not as
// "[redacted]", and works when a Go client sends it back through the
// library's own request types, which encode it too.
func TestHTTP_ResponseTokensAreUsable(t *testing.T) {
	e := authtest.New(t, authtest.WithPlugins(wirePlugins))
	u := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: harnessUser})
	h := harnessHandler(e.Auth)

	creator := e.Browser(h)
	creator.SetSession(e.SignIn(u.ID))
	var created invite.Created
	creator.Post("/auth/invite/create", invite.Request{}).Expect(http.StatusOK).Decode(&created)
	if created.Token == "" || created.Token.Reveal() == redactedJSON {
		t.Fatalf("invite.create answered token %q", created.Token.Reveal())
	}
	// A signed-out visitor activates it with the Go request type.
	e.Browser(h).Post("/auth/invite/activate", invite.TokenRequest{Token: created.Token}).Expect(http.StatusOK)

	var started emailchallenge.Result
	e.Browser(h).Post("/auth/emailchallenge/start", emailchallenge.StartOrToken{Identifier: harnessUser}).Expect(http.StatusOK).Decode(&started)
	if started.PollToken == "" || started.PollToken.Reveal() == redactedJSON {
		t.Fatalf("emailchallenge.start answered pollToken %q", started.PollToken.Reveal())
	}
	// A client with no cookie jar polls with the token alone: a fresh
	// browser has no flow cookie, so only the body can bind it.
	var polled emailchallenge.Result
	e.Browser(h).Post("/auth/emailchallenge/poll", emailchallenge.StartOrToken{PollToken: started.PollToken}).Expect(http.StatusOK).Decode(&polled)
	if polled.State != emailchallenge.StatePending {
		t.Fatalf("cookieless poll = %q, want %q", polled.State, emailchallenge.StatePending)
	}
}

// TestHTTP_ListPagingFromTheQueryString: a list operation's numeric query
// parameters decode without a `,string` tag on the field, and a value that
// is not a number is still refused.
func TestHTTP_ListPagingFromTheQueryString(t *testing.T) {
	e := authtest.New(t, authtest.WithPlugins(wirePlugins))
	u := e.CreateUser("Ada", authtest.Identity{Kind: email.KindEmail, Value: harnessUser})
	b := e.Browser(harnessHandler(e.Auth))
	b.SetSession(e.SignIn(u.ID))
	for range 2 {
		b.Post("/auth/invite/create", invite.Request{}).Expect(http.StatusOK)
	}
	var page invite.ListResult
	b.Get("/auth/invite/list?limit=1&offset=1").Expect(http.StatusOK).Decode(&page)
	if len(page.Invites) != 1 || page.Total != 2 {
		t.Fatalf("invite.list?limit=1 = %d rows of %d", len(page.Invites), page.Total)
	}
	b.Get("/auth/referral/list?limit=5&offset=0").Expect(http.StatusOK)
	if r := b.Get("/auth/invite/list?limit=ten"); r.Status != http.StatusBadRequest || r.ErrorCode() != auth.ErrBadRequest.Code {
		t.Fatalf("limit=ten = %d %q, want 400 %q", r.Status, r.ErrorCode(), auth.ErrBadRequest.Code)
	}
}
