package email_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// TestNoMail: without a mailer auth.New still refuses the plugin unless the
// app says NoMail; with NoMail it needs neither a mailer nor a base URL,
// serves only the routes that mail nobody, and Deliver refuses; NoMail with
// a mailer or with any option that mails is refused naming that option.
func TestNoMail(t *testing.T) {
	if _, err := auth.New(auth.WithBaseURL("https://x.example"), auth.WithPlugins(signIn{}, email.New(email.Login()))); !errors.Is(err, email.ErrNoMailer) || !strings.Contains(err.Error(), "NoMail") {
		t.Fatalf("no mailer and no NoMail: %v", err)
	}
	p := email.New(email.Login(), email.Multiple(), email.NoMail())
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatalf("NoMail without a mailer or a base URL: %v", err)
	}
	var routes []string
	for _, op := range p.Operations() {
		routes = append(routes, op.Route())
	}
	if got := strings.Join(routes, " "); got != "/email/list /email/make-primary /email/remove" {
		t.Fatalf("NoMail routes = %s", got)
	}
	if err := p.Deliver(context.Background(), auth.Identity{Kind: email.KindEmail, Value: "a@b.co"}, auth.Message{Purpose: auth.PurposeVerify}); !errors.Is(err, email.ErrNoMailer) {
		t.Fatalf("Deliver under NoMail: %v", err)
	}
	for name, opt := range map[string]email.Option{
		"email.WithMailer":         email.WithMailer(noMail),
		"email.Recover":            email.Recover(),
		"email.SignInWithCode":     email.SignInWithCode(),
		"email.SignUpWithCode":     email.SignUpWithCode(),
		"email.VerifyByCode":       email.VerifyByCode(),
		"email.Welcome":            email.Welcome(),
		"email.SignInOnVerify":     email.SignInOnVerify(),
		"email.ApproveChangeFirst": email.ApproveChangeFirst(),
		"email.VerifyByGET":        email.VerifyByGET("/verified"),
		"email.ResendOnSignIn":     email.ResendOnSignIn(),
	} {
		_, err := auth.New(auth.WithBaseURL("https://x.example"), auth.WithPlugins(signIn{}, email.New(email.Login(), email.NoMail(), opt)))
		if !errors.Is(err, email.ErrNeedsMail) || !strings.Contains(err.Error(), name) {
			t.Errorf("NoMail with %s: %v", name, err)
		}
	}
}
