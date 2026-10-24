package email_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// TestNew_CodesNeedLogin: a sign-in code for an address that cannot sign in
// would be a way in that the kind forbids, so auth.New refuses it.
func TestNew_CodesNeedLogin(t *testing.T) {
	_, err := auth.New(auth.WithBaseURL("https://x.example"), auth.WithPlugins(signIn{}, email.New(email.WithMailer(noMail), email.SignInWithCode())))
	if !errors.Is(err, email.ErrCodesNeedLogin) {
		t.Fatalf("codes without Login = %v", err)
	}
}

// TestCodeOperations_OnlyWhenCodesSignIn: the code endpoints and their rate
// limits exist only when code sign-in is on, so an app without it exposes no
// route that mails codes.
func TestCodeOperations_OnlyWhenCodesSignIn(t *testing.T) {
	has := func(p *email.Plugin, id auth.EndpointID) (op, rule bool) {
		for _, o := range p.Operations() {
			if o.Info().ID == id {
				op = true
			}
		}
		for _, r := range p.RateLimits() {
			if r.Match == id {
				rule = true
			}
		}
		return op, rule
	}
	if op, rule := has(email.New(email.Login()), email.EndpointSendCode); op || rule {
		t.Fatalf("codes off: operation %v, rate rule %v", op, rule)
	}
	if op, rule := has(email.New(email.Login(), email.SignUpWithCode()), email.EndpointSendCode); !op || !rule {
		t.Fatalf("codes on: operation %v, rate rule %v", op, rule)
	}
}

func TestCodeRequest_RateIdentifierFolds(t *testing.T) {
	if (email.CodeRequest{Email: " A@B.co ", Code: "1"}).RateIdentifier() != "a@b.co" {
		t.Fatal("guesses must be counted per normalized address")
	}
}

// TestDefaultTemplates_UseTheSendersWording: a purpose the email plugin does
// not know (an organization invite, say) is worded by its sender through
// DefaultSubject and DefaultText; without them the generic fallback remains.
func TestDefaultTemplates_UseTheSendersWording(t *testing.T) {
	const other auth.Purpose = "organization.invite"
	cases := []struct {
		m                     auth.Message
		wantSubject, wantText string
	}{
		{auth.Message{Purpose: other, Link: "https://l", DefaultSubject: "Join Acme", DefaultText: "Accept: https://l"}, "Join Acme", "Accept: https://l"},
		{auth.Message{Purpose: other, Link: "https://l", DefaultText: "Accept: https://l"}, "A message about your account", "Accept: https://l"},
		{auth.Message{Purpose: other, Link: "https://l"}, "A message about your account", "https://l"},
	}
	for i, c := range cases {
		if s, text := email.DefaultTemplates(c.m); s != c.wantSubject || text != c.wantText {
			t.Errorf("case %d: %q / %q, want %q / %q", i, s, text, c.wantSubject, c.wantText)
		}
	}
	// The core's own purposes keep the plugin's wording.
	if s, _ := email.DefaultTemplates(auth.Message{Purpose: auth.PurposeReset, DefaultSubject: "ignored", DefaultText: "ignored"}); s != "Reset your password" {
		t.Errorf("reset subject = %q", s)
	}
}

// TestCodeLimitOptions: the two limit options replace the default rate
// rules of the code routes, and nothing else.
func TestCodeLimitOptions(t *testing.T) {
	p := email.New(email.Login(), email.SignInWithCode(), email.WithCodeSendLimit(7, 2*time.Hour), email.WithCodeTryLimit(4, time.Minute))
	got := map[auth.EndpointID]auth.RateRule{}
	for _, r := range p.RateLimits() {
		got[r.Match] = r
	}
	if r := got[email.EndpointSendCode]; r.Limit != 7 || r.Window != 2*time.Hour {
		t.Fatalf("send-code rule = %+v", r)
	}
	if r := got[email.EndpointSignInCode]; r.Limit != 4 || r.Window != time.Minute {
		t.Fatalf("sign-in-code rule = %+v", r)
	}
	if r := got[email.EndpointResend]; r.Limit != 3 || r.Window != time.Hour {
		t.Fatalf("resend rule changed: %+v", r)
	}
}

// TestNew_SignInOnVerifyNeedsLogin: a verify link that signs in would be a
// way in for a kind that cannot sign in, so auth.New refuses it.
func TestNew_SignInOnVerifyNeedsLogin(t *testing.T) {
	_, err := auth.New(auth.WithBaseURL("https://x.example"), auth.WithPlugins(signIn{}, email.New(email.WithMailer(noMail), email.SignInOnVerify())))
	if !errors.Is(err, email.ErrSignInOnVerifyNeedsLogin) {
		t.Fatalf("SignInOnVerify without Login = %v", err)
	}
	if _, err := auth.New(auth.WithBaseURL("https://x.example"), auth.WithPlugins(signIn{}, email.New(email.Login(), email.WithMailer(noMail), email.SignInOnVerify()))); err != nil {
		t.Fatalf("SignInOnVerify with Login = %v", err)
	}
}

// TestApproveChangeFirst_RegistersTheRoute: approve-change exists only with
// the option, so an app without it exposes no extra public route.
func TestApproveChangeFirst_RegistersTheRoute(t *testing.T) {
	has := func(p *email.Plugin) bool {
		for _, o := range p.Operations() {
			if o.Info().ID == email.EndpointApproveChange {
				return true
			}
		}
		return false
	}
	if has(email.New()) {
		t.Fatal("approve-change registered without ApproveChangeFirst")
	}
	if !has(email.New(email.ApproveChangeFirst())) {
		t.Fatal("approve-change missing with ApproveChangeFirst")
	}
	// The code form of the approval exists only with both switches, and is
	// rate limited per address like the other code checks.
	hasCode := func(p *email.Plugin) (route, rule bool) {
		for _, o := range p.Operations() {
			route = route || o.Info().ID == email.EndpointApproveCode
		}
		for _, r := range p.RateLimits() {
			rule = rule || r.Match == email.EndpointApproveCode && r.Key == auth.ByIdentifier && r.Limit > 0
		}
		return route, rule
	}
	for _, p := range []*email.Plugin{email.New(), email.New(email.ApproveChangeFirst()), email.New(email.VerifyByCode())} {
		if route, rule := hasCode(p); route || rule {
			t.Fatalf("approve-change-code present without both switches: route %v rule %v", route, rule)
		}
	}
	if route, rule := hasCode(email.New(email.ApproveChangeFirst(), email.VerifyByCode())); !route || !rule {
		t.Fatalf("approve-change-code missing with both switches: route %v rule %v", route, rule)
	}
	if last := email.CodeKindValues[len(email.CodeKindValues)-1]; last != email.CodeKindApprove {
		t.Fatalf("CodeKindValues ends with %q", last)
	}
	if got := email.DefaultLink("https://app.example.com", email.PurposeApproveToken, auth.Token("t")); got != "https://app.example.com/approve-email-change?token=t" {
		t.Fatalf("approval link = %q", got)
	}
}
