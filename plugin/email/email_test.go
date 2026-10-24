package email_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

func TestNormalizeKeepsDotsAndTags(t *testing.T) {
	if v, _ := email.Normalize("  A.B+Tag@Example.COM "); v != "a.b+tag@example.com" {
		t.Fatalf("Normalize = %q", v)
	}
}

func TestValidate(t *testing.T) {
	for _, ok := range []string{"a@b.co", "émile@example.com", "a+b@x.io"} {
		if err := email.Validate(ok); err != nil {
			t.Errorf("Validate(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "@b.co", "a@", "a@b@c.co", "a b@c.co", "a@localhost", strings.Repeat("a", 250) + "@b.co"} {
		if err := email.Validate(bad); err == nil {
			t.Errorf("Validate(%q) accepted", bad)
		}
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := auth.New(auth.WithBaseURL("https://x.example"), auth.WithPlugins(signIn{}, email.New())); !errors.Is(err, email.ErrNoMailer) {
		t.Fatalf("no mailer: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, email.New(email.WithMailer(noMail)))); !errors.Is(err, email.ErrNoBaseURL) {
		t.Fatalf("no base URL: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, email.New(email.WithMailer(noMail), email.RequireVerified(),
		email.Links(func(auth.Purpose, auth.Token) string { return "x" })))); err != nil {
		t.Fatalf("links instead of a base URL: %v", err)
	}
}

func TestOptions_ShapeTheKind(t *testing.T) {
	cases := []struct {
		opts                   []email.Option
		unique, login, recover bool
	}{
		{nil, true, false, false},
		{[]email.Option{email.Login(), email.Recover()}, true, true, true},
		{[]email.Option{email.Contact()}, false, false, false},
	}
	for _, c := range cases {
		k := email.New(c.opts...).Identifiers()[0]
		if k.Unique != c.unique || k.CanLogin != c.login || k.CanRecover != c.recover || !k.UniqueOnlyVerified || !k.Verifiable {
			t.Errorf("opts %d: kind = %+v", len(c.opts), k)
		}
	}
	custom := email.New(email.WithNormalizer(func(s string) (string, error) { return "x", nil })).Identifiers()[0]
	if v, _ := custom.Normalize("anything"); v != "x" {
		t.Error("WithNormalizer not applied")
	}
}

func TestDefaultLink_PointsAtAPageNotAnAPIRoute(t *testing.T) {
	got := email.DefaultLink("https://app.example.com", email.PurposeVerifyToken, auth.Token("a+b/c"))
	if got != "https://app.example.com/verify-email?token=a%2Bb%2Fc" {
		t.Fatalf("link = %q", got)
	}
}

func TestDefaultTemplates_EveryPurposeHasASubject(t *testing.T) {
	for _, p := range []auth.Purpose{auth.PurposeVerify, auth.PurposeReset, auth.PurposeSignUpAttempt, auth.PurposeChanged, auth.PurposeSignInCode, auth.PurposeSignInLink, auth.PurposeWelcome, "other.purpose"} {
		subject, text := email.DefaultTemplates(auth.Message{Purpose: p, Link: "https://l", Code: "123456"})
		if subject == "" || text == "" {
			t.Errorf("%s: empty template", p)
		}
	}
	if _, text := email.DefaultTemplates(auth.Message{Purpose: auth.PurposeSignUpAttempt, Link: "https://l"}); strings.Contains(text, "https://l") {
		t.Error("a sign-up notice must carry no link")
	}
}

func TestDeliver_UsesTheTemplate(t *testing.T) {
	var got email.Mail
	p := email.New(email.WithMailer(email.MailerFunc(func(_ context.Context, m email.Mail) error { got = m; return nil })))
	if err := p.Deliver(context.Background(), auth.Identity{Value: "a@b.co"}, auth.Message{Purpose: auth.PurposeReset, Link: "https://r"}); err != nil {
		t.Fatal(err)
	}
	if got.To != "a@b.co" || got.Subject != "Reset your password" || !strings.Contains(got.Text, "https://r") {
		t.Fatalf("mail = %+v", got)
	}
}

func TestColumns_AreNullableTextAndTimestamp(t *testing.T) {
	cols := email.New().Columns()
	if len(cols) != 2 || !cols[0].Nullable || cols[0].Type != auth.ColumnText || cols[1].Type != auth.ColumnTimestamp {
		t.Fatalf("columns = %+v", cols)
	}
}

func TestAddressRequest_RateIdentifierFolds(t *testing.T) {
	if (email.AddressRequest{Email: " A@B.co "}).RateIdentifier() != "a@b.co" {
		t.Fatal("rate key must fold like the normalizer")
	}
}

func TestTemplatesByLocale_FallsBackThroughTheChain(t *testing.T) {
	var got email.Mail
	p := email.New(
		email.WithMailer(email.MailerFunc(func(_ context.Context, m email.Mail) error { got = m; return nil })),
		email.TemplatesByLocale(map[string]email.TemplateFunc{"de": func(auth.Message) (string, string) { return "Passwort zurücksetzen", "…" }}),
		// Templates after TemplatesByLocale must not drop the translations.
		email.Templates(email.DefaultTemplates),
	)
	send := func(locale string) string {
		_ = p.Deliver(context.Background(), auth.Identity{Value: "a@b.co"}, auth.Message{Purpose: auth.PurposeReset, Locale: locale})
		return got.Subject
	}
	if s := send("de-AT"); s != "Passwort zurücksetzen" {
		t.Fatalf("de-AT = %q", s)
	}
	if s := send("fr"); s != "Reset your password" {
		t.Fatalf("fr = %q, want the English default", s)
	}
}

// TestDefaultTemplates_CodeForms: a verify or reset message that carries a
// code and no link is worded for the code; with a link the link wins.
func TestDefaultTemplates_CodeForms(t *testing.T) {
	for _, p := range []auth.Purpose{auth.PurposeVerify, auth.PurposeReset} {
		subject, text := email.DefaultTemplates(auth.Message{Purpose: p, Code: "424242"})
		if !strings.Contains(text, "424242") || !strings.Contains(subject, "code") || strings.Contains(text, "link") {
			t.Fatalf("%s code form = %q / %q", p, subject, text)
		}
		_, withLink := email.DefaultTemplates(auth.Message{Purpose: p, Code: "424242", Link: "https://x/l"})
		if !strings.Contains(withLink, "https://x/l") {
			t.Fatalf("%s with a link = %q", p, withLink)
		}
	}
}

// TestVerifyByCode_Wiring: the code routes and their rate rules exist only
// under VerifyByCode.
func TestVerifyByCode_Wiring(t *testing.T) {
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
	off := email.New(email.WithMailer(noMail))
	on := email.New(email.WithMailer(noMail), email.VerifyByCode())
	for _, id := range []auth.EndpointID{email.EndpointVerifyCode, email.EndpointConfirmCode} {
		if op, rule := has(off, id); op || rule {
			t.Fatalf("%s present without VerifyByCode", id)
		}
		if op, rule := has(on, id); !op || !rule {
			t.Fatalf("%s missing under VerifyByCode", id)
		}
	}
	if (email.AddressCodeRequest{Email: " A@B.co "}).RateIdentifier() != "a@b.co" {
		t.Fatal("rate key must fold like the normalizer")
	}
}

// TestCheckMetadata pins the bounds on client-supplied metadata.
func TestCheckMetadata(t *testing.T) {
	if err := email.CheckMetadata(nil); err != nil {
		t.Fatal(err)
	}
	ok := map[string]string{}
	for i := range email.MaxMetadataEntries {
		ok[string(rune('a'+i))] = strings.Repeat("v", email.MaxMetadataLength)
	}
	if err := email.CheckMetadata(ok); err != nil {
		t.Fatalf("at the bounds = %v", err)
	}
	ok["one more"] = "x"
	if err := email.CheckMetadata(ok); !errors.Is(err, auth.ErrBadRequest) {
		t.Fatalf("over the count = %v", err)
	}
	if err := email.CheckMetadata(map[string]string{strings.Repeat("k", email.MaxMetadataLength+1): "v"}); !errors.Is(err, auth.ErrBadRequest) {
		t.Fatalf("a key too long = %v", err)
	}
}
