package organization

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// signInStub satisfies the core's "at least one sign-in method" rule.
type signInStub struct{}

func (signInStub) Name() string  { return "signin" }
func (signInStub) SignsIn() bool { return true }

// fakeEmail is a plugin that is only NAMED "email": it satisfies Requires,
// which checks names, but registers no email identifier kind.
type fakeEmail struct{}

func (fakeEmail) Name() string { return email.PluginName }

// wireNoDB wires the plugin with no database, so Conn fails.
func wireNoDB(t *testing.T) *Plugin {
	t.Helper()
	p := New()
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"),
		auth.WithPlugins(signInStub{}, email.New(email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil }))), p)); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestNoDatabase_Surfaces: a plugin wired without a database reports
// auth.ErrNoDatabase rather than an empty answer.
func TestNoDatabase_Surfaces(t *testing.T) {
	p := wireNoDB(t)
	ctx := context.Background()
	if _, err := p.RoleOf(ctx, "org_1", "usr_1"); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("RoleOf without a database: %v", err)
	}
	if _, err := p.Sweep(ctx, p.core.Now()); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("Sweep without a database: %v", err)
	}
}

// TestValidate_RefusesUndeliverableInvitations: a plugin merely named "email"
// passes Requires but cannot address an invitation, and an invitation mail
// needs a link.
func TestValidate_RefusesUndeliverableInvitations(t *testing.T) {
	_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, fakeEmail{}, New()))
	if err == nil || !strings.Contains(err.Error(), "addressed by email") {
		t.Fatalf("no email kind: %v", err)
	}
	noMail := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	// The email plugin gets its own links, so only this plugin lacks one.
	emailLinks := email.Links(func(auth.Purpose, auth.Token) string { return "https://x/e" })
	_, err = auth.New(auth.WithPlugins(signInStub{}, email.New(email.WithMailer(noMail), emailLinks), New()))
	if err == nil || !strings.Contains(err.Error(), "invitation links") {
		t.Fatalf("no base URL and no InviteLink: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signInStub{}, email.New(email.WithMailer(noMail), emailLinks), New(InviteLink(func() string { return "https://x/i" })))); err != nil {
		t.Fatalf("InviteLink stands in for a base URL: %v", err)
	}
}

// TestMigrations_RefusesAnUnknownEngine: DDL for an engine the core does not
// support would be guessed, so it is refused.
func TestMigrations_RefusesAnUnknownEngine(t *testing.T) {
	if _, err := wireNoDB(t).TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
}

// TestInit_DefaultLinkIsBaseURLPlusInvitePage: a trailing slash on the base
// URL does not double up.
func TestInit_DefaultLinkIsBaseURLPlusInvitePage(t *testing.T) {
	p := New()
	noMail := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com/"), auth.WithPlugins(signInStub{}, email.New(email.WithMailer(noMail)), p)); err != nil {
		t.Fatal(err)
	}
	if got := p.links(); got != "https://app.example.com"+DefaultInvitePage {
		t.Fatalf("link = %q", got)
	}
}

// TestValidate_RefusesAnEmptyInviteLimit: a zero limit or window would make
// every invitation refused or unlimited by accident.
func TestValidate_RefusesAnEmptyInviteLimit(t *testing.T) {
	noMail := email.MailerFunc(func(context.Context, email.Mail) error { return nil })
	for _, p := range []*Plugin{New(InviteLimit(0, time.Hour)), New(InviteLimit(5, 0))} {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(signInStub{}, email.New(email.WithMailer(noMail)), p))
		if err == nil || !strings.Contains(err.Error(), "InviteLimit") {
			t.Fatalf("err = %v", err)
		}
	}
}

// TestMembersQuery_JoinsTheCoreUser pins the exported statement an app may run
// itself: members joined to auth_user, oldest member first.
func TestMembersQuery_JoinsTheCoreUser(t *testing.T) {
	p := wireNoDB(t)
	var m Member
	q, err := MembersQuery(p.core, "org_1", &m)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`INNER JOIN "auth_user"`, `"om"."org_id" = `, `ORDER BY "om"."joined_at" ASC`} {
		if !strings.Contains(q.SQL, want) {
			t.Fatalf("SQL lacks %s:\n%s", want, q.SQL)
		}
	}
	if len(q.Args) != 1 || q.Args[0] != "org_1" {
		t.Fatalf("args = %v", q.Args)
	}
}
