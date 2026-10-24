package invite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/invite"
)

// noMail drops every message; these tests never send.
var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

func emailPlugin() *email.Plugin {
	return email.New(email.Login(), email.WithMailer(noMail), email.Links(func(auth.Purpose, auth.Token) string { return "x" }))
}

// signIn is the smallest sign-in method, so auth.New accepts a setup.
type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

var base = auth.WithBaseURL("https://app.example.com")

// TestValidate refuses lifetimes that are not positive or too long, and a
// setup with no way to build a link.
func TestValidate(t *testing.T) {
	for name, p := range map[string]*invite.Plugin{
		"ttl":        invite.New(invite.WithTTL(0)),
		"long ttl":   invite.New(invite.WithTTL(invite.MaxTTL + time.Second)),
		"cookie ttl": invite.New(invite.WithCookieTTL(-time.Second)),
	} {
		if _, err := auth.New(base, auth.WithPlugins(signIn{}, emailPlugin(), p)); !errors.Is(err, invite.ErrBadTTL) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, emailPlugin(), invite.New())); !errors.Is(err, invite.ErrNoBase) {
		t.Errorf("no base: %v", err)
	}
	// A private invite is mailed: without a plugin that delivers email it
	// is refused at start-up, unless PublicOnly turns private invites off.
	if _, err := auth.New(base, auth.WithPlugins(signIn{}, invite.New())); !errors.Is(err, invite.ErrNoEmail) {
		t.Errorf("no email plugin: %v", err)
	}
	if _, err := auth.New(base, auth.WithPlugins(signIn{}, invite.New(invite.PublicOnly()))); err != nil {
		t.Errorf("PublicOnly without the email plugin: %v", err)
	}
	links := invite.Links(func(auth.Token) string { return "https://x/i" })
	if _, err := auth.New(auth.WithPlugins(signIn{}, emailPlugin(), invite.New(links, invite.HideInviter(), invite.WithTTL(time.Minute), invite.WithCookieTTL(time.Minute)))); err != nil {
		t.Fatalf("Links without a base URL = %v", err)
	}
}

// TestWiring: tables, the rows DeleteUser removes, migrations on every
// engine, the operations and their rate rules.
func TestWiring(t *testing.T) {
	p := invite.New()
	if p.Name() != invite.PluginName {
		t.Fatal("name")
	}
	if _, err := auth.New(base, auth.WithPlugins(signIn{}, emailPlugin(), p)); err != nil {
		t.Fatal(err)
	}
	if ts := p.Tables(); len(ts) != 2 || ts[0] != invite.TableInvite || ts[1] != invite.TableUse {
		t.Fatalf("Tables = %+v", ts)
	}
	ut := p.UserTables()
	if len(ut) != 2 || ut[0].Column != invite.ColCreatedBy || ut[1].Column != invite.ColUseUser {
		t.Fatalf("UserTables = %+v", ut)
	}
	for _, engine := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(ms) != 1 || len(ms[0].Statements) != 2 || !strings.Contains(ms[0].Statements[1], "PRIMARY KEY") {
			t.Fatalf("%s migrations = %+v %v", engine, ms, err)
		}
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("unknown engine = %v", err)
	}
	if n := len(p.Operations()); n != 6 {
		t.Fatalf("%d operations", n)
	}
	if n := len(p.RateLimits()); n != 3 {
		t.Fatalf("%d rate rules", n)
	}
	hooks := p.DataHooks()
	if hooks.User.AfterCreate == nil || hooks.Session.AfterCreate == nil {
		t.Fatal("the user and session hooks must be set")
	}
}

func TestDefaultText(t *testing.T) {
	if got := invite.DefaultText("Ines", "https://x/i"); !strings.HasPrefix(got, "Ines invited you") || !strings.Contains(got, "https://x/i") {
		t.Fatalf("named = %q", got)
	}
	if got := invite.DefaultText("", "https://x/i"); !strings.HasPrefix(got, "You have been invited") {
		t.Fatalf("anonymous = %q", got)
	}
}
