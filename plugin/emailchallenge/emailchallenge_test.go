package emailchallenge_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
)

// noMail is a mailer that drops every message; these tests never send.
var noMail = email.MailerFunc(func(context.Context, email.Mail) error { return nil })

// mute registers a sign-in, verifiable kind whose plugin cannot deliver.
type mute struct{}

const kindMute auth.IdentifierKindName = "mute"

func (mute) Name() string { return "mute" }
func (mute) Identifiers() []auth.IdentifierKind {
	return []auth.IdentifierKind{{
		Name: kindMute, Unique: true, CanLogin: true, Verifiable: true,
		Normalize: func(raw string) (string, error) { return raw, nil },
	}}
}

var base = auth.WithBaseURL("https://app.example.com")

// emailPlugin builds links of its own, so a test without a base URL fails
// only on this plugin.
func emailPlugin() *email.Plugin {
	return email.New(email.Login(), email.WithMailer(noMail), email.Links(func(auth.Purpose, auth.Token) string { return "x" }))
}

// TestValidate refuses every configuration that could never complete a
// challenge.
func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		opts []auth.Option
		want error
	}{
		{"ttl", []auth.Option{base, auth.WithPlugins(emailPlugin(), emailchallenge.New(emailchallenge.WithTTL(0)))}, emailchallenge.ErrBadTTL},
		{"attempts", []auth.Option{base, auth.WithPlugins(emailPlugin(), emailchallenge.New(emailchallenge.WithMaxAttempts(0)))}, emailchallenge.ErrBadAttempt},
		{"mode", []auth.Option{base, auth.WithPlugins(emailPlugin(), emailchallenge.New(emailchallenge.WithLinkMode("magic")))}, emailchallenge.ErrBadMode},
		{"base", []auth.Option{auth.WithPlugins(emailPlugin(), emailchallenge.New())}, emailchallenge.ErrNoBase},
		{"no kind", []auth.Option{base, auth.WithPlugins(mute{}, emailchallenge.New())}, emailchallenge.ErrNoKinds},
		{"no identifier at all", []auth.Option{base, auth.WithPlugins(emailchallenge.New())}, emailchallenge.ErrNoKinds},
		{"unknown kind", []auth.Option{base, auth.WithPlugins(emailPlugin(), emailchallenge.New(emailchallenge.Kinds("fax")))}, emailchallenge.ErrBadKinds},
		{"mute kind", []auth.Option{base, auth.WithPlugins(mute{}, emailPlugin(), emailchallenge.New(emailchallenge.Kinds(kindMute)))}, emailchallenge.ErrBadKinds},
	}
	for _, c := range cases {
		if _, err := auth.New(c.opts...); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	// Beside a kind that delivers, a mute one is left out; Links replaces
	// the base URL; an explicit deliverable kind is accepted.
	links := emailchallenge.Links(func(auth.Token) string { return "https://x/l" })
	if _, err := auth.New(auth.WithPlugins(mute{}, emailPlugin(), emailchallenge.New(links, emailchallenge.Kinds(email.KindEmail), emailchallenge.WithTTL(time.Minute), emailchallenge.WithMaxAttempts(5), emailchallenge.WithLinkMode(emailchallenge.SameDevice)))); err != nil {
		t.Fatalf("explicit kind with Links = %v", err)
	}
}

// TestInit_LeavesOutAMuteKind: with no Kinds, the defaults skip a kind whose
// plugin cannot deliver rather than fail on it.
func TestInit_LeavesOutAMuteKind(t *testing.T) {
	if _, err := auth.New(base, auth.WithPlugins(mute{}, emailPlugin(), emailchallenge.New())); err != nil {
		t.Fatal(err)
	}
}

// TestWiring: the table, its migration on every engine, the operations and
// their rate rules.
func TestWiring(t *testing.T) {
	p := emailchallenge.New()
	if p.Name() != emailchallenge.PluginName || !p.SignsIn() {
		t.Fatal("name or SignsIn")
	}
	if _, err := auth.New(base, auth.WithPlugins(emailPlugin(), p)); err != nil {
		t.Fatal(err)
	}
	if ts := p.Tables(); len(ts) != 1 || ts[0] != emailchallenge.TableChallenge {
		t.Fatalf("Tables = %+v", ts)
	}
	for _, engine := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(ms) != 1 || !strings.Contains(ms[0].Statements[0], emailchallenge.TableNameChallenge) {
			t.Fatalf("%s migrations = %+v %v", engine, ms, err)
		}
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("unknown engine = %v", err)
	}
	if n := len(p.Operations()); n != 5 {
		t.Fatalf("%d operations", n)
	}
	ids := map[auth.EndpointID]bool{}
	for _, r := range p.RateLimits() {
		ids[r.Match] = true
	}
	for _, id := range []auth.EndpointID{emailchallenge.EndpointStart, emailchallenge.EndpointPoll, emailchallenge.EndpointVerifyOTP, emailchallenge.EndpointApprove, emailchallenge.EndpointContext} {
		if !ids[id] {
			t.Errorf("no rate rule for %s", id)
		}
	}
}

func TestRateIdentifier_Folds(t *testing.T) {
	if got := (emailchallenge.StartOrToken{Identifier: " Ada@Example.COM "}).RateIdentifier(); got != "ada@example.com" {
		t.Fatalf("RateIdentifier = %q", got)
	}
}

func TestDefaultText(t *testing.T) {
	got := emailchallenge.DefaultText("https://x/l?token=t", "123456", "Firefox", "203.0.113.1")
	for _, want := range []string{"https://x/l?token=t", "123456", "Firefox (203.0.113.1)", "ignore"} {
		if !strings.Contains(got, want) {
			t.Errorf("text lacks %q: %s", want, got)
		}
	}
	if strings.Contains(emailchallenge.DefaultText("l", "1", "", ""), "came from") {
		t.Error("a request with no client details names one")
	}
}
