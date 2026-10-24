package referral

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// signIn is the smallest sign-in method, so auth.New accepts a setup.
type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

func TestCheckSteps(t *testing.T) {
	for _, bad := range [][]string{{""}, {" a"}, {StepSignUp}, {"a", "a"}} {
		if err := checkSteps(bad); !errors.Is(err, ErrBadSteps) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if err := checkSteps([]string{"email_verified", "first_purchase"}); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(Steps("x", "x")))); !errors.Is(err, ErrBadSteps) {
		t.Fatalf("New with duplicate steps = %v", err)
	}
}

func TestNormalizeAndMask(t *testing.T) {
	if got := NormalizeCode(" ab12cd34 "); got != "AB12CD34" {
		t.Fatalf("NormalizeCode = %q", got)
	}
	cases := map[string]string{"": "", "ada@example.com": "a***@example.com", "nope": "hidden", "@x": "hidden", "a@": "hidden"}
	for in, want := range cases {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewCode(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		c := newCode()
		if !codePattern.MatchString(c) {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
	if len(seen) < 50 {
		t.Fatal("codes repeat")
	}
}

func TestProgress(t *testing.T) {
	p := New(Steps("first_purchase"))
	if r := p.Required(); len(r) != 2 || r[0] != StepSignUp {
		t.Fatalf("Required = %v", r)
	}
	got := p.progress([]string{StepSignUp, "stray"})
	if got.IsCompleted || got.Completed != 1 || got.Total != 2 || len(got.RemainingSteps) != 1 || got.RemainingSteps[0] != "first_purchase" {
		t.Fatalf("progress = %+v", got)
	}
	if done := p.progress([]string{"first_purchase", StepSignUp}); !done.IsCompleted {
		t.Fatalf("all steps = %+v", done)
	}
}

// TestWiring: tables, the rows DeleteUser removes, migrations on every
// engine, operations, rate rules; MarkStep before auth.New says the plugin
// is not wired.
func TestWiring(t *testing.T) {
	p := New(ShowEmails(), AfterStep(func(context.Context, Event) {}))
	if _, err := p.MarkStep(context.Background(), "u", StepSignUp, nil); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("MarkStep before New = %v", err)
	}
	if p.Name() != PluginName {
		t.Fatal("name")
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	if len(p.Tables()) != 3 || len(p.UserTables()) != 3 || len(p.Operations()) != 3 || len(p.RateLimits()) != 1 {
		t.Fatal("wiring counts")
	}
	for _, engine := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(ms) != 1 || len(ms[0].Statements) != 3 || !strings.Contains(ms[0].Statements[1], ColReferred+" ") {
			t.Fatalf("%s migrations = %+v %v", engine, ms, err)
		}
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("unknown engine = %v", err)
	}
	if p.DataHooks().User.AfterCreate == nil {
		t.Fatal("no user hook")
	}
	if _, err := p.MarkStep(context.Background(), "u", "nope", nil); !errors.Is(err, ErrUnknownStep) {
		t.Fatalf("unknown step = %v", err)
	}
}
