package password

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestParseHash_RejectsWrongShape covers the two shapes the malformed-hash
// table does not: a PHC string with the wrong number of sections, and one
// whose parameter section does not scan.
func TestParseHash_RejectsWrongShape(t *testing.T) {
	for _, bad := range []string{
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdA",             // two sections
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaA$x",    // four sections
		"$argon2id$v=19$memory=64,t=1,p=1$c2FsdA$aGFzaA", // parameters do not scan
	} {
		if _, err := parseHash(bad); !errors.Is(err, errBadHash) {
			t.Errorf("parseHash(%q) err = %v, want errBadHash", bad, err)
		}
	}
}

// TestRequireClasses_CountsDigits: digits are their own class, so two classes
// (lowercase and digits) fail a three-class rule and a third passes it.
func TestRequireClasses_CountsDigits(t *testing.T) {
	ctx := context.Background()
	p := New(RequireClasses(3))
	if err := p.checkNew(ctx, "letters12345"); !errors.Is(err, ErrWeak) {
		t.Fatalf("lowercase and digits: %v, want ErrWeak", err)
	}
	if err := p.checkNew(ctx, "Letters12345"); err != nil {
		t.Fatalf("upper, lower and digits: %v", err)
	}
}

type failingChecker struct{ err error }

func (f failingChecker) Breached(context.Context, string) (bool, error) { return false, f.err }

// TestCheckNew_BreachCheckerErrorFailsClosed: a checker that cannot answer
// fails the new password with its error rather than letting it through.
func TestCheckNew_BreachCheckerErrorFailsClosed(t *testing.T) {
	down := errors.New("range API unreachable")
	p := New(CheckBreached(failingChecker{err: down}))
	if err := p.checkNew(context.Background(), "a long enough passphrase"); !errors.Is(err, down) {
		t.Fatalf("err = %v, want the checker's error", err)
	}
}

// TestMigrations_RefuseAnUnknownEngine wires the plugin first, as the core
// does before asking for migrations: the table is named through the core.
func TestMigrations_RefuseAnUnknownEngine(t *testing.T) {
	p := New(Argon2(fast))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, p)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	m, err := p.TypedMigrations(auth.EngineSQLite, auth.TypesFor(auth.EngineSQLite))
	if err != nil || len(m) != 1 || m[0].Owner != PluginName || len(m[0].Statements) != 1 {
		t.Fatalf("sqlite migrations = %+v, %v", m, err)
	}
}

// TestHasPassword_WithoutADatabaseIsAnError: a failed read is an error, never
// a "no password" answer an app could act on.
func TestHasPassword_WithoutADatabaseIsAnError(t *testing.T) {
	p := New(Argon2(fast))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, p)); err != nil {
		t.Fatal(err)
	}
	has, err := p.HasPassword(context.Background(), "usr_1")
	if !errors.Is(err, auth.ErrNoDatabase) || has {
		t.Fatalf("HasPassword = %v, %v; want false and ErrNoDatabase", has, err)
	}
}

// TestInit_DefaultResetLinkEscapesTheToken: the default link is the app's
// reset page with the token as a query parameter, escaped, and without a
// doubled slash when the base URL ends in one.
func TestInit_DefaultResetLinkEscapesTheToken(t *testing.T) {
	p := New(Argon2(fast))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com/"), auth.WithPlugins(loginKind{recover: true}, p)); err != nil {
		t.Fatal(err)
	}
	if got, want := p.links("a+b/c"), "https://app.example.com/reset-password?token=a%2Bb%2Fc"; got != want {
		t.Fatalf("link = %s, want %s", got, want)
	}
}

// TestOperations_SwitchesRemoveRoutes: WithoutSignUp drops sign-up and its
// rate rules, WithoutRecovery drops forgot and reset; verify is always there.
func TestOperations_SwitchesRemoveRoutes(t *testing.T) {
	ids := func(p *Plugin) map[auth.EndpointID]bool {
		out := map[auth.EndpointID]bool{}
		for _, op := range p.Operations() {
			out[op.Info().ID] = true
		}
		return out
	}
	all := ids(New())
	for _, id := range []auth.EndpointID{EndpointSignUp, EndpointSignIn, EndpointForgot, EndpointReset, EndpointChange, EndpointVerify} {
		if !all[id] {
			t.Fatalf("default plugin lacks %s", id)
		}
	}
	noUp := New(WithoutSignUp())
	if got := ids(noUp); got[EndpointSignUp] || !got[EndpointSignIn] || !got[EndpointVerify] {
		t.Fatalf("WithoutSignUp operations = %v", got)
	}
	for _, r := range noUp.RateLimits() {
		if r.Match == EndpointSignUp {
			t.Fatal("WithoutSignUp must drop the sign-up rate rules too")
		}
	}
	if got := ids(New(WithoutRecovery())); got[EndpointForgot] || got[EndpointReset] || !got[EndpointSignUp] {
		t.Fatalf("WithoutRecovery operations = %v", got)
	}
	verifyLimited := false
	for _, r := range New().RateLimits() {
		verifyLimited = verifyLimited || (r.Match == EndpointVerify && r.Key == auth.ByIP)
	}
	if !verifyLimited {
		t.Fatal("verify must carry a per-IP rate rule")
	}
}
