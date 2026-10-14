package authcli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/sqlb"
)

type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

func run(t *testing.T, a *auth.Auth, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := authcli.Main(context.Background(), a, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestMain_UsageAndSQL(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, a); code != authcli.ExitUsage || !strings.Contains(errOut, "usage:") {
		t.Fatalf("no args: %d %q", code, errOut)
	}
	if code, _, _ := run(t, a, "migrate", "extra"); code != authcli.ExitUsage {
		t.Fatalf("extra arg: %d", code)
	}
	code, out, _ := run(t, a, "migrate", "sql")
	if code != authcli.ExitOK || !strings.Contains(out, "CREATE TABLE IF NOT EXISTS auth_user") {
		t.Fatalf("sql: %d %q", code, out)
	}
	// No database: status and migrate fail with a reason, not a panic.
	if code, _, errOut := run(t, a, "migrate", "status"); code != authcli.ExitFailed || !strings.Contains(errOut, "no database") {
		t.Fatalf("status without a database: %d %q", code, errOut)
	}
}

// unknownEngine is a dialect that renders Postgres SQL but names an engine the
// core has no DDL for, the way a third-party dialect would.
type unknownEngine struct{ sqlb.PostgresDialect }

func (unknownEngine) Name() string { return "oracle" }

func TestMain_SQLForAnEngineWithoutDDLFails(t *testing.T) {
	a, err := auth.New(auth.WithDialect(unknownEngine{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, a, "migrate", "sql")
	if code != authcli.ExitFailed || out != "" || !strings.Contains(errOut, "oracle") {
		t.Fatalf("sql for oracle: %d out=%q err=%q", code, out, errOut)
	}
}

// TestMain_HelpAndBadFlags: -h prints the usage and succeeds, because the
// operator asked for it; a bad flag or value is a usage error on every
// command.
func TestMain_HelpAndBadFlags(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"migrate", "-h"}, {"sweep", "-h"}} {
		if code, _, errOut := run(t, a, args...); code != authcli.ExitOK || !strings.Contains(errOut, "usage:") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	for _, args := range [][]string{
		{"migrate", "--no-such-flag"},
		{"sweep", "--retention", "soon"},
		{"sweep", "--retention", "-1h"},
		{"sweep", "extra"},
	} {
		if code, _, errOut := run(t, a, args...); code != authcli.ExitUsage || !strings.Contains(errOut, "usage:") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

// TestMain_EveryDatabaseCommandFailsWithoutADatabase: each command that
// reads or writes the database names the reason and exits 1, never 0 with an
// empty report an operator would read as "nothing to do".
func TestMain_EveryDatabaseCommandFailsWithoutADatabase(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"migrate"}, {"migrate", "--dry-run"}, {"migrate", "orphans"}, {"sweep"}} {
		code, out, errOut := run(t, a, args...)
		if code != authcli.ExitFailed || !strings.Contains(errOut, auth.ErrNoDatabase.Error()) || strings.Contains(out, "nothing to apply") {
			t.Errorf("%v: %d out=%q err=%q", args, code, out, errOut)
		}
	}
}

func TestMain_InfoPrintsTheWiring(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.MySQLDialect{}), auth.WithBaseURL("https://app.example.com"),
		auth.WithPlugins(signIn{}), auth.WithDisabledOperations(auth.EndpointSignOutAll))
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := run(t, a, "info")
	if code != authcli.ExitOK || errOut != "" {
		t.Fatalf("info: %d %q", code, errOut)
	}
	for _, want := range []string{"engine", "mysql", "base url", "https://app.example.com", "plugin", "stub", "disabled", string(auth.EndpointSignOutAll), "query", "/session", "signed_in", "0001_"} {
		if !strings.Contains(out, want) {
			t.Errorf("info output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/sign-out-all") {
		t.Error("a disabled operation must not be listed as a route")
	}
	code, out, _ = run(t, a, "info", "--json")
	if code != authcli.ExitOK {
		t.Fatalf("info --json: %d", code)
	}
	var in authcli.Info
	if err := json.Unmarshal([]byte(out), &in); err != nil {
		t.Fatalf("info --json is not JSON: %v\n%s", err, out)
	}
	if in.Engine != "mysql" || in.Version == "" || len(in.Plugins) != 1 || len(in.Operations) == 0 || len(in.Migrations) == 0 || len(in.Disabled) != 1 {
		t.Fatalf("info = %+v", in)
	}
	// Lifetimes are readable strings under JSON names, and they decode back
	// to the configured values: a support request carries "720h0m0s", never
	// a count of nanoseconds or a Go field name.
	for _, want := range []string{`"idleTimeout": "`, `"maxLifetime": "`, `"refreshAfter": "`, `"transientIdleTimeout": "`, `"freshWindow": "`} {
		if !strings.Contains(out, want) {
			t.Errorf("info --json lacks %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"IdleTimeout"`) {
		t.Errorf("info --json leaks a Go field name:\n%s", out)
	}
	if got, want := time.Duration(in.Session.MaxLifetime), a.Config().Session.MaxLifetime; got != want || want == 0 {
		t.Errorf("session max lifetime decoded as %s, configured %s", got, want)
	}
	if got, want := time.Duration(in.FreshWindow), a.Config().FreshWindow; got != want {
		t.Errorf("fresh window decoded as %s, configured %s", got, want)
	}
	if code, _, _ := run(t, a, "info", "extra"); code != authcli.ExitUsage {
		t.Fatalf("extra argument: %d", code)
	}
	if code, _, errOut := run(t, a, "info", "-h"); code != authcli.ExitOK || !strings.Contains(errOut, "usage:") {
		t.Fatalf("-h: %d %q", code, errOut)
	}
	// An engine without DDL has no migration list to report.
	a, err = auth.New(auth.WithDialect(unknownEngine{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, a, "info"); code != authcli.ExitFailed || !strings.Contains(errOut, "oracle") {
		t.Fatalf("info for oracle: %d %q", code, errOut)
	}
}

// TestDuration_RefusesWhatItCannotParse pins that a malformed duration in an
// Info document is an error, not a silent zero lifetime.
func TestDuration_RefusesWhatItCannotParse(t *testing.T) {
	var d authcli.Duration
	if err := json.Unmarshal([]byte(`"forever"`), &d); err == nil {
		t.Fatalf("decoded %q into %s", "forever", d)
	}
	if err := json.Unmarshal([]byte(`"90m"`), &d); err != nil || time.Duration(d) != 90*time.Minute || d.String() != "1h30m0s" {
		t.Fatalf("90m decoded as %s, %v", d, err)
	}
}
