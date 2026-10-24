package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// pastSessionLife is further ahead than any session lives by default, so
	// the session signed up "now" has expired when the sweep runs then.
	pastSessionLife = 60 * 24 * time.Hour
)

// TestCLI_MigrateThenServe walks an operator's first deploy: the server
// refuses to start on an empty database, the dry run lists what would be
// applied and changes nothing, migrate applies it, status shows nothing
// pending, and the server may start.
func TestCLI_MigrateThenServe(t *testing.T) {
	ctx := context.Background()
	a := newTestAuth(t, openTestDB(t))

	if _, handled := command(ctx, a, nil, &bytes.Buffer{}, &bytes.Buffer{}); handled {
		t.Fatal("no arguments must start the server, not the command line")
	}
	if err := requireMigrated(ctx, a); !errors.Is(err, errPending) {
		t.Fatalf("an empty database: %v, want errPending", err)
	}

	out := run(t, a, authcli.ExitOK, "migrate", "--dry-run")
	if !strings.Contains(out, "pending  core") || strings.Contains(out, "applied") {
		t.Fatalf("dry run:\n%s", out)
	}
	if err := requireMigrated(ctx, a); !errors.Is(err, errPending) {
		t.Fatal("the dry run applied something")
	}

	out = run(t, a, authcli.ExitOK, "migrate")
	if !strings.Contains(out, "applied core/0001_core_tables") {
		t.Fatalf("migrate:\n%s", out)
	}
	if out := run(t, a, authcli.ExitOK, "migrate"); !strings.Contains(out, "nothing to apply") {
		t.Fatalf("second migrate:\n%s", out)
	}
	if out := run(t, a, authcli.ExitOK, "migrate", "status"); !strings.Contains(out, "0 pending, 0 changed") {
		t.Fatalf("status:\n%s", out)
	}
	if err := requireMigrated(ctx, a); err != nil {
		t.Fatalf("after migrate: %v", err)
	}
}

// TestCLI_SQLAndUsage checks the read-only SQL print and that a typo is a
// usage error, exit code 2, which a script can tell from a failure.
func TestCLI_SQLAndUsage(t *testing.T) {
	a := newTestAuth(t, openTestDB(t))
	if out := run(t, a, authcli.ExitOK, "migrate", "sql"); !strings.Contains(out, "CREATE TABLE IF NOT EXISTS auth_user") {
		t.Fatalf("sql:\n%s", out)
	}
	if err := requireMigrated(context.Background(), a); !errors.Is(err, errPending) {
		t.Fatal("printing the SQL must not apply it")
	}
	run(t, a, authcli.ExitUsage, "migrat")
}

// TestCLI_SweepDeletesExpiredSessions signs a user up, then sweeps from an
// instance whose clock is two months later: the expired session is deleted.
func TestCLI_SweepDeletesExpiredSessions(t *testing.T) {
	db := openTestDB(t)
	a := newTestAuth(t, db)
	run(t, a, authcli.ExitOK, "migrate")
	pw, err := auth.PluginOf[*password.Plugin](a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.SignUp(context.Background(), password.SignUpRequest{Identifier: testEmail, Password: password.Secret(testPassword)}); err != nil {
		t.Fatal(err)
	}

	later := newTestAuth(t, db, auth.WithClock(func() time.Time { return time.Now().Add(pastSessionLife) }))
	out := run(t, later, authcli.ExitOK, "sweep")
	if !strings.Contains(out, "core.auth_session\t1") {
		t.Fatalf("sweep:\n%s", out)
	}
	if out := run(t, later, authcli.ExitOK, "sweep"); strings.Contains(out, "core.auth_session\t1") {
		t.Fatalf("a second sweep found the session again:\n%s", out)
	}
}

// run runs "auth <args>" as main would, checks the exit code, and returns
// stdout and stderr together.
func run(t *testing.T, a *auth.Auth, want int, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code, handled := command(context.Background(), a, append([]string{authCommand}, args...), &stdout, &stderr)
	if !handled || code != want {
		t.Fatalf("auth %s: handled=%v code=%d, want %d\n%s%s", strings.Join(args, " "), handled, code, want, stdout.String(), stderr.String())
	}
	return stdout.String() + stderr.String()
}

// openTestDB opens a fresh SQLite file with the app's pragmas.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestCLI_ConfigFromEnvironment sets AUTH_BASE_URL and AUTH_SESSION_IDLE and
// reads them back from "auth info --json": a set variable wins over the
// app's default, an unset one keeps it, and the JSON decodes into
// authcli.Info. A malformed duration stops newAuth with an error naming the
// variable.
func TestCLI_ConfigFromEnvironment(t *testing.T) {
	const (
		prodURL = "https://app.example.com"
		idle    = 48 * time.Hour
	)
	a := newEnvAuth(t, openTestDB(t), envMap{
		auth.EnvBaseURL:     prodURL,
		auth.EnvSessionIdle: idle.String(),
	})
	var info authcli.Info
	if err := json.Unmarshal([]byte(run(t, a, authcli.ExitOK, "info", "--json")), &info); err != nil {
		t.Fatal(err)
	}
	if info.BaseURL != prodURL || time.Duration(info.Session.IdleTimeout) != idle {
		t.Fatalf("info: base url %q, idle %s; want %q, %s", info.BaseURL, info.Session.IdleTimeout, prodURL, idle)
	}
	if info.Engine != "sqlite" || len(info.Plugins) != 2 || len(info.Operations) == 0 {
		t.Fatalf("info: engine %q, plugins %v, %d operations", info.Engine, info.Plugins, len(info.Operations))
	}

	if def := newTestAuth(t, openTestDB(t)); !strings.Contains(run(t, def, authcli.ExitOK, "info"), baseURL) {
		t.Fatal("no AUTH_BASE_URL must keep the app's default base URL")
	}

	_, err := newAuth(openTestDB(t), email.MailerFunc(func(context.Context, email.Mail) error { return nil }), envMap{auth.EnvSessionIdle: "7d"}.lookup)
	if err == nil || !strings.Contains(err.Error(), auth.EnvSessionIdle) {
		t.Fatalf("a malformed duration: %v, want an error naming %s", err, auth.EnvSessionIdle)
	}
}

// newTestAuth builds the app's Auth without migrating: migrating is what the
// command line under test does. No AUTH_* variable is set.
func newTestAuth(t *testing.T, db *sql.DB, extra ...auth.Option) *auth.Auth {
	t.Helper()
	return newEnvAuth(t, db, envMap{}, extra...)
}

// envMap stands in for the process environment: its lookup method has
// os.LookupEnv's signature, so a test sets variables without touching the
// real environment.
type envMap map[string]string

// lookup reports the value and whether the variable is set, as os.LookupEnv.
func (e envMap) lookup(name string) (string, bool) {
	v, ok := e[name]
	return v, ok
}

// newEnvAuth builds the app's Auth with env as its environment.
func newEnvAuth(t *testing.T, db *sql.DB, env envMap, extra ...auth.Option) *auth.Auth {
	t.Helper()
	a, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }), env.lookup, extra...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}
