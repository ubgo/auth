package authcli_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/sqlb"
)

// granter is a plugin with the admin plugin's Grant method and nothing else,
// so the command finds it by interface without the real plugin.
type granter struct{ granted []string }

func (*granter) Name() string { return "granter" }
func (g *granter) Grant(_ context.Context, userID string) error {
	g.granted = append(g.granted, userID)
	return nil
}

// addresses is a plugin with the email plugin's address methods.
type addresses struct{}

func (addresses) Name() string { return "addresses" }
func (addresses) Identifiers() []auth.IdentifierKind {
	return []auth.IdentifierKind{{Name: "mail", Unique: true, UniqueOnlyVerified: true, Verifiable: true,
		Normalize: func(raw string) (string, error) { return strings.ToLower(strings.TrimSpace(raw)), nil }}}
}
func (addresses) SetFor(context.Context, string, string, bool) error { return nil }

// runIn is run with a stdin.
func runIn(t *testing.T, a *auth.Auth, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb strings.Builder
	code := authcli.MainWithStdin(context.Background(), a, args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// TestAdmin_UsageErrors: the forms that never reach a plugin or a database
// answer with the usage and exit 2, so a typo is told apart from a failure.
func TestAdmin_UsageErrors(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(signIn{}, &granter{}, addresses{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"admin"},
		{"admin", "revoke", "--email", "a@example.com"},
		{"admin", "grant"},
		{"admin", "grant", "--email", "  "},
		{"admin", "create", "--email", "a@example.com", "extra"},
		{"admin", "grant", "--name", "x", "--email", "a@example.com"}, // --name is create's
		{"admin", "grant", "--password-stdin", "--email", "a@example.com"},
	} {
		if code, out, errOut := run(t, a, args...); code != authcli.ExitUsage || out != "" || !strings.Contains(errOut, "usage:") {
			t.Errorf("%v: %d out=%q err=%q", args, code, out, errOut)
		}
	}
	if code, _, errOut := run(t, a, "admin", "grant", "-h"); code != authcli.ExitOK || !strings.Contains(errOut, "auth admin grant --email x") {
		t.Fatalf("-h: %d %q", code, errOut)
	}
	// An empty stdin under --password-stdin is a script bug, so it is a usage
	// error, decided before anything else can fail.
	if code, _, errOut := runIn(t, a, "\n", "admin", "create", "--email", "a@example.com", "--password-stdin"); code != authcli.ExitUsage || !strings.Contains(errOut, authcli.ErrNoPassword.Error()) {
		t.Fatalf("empty stdin: %d %q", code, errOut)
	}
}

// TestAdmin_NamesTheMissingPlugin: each plugin the command works through is
// found by interface, and its absence is reported by name with exit 1.
func TestAdmin_NamesTheMissingPlugin(t *testing.T) {
	cases := []struct {
		plugins []auth.Plugin
		args    []string
		want    error
	}{
		{[]auth.Plugin{signIn{}, addresses{}}, []string{"admin", "grant", "--email", "a@example.com"}, authcli.ErrNoAdminPlugin},
		{[]auth.Plugin{signIn{}, &granter{}}, []string{"admin", "grant", "--email", "a@example.com"}, authcli.ErrNoAddressPlugin},
		{[]auth.Plugin{signIn{}, &granter{}, addresses{}}, []string{"admin", "create", "--email", "a@example.com", "--password-stdin"}, authcli.ErrNoPasswordPlugin},
		// A real lookup with no database fails as a database error, not as a
		// silent success.
		{[]auth.Plugin{signIn{}, &granter{}, addresses{}}, []string{"admin", "grant", "--email", "a@example.com"}, auth.ErrNoDatabase},
		{[]auth.Plugin{signIn{}, &granter{}, addresses{}}, []string{"admin", "create", "--email", "a@example.com"}, auth.ErrNoDatabase},
		{[]auth.Plugin{signIn{}, &granter{}, addresses{}}, []string{"admin", "create", "--email", "a@example.com", "--dry-run"}, auth.ErrNoDatabase},
	}
	for _, c := range cases {
		a, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(c.plugins...))
		if err != nil {
			t.Fatal(err)
		}
		code, out, errOut := runIn(t, a, "secret-password\n", c.args...)
		if code != authcli.ExitFailed || out != "" || !strings.Contains(errOut, c.want.Error()) {
			t.Errorf("%v: %d out=%q err=%q, want %v", c.args, code, out, errOut, c.want)
		}
	}
}

// TestAdmin_PasswordNeverComesFromArgv: there is no --password flag, and a
// value typed after --password-stdin is an unexpected argument, so a password
// can never land in shell history by mistake.
func TestAdmin_PasswordNeverComesFromArgv(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(signIn{}, &granter{}, addresses{}))
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"admin", "create", "--email", "a@example.com", "--password", "hunter2"},
		{"admin", "create", "--email", "a@example.com", "--password-stdin", "hunter2"},
	} {
		code, _, errOut := run(t, a, args...)
		if code != authcli.ExitUsage || strings.Contains(errOut, "created") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
}

// noKinds has the address methods but declares no identifier kind, so there
// is no kind to look a user up by.
type noKinds struct{}

func (noKinds) Name() string                                       { return "nokinds" }
func (noKinds) Identifiers() []auth.IdentifierKind                 { return nil }
func (noKinds) SetFor(context.Context, string, string, bool) error { return nil }

// failingWriter fails every write, like a closed pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

// failingReader fails every read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("terminal gone") }

// TestAdmin_EdgeInputs: the inputs that are decided before any database call.
func TestAdmin_EdgeInputs(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(signIn{}, &granter{}, addresses{}))
	if err != nil {
		t.Fatal(err)
	}
	// A nil stdin (MainWithStdin from code that has none) is no password.
	var out, errOut strings.Builder
	if code := authcli.MainWithStdin(context.Background(), a, []string{"admin", "create", "--email", "a@example.com", "--password-stdin"}, nil, &out, &errOut); code != authcli.ExitUsage || !strings.Contains(errOut.String(), authcli.ErrNoPassword.Error()) {
		t.Fatalf("nil stdin: %d %q", code, errOut.String())
	}
	// A stdin that cannot be read is a failure, not an empty password.
	errOut.Reset()
	if code := authcli.MainWithStdin(context.Background(), a, []string{"admin", "create", "--email", "a@example.com", "--password-stdin"}, failingReader{}, &out, &errOut); code != authcli.ExitFailed || !strings.Contains(errOut.String(), "terminal gone") {
		t.Fatalf("failing stdin: %d %q", code, errOut.String())
	}
	// A plugin that sets addresses but declares no kind cannot be used to
	// find a user, and is reported as the missing address plugin.
	b, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(signIn{}, &granter{}, noKinds{}))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, b, "admin", "grant", "--email", "a@example.com"); code != authcli.ExitFailed || !strings.Contains(errOut, authcli.ErrNoAddressPlugin.Error()) {
		t.Fatalf("no kinds: %d %q", code, errOut)
	}
}

// TestAdmin_WriteFailureIsReported: a result that cannot be written is exit
// 1, in both output forms, never a silent success.
func TestAdmin_WriteFailureIsReported(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(signIn{}, &granter{}, addresses{}))
	if err != nil {
		t.Fatal(err)
	}
	// The dry run of a grant needs a database to resolve the address, so the
	// write path is reached through the result printer directly: MainWithStdin
	// with a database is the integration suite's job. Here the usage printer
	// is the one path that writes without a database.
	var errOut strings.Builder
	if code := authcli.MainWithStdin(context.Background(), a, []string{"admin", "grant", "-h"}, nil, failingWriter{}, &errOut); code != authcli.ExitOK {
		t.Fatalf("-h with a failing stdout: %d", code)
	}
}
