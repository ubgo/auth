package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/password"
)

// Round 5 of the better-auth comparison: `auth admin grant` and `auth admin
// create` against a real database.

// r5Root is the address the first admin is created with.
const r5Root = "root@example.com"

// cliRun runs authcli with stdin and returns the exit code, stdout and stderr.
func cliRun(a *auth.Auth, stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := authcli.MainWithStdin(context.Background(), a, args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

// failingWriter fails every write, like a closed pipe.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

// isAdmin reads the admin plugin's column for the user.
func isAdmin(t *testing.T, a *auth.Auth, userID string) bool {
	t.Helper()
	var c admin.AdminColumns
	if err := a.LoadUserColumns(context.Background(), userID, admin.Bindings(&c)...); err != nil {
		t.Fatal(err)
	}
	return c.AdminGrantedAt != nil
}

func TestCLI_AdminCreate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, admin.New())
		// An address that is not one is refused before any write.
		if code, out, errOut := cliRun(a, "", "admin", "create", "--email", "not-an-address"); code != authcli.ExitFailed || out != "" || !strings.Contains(errOut, auth.ErrIdentifierInvalid.Code) {
			t.Fatalf("create with a malformed address: %d %q %q", code, out, errOut)
		}
		// A rehearsal creates nothing.
		code, out, errOut := cliRun(a, "", "admin", "create", "--email", r5Root, "--dry-run")
		if code != authcli.ExitOK || !strings.Contains(out, "would create "+r5Root) || errOut != "" {
			t.Fatalf("dry run: %d %q %q", code, out, errOut)
		}
		if n := countTable(t, e, auth.TableNameUser); n != 0 {
			t.Fatalf("the dry run created %d users", n)
		}
		// The real thing: a user with a verified address, the password from
		// stdin and admin rights, reported as JSON.
		code, out, errOut = cliRun(a, secret+"\n", "admin", "create", "--email", " Root@Example.com ", "--name", "Root", "--password-stdin", "--json")
		if code != authcli.ExitOK || errOut != "" {
			t.Fatalf("create: %d %q %q", code, out, errOut)
		}
		var res authcli.AdminResult
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("not JSON: %q: %v", out, err)
		}
		if res.Email != r5Root || res.UserID == "" || !res.Created || !res.Granted || !res.PasswordSet || res.DryRun {
			t.Fatalf("result = %+v", res)
		}
		if !isAdmin(t, a, res.UserID) {
			t.Fatal("the created user is not an admin")
		}
		in := must[password.SignInResult](t)(pw.SignIn(anon(a), password.SignInRequest{Identifier: r5Root, Password: secret}))
		if in.User.ID != res.UserID || in.User.Name != "Root" || in.VerificationRequired {
			t.Fatalf("sign-in as the created admin = %+v", in)
		}
		// The address is taken now: the second create fails, and so does its
		// rehearsal, and neither leaves a user behind.
		for _, extra := range [][]string{nil, {"--dry-run"}} {
			code, out, errOut = cliRun(a, "", append([]string{"admin", "create", "--email", r5Root}, extra...)...)
			if code != authcli.ExitFailed || out != "" || !strings.Contains(errOut, auth.ErrIdentityTaken.Error()) {
				t.Fatalf("create of a taken address %v: %d %q %q", extra, code, out, errOut)
			}
		}
		if n := countTable(t, e, auth.TableNameUser); n != 1 {
			t.Fatalf("%d users after the refused creates, want 1", n)
		}
		// A refused password rolls the whole creation back.
		code, _, errOut = cliRun(a, "short\n", "admin", "create", "--email", "second@example.com", "--password-stdin")
		if code != authcli.ExitFailed || !strings.Contains(errOut, password.ErrTooShort.Code) {
			t.Fatalf("weak password: %d %q", code, errOut)
		}
		if n := countTable(t, e, auth.TableNameUser); n != 1 {
			t.Fatalf("%d users after the refused password, want 1: the creation was not rolled back", n)
		}
		// Without a password the user exists and nobody can sign in with one.
		code, out, errOut = cliRun(a, "", "admin", "create", "--email", "second@example.com")
		if code != authcli.ExitOK || !strings.HasPrefix(out, "created second@example.com (") || strings.Contains(out, "password") || errOut != "" {
			t.Fatalf("create without a password: %d %q %q", code, out, errOut)
		}
		if _, err := pw.SignIn(anon(a), password.SignInRequest{Identifier: "second@example.com", Password: secret}); !errors.Is(err, password.ErrInvalidCredentials) {
			t.Fatalf("sign-in with no password set: %v", err)
		}
	})
	t.Run("faults dry run", func(t *testing.T) {
		// The rehearsal's one database call, the address lookup, fails loudly.
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), admin.New())
			return func(context.Context) error {
				code, _, errOut := cliRun(a, "", "admin", "create", "--email", r5Root, "--dry-run")
				if code != authcli.ExitOK {
					return errors.New(errOut)
				}
				return nil
			}
		})
	})
	t.Run("faults", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), admin.New())
			return func(context.Context) error {
				code, _, errOut := cliRun(a, secret+"\n", "admin", "create", "--email", r5Root, "--password-stdin")
				if code != authcli.ExitOK {
					return errors.New(errOut)
				}
				return nil
			}
		})
	})
}

func TestCLI_AdminGrant(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, nil, em, pw, admin.New())
		up := must[password.SignInResult](t)(pw.SignUp(anon(a), password.SignUpRequest{Identifier: alice, Password: secret, Name: "Alice"}))
		// An unverified address is refused: whoever typed it first would
		// otherwise become the admin.
		code, out, errOut := cliRun(a, "", "admin", "grant", "--email", alice)
		if code != authcli.ExitFailed || out != "" || !strings.Contains(errOut, auth.ErrIdentityNotFound.Error()) {
			t.Fatalf("grant to an unverified address: %d %q %q", code, out, errOut)
		}
		if isAdmin(t, a, up.User.ID) {
			t.Fatal("granted to an unverified address")
		}
		a.WaitDeliveries()
		if _, err := em.Verify(anon(a), e.mail.LastToken(t, a, alice)); err != nil {
			t.Fatal(err)
		}
		code, out, errOut = cliRun(a, "", "admin", "grant", "--email", alice, "--dry-run", "--json")
		var res authcli.AdminResult
		if code != authcli.ExitOK || errOut != "" || json.Unmarshal([]byte(out), &res) != nil || res.UserID != up.User.ID || !res.DryRun || res.Granted {
			t.Fatalf("dry run: %d %q %q %+v", code, out, errOut, res)
		}
		if isAdmin(t, a, up.User.ID) {
			t.Fatal("the dry run granted")
		}
		code, out, errOut = cliRun(a, "", "admin", "grant", "--email", strings.ToUpper(alice))
		if code != authcli.ExitOK || out != alice+" ("+up.User.ID+") is an admin\n" || errOut != "" {
			t.Fatalf("grant: %d %q %q", code, out, errOut)
		}
		if !isAdmin(t, a, up.User.ID) {
			t.Fatal("not granted")
		}
		// Granting twice is a no-op, like set-admin.
		if code, _, errOut = cliRun(a, "", "admin", "grant", "--email", alice); code != authcli.ExitOK || errOut != "" {
			t.Fatalf("second grant: %d %q", code, errOut)
		}
		if code, _, errOut = cliRun(a, "", "admin", "grant", "--email", "nobody@example.com"); code != authcli.ExitFailed || !strings.Contains(errOut, auth.ErrIdentityNotFound.Error()) {
			t.Fatalf("grant to an unknown address: %d %q", code, errOut)
		}
		// A result that cannot be written is a failure, in both output forms.
		for _, extra := range [][]string{nil, {"--json"}} {
			var errb bytes.Buffer
			if code := authcli.MainWithStdin(context.Background(), a, append([]string{"admin", "grant", "--email", alice, "--dry-run"}, extra...), nil, failingWriter{}, &errb); code != authcli.ExitFailed || !strings.Contains(errb.String(), "pipe closed") {
				t.Fatalf("failing stdout %v: %d %q", extra, code, errb.String())
			}
		}
	})
	t.Run("faults", func(t *testing.T) {
		sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
			a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), admin.New())
			identUser(t, a, alice)
			return func(context.Context) error {
				code, _, errOut := cliRun(a, "", "admin", "grant", "--email", alice)
				if code != authcli.ExitOK {
					return errors.New(errOut)
				}
				return nil
			}
		})
	})
}
