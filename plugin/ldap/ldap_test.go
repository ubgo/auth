package ldap_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/ldap"
)

// countingDirectory answers with err and counts its calls.
type countingDirectory struct {
	calls int
	err   error
}

func (d *countingDirectory) Authenticate(context.Context, string, string) (ldap.Entry, error) {
	d.calls++
	return ldap.Entry{}, d.err
}

func newPlugin(t *testing.T, d ldap.Directory) *ldap.Plugin {
	t.Helper()
	p := ldap.New(ldap.WithDirectory(d))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestValidate_NeedsADirectory: a plugin without a directory could never
// check a password, so auth.New refuses it.
func TestValidate_NeedsADirectory(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(ldap.New())); !errors.Is(err, ldap.ErrNoDirectory) {
		t.Fatalf("err = %v, want ErrNoDirectory", err)
	}
}

// TestSignIn_RefusesBadInputBeforeTheDirectory: an empty password (an
// anonymous bind to LDAP), an empty or oversized username, an oversized
// password and a NUL byte are refused without a directory call, with the
// same answer as a wrong password.
func TestSignIn_RefusesBadInputBeforeTheDirectory(t *testing.T) {
	d := &countingDirectory{}
	p := newPlugin(t, d)
	for _, in := range [][2]string{
		{"ada", ""}, {"", "pw"}, {"   ", "pw"}, {strings.Repeat("a", ldap.MaxUsernameLength+1), "pw"},
		{"ada", strings.Repeat("p", ldap.MaxPasswordLength+1)}, {"ad\x00a", "pw"},
	} {
		if _, err := p.SignIn(context.Background(), in[0], in[1]); !errors.Is(err, ldap.ErrCredentialsInvalid) {
			t.Errorf("%q: err = %v, want ErrCredentialsInvalid", in[0], err)
		}
	}
	if d.calls != 0 {
		t.Fatalf("the directory was asked %d times", d.calls)
	}
}

// TestSignIn_DirectoryAnswers: the directory's verdicts map to the wire
// errors: invalid and ambiguous both read as a wrong password, anything
// else as the directory being unavailable, never as a wrong password.
func TestSignIn_DirectoryAnswers(t *testing.T) {
	for _, tc := range []struct {
		dir  error
		want error
	}{
		{ldap.ErrInvalidCredentials, ldap.ErrCredentialsInvalid},
		{ldap.ErrAmbiguousUser, ldap.ErrCredentialsInvalid},
		{errors.New("connection refused"), ldap.ErrDirectoryUnavailable},
	} {
		p := newPlugin(t, &countingDirectory{err: tc.dir})
		if _, err := p.SignIn(context.Background(), "ada", "pw"); !errors.Is(err, tc.want) {
			t.Errorf("directory %v: err = %v, want %v", tc.dir, err, tc.want)
		}
	}
}

// TestEntry_Get matches attribute names without regard to case, as LDAP
// does.
func TestEntry_Get(t *testing.T) {
	e := ldap.Entry{Attributes: map[string][]string{"Mail": {"a@x"}, "cn": {}}}
	if e.Get("mail") != "a@x" || e.Get("MAIL") != "a@x" || e.Get("cn") != "" || e.Get("mai") != "" || e.Get("mbil") != "" {
		t.Fatalf("Get: %q %q %q", e.Get("mail"), e.Get("MAIL"), e.Get("cn"))
	}
}

func TestMigrations_PerEngine(t *testing.T) {
	p := newPlugin(t, &countingDirectory{})
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	my, err := p.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(my) != 1 || len(my[0].Statements) != 1 || !strings.Contains(my[0].Statements[0], "INDEX ") {
		t.Fatalf("mysql: %+v, %v", my, err)
	}
	pg, err := p.TypedMigrations(auth.EnginePostgres, auth.TypesFor(auth.EnginePostgres))
	if err != nil || len(pg) != 1 || len(pg[0].Statements) != 2 || !strings.Contains(pg[0].Statements[0], ldap.ColSubject+" ") {
		t.Fatalf("postgres: %+v, %v", pg, err)
	}
}
