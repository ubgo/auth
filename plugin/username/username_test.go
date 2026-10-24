package username_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/username"
	"github.com/ubgo/sqlb"
)

type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

func wire(t *testing.T, p *username.Plugin) *auth.Auth {
	t.Helper()
	a, err := auth.New(auth.WithPlugins(signIn{}, p))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestValidate(t *testing.T) {
	for _, ok := range []string{"ada", "ada_lovelace", "a1-2", "ab"} {
		if err := username.Validate(ok); err != nil {
			t.Errorf("Validate(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"a", "1ada", "ada@x", "+ada", "ada lovelace", "Ada", strings.Repeat("a", username.MaxLength+1), "ädа"} {
		if err := username.Validate(bad); err == nil {
			t.Errorf("Validate(%q) accepted", bad)
		}
	}
}

func TestNormalize(t *testing.T) {
	if v, _ := username.Normalize("  Khanakia "); v != "khanakia" {
		t.Fatalf("Normalize = %q", v)
	}
}

func TestIsReserved_CoversRouteCollisionsAndIsAdditive(t *testing.T) {
	p := username.New(username.Reserved("Khanakia"))
	for _, n := range []string{"admin", "Settings", "KHANAKIA"} {
		if !p.IsReserved(n) {
			t.Errorf("%q must be reserved", n)
		}
	}
	if p.IsReserved("ada") {
		t.Error("an ordinary handle is not reserved")
	}
}

func TestKind_IsUniqueOverEveryRow(t *testing.T) {
	a := wire(t, username.New(username.Login()))
	k, ok := a.Config().Identifier(username.KindUsername)
	if !ok || !k.Unique || k.UniqueOnlyVerified || !k.CanLogin || k.CanRecover || k.Verifiable {
		t.Fatalf("kind = %+v", k)
	}
}

func TestByHandleQuery_ComparesTheNormalFormExactly(t *testing.T) {
	a := wire(t, username.New())
	var u auth.User
	q, err := username.ByHandleQuery(a, " Ada ", &u)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(q.SQL), "lower(") {
		t.Fatalf("SQL folds case a second time: %s", q.SQL)
	}
	if len(q.Args) < 2 || q.Args[len(q.Args)-1] != "ada" {
		t.Fatalf("args = %v, want the normalized handle last", q.Args)
	}
}

func TestUserJoin_IsLeftAndKindScoped(t *testing.T) {
	j := username.UserJoin()
	if j.Type != sqlb.JoinLeft || j.Table.Alias != username.TableAliasIdentity || len(j.On) != 2 {
		t.Fatalf("join = %+v", j)
	}
}

func TestData_AbsenceIsDistinguishable(t *testing.T) {
	if (&username.Data{}).Exists() || !(&username.Data{Handle: "ada"}).Exists() {
		t.Fatal("Exists must follow Handle")
	}
}

func TestNew_ScopedHandles(t *testing.T) {
	a := wire(t, username.New(username.Login(), username.ScopedByTenant()))
	k, _ := a.Config().Identifier(username.KindUsername)
	if !k.ScopedByTenant {
		t.Fatal("ScopedByTenant not applied")
	}
}

// TestClaim_Unwired: Claim on a plugin auth.New never wired reports it rather
// than dereferencing a nil core.
func TestClaim_Unwired(t *testing.T) {
	if err := username.New().Claim(context.Background(), "usr_x", "ada"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Claim unwired = %v", err)
	}
}
