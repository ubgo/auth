package apikey

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// stubSignIn is the minimum sign-in method auth.New demands.
type stubSignIn struct{}

func (stubSignIn) Name() string  { return "stub" }
func (stubSignIn) SignsIn() bool { return true }

func TestValidate_ScopesAndPrefix(t *testing.T) {
	for _, bad := range []string{"", "orders read", "orders\tread"} {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(Scopes("ok", bad))))
		if !errors.Is(err, ErrBadScope) {
			t.Errorf("scope %q: %v", bad, err)
		}
	}
	for _, bad := range []string{"k_", "ubk", "ubk-"} {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(Scopes("ok"), Prefix(bad))))
		if !errors.Is(err, ErrBadPrefix) {
			t.Errorf("prefix %q: %v", bad, err)
		}
	}
	p := New(Scopes("ok"), Prefix("acme_"))
	if _, err := auth.New(auth.WithPlugins(stubSignIn{}, p)); err != nil || p.TokenPrefix() != "acme_" {
		t.Fatalf("a valid prefix: %q %v", p.TokenPrefix(), err)
	}
}

func TestMigrations_PerEngine(t *testing.T) {
	p := New(Scopes("ok"))
	if _, err := auth.New(auth.WithPlugins(stubSignIn{}, p)); err != nil {
		t.Fatal(err)
	}
	keyUserIndex := TableNameKey + keyUserIndexSuffix
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); err == nil {
		t.Fatal("an unknown engine must be refused")
	}
	my, err := p.TypedMigrations(auth.EngineMySQL, auth.TypesFor(auth.EngineMySQL))
	if err != nil || len(my[0].Statements) != 1 || !strings.Contains(my[0].Statements[0], "INDEX "+keyUserIndex) {
		t.Fatalf("mysql = %+v %v", my, err)
	}
	pg, err := p.TypedMigrations(auth.EnginePostgres, auth.TypesFor(auth.EnginePostgres))
	if err != nil || len(pg[0].Statements) != 2 || !strings.HasPrefix(pg[0].Statements[1], "CREATE INDEX IF NOT EXISTS "+keyUserIndex) {
		t.Fatalf("postgres = %+v %v", pg, err)
	}
}

// TestNoDatabase_ReportsInsteadOfPanicking pins a fixed bug: ResolveToken
// read through Auth.DB(), which is nil on an Auth built without a database,
// and a bearer key then dereferenced it.
func TestNoDatabase_ReportsInsteadOfPanicking(t *testing.T) {
	p := New(Scopes("ok"))
	if _, err := auth.New(auth.WithDialect(sqlb.SQLiteDialect{}), auth.WithPlugins(stubSignIn{}, p)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := p.ResolveToken(ctx, auth.Token(DefaultPrefix+"anything")); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("resolve without a database: %v", err)
	}
	if _, err := p.CreateFor(ctx, "usr_1", CreateRequest{}, Limits{}); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("create without a database: %v", err)
	}
}

func TestSplitScopes(t *testing.T) {
	if got := splitScopes(""); got == nil || len(got) != 0 {
		t.Fatalf("no scopes = %#v, want an empty, non-nil list", got)
	}
	if got := splitScopes("a b"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("two scopes = %#v", got)
	}
}
