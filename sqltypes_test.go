package auth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// typedPlugin implements TypedMigrator and records the types it was given.
type typedPlugin struct{ got *auth.SQLTypes }

func (typedPlugin) Name() string { return "typed" }

func (p typedPlugin) TypedMigrations(_ string, t auth.SQLTypes) ([]auth.Migration, error) {
	*p.got = t
	return []auth.Migration{{Owner: "typed", Name: "0001", Statements: []string{"CREATE TABLE typed_x (id " + t.Key + ")"}}}, nil
}

// untypedPlugin writes DDL through the old Migrator only.
type untypedPlugin struct{}

func (untypedPlugin) Name() string { return "untyped" }

func (untypedPlugin) Migrations(engine string) ([]auth.Migration, error) {
	return []auth.Migration{{Owner: "untyped", Name: "0001", Statements: []string{"CREATE TABLE untyped_x (id " + auth.TypesFor(engine).Key + ")"}}}, nil
}

// migrationSQL builds a Postgres Auth with opts and returns its DDL.
func migrationSQL(t *testing.T, opts ...auth.Option) (*auth.Auth, string) {
	t.Helper()
	a, err := newAuth(append([]auth.Option{auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{on: true})}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	sql, err := a.MigrationSQL()
	if err != nil {
		t.Fatal(err)
	}
	return a, sql
}

// TestWithSQLTypes_OverridesOnlyTheFieldsSet: an override changes the core's
// DDL for the fields it sets and nothing else, an empty override changes
// nothing, and Auth.SQLTypes reports the merged result.
func TestWithSQLTypes_OverridesOnlyTheFieldsSet(t *testing.T) {
	_, plain := migrationSQL(t)
	_, empty := migrationSQL(t, auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{}))
	if plain != empty {
		t.Fatal("an empty override changed the DDL")
	}
	a, uuid := migrationSQL(t, auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{Key: "UUID"}))
	if !strings.Contains(uuid, " UUID") || !strings.Contains(uuid, "TIMESTAMPTZ") {
		t.Fatalf("Key must become UUID and Timestamp stay TIMESTAMPTZ:\n%s", uuid)
	}
	want := auth.TypesFor(auth.EnginePostgres)
	want.Key, want.ID = "UUID", "UUID" // a Key-only override retypes ids too
	if got := a.SQLTypes(); got != want {
		t.Fatalf("SQLTypes() = %+v, want %+v", got, want)
	}
	// A later call for the same engine wins field by field.
	b, _ := migrationSQL(t, auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{Key: "UUID"}), auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{Long: "VARCHAR(8000)"}))
	if got := b.SQLTypes(); got.Key != "UUID" || got.Long != "VARCHAR(8000)" {
		t.Fatalf("two calls merged to %+v", got)
	}
	// An override for another engine leaves this one alone.
	_, other := migrationSQL(t, auth.WithSQLTypes(auth.EngineMySQL, auth.SQLTypes{Key: "CHAR(36)"}))
	if other != plain {
		t.Fatal("a MySQL override changed the Postgres DDL")
	}
}

// TestWithSQLTypes_ReachesTypedPluginsAndRefusesUntyped: a TypedMigrator
// gets the overridden types; a plugin on the old Migrator, which would keep
// the built-in ones, makes New refuse the override for the app's engine but
// not for another engine; an engine the core cannot write is refused.
func TestWithSQLTypes_ReachesTypedPluginsAndRefusesUntyped(t *testing.T) {
	var got auth.SQLTypes
	_, sql := migrationSQL(t, auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{Key: "UUID"}), auth.WithPlugins(typedPlugin{got: &got}))
	if got.Key != "UUID" || !strings.Contains(sql, "typed_x (id UUID)") {
		t.Fatalf("typed plugin got %+v:\n%s", got, sql)
	}
	_, sql = migrationSQL(t, auth.WithPlugins(typedPlugin{got: &got}))
	if got != auth.TypesFor(auth.EnginePostgres) {
		t.Fatalf("without an override the typed plugin got %+v", got)
	}

	pg := auth.WithDialect(sqlb.PostgresDialect{})
	_, err := newAuth(pg, auth.WithPlugins(signIn{on: true}, untypedPlugin{}), auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{Key: "UUID"}))
	if !errors.Is(err, auth.ErrBadOperation) || !strings.Contains(err.Error(), "untyped") {
		t.Fatalf("untyped plugin under an override = %v, want ErrBadOperation naming it", err)
	}
	if _, err := newAuth(pg, auth.WithPlugins(signIn{on: true}, untypedPlugin{}), auth.WithSQLTypes(auth.EngineMySQL, auth.SQLTypes{Key: "CHAR(36)"})); err != nil {
		t.Fatalf("an override for another engine refused an untyped plugin: %v", err)
	}
	if _, err := newAuth(pg, auth.WithPlugins(signIn{on: true}), auth.WithSQLTypes("sqlserver", auth.SQLTypes{Key: "NVARCHAR(191)"})); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("an unknown engine = %v, want ErrEngineNotSupported", err)
	}
}
