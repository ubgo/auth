package auth_test

import (
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestWithSQLTypes_IDTypesOnlyIDColumns: an ID override retypes the id
// columns and leaves every Key column (a kind, a purpose) alone; a Key
// override without ID retypes both, as before ID existed; an explicit ID
// wins over a Key given beside it.
func TestWithSQLTypes_IDTypesOnlyIDColumns(t *testing.T) {
	a, ddl := migrationSQL(t, auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{ID: "UUID"}))
	for _, want := range []string{auth.ColUserID + " UUID NOT NULL PRIMARY KEY", auth.ColIdentityUserID + " UUID NOT NULL", auth.ColIdentityKind + " TEXT NOT NULL", auth.ColVerificationPurpose + " TEXT NOT NULL"} {
		if !strings.Contains(ddl, want) {
			t.Errorf("ID override: DDL lacks %q", want)
		}
	}
	if got := a.SQLTypes(); got.ID != "UUID" || got.Key != "TEXT" {
		t.Fatalf("SQLTypes() = %+v", got)
	}
	k, _ := migrationSQL(t, auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{Key: "VARCHAR(191)"}))
	if got := k.SQLTypes(); got.ID != "VARCHAR(191)" || got.Key != "VARCHAR(191)" {
		t.Fatalf("a Key-only override must retype ids too: %+v", got)
	}
	both, _ := migrationSQL(t, auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{Key: "VARCHAR(191)"}), auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{ID: "UUID"}))
	if got := both.SQLTypes(); got.ID != "UUID" || got.Key != "VARCHAR(191)" {
		t.Fatalf("explicit ID with a Key override = %+v", got)
	}
	for _, engine := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		if ty := auth.TypesFor(engine); ty.ID != ty.Key {
			t.Errorf("%s: built-in ID %q differs from Key %q", engine, ty.ID, ty.Key)
		}
	}
}
