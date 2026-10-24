package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// The schema check's pure parts; the database comparison is in the
// integration suite (r2_core_test.go).

func TestSchemaReport_OKAndError(t *testing.T) {
	var ok auth.SchemaReport
	if !ok.OK() || ok.Error() != "" {
		t.Fatalf("empty report: ok=%v err=%q", ok.OK(), ok.Error())
	}
	r := auth.SchemaReport{
		PendingMigrations: []string{"core/0003_x"}, ChangedMigrations: []string{"p/0001"},
		MissingTables: []string{"auth_thing"}, MissingColumns: []string{"auth_user.plan"},
	}
	msg := r.Error()
	for _, want := range []string{"1 pending migration(s): core/0003_x", "1 changed migration(s): p/0001", "1 missing table(s): auth_thing", "1 missing column(s): auth_user.plan"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Error() = %q, want it to contain %q", msg, want)
		}
	}
	if r.OK() {
		t.Fatal("a report with findings is not OK")
	}
}

func TestCheckSchema_NeedsADatabase(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.CheckSchema(context.Background()); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("CheckSchema: %v, want ErrNoDatabase", err)
	}
	if err := a.RequireSchema(context.Background()); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("RequireSchema: %v, want ErrNoDatabase", err)
	}
}

// TestMigrations_DefineEveryCoreTableAndColumn reads the expected schema the
// check derives from the migrations, through the Postgres statements, and
// pins that every core table and column the queries name is in it. Were a
// column added to the constants but not to a migration, the check would be
// blind to it and every engine would fail at the first query.
func TestMigrations_DefineEveryCoreTableAndColumn(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	expected := auth.ExpectedSchema(ms)
	for table, cols := range map[string][]string{
		auth.TableNameUser:         auth.CoreUserColumns,
		auth.TableNameSession:      {auth.ColSessionID, auth.ColSessionTokenHash, auth.ColSessionIdleSeconds, auth.ColSessionMaxExpiresAt},
		auth.TableNameIdentity:     {auth.ColIdentityID, auth.ColIdentityScopeID},
		auth.TableNameVerification: {auth.ColVerificationID, auth.ColVerificationMeta},
		auth.TableNameCode:         {"id"},
	} {
		got, ok := expected[table]
		if !ok {
			t.Errorf("%s is not created by any migration", table)
			continue
		}
		for _, c := range cols {
			found := false
			for _, g := range got {
				found = found || g == c
			}
			if !found {
				t.Errorf("%s.%s is not created by any migration (have %v)", table, c, got)
			}
		}
		// Constraints are not columns.
		for _, g := range got {
			if up := strings.ToUpper(g); up == "FOREIGN" || up == "PRIMARY" || up == "INDEX" || up == "UNIQUE" {
				t.Errorf("%s: constraint %q read as a column", table, g)
			}
		}
	}
}

func TestImportUsers_NeedsADatabase(t *testing.T) {
	a, err := newAuth(auth.WithPlugins(basic("s")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ImportUsers(context.Background(), nil); !errors.Is(err, auth.ErrNoDatabase) {
		t.Fatalf("ImportUsers: %v, want ErrNoDatabase", err)
	}
}
