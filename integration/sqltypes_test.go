package integration

import (
	"context"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// textKeys is the WithSQLTypes override the engine test applies: a key type
// every engine accepts and indexes, different from each built-in spelling.
var textKeys = map[string]string{
	auth.EnginePostgres: "VARCHAR(191)",
	auth.EngineMySQL:    "VARCHAR(190)",
	auth.EngineSQLite:   "VARCHAR(191)",
}

// TestSQLTypes_OverrideMigratesAndRuns: core tables and the ledger created
// with an overridden key type migrate on the real engine, a second run
// applies nothing, and a user and a session round-trip through them.
func TestSQLTypes_OverrideMigratesAndRuns(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		a := e.newAuth(t, []auth.Option{auth.WithSQLTypes(e.engine, auth.SQLTypes{Key: textKeys[e.engine]})}, e.emailPlugin(email.SignInWithCode()))
		ctx := context.Background()
		if got := a.SQLTypes().Key; got != textKeys[e.engine] {
			t.Fatalf("SQLTypes().Key = %q", got)
		}
		applied, err := a.Migrate(ctx)
		if err != nil || len(applied) != 0 {
			t.Fatalf("second migrate applied %v, %v", applied, err)
		}
		u, err := a.CreateUser(ctx, auth.NewUser{Name: "Typed"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := a.CreateSession(ctx, u.ID, auth.Client{}); err != nil {
			t.Fatal(err)
		}
		if got, err := a.User(ctx, u.ID); err != nil || got.Name != "Typed" {
			t.Fatalf("read back %+v %v", got, err)
		}
	})
}
