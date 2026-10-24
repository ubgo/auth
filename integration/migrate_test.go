package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
)

// everyPlugin is the full set, so the migration test creates every table.
func (e *env) everyPlugin() []auth.Plugin {
	return []auth.Plugin{
		e.emailPlugin(), e.phonePlugin(phone.Login(), phone.SignInWithCode()), username.New(username.Login()), e.passwordPlugin(),
		oauth.New(oauth.WithProviders(oauth.Google("id", "secret"))), organization.New(),
	}
}

func TestMigrate_CreatesEverythingAndIsIdempotent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		a := e.newAuth(t, nil, e.everyPlugin()...)
		again, err := a.Migrate(ctx)
		if err != nil {
			t.Fatalf("second migrate: %v", err)
		}
		if len(again) != 0 {
			t.Fatalf("second migrate applied %v, want nothing", again)
		}
		var n int
		if err := e.db.QueryRow("SELECT COUNT(*) FROM " + tbl(auth.TableNameMigrations)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		ms, _ := a.Migrations()
		if n != len(ms) {
			t.Fatalf("ledger has %d rows, want %d", n, len(ms))
		}
	})
}

func TestMigrate_ChangedMigrationStopsTheRun(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		a := e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin())
		if _, err := e.db.Exec("UPDATE " + tbl(auth.TableNameMigrations) + " SET checksum = 'tampered' WHERE owner = 'password'"); err != nil {
			t.Fatal(err)
		}
		_, err := a.Migrate(ctx)
		if !errors.Is(err, auth.ErrChecksumMismatch) {
			t.Fatalf("err = %v, want ErrChecksumMismatch", err)
		}
	})
}

// TestMigrate_PluginAddedLater is the app that runs for a year and then adds
// a plugin: only the new plugin's migrations run.
func TestMigrate_PluginAddedLater(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin())
		later, err := auth.New(e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)),
			auth.WithPlugins(e.emailPlugin(), e.passwordPlugin(), username.New(username.Login())))
		if err != nil {
			t.Fatal(err)
		}
		applied, err := later.Migrate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(applied) != 1 || applied[0] != "username/0000_identity_unique_username_all" {
			t.Fatalf("applied %v, want only the username index", applied)
		}
	})
}
