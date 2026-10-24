package sessiondata

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// The plugin's behaviour against a database is in integration/
// sessiondata_test.go on every engine; here are the parts that need none:
// the declarations, the DDL per engine and the refusals before Init.

func TestPlugin_Declarations(t *testing.T) {
	p := New()
	if p.Name() != PluginName {
		t.Fatalf("Name = %q", p.Name())
	}
	if ts := p.Tables(); len(ts) != 1 || ts[0].Name != TableNameData {
		t.Fatalf("Tables = %v", ts)
	}
	if uts := p.UserTables(); len(uts) != 1 || uts[0].Table.Name != TableNameData || uts[0].Column != ColUserID {
		t.Fatalf("UserTables = %v, want the data table by user id", uts)
	}
	if h := p.DataHooks(); h.Session.AfterCreate != nil {
		t.Fatal("without WithInitial the plugin hooks nothing")
	}
	if h := New(WithInitial(func(context.Context, auth.Session) (any, error) { return nil, nil })).DataHooks(); h.Session.AfterCreate == nil {
		t.Fatal("WithInitial must hook session creation")
	}
}

func TestPlugin_MigrationsPerEngine(t *testing.T) {
	a, err := auth.New(auth.WithPlugins(signIn{}, New()))
	if err != nil {
		t.Fatal(err)
	}
	p, err := auth.PluginOf[*Plugin](a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("an unknown engine = %v, want ErrEngineNotSupported", err)
	}
	for engine, wantIndex := range map[string]string{
		auth.EngineMySQL:    ", INDEX " + TableNameData + indexUserSuffix + " (" + ColUserID + "))",
		auth.EnginePostgres: "CREATE INDEX IF NOT EXISTS " + TableNameData + indexUserSuffix,
		auth.EngineSQLite:   "CREATE INDEX IF NOT EXISTS " + TableNameData + indexUserSuffix,
	} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(ms) != 1 || ms[0].Owner != PluginName || ms[0].Name != migrationTable {
			t.Fatalf("%s: Migrations = %+v, %v", engine, ms, err)
		}
		all := strings.Join(ms[0].Statements, "\n")
		for _, want := range []string{"CREATE TABLE IF NOT EXISTS " + TableNameData, ColSessionID + " ", ColUserID + " ", ColData + " ", ColExpiresAt + " ", ColUpdatedAt + " ", wantIndex} {
			if !strings.Contains(all, want) {
				t.Errorf("%s: statements lack %q:\n%s", engine, want, all)
			}
		}
		if strings.Contains(all, "FOREIGN KEY") || strings.Contains(all, "CASCADE") {
			t.Errorf("%s: the table must carry no foreign key (ADR-0002):\n%s", engine, all)
		}
	}
}

func TestPlugin_RefusesBeforeInit(t *testing.T) {
	p := New()
	if err := p.SetFor(context.Background(), auth.Session{ID: "s1"}, 1); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("SetFor before Init = %v, want ErrOperationNotWired", err)
	}
	if _, _, err := GetFor[int](context.Background(), p, "s1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("GetFor before Init = %v, want ErrOperationNotWired", err)
	}
}

func TestHardStop(t *testing.T) {
	exp := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	max := exp.Add(time.Hour)
	if got := hardStop(auth.Session{ExpiresAt: exp}); !got.Equal(exp) {
		t.Fatalf("a session with no hard stop uses its expiry: %v", got)
	}
	if got := hardStop(auth.Session{ExpiresAt: exp, MaxExpiresAt: &max}); !got.Equal(max) {
		t.Fatalf("a session with a hard stop uses it: %v", got)
	}
}

// signIn is the one sign-in method auth.New requires.
type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }
