package terms_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/terms"
)

type signIn struct{}

func (signIn) Name() string  { return "signin" }
func (signIn) SignsIn() bool { return true }

// TestNew_RequiresAVersion: without Current the plugin would refuse every
// user, so auth.New fails instead.
func TestNew_RequiresAVersion(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, terms.New())); !errors.Is(err, terms.ErrNoVersion) {
		t.Fatalf("err = %v", err)
	}
	p := terms.New(terms.Current("2026-09"))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	if p.Version() != "2026-09" {
		t.Fatalf("Version = %q", p.Version())
	}
}

// TestHistory_Wiring: the history table is declared, listed for DeleteUser,
// created with a backfill from auth_user on every engine and refused on an
// unknown one; History before auth.New says the plugin is not wired. The
// behaviour on a database is in integration/r23_test.go.
func TestHistory_Wiring(t *testing.T) {
	p := terms.New(terms.Current("2026-09"))
	if _, err := p.History(context.Background(), "u1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("History before New = %v", err)
	}
	if ts := p.Tables(); len(ts) != 1 || ts[0] != terms.TableAcceptance {
		t.Fatalf("Tables = %+v", ts)
	}
	if ut := p.UserTables(); len(ut) != 1 || ut[0].Table != terms.TableAcceptance || ut[0].Column != terms.ColAcceptanceUserID {
		t.Fatalf("UserTables = %+v", ut)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	for _, engine := range []string{auth.EnginePostgres, auth.EngineMySQL, auth.EngineSQLite} {
		ms, err := p.TypedMigrations(engine, auth.TypesFor(engine))
		if err != nil || len(ms) != 1 || len(ms[0].Statements) != 2 {
			t.Fatalf("%s migrations = %+v, %v", engine, ms, err)
		}
		create, backfill := ms[0].Statements[0], ms[0].Statements[1]
		if !strings.Contains(create, terms.TableNameAcceptance) || !strings.Contains(create, "PRIMARY KEY") {
			t.Fatalf("%s create = %s", engine, create)
		}
		if !strings.HasPrefix(backfill, "INSERT INTO "+terms.TableNameAcceptance) || !strings.Contains(backfill, "FROM "+auth.TableNameUser) {
			t.Fatalf("%s backfill = %s", engine, backfill)
		}
	}
	if _, err := p.TypedMigrations("oracle", auth.TypesFor("oracle")); !errors.Is(err, auth.ErrEngineNotSupported) {
		t.Fatalf("unknown engine = %v", err)
	}
}
