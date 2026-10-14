package auth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/ubgo/sqlb"
)

// The driver packages the library knows map to their dialect, any pgx major
// version included, and a lookalike path does not.
func TestDialectOfPackage(t *testing.T) {
	for pkg, want := range map[string]sqlb.Dialect{
		"github.com/jackc/pgx/v5/stdlib":       sqlb.PostgresDialect{},
		"github.com/lib/pq":                    sqlb.PostgresDialect{},
		"github.com/go-sql-driver/mysql":       sqlb.MySQLDialect{},
		"modernc.org/sqlite":                   sqlb.SQLiteDialect{},
		"github.com/mattn/go-sqlite3":          sqlb.SQLiteDialect{},
		"github.com/ncruces/go-sqlite3/driver": sqlb.SQLiteDialect{},
	} {
		if got, ok := dialectOfPackage(pkg); !ok || got != want {
			t.Errorf("%s: %T, %v; want %T", pkg, got, ok, want)
		}
	}
	for _, pkg := range []string{"github.com/lib/pqx", "github.com/XSAM/otelsql", ""} {
		if _, ok := dialectOfPackage(pkg); ok {
			t.Errorf("%q named a dialect", pkg)
		}
	}
}

// probeDB is the script database answering the probes it is given; every
// other probe fails.
func probeDB(answers ...scriptAnswer) *sql.DB {
	fail := errors.New("no such function")
	all := append(answers, scriptAnswer{match: probeSQLite, err: fail}, scriptAnswer{match: probeVersion, err: fail}, scriptAnswer{match: probeMySQL, err: fail})
	return sql.OpenDB(&script{answers: all})
}

func row(v string) [][]driver.Value { return [][]driver.Value{{v}} }

// An unknown driver (the script's, as a wrapper would be) is probed: each
// engine is told apart by the one query only it answers, a version() without
// PostgreSQL in it is not taken for Postgres, and a database that answers
// none of the three is ErrUnknownDialect.
func TestDetectDialect_Probes(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		db   *sql.DB
		want sqlb.Dialect
	}{
		{"sqlite", probeDB(scriptAnswer{match: probeSQLite, cols: []string{"v"}, rows: row("3.46.0")}), sqlb.SQLiteDialect{}},
		{"postgres", probeDB(scriptAnswer{match: probeVersion, cols: []string{"v"}, rows: row("PostgreSQL 17.2 on aarch64")}), sqlb.PostgresDialect{}},
		{"mysql", probeDB(scriptAnswer{match: probeVersion, cols: []string{"v"}, rows: row("8.4.3")}, scriptAnswer{match: probeMySQL, cols: []string{"v"}, rows: row("8.4.3")}), sqlb.MySQLDialect{}},
	}
	for _, tc := range cases {
		got, err := DetectDialect(ctx, tc.db)
		if err != nil || got != tc.want {
			t.Errorf("%s: %T, %v", tc.name, got, err)
		}
	}
	if _, err := DetectDialect(ctx, probeDB()); !errors.Is(err, ErrUnknownDialect) {
		t.Fatalf("no answers: %v", err)
	}
	// A version() that does not name PostgreSQL, from an engine without
	// @@version, is unknown, not Postgres.
	if _, err := DetectDialect(ctx, probeDB(scriptAnswer{match: probeVersion, cols: []string{"v"}, rows: row("CockroachDB")})); !errors.Is(err, ErrUnknownDialect) {
		t.Fatalf("a lookalike version: %v", err)
	}
}

// WithDBAuto sets the detected dialect, and New fails when there is none.
func TestWithDBAuto(t *testing.T) {
	a, err := New(WithBaseURL("https://app.example.com"), WithPlugins(scriptSignIn{}), WithDBAuto(probeDB(scriptAnswer{match: probeSQLite, cols: []string{"v"}, rows: row("3")})))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Dialect().(sqlb.SQLiteDialect); !ok || a.DB() == nil {
		t.Fatalf("dialect %T, db %v", a.Dialect(), a.DB())
	}
	if _, err := New(WithBaseURL("https://app.example.com"), WithPlugins(scriptSignIn{}), WithDBAuto(probeDB())); !errors.Is(err, ErrUnknownDialect) {
		t.Fatalf("err = %v, want ErrUnknownDialect", err)
	}
}
