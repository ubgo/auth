package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ubgo/sqlb"
)

// ErrUnknownDialect is DetectDialect's answer for a database it cannot name
// as Postgres, MySQL or SQLite: pass the dialect with WithDB instead.
var ErrUnknownDialect = errors.New("auth: cannot tell which SQL dialect the database speaks; pass it with auth.WithDB(db, dialect)")

// DetectTimeout bounds the probe queries WithDBAuto runs inside New for a
// driver it does not know by type, so a database that does not answer fails
// New instead of hanging it.
//
//ds:def id=core-detecttimeout-2wq8nd5k owner=@khanakia stability=stable
const DetectTimeout = 5 * time.Second

// driverDialects names the dialect of each driver package the library knows,
// by package path prefix (any major version of pgx). It is how better-auth
// infers the dialect from a pg.Pool or a mysql2 pool, with no query.
var driverDialects = []struct {
	pkg     string
	dialect sqlb.Dialect
}{
	{"github.com/jackc/pgx", sqlb.PostgresDialect{}},
	{"github.com/lib/pq", sqlb.PostgresDialect{}},
	{"github.com/go-sql-driver/mysql", sqlb.MySQLDialect{}},
	{"modernc.org/sqlite", sqlb.SQLiteDialect{}},
	{"github.com/mattn/go-sqlite3", sqlb.SQLiteDialect{}},
	{"github.com/ncruces/go-sqlite3", sqlb.SQLiteDialect{}},
}

// The probe statements, each valid on exactly the engines its comment names.
const (
	// probeSQLite succeeds on SQLite only.
	probeSQLite = "SELECT sqlite_version()"
	// probeVersion succeeds on Postgres (whose answer names PostgreSQL) and
	// on MySQL and MariaDB (whose answer is a bare version number).
	probeVersion = "SELECT version()"
	// probeMySQL succeeds on MySQL and MariaDB, not on Postgres.
	probeMySQL = "SELECT @@version"
	// postgresMarker is in every Postgres version() answer.
	postgresMarker = "PostgreSQL"
)

// DetectDialect names the dialect db speaks, so an app can pass a bare
// *sql.DB as it passes a pool to better-auth. It looks at the driver's type
// first, which costs nothing and covers pgx, lib/pq, go-sql-driver/mysql and
// the three common SQLite drivers. A driver it does not know by type, which
// is any wrapper such as otelsql, is asked with up to three probe queries:
// sqlite_version() answers only on SQLite, version() names PostgreSQL only
// on Postgres, and @@version answers only on MySQL and MariaDB. Anything
// else is ErrUnknownDialect, never a guess.
func DetectDialect(ctx context.Context, db *sql.DB) (sqlb.Dialect, error) {
	if d, ok := dialectOfDriver(db); ok {
		return d, nil
	}
	var v string
	if db.QueryRowContext(ctx, probeSQLite).Scan(&v) == nil {
		return sqlb.SQLiteDialect{}, nil
	}
	if db.QueryRowContext(ctx, probeVersion).Scan(&v) == nil && strings.Contains(v, postgresMarker) {
		return sqlb.PostgresDialect{}, nil
	}
	if db.QueryRowContext(ctx, probeMySQL).Scan(&v) == nil {
		return sqlb.MySQLDialect{}, nil
	}
	return nil, ErrUnknownDialect
}

// dialectOfDriver names the dialect from the driver's package path alone.
func dialectOfDriver(db *sql.DB) (sqlb.Dialect, bool) {
	t := reflect.TypeOf(db.Driver())
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return dialectOfPackage(t.PkgPath())
}

// dialectOfPackage looks pkg up in driverDialects.
func dialectOfPackage(pkg string) (sqlb.Dialect, bool) {
	for _, d := range driverDialects {
		if pkg == d.pkg || strings.HasPrefix(pkg, d.pkg+"/") {
			return d.dialect, true
		}
	}
	return nil, false
}

// WithDBAuto is WithDB with the dialect found by DetectDialect, for an app
// that would rather not name it. New runs the detection, bounded by
// DetectTimeout, and fails with ErrUnknownDialect when the database is none
// of the three. WithDB stays the explicit form, and the one to use when the
// driver is wrapped and New should run no query.
//
//ds:def id=opt-withdbauto-7kq3nw8d owner=@khanakia stability=stable
func WithDBAuto(db *sql.DB) Option {
	return func(s *settings) {
		// Detection queries the handle, so a nil one panicked inside
		// DetectDialect; refused here like any nil option.
		if s.optErrs.RefuseNil("auth.WithDBAuto", db) {
			return
		}
		s.db = db
		ctx, cancel := context.WithTimeout(context.Background(), DetectTimeout)
		defer cancel()
		d, err := DetectDialect(ctx, db)
		if err != nil {
			s.optErrs.JoinOptionErr(fmt.Errorf("auth.WithDBAuto: %w", err))
			return
		}
		s.cfg.Dialect = d
	}
}
