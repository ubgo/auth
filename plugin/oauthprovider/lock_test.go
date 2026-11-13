package oauthprovider

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/sqlb"
)

// forUpdate renders FOR UPDATE last on Postgres and MySQL, and fails the
// statement on SQLite instead of rendering a lock SQLite does not take.
func TestForUpdate_RendersPerDialect(t *testing.T) {
	read := func(d sqlb.Dialect) (sqlb.Query, error) {
		var id string
		return sqlb.NewSelect(d).Columns(sqlb.Bind(TokenID, &id)).From(TableToken).Where(sqlb.Eq(TokenRefresh, []byte("h"))).Clause(forUpdate{}).Build()
	}
	for name, d := range map[string]sqlb.Dialect{sqlb.DialectPostgres: sqlb.PostgresDialect{}, sqlb.DialectMySQL: sqlb.MySQLDialect{}} {
		q, err := read(d)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.HasSuffix(q.SQL, " "+kwForUpdate) {
			t.Errorf("%s: %q does not end with %s", name, q.SQL, kwForUpdate)
		}
	}
	if _, err := read(sqlb.SQLiteDialect{}); !errors.Is(err, sqlb.ErrUnsupportedDialect) {
		t.Errorf("sqlite: %v, want ErrUnsupportedDialect", err)
	}
}
