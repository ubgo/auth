package auth_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// stableColumns is the contract of what an app may SELECT and JOIN across
// versions. A column listed here keeps its name, its type and its meaning
// within a major version; one not listed (an index, a flag an app has no use
// for) may change. Changing this list is a breaking change: it needs a new
// major version and a CHANGELOG entry tagged **[breaking]**.
//
// The test reads the core's own CREATE TABLE statements, so a column renamed
// or dropped in migrate.go fails here even if nobody remembered the contract.
var stableColumns = map[string][]string{
	auth.TableNameUser:     {"id", "name", "image", "created_at", "updated_at"},
	auth.TableNameIdentity: {"id", "user_id", "kind", "value", "value_raw", "verified_at", "is_primary", "scope_id", "created_at"},
	auth.TableNameSession:  {"id", "user_id", "expires_at", "last_seen_at", "ip", "user_agent", "created_at", "second_factor_pending", "impersonated_by"},
}

var createTable = regexp.MustCompile(`CREATE TABLE IF NOT EXISTS (\w+) \((.*)\)`)

func TestStableColumns_AreAllCreated(t *testing.T) {
	a, err := newAuth(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{on: true}))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	created := map[string][]string{}
	for _, m := range ms {
		for _, st := range m.Statements {
			mm := createTable.FindStringSubmatch(st)
			if mm == nil {
				continue
			}
			for _, part := range strings.Split(mm[2], ", ") {
				if f := strings.Fields(part); len(f) > 1 && f[0] != "FOREIGN" && f[0] != "PRIMARY" && f[0] != "UNIQUE" {
					created[mm[1]] = append(created[mm[1]], f[0])
				}
			}
		}
	}
	for table, cols := range stableColumns {
		for _, c := range cols {
			if !slices.Contains(created[table], c) {
				t.Errorf("stable column %s.%s is not created any more: a breaking change", table, c)
			}
		}
	}
}
