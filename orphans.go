package auth

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// OrphanKind says what an Orphan is.
type OrphanKind string

// Orphan kinds.
const (
	// OrphanOwner is a migration owner in the ledger that no registered
	// plugin is: a plugin that was removed. Name is the owner.
	OrphanOwner OrphanKind = "owner"
	// OrphanTable is an auth_* table that neither the core nor a registered
	// plugin declares. Name is the table.
	OrphanTable OrphanKind = "table"
	// OrphanColumn is a column of auth_user that neither the core nor a
	// registered plugin declares. Name is the column.
	OrphanColumn OrphanKind = "column"
)

// OrphanKindValues is the canonical iteration order over orphan kinds.
var OrphanKindValues = []OrphanKind{OrphanOwner, OrphanTable, OrphanColumn}

// Orphan is something in the database that the current configuration does not
// own.
//
//ds:def id=core-orphan-5rmbmqxz owner=@khanakia stability=stable
type Orphan struct {
	Kind OrphanKind
	Name string
}

// authTablePrefix is the prefix every library table carries.
const authTablePrefix = "auth_"

// Orphans lists what a removed plugin left behind. It only reports: the
// library never drops user data because configuration changed, so the
// operator decides what to delete.
//
// A table counts as owned when the core has it or a registered plugin lists
// it through TableOwner. A plugin that owns a table must list it there, or
// its own table is reported here.
//
//ds:def id=core-orphans-fmffsrbr owner=@khanakia stability=stable
func (a *Auth) Orphans(ctx context.Context) ([]Orphan, error) {
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	owners := map[string]bool{CorePluginName: true}
	// By real name, since the catalogue reports real names.
	tables := map[string]bool{}
	for _, t := range a.declaredTables() {
		tables[a.TableName(t)] = true
	}
	for _, p := range a.plugins {
		owners[p.Name()] = true
	}
	columns := map[string]bool{}
	for _, c := range CoreUserColumns {
		columns[c] = true
	}
	for _, c := range a.columns {
		columns[c.Name] = true
	}
	var out []Orphan

	ledger, err := a.listNames(ctx, "read ledger", "SELECT DISTINCT owner FROM "+a.TableName(TableMigrations))
	if err != nil {
		return nil, err
	}
	for _, o := range ledger {
		if !owners[o] {
			out = append(out, Orphan{Kind: OrphanOwner, Name: o})
		}
	}

	names, err := a.listNames(ctx, "list tables", a.tablesQuery())
	if err != nil {
		return nil, err
	}
	// A removed plugin's table carries the library prefix under this Auth's
	// table prefix, as every table did while the plugin was registered. A
	// table that plugin had renamed with RenameTable cannot be told apart
	// from the app's own and is not reported.
	orphanPrefix := a.tablePrefix + authTablePrefix
	for _, n := range names {
		if strings.HasPrefix(n, orphanPrefix) && !tables[n] {
			out = append(out, Orphan{Kind: OrphanTable, Name: n})
		}
	}
	cols, err := a.listNames(ctx, "list columns", a.columnsQuery(a.TableName(TableUser)))
	if err != nil {
		return nil, err
	}
	for _, n := range cols {
		// MySQL's generated uniqueness columns live on auth_identity, never
		// on auth_user, so every auth_user column must be declared.
		if !columns[n] {
			out = append(out, Orphan{Kind: OrphanColumn, Name: n})
		}
	}
	slices.SortFunc(out, func(x, y Orphan) int {
		if c := strings.Compare(string(x.Kind), string(y.Kind)); c != 0 {
			return c
		}
		return strings.Compare(x.Name, y.Name)
	})
	return out, nil
}

// tablesQuery lists the tables of the current database or schema.
func (a *Auth) tablesQuery() string {
	switch a.Engine() {
	case EngineMySQL:
		return "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"
	case EngineSQLite:
		return "SELECT name FROM sqlite_master WHERE type = 'table'"
	default:
		return "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()"
	}
}

// columnsQuery lists the columns of table. table is always a real table name
// the configuration resolved (TableName), never input, so building the
// statement by concatenation is safe.
func (a *Auth) columnsQuery(table string) string {
	switch a.Engine() {
	case EngineMySQL:
		return "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = '" + table + "'"
	case EngineSQLite:
		return "SELECT name FROM pragma_table_info('" + table + "')"
	default:
		return "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = '" + table + "'"
	}
}

// listNames runs q, a query of one text column, and returns every value. what
// names the step in the error, so an operator reading "auth: list columns: …"
// knows which catalogue query failed.
func (a *Auth) listNames(ctx context.Context, what, q string) ([]string, error) {
	rows, err := a.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("auth: %s: %w", what, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("auth: %s: %w", what, err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("auth: %s: %w", what, err)
	}
	return out, nil
}
