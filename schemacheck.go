package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Schema check: is the live database able to hold what this configuration
// writes? The ledger says which migrations ran; this compares the tables and
// columns the migrations create with what the catalogue reports, so a
// database behind the code, or one edited by hand, is found at start or by
// an operator, not by the first request that hits a missing column.

// SchemaReport is what CheckSchema found.
//
//ds:def id=core-schemareport-6vm3kq8t owner=@khanakia stability=stable
type SchemaReport struct {
	// PendingMigrations are the "owner/name" labels the ledger lacks, in
	// the order Migrate would apply them.
	PendingMigrations []string
	// ChangedMigrations are applied migrations whose statements changed
	// since; Migrate refuses to run while any exists.
	ChangedMigrations []string
	// MissingTables are tables the migrations create that the database
	// lacks.
	MissingTables []string
	// MissingColumns are "table.column" pairs the migrations create that the
	// database lacks, on tables that exist.
	MissingColumns []string
}

// OK reports whether the database holds everything the configuration needs.
func (r SchemaReport) OK() bool {
	return len(r.PendingMigrations) == 0 && len(r.ChangedMigrations) == 0 && len(r.MissingTables) == 0 && len(r.MissingColumns) == 0
}

// Error words the report for a log line or an operator; "" when OK.
func (r SchemaReport) Error() string {
	if r.OK() {
		return ""
	}
	var parts []string
	if n := len(r.PendingMigrations); n > 0 {
		parts = append(parts, fmt.Sprintf("%d pending migration(s): %s", n, strings.Join(r.PendingMigrations, ", ")))
	}
	if n := len(r.ChangedMigrations); n > 0 {
		parts = append(parts, fmt.Sprintf("%d changed migration(s): %s", n, strings.Join(r.ChangedMigrations, ", ")))
	}
	if n := len(r.MissingTables); n > 0 {
		parts = append(parts, fmt.Sprintf("%d missing table(s): %s", n, strings.Join(r.MissingTables, ", ")))
	}
	if n := len(r.MissingColumns); n > 0 {
		parts = append(parts, fmt.Sprintf("%d missing column(s): %s", n, strings.Join(r.MissingColumns, ", ")))
	}
	return "auth: schema is behind the code: " + strings.Join(parts, "; ")
}

// ErrSchemaBehind is what RequireSchema returns when the database lacks a
// migration, a table or a column the code needs; the wrapped text lists
// them.
var ErrSchemaBehind = errors.New("auth: schema is behind the code")

// CheckSchema compares the database with what this configuration's
// migrations create: the ledger for pending and changed migrations, the
// catalogue for the tables and columns. It changes nothing. It reads the
// expected tables and columns from the migration statements themselves
// (CREATE TABLE and ALTER TABLE … ADD COLUMN), so a plugin's own table is
// checked with no declaration beyond its migration.
//
//ds:def id=core-checkschema-8xq2nw5r owner=@khanakia stability=stable
func (a *Auth) CheckSchema(ctx context.Context) (SchemaReport, error) {
	if a.db == nil {
		return SchemaReport{}, ErrNoDatabase
	}
	var r SchemaReport
	states, err := a.MigrationStatus(ctx)
	if err != nil {
		return r, err
	}
	for _, s := range states {
		switch {
		case s.Changed:
			r.ChangedMigrations = append(r.ChangedMigrations, s.Owner+"/"+s.Name)
		case !s.Applied:
			r.PendingMigrations = append(r.PendingMigrations, s.Owner+"/"+s.Name)
		}
	}
	ms, err := a.Migrations()
	if err != nil {
		return r, err
	}
	expected := expectedSchema(ms)
	live, err := a.listNames(ctx, "list tables", a.tablesQuery())
	if err != nil {
		return r, err
	}
	have := map[string]bool{}
	for _, t := range live {
		have[t] = true
	}
	tables := make([]string, 0, len(expected))
	for t := range expected {
		tables = append(tables, t)
	}
	slices.Sort(tables)
	for _, t := range tables {
		if !have[t] {
			r.MissingTables = append(r.MissingTables, t)
			continue
		}
		cols, err := a.listNames(ctx, "list columns", a.columnsQuery(t))
		if err != nil {
			return r, err
		}
		for _, c := range expected[t] {
			if !slices.Contains(cols, c) {
				r.MissingColumns = append(r.MissingColumns, t+"."+c)
			}
		}
	}
	return r, nil
}

// RequireSchema is CheckSchema for start-up: nil when the database holds
// everything, ErrSchemaBehind (wrapping the report's wording) when not, and
// the database error otherwise. An app calls it after auth.New and before
// serving, so a deploy that forgot to migrate fails to start instead of
// failing its users one request at a time.
//
//ds:def id=core-requireschema-2tk9vp7m owner=@khanakia stability=stable
func (a *Auth) RequireSchema(ctx context.Context) error {
	r, err := a.CheckSchema(ctx)
	if err != nil {
		return err
	}
	if r.OK() {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrSchemaBehind, strings.TrimPrefix(r.Error(), ErrSchemaBehind.Error()+": "))
}

// The DDL shapes the migrations use. Statements are the library's and its
// plugins' own, written by the generators in migrate.go and by plugin
// authors following them, which is what makes a pattern match safe here:
// this reads known shapes, it does not parse SQL.
var (
	createTablePattern = regexp.MustCompile(`(?is)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)[^)]*$`)
	addColumnPattern   = regexp.MustCompile(`(?is)^\s*ALTER\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+COLUMN\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

// tableConstraintWords start a CREATE TABLE item that is not a column.
var tableConstraintWords = map[string]bool{"PRIMARY": true, "FOREIGN": true, "UNIQUE": true, "INDEX": true, "KEY": true, "CONSTRAINT": true, "CHECK": true}

// expectedSchema reads the tables and their columns out of the migrations,
// in the order the statements define them.
func expectedSchema(ms []Migration) map[string][]string {
	out := map[string][]string{}
	for _, m := range ms {
		for _, st := range m.Statements {
			if mm := createTablePattern.FindStringSubmatch(st); mm != nil {
				table := mm[1]
				for _, item := range splitTopLevel(mm[2]) {
					fields := strings.Fields(item)
					if len(fields) == 0 || tableConstraintWords[strings.ToUpper(fields[0])] {
						continue
					}
					out[table] = append(out[table], fields[0])
				}
				continue
			}
			if mm := addColumnPattern.FindStringSubmatch(st); mm != nil {
				out[mm[1]] = append(out[mm[1]], mm[2])
			}
		}
	}
	return out
}

// splitTopLevel splits a CREATE TABLE body on the commas outside parentheses,
// so "FOREIGN KEY (a) REFERENCES t (b)" stays one item.
func splitTopLevel(body string) []string {
	var out []string
	depth, start := 0, 0
	for i, r := range body {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, body[start:i])
				start = i + 1
			}
		}
	}
	return append(out, body[start:])
}

// ExpectedSchema returns the tables and columns, in definition order, that
// the given migrations create: what CheckSchema compares the database with.
// Exported for tools and tests that want the derived schema without a
// database.
func ExpectedSchema(ms []Migration) map[string][]string { return expectedSchema(ms) }
