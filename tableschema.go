package auth

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ubgo/sqlb"
)

// Declarative plugin tables: a plugin's `schema` (fields with type,
// required, unique and table-level indexes). A plugin describes its
// table once and SchemaMigration writes the DDL for the engine, so it no
// longer hand-writes three dialects of CREATE TABLE. Writing DDL by hand with
// TypesFor stays possible for anything the description cannot say.
//
// There is no `references`/`onDelete`: the library creates no foreign keys
// (ADR-0002). A table whose rows belong to a user is declared through
// UserTableOwner instead, and DeleteUser removes its rows in Go.

// SchemaColumn is one column of a TableSchema. Type is a portable
// ColumnType; a text column takes the engine's indexable text type, so it
// can be unique or indexed on every engine.
//
//ds:def id=core-schemacolumn-5kq8wn2x owner=@khanakia stability=stable
type SchemaColumn struct {
	Name string
	Type ColumnType
	// Nullable makes the column optional. A NOT NULL column added
	// to a table with rows needs Default.
	Nullable bool
	// Default is a constant SQL literal ("''", "false", "0"), or empty.
	Default string
	// Unique adds a unique index on the column alone.
	Unique bool
}

// SchemaIndex is an index over one or more columns of a TableSchema.
//
//ds:def id=core-schemaindex-3wn7kq4d owner=@khanakia stability=stable
type SchemaIndex struct {
	// Name is unique within the table; the index is created as
	// <real table name>_<Name>, so a renamed table renames its indexes.
	Name    string
	Columns []string
	Unique  bool
}

// TableSchema describes a plugin's table: a text primary key named ID, the
// columns and the indexes.
//
//ds:def id=core-tableschema-8nq2wk6x owner=@khanakia stability=stable
type TableSchema struct {
	Table   sqlb.Table
	ID      string
	Columns []SchemaColumn
	Indexes []SchemaIndex
}

// ErrBadSchema is a TableSchema SchemaMigration cannot write: a name that is
// not a lower-case identifier, a duplicate column or index, an unknown type,
// an index naming a column the table does not have, or no ID.
var ErrBadSchema = errors.New("auth: table schema is not valid")

// SchemaMigration writes the migration that creates s for engine, owned by
// owner and named name, under the table's real name (RenameTable and
// WithTablePrefix apply). Idempotent like the core's own: CREATE TABLE IF
// NOT EXISTS, and indexes with IF NOT EXISTS, or inside the CREATE TABLE on
// MySQL, which has no CREATE INDEX IF NOT EXISTS. It creates no foreign key.
//
//ds:def id=core-schemamigration-6wq3nk8x owner=@khanakia stability=stable
func (a *Auth) SchemaMigration(engine, owner, name string, s TableSchema) (Migration, error) {
	if err := CheckEngine(engine); err != nil {
		return Migration{}, err
	}
	if err := s.validate(); err != nil {
		return Migration{}, err
	}
	t := a.typesFor(engine)
	table := a.TableName(s.Table)
	defs := []string{s.ID + " " + t.ID + " PRIMARY KEY"}
	for _, c := range s.Columns {
		defs = append(defs, c.Name+" "+schemaType(t, c.Type)+nullClause(c.Nullable)+defaultClause(c.Default))
	}
	indexes := s.allIndexes()
	var after []string
	for _, i := range indexes {
		idx := table + "_" + i.Name
		cols := strings.Join(i.Columns, ", ")
		if engine == EngineMySQL {
			kind := "INDEX "
			if i.Unique {
				kind = "UNIQUE INDEX "
			}
			defs = append(defs, kind+idx+" ("+cols+")")
			continue
		}
		kind := "CREATE INDEX IF NOT EXISTS "
		if i.Unique {
			kind = "CREATE UNIQUE INDEX IF NOT EXISTS "
		}
		after = append(after, kind+idx+" ON "+table+" ("+cols+")")
	}
	st := append([]string{"CREATE TABLE IF NOT EXISTS " + table + " (" + strings.Join(defs, ", ") + ")" + t.TableSuffix}, after...)
	return Migration{Owner: owner, Name: name, Statements: st}, nil
}

// schemaType is ct's spelling on the engine of t; validate refused any
// other type.
func schemaType(t SQLTypes, ct ColumnType) string {
	switch ct {
	case ColumnTimestamp:
		return t.Timestamp
	case ColumnBool:
		return t.Bool
	case ColumnInt:
		return t.Int
	}
	return t.Value
}

func nullClause(nullable bool) string {
	if nullable {
		return " NULL"
	}
	return " NOT NULL"
}

func defaultClause(d string) string {
	if d == "" {
		return ""
	}
	return " DEFAULT " + d
}

// allIndexes is the declared indexes plus one unique index per Unique
// column, named <column>_key.
func (s TableSchema) allIndexes() []SchemaIndex {
	out := slices.Clone(s.Indexes)
	for _, c := range s.Columns {
		if c.Unique {
			out = append(out, SchemaIndex{Name: c.Name + "_key", Columns: []string{c.Name}, Unique: true})
		}
	}
	return out
}

// validate checks every name against KindNamePattern (they are written into
// SQL as given) and every reference against the declared columns.
func (s TableSchema) validate() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s: "+format, append([]any{ErrBadSchema, s.Table.Name}, args...)...)
	}
	if !KindNamePattern.MatchString(s.ID) {
		return bad("id column %q", s.ID)
	}
	cols := map[string]bool{s.ID: true}
	for _, c := range s.Columns {
		switch {
		case !KindNamePattern.MatchString(c.Name) || cols[c.Name]:
			return bad("column %q is not a name or is declared twice", c.Name)
		case !slices.Contains(ColumnTypeValues, c.Type):
			return bad("column %q has unknown type %q", c.Name, c.Type)
		case strings.ContainsAny(c.Default, ";\n"):
			return bad("column %q default %q", c.Name, c.Default)
		}
		cols[c.Name] = true
	}
	names := map[string]bool{}
	for _, i := range s.allIndexes() {
		if !KindNamePattern.MatchString(i.Name) || names[i.Name] || len(i.Columns) == 0 {
			return bad("index %q is not a name, is declared twice or has no column", i.Name)
		}
		names[i.Name] = true
		for _, c := range i.Columns {
			if !cols[c] {
				return bad("index %q names column %q, which the table does not have", i.Name, c)
			}
		}
	}
	return nil
}
