package auth

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/ubgo/sqlb"
)

// ColumnType is the portable type of a plugin column. The core maps it to each
// engine's spelling in the generated migration.
type ColumnType string

// Portable column types. Deliberately few: a plugin column is a flag, a
// timestamp, a short string or a number. Anything larger belongs in the
// plugin's own table.
const (
	ColumnText      ColumnType = "text"
	ColumnTimestamp ColumnType = "timestamp"
	ColumnBool      ColumnType = "bool"
	ColumnInt       ColumnType = "int"
)

// ColumnTypeValues is the canonical iteration order over column types.
var ColumnTypeValues = []ColumnType{ColumnText, ColumnTimestamp, ColumnBool, ColumnInt}

// ColumnExtension is a column a plugin adds to a core table.
//
// It exists so a flag such as "two-factor is on" costs no join: the column is
// a flat field of the user. The plugin owns it — only that plugin may write it,
// through SetUserColumn — and New refuses two plugins that add one column.
//
//ds:def id=core-columnextension-awxhnyvt owner=@khanakia stability=stable
type ColumnExtension struct {
	// Table is the core table to extend. Only auth_user is extendable: it is
	// the one row every request loads.
	Table string
	// Name must match KindNamePattern and should carry the plugin's name, as
	// "two_factor_enabled", so it cannot collide with another plugin's.
	Name     string
	Type     ColumnType
	Nullable bool
	// Default is a constant SQL literal such as "''" or "false", or empty for
	// none. A NOT NULL column needs one, so existing rows can be filled.
	Default string
	Unique  bool

	owner string
}

// ColumnExtender adds columns to core tables.
type ColumnExtender interface {
	Columns() []ColumnExtension
}

// AppName is the owner name of what the app itself registers: its columns
// (WithUserColumns, written through SetUserColumn with this name) and its
// hooks (HookSourceApp). No plugin may take it, so an app column and a plugin
// column can never share an owner.
//
//ds:def id=core-appname-3kq8vz2m owner=@khanakia stability=stable
const AppName = "app"

// WithUserColumns adds columns to auth_user that the app owns, with no plugin
// to write: a plan, a locale, a flag. Each column is declared, migrated and
// loaded exactly as a plugin's (ColumnExtension, LoadUser), and written
// through SetUserColumn with AppName as the owner, so the one rule "writes
// are closed" holds for the app's columns too. Table may be left empty and
// is auth_user. New refuses a column a plugin also adds.
//
//ds:def id=opt-withusercolumns-7mt4wq9k owner=@khanakia stability=stable
func WithUserColumns(cols ...ColumnExtension) Option {
	return func(s *settings) { s.userColumns = append(s.userColumns, cols...) }
}

// ErrNotColumnOwner is returned when a plugin writes a column it did not add.
var ErrNotColumnOwner = errors.New("auth: plugin writes a column it does not own")

func (a *Auth) collectColumns(appCols []ColumnExtension) error {
	owner := map[string]string{}
	for _, c := range CoreUserColumns {
		owner[c] = CorePluginName
	}
	for _, p := range a.plugins {
		ext, ok := p.(ColumnExtender)
		if !ok {
			continue
		}
		if err := a.addColumns(owner, p.Name(), ext.Columns()); err != nil {
			return err
		}
	}
	for i := range appCols {
		// The app's columns default to the one extendable table, so the
		// option reads as a list of columns and not of table names.
		if appCols[i].Table == "" {
			appCols[i].Table = TableNameUser
		}
	}
	return a.addColumns(owner, AppName, appCols)
}

// addColumns checks and registers one owner's columns: a plugin's, or the
// app's under AppName. The checks are the same for both, so an app column
// cannot do what a plugin column cannot.
func (a *Auth) addColumns(owner map[string]string, name string, cols []ColumnExtension) error {
	who := "plugin " + strconv.Quote(name)
	if name == AppName {
		who = "auth.WithUserColumns"
	}
	for _, c := range cols {
		switch {
		case c.Table != TableNameUser:
			return fmt.Errorf("%w: %s extends %q; only %s is extendable", ErrColumnConflict, who, c.Table, TableNameUser)
		case !KindNamePattern.MatchString(c.Name):
			return fmt.Errorf("%w: %s: column name %q must match %s", ErrColumnConflict, who, c.Name, KindNamePattern)
		case !slices.Contains(ColumnTypeValues, c.Type):
			return fmt.Errorf("%w: %s: column %q has unknown type %q", ErrColumnConflict, who, c.Name, c.Type)
		case !c.Nullable && c.Default == "":
			return fmt.Errorf("%w: %s: column %q is NOT NULL with no default, so existing rows cannot be filled", ErrColumnConflict, who, c.Name)
		}
		if prev, dup := owner[c.Name]; dup {
			return fmt.Errorf("%w: column %q.%q is added by %q and by %s", ErrColumnConflict, c.Table, c.Name, prev, who)
		}
		owner[c.Name] = name
		c.owner = name
		a.columns = append(a.columns, c)
	}
	return nil
}

// SetUserColumn writes a column that plugin added to auth_user, for userID.
//
// It refuses a column the plugin did not add. That check is the enforcement
// point for "writes are closed": a plugin also holds the transaction and could
// run any SQL, so this is the one sanctioned path, and a source test keeps
// plugins in this module on it.
//
//ds:def id=core-setusercolumn-27hrnywb owner=@khanakia stability=stable
func SetUserColumn[T any](ctx context.Context, a *Auth, plugin, userID string, col sqlb.Expr[T], v T) error {
	if col.Table().Name != TableNameUser || !a.ownsColumn(plugin, col.Name()) {
		return fmt.Errorf("%w: %q writes %q", ErrNotColumnOwner, plugin, col.Name())
	}
	q := sqlb.NewUpdate(a.cfg.Dialect).Table(TableUser).
		Set(sqlb.Set(col, v), sqlb.Set(UserUpdatedAt, a.now())).Where(sqlb.Eq(UserID, userID))
	_, err := a.Exec(ctx, q)
	return err
}

func (a *Auth) ownsColumn(plugin, name string) bool {
	for _, c := range a.columns {
		if c.owner == plugin && c.Name == name {
			return true
		}
	}
	return false
}

// Scannable is a destination that knows its own bindings: the app's composite
// user, which embeds auth.User and each plugin's column struct.
//
//ds:def id=core-scannable-ub3d9d7d owner=@khanakia stability=stable
type Scannable interface {
	Bindings() []sqlb.Binding
}

// Joiner is a Scannable that also needs joined tables, for plugin data that
// lives in a table of its own. Optional.
//
//ds:def id=core-joiner-27twn9va owner=@khanakia stability=stable
type Joiner interface {
	Joins() []sqlb.Join
}

// LoadUser fills dst with the user id in one statement: every binding dst
// declares, and every join it asks for.
//
//ds:def id=core-loaduser-j69m8w4a owner=@khanakia stability=stable
func (a *Auth) LoadUser(ctx context.Context, id string, dst Scannable) error {
	var joins []sqlb.Join
	if j, ok := dst.(Joiner); ok {
		joins = j.Joins()
	}
	return a.loadUser(ctx, id, dst.Bindings(), joins...)
}

// LoadUserColumns reads chosen columns of one user, for a plugin that needs
// only its own columns.
func (a *Auth) LoadUserColumns(ctx context.Context, id string, bs ...sqlb.Binding) error {
	return a.loadUser(ctx, id, bs)
}

// loadUser is the one read of a user row behind User, LoadUser and
// LoadUserColumns: bs scanned from auth_user joined with joins, and "no row"
// reported as ErrUserNotFound.
func (a *Auth) loadUser(ctx context.Context, id string, bs []sqlb.Binding, joins ...sqlb.Join) error {
	q := a.Select().Columns(bs...).From(TableUser)
	if len(joins) > 0 {
		q = q.Join(joins...)
	}
	err := a.One(ctx, q.Where(sqlb.Eq(UserID, id)).Limit(1))
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrUserNotFound
	}
	return err
}
