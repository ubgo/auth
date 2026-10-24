package auth

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"

	"github.com/ubgo/sqlb"
	"github.com/ubgo/sqlb/render"
)

// Table names: labels and real names.
//
// Every table the core or a plugin declares has a label, the Name in its
// package-level sqlb.Table value (TableUser.Name is "auth_user"). The label is
// what the Go code is written against and never changes. The real name is what
// the database sees, and an app may choose it per Auth with RenameTable and
// WithTablePrefix: two apps sharing one database, or a schema whose naming
// rules forbid the auth_ prefix, keep the same Go code.
//
// The mapping is applied in exactly two places. Every statement built with
// sqlb renders through the Auth's dialect, and that dialect is wrapped so that
// quoting a table label writes its real name (renamingDialect). Everything
// else that names a table, which is only DDL and the catalogue queries, calls
// TableName. A plugin therefore never concatenates a TableName constant into
// SQL: it names tables through the Auth, and the guard test on the plugin
// sources (TestGuard_TableNamesNeverConcatenated) refuses the shortcut.
//
// Columns are not renamed. The dialect is not told which table a column
// belongs to, so a column named exactly like a table label would be renamed
// with it; New refuses that configuration (checkTableLabelCollisions).

// Table-name errors, returned by New.
var (
	// ErrUnknownTable is returned for a RenameTable whose table neither the
	// core nor a registered plugin declares: a hand-built sqlb.Table, or a
	// plugin's table whose plugin is not in WithPlugins. A rename nothing
	// uses would otherwise sit in the configuration looking applied.
	ErrUnknownTable = errors.New("auth: RenameTable names a table that no registered plugin or the core declares")
	// ErrTableNameConflict is returned when two tables would share one real
	// name, or one table is renamed twice. The symptom otherwise is one
	// CREATE TABLE succeeding and the next failing on a name that exists.
	ErrTableNameConflict = errors.New("auth: two tables would share one real name")
	// ErrBadTableName is returned for a real name or a prefix that is not a
	// plain SQL identifier, or that makes an identifier the engines cannot
	// hold (see maxIdentifierLength).
	ErrBadTableName = errors.New("auth: table name is not a valid SQL identifier")
)

// tableIdentPattern is what a real table name or a prefix may be: letters,
// digits and underscores, not starting with a digit. Every engine accepts it
// unquoted and quoted alike, so a name never depends on the quoting rule.
var tableIdentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// tableRename is one RenameTable call, kept in order so a table renamed twice
// is reported as a conflict instead of silently taking the last value.
type tableRename struct {
	table sqlb.Table
	real  string
}

// RenameTable gives one table a real name of the app's choosing. t must be a
// declared table value — auth.TableUser, auth.TableIdentity, apikey.TableKey,
// any plugin's exported Table… — never a hand-built sqlb.Table: New refuses a
// table that the core or a registered plugin does not declare, so a rename
// cannot miss its target. The name is used exactly as given; WithTablePrefix
// does not apply to it. Decide before the first deploy: renaming a table that
// exists is an ALTER TABLE the app runs itself, since the migration ledger
// records what was created and not what it was called.
//
//ds:def id=opt-renametable-7r3tqk2d owner=@khanakia stability=stable
func RenameTable(t sqlb.Table, realName string) Option {
	return func(s *settings) { s.tableRenames = append(s.tableRenames, tableRename{table: t, real: realName}) }
}

// WithTablePrefix prepends prefix to the real name of every table, the core's
// and every plugin's, except a table RenameTable names explicitly. It is the
// one-line way to keep two apps, or two instances of one app, in one database
// or schema: WithTablePrefix("billing_") puts the users in billing_auth_user.
// The prefix must be a plain identifier start (letters, digits, underscores);
// it is written verbatim, so end it with an underscore if you want one.
//
//ds:def id=opt-withtableprefix-4mv8xq7c owner=@khanakia stability=stable
func WithTablePrefix(prefix string) Option {
	return func(s *settings) { s.tablePrefix = prefix }
}

// coreTableList are the tables the core creates, so every one of them can be
// renamed and none can be claimed by a plugin.
var coreTableList = []sqlb.Table{TableUser, TableIdentity, TableSession, TableVerification, TableCode, TableRateLimit, TableDeliveryOutbox, TableMigrations}

// TableName returns the real name of a declared table under this Auth's
// configuration: the label itself by default, the prefixed or renamed one
// under WithTablePrefix or RenameTable. It is for the SQL the app and a plugin
// write by hand, DDL above all; a statement built with sqlb through
// a.Select, a.Exec, a.One or a.Each already renders the real name.
//
// A table nothing declared is returned unchanged, because the app's own tables
// pass through here too when it builds a join by hand.
//
//ds:def id=core-tablename-9nq2wv5h owner=@khanakia stability=stable
func (a *Auth) TableName(t sqlb.Table) string { return a.realTableName(t.Name) }

// realTableName is TableName by label, for the core's own generators, which
// hold labels as strings (ColumnExtension.Table, the catalogue queries).
func (a *Auth) realTableName(label string) string {
	if real, ok := a.tableNames[label]; ok {
		return real
	}
	return label
}

// resolveTableNames builds the label-to-real-name map from the prefix and the
// renames and checks it: every renamed table is declared, every real name is
// an identifier the engines keep intact, no two tables share one. It runs
// after the plugins are known and before any of them is initialised, because
// Init may already build statements through a.Dialect().
//
// The dialect is wrapped only when some name differs from its label, so a
// configuration without renaming renders through the dialect it was given,
// byte for byte as before this feature existed.
func (a *Auth) resolveTableNames(prefix string, renames []tableRename) error {
	if prefix != "" && !tableIdentPattern.MatchString(prefix) {
		return fmt.Errorf("%w: prefix %q", ErrBadTableName, prefix)
	}
	declared := map[string]string{}
	for _, t := range coreTableList {
		declared[t.Name] = CorePluginName
	}
	for _, p := range a.plugins {
		to, ok := p.(TableOwner)
		if !ok {
			continue
		}
		for _, t := range to.Tables() {
			if _, core := declared[t.Name]; !core {
				declared[t.Name] = p.Name()
			}
		}
	}
	names := make(map[string]string, len(declared))
	for label := range declared {
		names[label] = prefix + label
	}
	renamed := map[string]bool{}
	for _, r := range renames {
		label := r.table.Name
		if _, ok := declared[label]; !ok {
			return fmt.Errorf("%w: %q; a plugin's table needs its plugin in WithPlugins", ErrUnknownTable, label)
		}
		if renamed[label] {
			return fmt.Errorf("%w: %q is renamed twice", ErrTableNameConflict, label)
		}
		if !tableIdentPattern.MatchString(r.real) {
			return fmt.Errorf("%w: %q for table %q", ErrBadTableName, r.real, label)
		}
		renamed[label] = true
		names[label] = r.real
	}
	byReal := map[string]string{}
	// Labels in order, so the pair named in the error is always the same
	// (the first label first), not whichever the map happened to yield.
	labels := make([]string, 0, len(names))
	for label := range names {
		labels = append(labels, label)
	}
	slices.Sort(labels)
	for _, label := range labels {
		real := names[label]
		if first, dup := byReal[real]; dup {
			return fmt.Errorf("%w: %q and %q are both %q", ErrTableNameConflict, first, label, real)
		}
		byReal[real] = label
	}
	a.tableNames = names
	a.tablePrefix = prefix
	for label, real := range names {
		if label != real {
			a.tablesRenamed = true
			break
		}
	}
	if err := a.checkDerivedIdentifiers(); err != nil {
		return err
	}
	if a.tablesRenamed {
		a.cfg.Dialect = renamingDialect{inner: a.cfg.Dialect, names: names}
	}
	return nil
}

// checkDerivedIdentifiers refuses a real name that makes an identifier the
// migrations derive from it longer than every engine keeps intact: the table
// name itself, each core index, each identity uniqueness index and each
// column extension's unique index. Postgres would truncate such a name without
// an error, so two long names could become one index and the second CREATE
// would create nothing (see maxKindNameLength).
func (a *Auth) checkDerivedIdentifiers() error {
	check := func(ident, what string) error {
		if len(ident) > maxIdentifierLength {
			return fmt.Errorf("%w: %s %q is %d bytes, more than %d", ErrBadTableName, what, ident, len(ident), maxIdentifierLength)
		}
		return nil
	}
	for label, real := range a.tableNames {
		if err := check(real, "table name for "+strconv.Quote(label)); err != nil {
			return err
		}
	}
	for _, name := range a.coreIndexNames() {
		if err := check(name, "index name"); err != nil {
			return err
		}
	}
	for _, k := range a.cfg.Identifiers {
		if k.Unique {
			if err := check(a.identityIndexName(k), "index name"); err != nil {
				return err
			}
		}
	}
	for _, c := range a.columns {
		if c.Unique {
			if err := check(a.columnKeyIndexName(c), "index name"); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkTableLabelCollisions refuses, under renaming, a column or an alias
// named exactly like a table label. QuoteIdent cannot tell a column from a
// table, so such a column would be renamed with the table. It reads the
// columns from the migrations, as CheckSchema does, so a plugin's own table
// is covered with no declaration beyond its migration. Without renaming the
// map is the identity and nothing can collide, so the check is skipped: it
// would otherwise refuse a dialect the migrations do not support.
func (a *Auth) checkTableLabelCollisions() error {
	if !a.tablesRenamed {
		return nil
	}
	ms, err := a.Migrations()
	if err != nil {
		return err
	}
	for table, cols := range expectedSchema(ms) {
		for _, c := range cols {
			if _, isLabel := a.tableNames[c]; isLabel {
				return fmt.Errorf("%w: column %s.%s is named like a table, so renaming would rename it too", ErrTableNameConflict, table, c)
			}
		}
	}
	for _, t := range a.declaredTables() {
		if _, isLabel := a.tableNames[t.Alias]; isLabel {
			return fmt.Errorf("%w: alias %q of table %q is named like a table", ErrTableNameConflict, t.Alias, t.Name)
		}
	}
	return nil
}

// declaredTables lists every table the core and the registered plugins
// declare, core first, in plugin order.
func (a *Auth) declaredTables() []sqlb.Table {
	out := append([]sqlb.Table(nil), coreTableList...)
	for _, p := range a.plugins {
		if to, ok := p.(TableOwner); ok {
			out = append(out, to.Tables()...)
		}
	}
	return out
}

// renamingDialect is the Auth's dialect under RenameTable or WithTablePrefix:
// the given dialect with QuoteIdent mapping a table label to its real name.
// Every statement sqlb renders writes a table name through QuoteIdent
// (Table.Qualified, Table.Qualifier, the FROM, JOIN, INSERT, UPDATE and
// DELETE targets, and the by-table-name qualification mode), so this one
// method covers every query.
//
// The optional capabilities sqlb asks a dialect for are forwarded one by one,
// each answering what a dialect without the capability answers when the
// inner one lacks it, so wrapping changes no rendering decision. A test
// compares the method set with each sqlb dialect's, so a capability sqlb adds
// cannot be lost by the wrapper unnoticed.
type renamingDialect struct {
	inner sqlb.Dialect
	names map[string]string
}

func (d renamingDialect) Placeholder(n int) string { return d.inner.Placeholder(n) }

// QuoteIdent writes ident quoted for the inner dialect, as its real name when
// ident is a table label.
func (d renamingDialect) QuoteIdent(ident string) string {
	if real, ok := d.names[ident]; ok {
		ident = real
	}
	return d.inner.QuoteIdent(ident)
}

// Name reports the inner engine, so Engine, sqlb's engine packages and the
// migration generators see the engine they were given.
func (d renamingDialect) Name() string { return sqlb.DialectName(d.inner) }

func (d renamingDialect) SupportsReturning() bool {
	r, ok := d.inner.(render.Returning)
	return ok && r.SupportsReturning()
}

func (d renamingDialect) SupportsLikeEscape() bool {
	r, ok := d.inner.(render.LikeEscaping)
	return ok && r.SupportsLikeEscape()
}

func (d renamingDialect) SupportsILike() bool {
	r, ok := d.inner.(render.CaseInsensitiveLike)
	return ok && r.SupportsILike()
}

func (d renamingDialect) SupportsCombinedAlter() bool {
	r, ok := d.inner.(render.CombinedAlter)
	return ok && r.SupportsCombinedAlter()
}

func (d renamingDialect) SupportsUnrestrictedAddColumn() bool {
	r, ok := d.inner.(render.UnrestrictedAddColumn)
	return ok && r.SupportsUnrestrictedAddColumn()
}

func (d renamingDialect) SupportsInsertAlias() bool {
	r, ok := d.inner.(render.InsertAliasing)
	return ok && r.SupportsInsertAlias()
}

// QuoteLiteral forwards to the inner dialect; the value is `any` because that
// is sqlb's render.LiteralQuoting signature. A dialect without the capability
// answers render.ErrNoLiteralQuoting, which is what sqlb reports for one.
func (d renamingDialect) QuoteLiteral(v any) (string, error) {
	q, ok := d.inner.(render.LiteralQuoting)
	if !ok {
		return "", render.ErrNoLiteralQuoting
	}
	return q.QuoteLiteral(v)
}

// TextParam forwards to the inner dialect; without the capability the
// placeholder is written bare, which is what sqlb does for such a dialect.
func (d renamingDialect) TextParam(placeholder string) string {
	if u, ok := d.inner.(render.UntypedParameters); ok {
		return u.TextParam(placeholder)
	}
	return placeholder
}

// NumericParam forwards to the inner dialect; the value is `any` because that
// is sqlb's render.NumericParameters signature. Without the capability the
// placeholder is written bare, as sqlb does for such a dialect.
func (d renamingDialect) NumericParam(placeholder string, v any) string {
	if n, ok := d.inner.(render.NumericParameters); ok {
		return n.NumericParam(placeholder, v)
	}
	return placeholder
}
