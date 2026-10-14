package auth

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ubgo/sqlb"
	"github.com/ubgo/sqlb/render"
)

// tablePlugin is a plugin that owns one table and signs users in, so a New
// with only it is valid.
type tablePlugin struct {
	name  string
	table sqlb.Table
}

func (p tablePlugin) Name() string         { return p.name }
func (p tablePlugin) SignsIn() bool        { return true }
func (p tablePlugin) Tables() []sqlb.Table { return []sqlb.Table{p.table} }

// newTables wires the plugin with the given options and a dialect only.
func newTables(t *testing.T, opts ...Option) (*Auth, error) {
	t.Helper()
	p := tablePlugin{name: "widgets", table: sqlb.Table{Name: "auth_widget", Alias: "w"}}
	return New(append([]Option{WithDialect(sqlb.PostgresDialect{}), WithPlugins(p)}, opts...)...)
}

// TestTableNames_DefaultIsTheLabel: without RenameTable or WithTablePrefix
// every table's real name is its label and the dialect is the one given.
func TestTableNames_DefaultIsTheLabel(t *testing.T) {
	a, err := newTables(t)
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range append(coreTableList, sqlb.Table{Name: "auth_widget"}, sqlb.Table{Name: "app_orders"}) {
		if got := a.TableName(tb); got != tb.Name {
			t.Errorf("TableName(%s) = %q", tb.Name, got)
		}
	}
	if _, wrapped := a.Dialect().(renamingDialect); wrapped || a.tablesRenamed {
		t.Fatal("no renaming must leave the dialect as given")
	}
}

// TestTableNames_PrefixAndRenameResolve: the prefix applies to every declared
// table, a RenameTable name is used as given, undeclared tables pass through,
// and every rendered statement, the DDL and the foreign key use the real
// names.
func TestTableNames_PrefixAndRenameResolve(t *testing.T) {
	a, err := newTables(t, WithTablePrefix("t_"), RenameTable(TableUser, "members"), RenameTable(TableMigrations, "schema_log"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		TableNameUser: "members", TableNameMigrations: "schema_log", TableNameIdentity: "t_auth_identity",
		TableNameSession: "t_auth_session", TableNameCode: "t_auth_code", TableNameRateLimit: "t_auth_rate_limit",
		"auth_widget": "t_auth_widget", "app_orders": "app_orders",
	}
	for label, real := range want {
		if got := a.TableName(sqlb.Table{Name: label}); got != real {
			t.Errorf("TableName(%s) = %q, want %q", label, got, real)
		}
	}
	if !a.tablesRenamed {
		t.Fatal("tablesRenamed must be set")
	}
	var u User
	q, err := a.Select().Columns(UserBindings(&u)...).From(TableUser).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: TableSession, On: []sqlb.Predicate{sqlb.EqExpr(SessionUserID, UserID)}}).
		Where(sqlb.Eq(SessionID, "ses_1")).Build()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`FROM "members" AS "u"`, `JOIN "t_auth_session" AS "s"`, `"u"."id"`, `"s"."user_id"`} {
		if !strings.Contains(q.SQL, s) {
			t.Errorf("SQL lacks %s:\n%s", s, q.SQL)
		}
	}
	if strings.Contains(q.SQL, "auth_user") || strings.Contains(q.SQL, `"auth_session"`) {
		t.Fatalf("a label leaked into the SQL:\n%s", q.SQL)
	}
	ins, err := sqlb.NewInsert(a.Dialect()).Into(TableUser).Row(sqlb.Set(UserID, "usr_1")).Build()
	if err != nil || !strings.Contains(ins.SQL, `INTO "members"`) {
		t.Fatalf("insert = %q %v", ins.SQL, err)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, m := range ms {
		all += strings.Join(m.Statements, "\n") + "\n"
	}
	for _, s := range []string{
		"CREATE TABLE IF NOT EXISTS members (", "CREATE TABLE IF NOT EXISTS t_auth_identity (",
		"CREATE INDEX IF NOT EXISTS t_auth_identity_user_idx ON t_auth_identity",
		"CREATE INDEX IF NOT EXISTS t_auth_code_subject_idx ON t_auth_code", "ALTER TABLE members ADD COLUMN sessions_valid_after",
	} {
		if !strings.Contains(all, s) {
			t.Errorf("migrations lack %q:\n%s", s, all)
		}
	}
	if strings.Contains(all, " auth_user") || strings.Contains(all, " auth_identity") || strings.Contains(all, " auth_code") {
		t.Fatalf("a label leaked into the DDL:\n%s", all)
	}
	if ledger := ledgerDDL(TypesFor(EnginePostgres), a.TableName(TableMigrations)); !strings.HasPrefix(ledger, "CREATE TABLE IF NOT EXISTS schema_log (") {
		t.Fatalf("ledger DDL = %q", ledger)
	}
	if ratel := a.rateLimitMigration(EnginePostgres).Statements[0]; !strings.HasPrefix(ratel, "CREATE TABLE IF NOT EXISTS t_auth_rate_limit (") {
		t.Fatalf("rate limit DDL = %q", ratel)
	}
}

// TestTableNames_IdentityAndColumnIndexesFollowTheTable: the generated index
// names carry the real table name, so two prefixed instances in one Postgres
// schema, where index names are global, do not collide; the migration names
// (ledger keys) keep the label.
func TestTableNames_IdentityAndColumnIndexesFollowTheTable(t *testing.T) {
	kindPlugin := kindsPlugin{name: "mail", kinds: []IdentifierKind{{Name: "mail", Unique: true, UniqueOnlyVerified: true, CanLogin: true, Normalize: func(s string) (string, error) { return s, nil }}}}
	a, err := New(WithDialect(sqlb.MySQLDialect{}), WithPlugins(kindPlugin, tablePlugin{name: "w", table: sqlb.Table{Name: "auth_w", Alias: "w"}}),
		WithTablePrefix("t_"), WithUserColumns(ColumnExtension{Name: "app_code", Type: ColumnText, Nullable: true, Unique: true}))
	if err != nil {
		t.Fatal(err)
	}
	ms, err := a.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	var idx, col Migration
	for _, m := range ms {
		switch {
		case strings.HasPrefix(m.Name, "0000_identity_unique_"):
			idx = m
		case strings.HasPrefix(m.Name, "0000_column_"):
			col = m
		}
	}
	if idx.Name != "0000_identity_unique_mail_verified" || !strings.Contains(idx.Statements[1], "CREATE UNIQUE INDEX t_auth_identity_mail_verified_uniq ON t_auth_identity (") {
		t.Fatalf("identity index = %+v", idx)
	}
	if col.Name != "0000_column_auth_user_app_code" || col.Statements[0] != "ALTER TABLE t_auth_user ADD COLUMN app_code VARCHAR(320) NULL" ||
		col.Statements[1] != "CREATE UNIQUE INDEX t_auth_user_app_code_key ON t_auth_user (app_code)" {
		t.Fatalf("column migration = %+v", col)
	}
}

// kindsPlugin registers identifier kinds and signs in.
type kindsPlugin struct {
	name  string
	kinds []IdentifierKind
}

func (p kindsPlugin) Name() string                  { return p.name }
func (p kindsPlugin) SignsIn() bool                 { return true }
func (p kindsPlugin) Identifiers() []IdentifierKind { return p.kinds }

// TestTableNames_Refusals: every misconfiguration New must refuse, with the
// sentinel the app can match.
func TestTableNames_Refusals(t *testing.T) {
	long := strings.Repeat("x", maxIdentifierLength+1)
	for _, tc := range []struct {
		name string
		opts []Option
		err  error
		text string
	}{
		{"a hand-built table", []Option{RenameTable(sqlb.Table{Name: "x"}, "y")}, ErrUnknownTable, `"x"`},
		{"a plugin table whose plugin is absent", []Option{RenameTable(sqlb.Table{Name: "auth_api_key"}, "keys")}, ErrUnknownTable, "WithPlugins"},
		{"a table renamed twice", []Option{RenameTable(TableUser, "a"), RenameTable(TableUser, "b")}, ErrTableNameConflict, "renamed twice"},
		{"two tables with one real name", []Option{RenameTable(TableUser, "same"), RenameTable(TableSession, "same")}, ErrTableNameConflict, `"auth_session" and "auth_user" are both "same"`},
		{"a real name that is another table's", []Option{RenameTable(TableUser, TableNameSession)}, ErrTableNameConflict, `"auth_session"`},
		{"a prefix colliding with a rename", []Option{WithTablePrefix("t_"), RenameTable(TableUser, "t_auth_session")}, ErrTableNameConflict, `"t_auth_session"`},
		{"a name with a dash", []Option{RenameTable(TableUser, "my-users")}, ErrBadTableName, `"my-users"`},
		{"a name starting with a digit", []Option{RenameTable(TableUser, "1users")}, ErrBadTableName, `"1users"`},
		{"an empty name", []Option{RenameTable(TableUser, "")}, ErrBadTableName, `""`},
		{"a name with a quote", []Option{RenameTable(TableUser, `u"sers`)}, ErrBadTableName, "sers"},
		{"a prefix with a dot", []Option{WithTablePrefix("app.")}, ErrBadTableName, `"app."`},
		{"a name over the limit", []Option{RenameTable(TableUser, long)}, ErrBadTableName, "more than 63"},
		{"a prefix that makes an index name too long", []Option{WithTablePrefix(strings.Repeat("p", 40) + "_")}, ErrBadTableName, "index name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTables(t, tc.opts...)
			if !errors.Is(err, tc.err) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("err = %v, want %v containing %q", err, tc.err, tc.text)
			}
		})
	}
}

// TestTableNames_ColumnNamedLikeATableIsRefusedUnderRenaming: QuoteIdent
// cannot tell a column from a table, so a column named like a table label
// would be renamed with it; under renaming New refuses it, and without
// renaming the same column is fine.
func TestTableNames_ColumnNamedLikeATableIsRefusedUnderRenaming(t *testing.T) {
	col := ColumnExtension{Name: TableNameSession, Type: ColumnText, Nullable: true}
	if _, err := newTables(t, WithUserColumns(col)); err != nil {
		t.Fatalf("without renaming: %v", err)
	}
	_, err := newTables(t, WithTablePrefix("t_"), WithUserColumns(col))
	if !errors.Is(err, ErrTableNameConflict) || !strings.Contains(err.Error(), "t_auth_user.auth_session is named like a table") {
		t.Fatalf("under renaming: %v", err)
	}
	// An alias named like a table label is refused the same way.
	p := tablePlugin{name: "widgets", table: sqlb.Table{Name: "auth_widget", Alias: TableNameCode}}
	_, err = New(WithDialect(sqlb.PostgresDialect{}), WithPlugins(p), WithTablePrefix("t_"))
	if !errors.Is(err, ErrTableNameConflict) || !strings.Contains(err.Error(), `alias "auth_code"`) {
		t.Fatalf("alias: %v", err)
	}
	// Renaming on an engine the migrations do not support cannot be checked
	// and is refused as such; without renaming the same engine is accepted.
	if _, err := newTables(t, WithDialect(sqlb.ClickHouseDialect{})); err != nil {
		t.Fatalf("clickhouse without renaming: %v", err)
	}
	if _, err := newTables(t, WithDialect(sqlb.ClickHouseDialect{}), WithTablePrefix("t_")); !errors.Is(err, ErrEngineNotSupported) {
		t.Fatalf("clickhouse with renaming: %v", err)
	}
}

// TestRenamingDialect_KeepsEveryCapability: the wrapper has every method of
// every sqlb dialect, so a capability sqlb adds and the wrapper does not
// forward fails here rather than silently changing how a statement renders;
// and each forwarded answer equals the inner dialect's.
func TestRenamingDialect_KeepsEveryCapability(t *testing.T) {
	wrapper := reflect.TypeOf(renamingDialect{})
	for _, d := range []sqlb.Dialect{sqlb.PostgresDialect{}, sqlb.MySQLDialect{}, sqlb.SQLiteDialect{}} {
		inner := reflect.TypeOf(d)
		for i := 0; i < inner.NumMethod(); i++ {
			m := inner.Method(i)
			wm, ok := wrapper.MethodByName(m.Name)
			if !ok {
				t.Errorf("%s: renamingDialect lacks %s", inner, m.Name)
				continue
			}
			if wm.Type.NumIn() != m.Type.NumIn() || wm.Type.NumOut() != m.Type.NumOut() {
				t.Errorf("%s.%s: signature differs", inner, m.Name)
			}
		}
		w := renamingDialect{inner: d, names: map[string]string{"auth_user": "members"}}
		if sqlb.DialectName(w) != sqlb.DialectName(d) {
			t.Errorf("%s: Name = %q", inner, sqlb.DialectName(w))
		}
		if w.Placeholder(2) != d.Placeholder(2) {
			t.Errorf("%s: Placeholder differs", inner)
		}
		if w.QuoteIdent("auth_user") != d.QuoteIdent("members") || w.QuoteIdent("name") != d.QuoteIdent("name") {
			t.Errorf("%s: QuoteIdent maps only labels: %q %q", inner, w.QuoteIdent("auth_user"), w.QuoteIdent("name"))
		}
		for name, got := range map[string]bool{
			"SupportsReturning": w.SupportsReturning(), "SupportsLikeEscape": w.SupportsLikeEscape(), "SupportsILike": w.SupportsILike(),
			"SupportsCombinedAlter": w.SupportsCombinedAlter(), "SupportsUnrestrictedAddColumn": w.SupportsUnrestrictedAddColumn(), "SupportsInsertAlias": w.SupportsInsertAlias(),
		} {
			want := false
			if m, ok := inner.MethodByName(name); ok {
				want = m.Func.Call([]reflect.Value{reflect.ValueOf(d)})[0].Bool()
			}
			if got != want {
				t.Errorf("%s.%s = %v, want %v", inner, name, got, want)
			}
		}
		lit, err := w.QuoteLiteral("it's")
		want, werr := d.(render.LiteralQuoting).QuoteLiteral("it's")
		if lit != want || !errors.Is(err, werr) {
			t.Errorf("%s: QuoteLiteral = %q %v, want %q %v", inner, lit, err, want, werr)
		}
		wantText, wantNum := "$1", "$1"
		if u, ok := d.(render.UntypedParameters); ok {
			wantText = u.TextParam("$1")
		}
		if n, ok := d.(render.NumericParameters); ok {
			wantNum = n.NumericParam("$1", 3)
		}
		if w.TextParam("$1") != wantText || w.NumericParam("$1", 3) != wantNum {
			t.Errorf("%s: TextParam %q NumericParam %q", inner, w.TextParam("$1"), w.NumericParam("$1", 3))
		}
	}
	// A dialect with none of the capabilities gets the declining answers.
	bare := renamingDialect{inner: bareDialect{}, names: map[string]string{}}
	if sqlb.DialectName(bare) != sqlb.DialectUnknown || bare.SupportsReturning() || bare.TextParam("?") != "?" || bare.NumericParam("?", 1) != "?" {
		t.Fatal("a bare dialect must decline every capability")
	}
	if _, err := bare.QuoteLiteral(1); !errors.Is(err, render.ErrNoLiteralQuoting) {
		t.Fatalf("QuoteLiteral on a bare dialect: %v", err)
	}
}

// bareDialect has only the two required methods.
type bareDialect struct{}

func (bareDialect) Placeholder(int) string         { return "?" }
func (bareDialect) QuoteIdent(ident string) string { return ident }

// TestOptions_RunsEachInOrder: a grouped option applies its members in order,
// so a later one overrides an earlier one as it would when listed flat.
func TestOptions_RunsEachInOrder(t *testing.T) {
	a, err := newTables(t, Options(WithTablePrefix("a_"), WithTablePrefix("b_"), WithBaseURL("https://x.example")))
	if err != nil {
		t.Fatal(err)
	}
	if a.TableName(TableUser) != "b_auth_user" || a.Config().BaseURL != "https://x.example" {
		t.Fatalf("TableName = %q BaseURL = %q", a.TableName(TableUser), a.Config().BaseURL)
	}
}

// TestSweepKey_IsOwnerDotLabel pins the SweepResult key shape, which stays
// the label under renaming.
func TestSweepKey_IsOwnerDotLabel(t *testing.T) {
	if got := sweepKey(CorePluginName, TableNameSession); got != "core.auth_session" {
		t.Fatalf("sweepKey = %q", got)
	}
}

// TestTableNames_DerivedIndexLengthsAreChecked: a real name that fits by
// itself can still push an identity uniqueness index or a column's unique
// index past the engines' limit; both are refused at New, naming the index.
func TestTableNames_DerivedIndexLengthsAreChecked(t *testing.T) {
	longKind := kindsPlugin{name: "k", kinds: []IdentifierKind{{Name: IdentifierKindName(strings.Repeat("k", maxKindNameLength)), Unique: true, UniqueOnlyVerified: true, ScopedByTenant: true, CanLogin: true, Normalize: func(s string) (string, error) { return s, nil }}}}
	_, err := New(WithDialect(sqlb.PostgresDialect{}), WithPlugins(longKind), WithTablePrefix("p_"))
	if !errors.Is(err, ErrBadTableName) || !strings.Contains(err.Error(), "index name") || !strings.Contains(err.Error(), "_uniq") {
		t.Fatalf("identity index over the limit: %v", err)
	}
	col := ColumnExtension{Name: strings.Repeat("c", 31), Type: ColumnText, Nullable: true, Unique: true}
	_, err = newTables(t, WithTablePrefix(strings.Repeat("a", 18)+"_"), WithUserColumns(col))
	if !errors.Is(err, ErrBadTableName) || !strings.Contains(err.Error(), "_key") {
		t.Fatalf("column index over the limit: %v", err)
	}
	if _, err := newTables(t, WithUserColumns(col)); err != nil {
		t.Fatalf("the same column without the prefix fits: %v", err)
	}
}

// userTablePlugin declares tables and user tables independently, so each
// refusal of collectUserTables can be produced.
type userTablePlugin struct {
	tablePlugin
	user []UserTable
}

func (p userTablePlugin) UserTables() []UserTable { return p.user }

// TestUserTables_Refusals: a user table must be one the plugin declares,
// with an identifier column, listed once; UserTables lists the plugins' then
// the core's.
func TestUserTables_Refusals(t *testing.T) {
	base := tablePlugin{name: "widgets", table: sqlb.Table{Name: "auth_widget", Alias: "w"}}
	for _, tc := range []struct {
		name string
		user []UserTable
		text string
	}{
		{"an undeclared table", []UserTable{{Table: sqlb.Table{Name: "auth_other"}, Column: "user_id"}}, `lists "auth_other", which it does not declare`},
		{"a column that is not an identifier", []UserTable{{Table: base.table, Column: "user id"}}, `column "user id"`},
		{"a pair listed twice", []UserTable{{Table: base.table, Column: "user_id"}, {Table: base.table, Column: "user_id"}}, "listed by"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(WithDialect(sqlb.PostgresDialect{}), WithPlugins(userTablePlugin{base, tc.user}))
			if !errors.Is(err, ErrBadUserTable) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("err = %v, want ErrBadUserTable containing %q", err, tc.text)
			}
		})
	}
	a, err := New(WithDialect(sqlb.PostgresDialect{}), WithPlugins(userTablePlugin{base, []UserTable{{Table: base.table, Column: "owner_id"}}}))
	if err != nil {
		t.Fatal(err)
	}
	got := a.UserTables()
	if len(got) != 3 || got[0].Table.Name != "auth_widget" || got[0].Column != "owner_id" || got[1].Table.Name != TableNameIdentity || got[2].Table.Name != TableNameSession {
		t.Fatalf("UserTables = %+v", got)
	}
}
