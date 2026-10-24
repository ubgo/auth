package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/sqlb"
)

// These tests are internal (package auth) because they pin behaviour that has
// no public seam on SQLite: the Postgres and MySQL branches of Migrate, Orphans
// and the database rate store, and the fail-closed guards of the pipeline. The
// integration suite runs the same code against real engines under
// "task test:engines"; this keeps it inside the default gate, with no server.

// scriptAnswer is how the script database answers a query whose text contains
// match: with cols and rows, or with err. nextErr fails the iteration after the
// rows, the way a connection dropped mid-result does.
type scriptAnswer struct {
	match   string
	cols    []string
	rows    [][]driver.Value
	err     error
	nextErr error
}

// script is a database that records every statement and answers queries from
// a list, so the engine-specific SQL the core writes can be read back and its
// failure branches driven. failOn fails any Exec whose text contains it.
type script struct {
	mu      sync.Mutex
	log     []string
	answers []scriptAnswer
	failOn  string
}

// errScript is the failure the script injects.
var errScript = errors.New("script: injected failure")

// scriptBegin and scriptCommit mark transaction boundaries in the log.
const (
	scriptBegin  = "BEGIN"
	scriptCommit = "COMMIT"
)

func (s *script) record(q string) {
	s.mu.Lock()
	s.log = append(s.log, q)
	s.mu.Unlock()
}

func (s *script) statements() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}

func (s *script) Connect(context.Context) (driver.Conn, error) { return &scriptConn{s: s}, nil }
func (s *script) Driver() driver.Driver                        { return scriptDriver{} }

// scriptDriver exists only because driver.Connector must name one.
type scriptDriver struct{}

func (scriptDriver) Open(string) (driver.Conn, error) { return nil, errScript }

type scriptConn struct{ s *script }

func (c *scriptConn) Prepare(string) (driver.Stmt, error) { return nil, errScript }
func (c *scriptConn) Close() error                        { return nil }
func (c *scriptConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *scriptConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.s.record(scriptBegin)
	return scriptTx{s: c.s}, nil
}

func (c *scriptConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	c.s.record(q)
	if c.s.failOn != "" && strings.Contains(q, c.s.failOn) {
		return nil, errScript
	}
	return driver.RowsAffected(1), nil
}

func (c *scriptConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.s.record(q)
	for _, a := range c.s.answers {
		if strings.Contains(q, a.match) {
			if a.err != nil {
				return nil, a.err
			}
			return &scriptRows{cols: a.cols, rows: a.rows, nextErr: a.nextErr}, nil
		}
	}
	return &scriptRows{cols: []string{"x"}}, nil
}

type scriptTx struct{ s *script }

func (t scriptTx) Commit() error   { t.s.record(scriptCommit); return nil }
func (t scriptTx) Rollback() error { return nil }

type scriptRows struct {
	cols    []string
	rows    [][]driver.Value
	nextErr error
	i       int
}

func (r *scriptRows) Columns() []string { return r.cols }
func (r *scriptRows) Close() error      { return nil }

func (r *scriptRows) Next(dst []driver.Value) error {
	if r.i >= len(r.rows) {
		if r.nextErr != nil {
			return r.nextErr
		}
		return io.EOF
	}
	copy(dst, r.rows[r.i])
	r.i++
	return nil
}

// scriptSignIn is the one sign-in method New insists on.
type scriptSignIn struct{}

func (scriptSignIn) Name() string  { return "signin" }
func (scriptSignIn) SignsIn() bool { return true }

// newScriptAuth wires an Auth on the script database with dialect d.
func newScriptAuth(t *testing.T, s *script, d sqlb.Dialect, opts ...Option) *Auth {
	t.Helper()
	db := sql.OpenDB(s)
	t.Cleanup(func() { db.Close() })
	a, err := New(append([]Option{WithDB(db, d), WithPlugins(scriptSignIn{})}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// indexOf returns the position of the first statement containing sub, or -1.
func indexOf(log []string, sub string) int {
	return slices.IndexFunc(log, func(q string) bool { return strings.Contains(q, sub) })
}

func TestMigrate_PostgresHoldsAnAdvisoryLockAndCommitsEachMigration(t *testing.T) {
	s := &script{}
	a := newScriptAuth(t, s, sqlb.PostgresDialect{})
	done, err := a.Migrate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{CorePluginName + "/" + coreTablesMigrationName, CorePluginName + "/" + sessionLifetimesMigrationName, CorePluginName + "/" + sessionRevokedMigrationName, CorePluginName + "/" + sessionDataMigrationName, CorePluginName + "/" + codeSealedMigrationName, CorePluginName + "/" + sessionReauthMigrationName, CorePluginName + "/" + sessionTasksMigrationName, CorePluginName + "/" + sessionPreviousTokenMigrationName}; !slices.Equal(done, want) {
		t.Fatalf("applied %v, want %v", done, want)
	}
	log := s.statements()
	lock, ddl, unlock := indexOf(log, "pg_advisory_lock($1)"), indexOf(log, "CREATE TABLE IF NOT EXISTS "+TableNameUser), indexOf(log, "pg_advisory_unlock($1)")
	if lock != 0 || ddl < lock || unlock != len(log)-1 {
		t.Fatalf("the lock must wrap the run: lock at %d, DDL at %d, unlock at %d of %v", lock, ddl, unlock, log)
	}
	ins := indexOf(log, "INSERT INTO "+TableNameMigrations)
	if ins < 0 || !strings.Contains(log[ins], "VALUES ($1, $2, $3, $4)") {
		t.Fatalf("the ledger row must use Postgres placeholders: %v", log)
	}
	if b, c := indexOf(log, scriptBegin), indexOf(log, scriptCommit); b < 0 || b > ddl || c < ins {
		t.Fatalf("the migration and its ledger row must share one transaction: %v", log)
	}
}

func TestMigrate_PostgresLockFailureStopsTheRun(t *testing.T) {
	s := &script{failOn: "pg_advisory_lock"}
	a := newScriptAuth(t, s, sqlb.PostgresDialect{})
	if _, err := a.Migrate(context.Background()); !errors.Is(err, errScript) || !strings.Contains(err.Error(), "take migration lock") {
		t.Fatalf("err = %v, want the lock failure", err)
	}
	if indexOf(s.statements(), "CREATE TABLE") >= 0 {
		t.Fatal("no DDL may run without the lock")
	}
}

// mysqlLock answers GET_LOCK with v.
func mysqlLock(v driver.Value) scriptAnswer {
	return scriptAnswer{match: "GET_LOCK", cols: []string{"l"}, rows: [][]driver.Value{{v}}}
}

func TestMigrate_MySQLTakesANamedLockAndRunsDDLOutsideATransaction(t *testing.T) {
	s := &script{answers: []scriptAnswer{mysqlLock(int64(1))}}
	a := newScriptAuth(t, s, sqlb.MySQLDialect{})
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	log := s.statements()
	if indexOf(log, scriptBegin) >= 0 {
		t.Fatalf("MySQL commits every DDL statement itself; no transaction may be opened: %v", log)
	}
	ins := indexOf(log, "INSERT INTO "+TableNameMigrations)
	if ins < 0 || !strings.Contains(log[ins], "VALUES (?, ?, ?, ?)") || ins < indexOf(log, "CREATE TABLE IF NOT EXISTS "+TableNameUser) {
		t.Fatalf("the ledger row follows the statements, with ? placeholders: %v", log)
	}
	if !strings.Contains(log[len(log)-1], "RELEASE_LOCK") {
		t.Fatalf("the lock must be released last: %v", log)
	}
}

func TestMigrate_MySQLRefusesWhenTheLockIsNotGranted(t *testing.T) {
	for name, ans := range map[string]scriptAnswer{
		"held by another process": mysqlLock(int64(0)),
		"lock error (NULL)":       mysqlLock(nil),
		"query fails":             {match: "GET_LOCK", err: errScript},
	} {
		t.Run(name, func(t *testing.T) {
			s := &script{answers: []scriptAnswer{ans}}
			a := newScriptAuth(t, s, sqlb.MySQLDialect{})
			_, err := a.Migrate(context.Background())
			if err == nil || !strings.Contains(err.Error(), "migration lock") {
				t.Fatalf("err = %v, want a migration lock error", err)
			}
			if indexOf(s.statements(), "CREATE TABLE") >= 0 {
				t.Fatal("no DDL may run without the lock")
			}
		})
	}
}

func TestMigrate_MySQLFailedStatementWritesNoLedgerRow(t *testing.T) {
	s := &script{answers: []scriptAnswer{mysqlLock(int64(1))}, failOn: "CREATE TABLE IF NOT EXISTS " + TableNameIdentity}
	a := newScriptAuth(t, s, sqlb.MySQLDialect{})
	done, err := a.Migrate(context.Background())
	if !errors.Is(err, errScript) || !strings.Contains(err.Error(), CorePluginName+"/0001_core_tables") {
		t.Fatalf("err = %v, want the failure naming the migration", err)
	}
	if len(done) != 0 || indexOf(s.statements(), "INSERT INTO "+TableNameMigrations) >= 0 {
		t.Fatalf("a failed migration must not be recorded: done %v", done)
	}
}

func TestMigrate_LedgerRowsThatDoNotScanAreAnError(t *testing.T) {
	s := &script{answers: []scriptAnswer{{match: "SELECT owner, name, checksum", cols: []string{"owner", "name", "checksum"}, rows: [][]driver.Value{{nil, "x", "y"}}}}}
	a := newScriptAuth(t, s, sqlb.PostgresDialect{})
	if _, err := a.MigrationStatus(context.Background()); err == nil {
		t.Fatal("a NULL owner in the ledger must fail the read, not be taken as an empty name")
	}
}

func TestPlaceholders_NumberedOnlyForPostgres(t *testing.T) {
	const q = "INSERT INTO t (a, b) VALUES (?, ?)"
	if got := placeholders(EnginePostgres, q); got != "INSERT INTO t (a, b) VALUES ($1, $2)" {
		t.Fatalf("postgres: %q", got)
	}
	for _, e := range []string{EngineMySQL, EngineSQLite} {
		if got := placeholders(e, q); got != q {
			t.Fatalf("%s: %q, want it unchanged", e, got)
		}
	}
}

// catalogue answers Orphans' three queries for an engine.
func catalogue(owners, tables, columns []string) []scriptAnswer {
	col := func(vs []string) [][]driver.Value {
		out := make([][]driver.Value, 0, len(vs))
		for _, v := range vs {
			out = append(out, []driver.Value{v})
		}
		return out
	}
	return []scriptAnswer{
		{match: "SELECT DISTINCT owner", cols: []string{"owner"}, rows: col(owners)},
		{match: "information_schema.tables", cols: []string{"table_name"}, rows: col(tables)},
		{match: "information_schema.columns", cols: []string{"column_name"}, rows: col(columns)},
	}
}

func TestOrphans_ReadsTheCatalogueOfEachServerEngine(t *testing.T) {
	for _, tc := range []struct {
		d      sqlb.Dialect
		schema string
	}{
		{sqlb.PostgresDialect{}, "current_schema()"},
		{sqlb.MySQLDialect{}, "DATABASE()"},
	} {
		t.Run(sqlb.DialectName(tc.d), func(t *testing.T) {
			s := &script{answers: catalogue(
				[]string{CorePluginName, "gone"},
				[]string{TableNameUser, "auth_old", "app_orders"},
				append(slices.Clone(CoreUserColumns), "legacy_flag"),
			)}
			a := newScriptAuth(t, s, tc.d)
			got, err := a.Orphans(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			want := []Orphan{{OrphanColumn, "legacy_flag"}, {OrphanOwner, "gone"}, {OrphanTable, "auth_old"}}
			if !slices.Equal(got, want) {
				t.Fatalf("orphans %v, want %v", got, want)
			}
			for _, q := range s.statements()[1:] {
				if !strings.Contains(q, tc.schema) {
					t.Fatalf("catalogue query %q must be confined to the current schema with %s", q, tc.schema)
				}
			}
		})
	}
}

func TestOrphans_CatalogueFailuresNameTheStep(t *testing.T) {
	for step, ans := range map[string]scriptAnswer{
		"read ledger":  {match: "SELECT DISTINCT owner", err: errScript},
		"list tables":  {match: "information_schema.tables", err: errScript},
		"list columns": {match: "information_schema.columns", cols: []string{"c"}, rows: [][]driver.Value{{nil}}},
	} {
		t.Run(step, func(t *testing.T) {
			s := &script{answers: []scriptAnswer{ans}}
			a := newScriptAuth(t, s, sqlb.PostgresDialect{})
			if _, err := a.Orphans(context.Background()); err == nil || !strings.Contains(err.Error(), "auth: "+step) {
				t.Fatalf("err = %v, want it to name %q", err, step)
			}
		})
	}
	t.Run("result dropped mid-way", func(t *testing.T) {
		s := &script{answers: []scriptAnswer{{match: "SELECT DISTINCT owner", cols: []string{"owner"}, nextErr: errScript}}}
		a := newScriptAuth(t, s, sqlb.PostgresDialect{})
		if _, err := a.Orphans(context.Background()); !errors.Is(err, errScript) {
			t.Fatalf("err = %v, want the iteration failure", err)
		}
	})
}

func TestDBRateStore_UpsertIsWrittenForEachEngine(t *testing.T) {
	for _, tc := range []struct {
		d      sqlb.Dialect
		upsert string
		sel    string
	}{
		{sqlb.PostgresDialect{}, "ON CONFLICT (" + colRateKeyHash + ") DO UPDATE", colRateKeyHash + " = $1"},
		{sqlb.MySQLDialect{}, "ON DUPLICATE KEY UPDATE", colRateKeyHash + " = ?"},
	} {
		t.Run(sqlb.DialectName(tc.d), func(t *testing.T) {
			s := &script{answers: []scriptAnswer{{match: "SELECT " + colRateHits, cols: []string{"hits"}, rows: [][]driver.Value{{int64(3)}}}}}
			a := newScriptAuth(t, s, tc.d, WithDBRateStore())
			n, err := (&dbRateStore{a: a}).Hit(context.Background(), "k", time.Minute)
			if err != nil || n != 3 {
				t.Fatalf("Hit = %d, %v; want the counter the database holds", n, err)
			}
			log := s.statements()
			if len(log) != 2 || !strings.Contains(log[0], tc.upsert) || !strings.Contains(log[1], tc.sel) {
				t.Fatalf("statements %v, want the %s upsert then the read", log, sqlb.DialectName(tc.d))
			}
		})
	}
}

func TestPrepare_ARenderFailureIsReturnedNotRun(t *testing.T) {
	s := &script{}
	a := newScriptAuth(t, s, sqlb.SQLiteDialect{})
	var v string
	bad := a.Select().Columns(sqlb.Bind(sqlb.Expr[string]{}, &v)).From(TableUser)
	if err := a.One(context.Background(), bad); !errors.Is(err, sqlb.ErrZeroExpr) || !strings.Contains(err.Error(), "auth: build statement") {
		t.Fatalf("err = %v, want the render error", err)
	}
	if len(s.statements()) != 0 {
		t.Fatal("a statement that did not render must not reach the database")
	}
}

func TestNoDatabase_EveryEntryPointSaysSo(t *testing.T) {
	a, err := New(WithPlugins(scriptSignIn{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	checks := map[string]error{
		"Tx":              a.Tx(ctx, func(context.Context, *sql.Tx) error { return nil }),
		"Conn":            func() error { _, err := a.Conn(ctx); return err }(),
		"User":            func() error { _, err := a.User(ctx, "u"); return err }(),
		"Sweep":           func() error { _, err := a.Sweep(ctx, time.Hour); return err }(),
		"Orphans":         func() error { _, err := a.Orphans(ctx); return err }(),
		"Migrate":         func() error { _, err := a.Migrate(ctx); return err }(),
		"MigrationStatus": func() error { _, err := a.MigrationStatus(ctx); return err }(),
		"DeleteSession":   a.DeleteSession(ctx, "u", "s"),
		"Identities":      func() error { _, err := a.Identities(ctx, "u"); return err }(),
	}
	for name, err := range checks {
		if !errors.Is(err, ErrNoDatabase) {
			t.Errorf("%s: %v, want ErrNoDatabase", name, err)
		}
	}
}

func TestAfterCommitAndAfterTx_RunAtOnceOutsideATransaction(t *testing.T) {
	a, err := New(WithPlugins(scriptSignIn{}))
	if err != nil {
		t.Fatal(err)
	}
	var ran []string
	a.AfterCommit(context.Background(), func(context.Context) { ran = append(ran, "commit") })
	a.AfterTx(context.Background(), func(context.Context) { ran = append(ran, "tx") })
	if !slices.Equal(ran, []string{"commit", "tx"}) {
		t.Fatalf("ran %v, want both at once, in order", ran)
	}
}

// TestCheckRequirement_FailsClosed pins the guards the pipeline never reaches
// by itself: it hands a pending session only to PendingSecondFactor
// operations, and New refuses an unknown requirement. Should either upstream
// rule ever slip, the requirement check must still refuse.
func TestCheckRequirement_FailsClosed(t *testing.T) {
	a, err := New(WithPlugins(scriptSignIn{}))
	if err != nil {
		t.Fatal(err)
	}
	pending := &Session{ID: "s", SecondFactorPending: true, CreatedAt: a.now()}
	for _, req := range []Requirement{SignedIn, FreshSignIn} {
		if err := a.checkRequirement(&Call{Op: OpInfo{Require: req}, Session: pending}); !errors.Is(err, ErrSignedOut) {
			t.Errorf("%s with a pending session: %v, want ErrSignedOut", req, err)
		}
	}
	full := &Session{ID: "s", CreatedAt: a.now()}
	if err := a.checkRequirement(&Call{Op: OpInfo{Require: PendingSecondFactor}, Session: full}); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("PendingSecondFactor with a full session: %v, want ErrSignedOut", err)
	}
	if err := a.checkRequirement(&Call{Op: OpInfo{Require: "made_up"}, Session: full}); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("unknown requirement: %v, want ErrSignedOut", err)
	}
}

func TestLimiter_RuleOfTheOtherKeyIsNotCounted(t *testing.T) {
	store := &countingStore{}
	l := &limiter{store: store, rules: map[EndpointID][]RateRule{
		"x.op": {{Match: "x.op", Key: ByIdentifier, Limit: 1, Window: time.Minute}},
	}}
	c := &Call{Op: OpInfo{ID: "x.op"}}
	if err := l.check(context.Background(), c, ByIP, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	if store.hits != 0 {
		t.Fatalf("an IP check counted %d hits against an identifier rule", store.hits)
	}
}

// countingStore counts hits and allows everything.
type countingStore struct{ hits int }

func (s *countingStore) Hit(context.Context, string, time.Duration) (int, error) {
	s.hits++
	return 1, nil
}

func TestLimiter_DerivedEmptyValueIsNotCounted(t *testing.T) {
	store := &countingStore{}
	l := &limiter{store: store, rules: map[EndpointID][]RateRule{
		"x.op": {{Match: "x.op", Key: ByIdentifier, Limit: 1, Window: time.Minute, Derive: func(string) string { return "" }}},
	}}
	if err := l.check(context.Background(), &Call{Op: OpInfo{ID: "x.op"}}, ByIdentifier, "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	if store.hits != 0 {
		t.Fatal("a rule whose Derive yields nothing must not count")
	}
}

// failingReader is a randomness source that has run dry.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errScript }

func TestIssueCode_NoRandomnessNoCode(t *testing.T) {
	a := newScriptAuth(t, &script{}, sqlb.SQLiteDialect{})
	saved := rand.Reader
	rand.Reader = failingReader{}
	defer func() { rand.Reader = saved }()
	if code, err := a.IssueCode(context.Background(), "p", "s", time.Minute); !errors.Is(err, errScript) || code != "" {
		t.Fatalf("IssueCode = %q, %v; want no code and the reader's error", code, err)
	}
}

// oddDialect is a dialect sqlb cannot name, standing in for an engine the
// core has no DDL for.
type oddDialect struct{}

func (oddDialect) Placeholder(int) string     { return "?" }
func (oddDialect) QuoteIdent(s string) string { return s }

func TestMigrations_AnEngineWithoutDDLIsRefusedEverywhere(t *testing.T) {
	s := &script{}
	a := newScriptAuth(t, s, oddDialect{})
	ctx := context.Background()
	for name, err := range map[string]error{
		"Migrations":      func() error { _, err := a.Migrations(); return err }(),
		"MigrationSQL":    func() error { _, err := a.MigrationSQL(); return err }(),
		"Migrate":         func() error { _, err := a.Migrate(ctx); return err }(),
		"MigrationStatus": func() error { _, err := a.MigrationStatus(ctx); return err }(),
	} {
		if !errors.Is(err, ErrEngineNotSupported) {
			t.Errorf("%s: %v, want ErrEngineNotSupported", name, err)
		}
	}
	if len(s.statements()) != 0 {
		t.Fatal("nothing may reach the database for an engine without DDL")
	}
}

func TestMigrate_AClosedDatabaseIsAnError(t *testing.T) {
	a := newScriptAuth(t, &script{}, sqlb.SQLiteDialect{})
	a.DB().Close()
	// database/sql does not export the error; its text is the contract.
	if _, err := a.Migrate(context.Background()); err == nil || !strings.Contains(err.Error(), "database is closed") {
		t.Fatalf("err = %v, want the closed database", err)
	}
}

// migrator ships the migrations (or failure) it holds.
type migrator struct {
	ms  []Migration
	err error
}

func (migrator) Name() string                             { return "mig" }
func (m migrator) Migrations(string) ([]Migration, error) { return m.ms, m.err }

func TestMigrations_APluginMigrationMustBeItsOwnAndWellFormed(t *testing.T) {
	for name, tc := range map[string]struct {
		m    migrator
		want string
	}{
		"its own failure":      {migrator{err: errScript}, `plugin "mig" migrations`},
		"another owner's name": {migrator{ms: []Migration{{Owner: CorePluginName, Name: "x"}}}, `ships a migration owned by "core"`},
	} {
		t.Run(name, func(t *testing.T) {
			a := newScriptAuth(t, &script{}, sqlb.SQLiteDialect{}, WithPlugins(tc.m))
			if _, err := a.Migrations(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

// columns adds the columns it holds to auth_user.
type columns []ColumnExtension

func (columns) Name() string                 { return "cols" }
func (c columns) Columns() []ColumnExtension { return c }

func TestMigrations_IntAndUniqueColumns(t *testing.T) {
	a := newScriptAuth(t, &script{}, sqlb.PostgresDialect{}, WithPlugins(columns{
		{Table: TableNameUser, Name: "cols_score", Type: ColumnInt, Default: "0", Unique: true},
	}))
	sql, err := a.MigrationSQL()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ALTER TABLE auth_user ADD COLUMN cols_score BIGINT NOT NULL DEFAULT 0",
		"CREATE UNIQUE INDEX auth_user_cols_score_key ON auth_user (cols_score)",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("migration SQL lacks %q:\n%s", want, sql)
		}
	}
}

func TestPromoteSession_OnlyAPendingSessionIsPromoted(t *testing.T) {
	a := newScriptAuth(t, &script{}, sqlb.SQLiteDialect{})
	for _, c := range []*Call{{}, {Session: &Session{ID: "s"}}} {
		if _, err := a.PromoteSession(context.Background(), c); !errors.Is(err, ErrSignedOut) {
			t.Fatalf("PromoteSession(%+v) = %v, want ErrSignedOut", c.Session, err)
		}
	}
}

func TestFindSignInIdentity_UnrecognisedInputIsInvalid(t *testing.T) {
	a := newScriptAuth(t, &script{}, sqlb.SQLiteDialect{})
	if _, _, err := a.FindSignInIdentity(context.Background(), "anything"); !errors.Is(err, ErrIdentifierInvalid) {
		t.Fatalf("err = %v, want ErrIdentifierInvalid with no sign-in kind to match", err)
	}
}

// TestKindName_LongestAllowedFitsEveryGeneratedIdentifier pins the fix for a
// kind name KindNamePattern accepted but whose index name was too long: every
// identifier generated for a kind of maxKindNameLength, in its longest mode,
// fits maxIdentifierLength on both server engines, and one character more is
// refused at New.
func TestKindName_LongestAllowedFitsEveryGeneratedIdentifier(t *testing.T) {
	if maxKindNameLength != 28 {
		t.Fatalf("maxKindNameLength = %d; the index name parts changed, recheck the bound", maxKindNameLength)
	}
	kind := IdentifierKind{Name: IdentifierKindName(strings.Repeat("k", maxKindNameLength)), Unique: true, UniqueOnlyVerified: true, ScopedByTenant: true}
	ident := regexp.MustCompile(`[a-z_]{20,}`)
	for _, e := range []string{EnginePostgres, EngineMySQL} {
		for _, st := range (&Auth{}).identityIndexMigration(e, "p", kind).Statements {
			for _, id := range ident.FindAllString(st, -1) {
				if len(id) > maxIdentifierLength {
					t.Errorf("%s: identifier %q is %d long, over %d", e, id, len(id), maxIdentifierLength)
				}
			}
		}
	}
	long := kind
	long.Name += "k"
	long.Normalize = func(s string) (string, error) { return s, nil }
	if err := validateKind(long); !errors.Is(err, ErrBadIdentifier) {
		t.Fatalf("a %d-character kind name: %v, want ErrBadIdentifier", len(long.Name), err)
	}
}
