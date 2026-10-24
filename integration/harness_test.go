// Package integration runs the library against real databases: SQLite always,
// and Postgres and MySQL when their DSNs are set.
//
// It is a separate module so the three drivers never reach the root go.mod:
// every consumer of the library would otherwise inherit dependencies it never
// builds. The root module's tests prove the SQL text; only these prove that a
// database accepts it, that the scan targets receive the values, and that the
// three engines give the same answers.
package integration

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/sqlb"
	_ "modernc.org/sqlite"
)

// DSN variables. Unset means the engine is skipped, loudly.
const (
	EnvPostgresDSN = "AUTH_TEST_PG_DSN"
	EnvMySQLDSN    = "AUTH_TEST_MYSQL_DSN"
	// EnvTablePrefix makes every Auth the harness builds rename its tables
	// with auth.WithTablePrefix. task integration:prefixed and
	// test:engines:prefixed set it to "t_", so the whole suite runs a second
	// time against renamed tables and any place that still uses a table's
	// label as its real name fails there.
	EnvTablePrefix = "AUTH_TEST_TABLE_PREFIX"
)

// tablePrefix is the EnvTablePrefix value, "" for the plain run.
func tablePrefix() string { return os.Getenv(EnvTablePrefix) }

// tbl is the real name of a library table in this run: the label under the
// run's prefix. Every raw statement a test writes against a library table
// names it through tbl, as an app would through a.TableName.
func tbl(label string) string { return tablePrefix() + label }

// testBaseURL is the app URL every test instance runs under.
const testBaseURL = "https://app.example.com"

// fastArgon2 makes password hashing take microseconds. Tests check behaviour,
// not cost; the production default is password.DefaultArgon2.
var fastArgon2 = password.Argon2Params{Memory: 64, Time: 1, Threads: 1}

type engine struct {
	name string
	open func(t testing.TB) (*sql.DB, sqlb.Dialect)
}

var skipOnce sync.Map

// engines returns every engine this run can reach.
func engines(t testing.TB) []engine {
	t.Helper()
	out := []engine{{name: auth.EngineSQLite, open: openSQLite}}
	if dsn := os.Getenv(EnvPostgresDSN); dsn != "" {
		out = append(out, engine{name: auth.EnginePostgres, open: func(t testing.TB) (*sql.DB, sqlb.Dialect) { return openPostgres(t, dsn) }})
	} else if _, seen := skipOnce.LoadOrStore(EnvPostgresDSN, true); !seen {
		fmt.Fprintf(os.Stderr, "SKIP postgres: set %s (task test:engines does)\n", EnvPostgresDSN)
	}
	if dsn := os.Getenv(EnvMySQLDSN); dsn != "" {
		out = append(out, engine{name: auth.EngineMySQL, open: func(t testing.TB) (*sql.DB, sqlb.Dialect) { return openMySQL(t, dsn) }})
	} else if _, seen := skipOnce.LoadOrStore(EnvMySQLDSN, true); !seen {
		fmt.Fprintf(os.Stderr, "SKIP mysql: set %s (task test:engines does)\n", EnvMySQLDSN)
	}
	return out
}

// eachEngine runs fn once per engine, each on an empty database.
func eachEngine(t *testing.T, fn func(t *testing.T, e *env)) {
	for _, eng := range engines(t) {
		t.Run(eng.name, func(t *testing.T) {
			db, d := eng.open(t)
			fn(t, newEnv(t, eng.name, db, d))
		})
	}
}

// sqlitePragmas are the pragmas sqlb's SQLite driver sets: WAL and a busy
// timeout. No foreign-key pragma: the library creates no foreign keys
// (ADR-0002), so SQLite needs nothing turned on.
const sqlitePragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

// sqliteDSN builds a file: URI for path with the given query. It escapes the
// path rather than concatenating it, because a test that calls eachEngine
// twice names its second subtest "sqlite#01", t.TempDir puts that "#" in the
// path, and an unescaped "#" starts the URI fragment: SQLite would open a
// fixed, truncated path shared by every run, and a later run would find the
// rows of an earlier one. Only the path is escaped: a url.URL with a scheme
// writes a relative path as "file://name", which SQLite reads as a host.
func sqliteDSN(path, query string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + query
}

// openSQLite uses a file, not :memory:, so the pool can hold several
// connections the way a real deployment does, with the pragmas sqlb's SQLite
// driver sets: WAL and a busy timeout.
func openSQLite(t testing.TB) (*sql.DB, sqlb.Dialect) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	dsn := sqliteDSN(path, sqlitePragmas)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, sqlb.SQLiteDialect{}
}

// testTablePrefixes name the tables a test may create: the library's own
// (every core and plugin table starts with "auth_", and the audit plugin's
// with "audit_") and the app tables the examples-in-tests add ("app_"), each
// also under the run's table prefix. Resetting by prefix instead of by a
// typed list means a table a new plugin adds is dropped too: a typed list
// went stale in round 2 and left auth_two_factor_device behind, which
// TestOrphans then reported.
var testTablePrefixes = func() []string {
	base := []string{"auth_", "audit_", "app_"}
	out := append([]string(nil), base...)
	if p := tablePrefix(); p != "" {
		for _, b := range base {
			out = append(out, p+b)
		}
	}
	return out
}()

// tablesToReset lists the tables of the current database or schema whose
// names start with a testTablePrefixes entry. The test databases are private
// to the suite, so dropping every such table is the reset.
func tablesToReset(t testing.TB, ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, catalog string) []string {
	t.Helper()
	rows, err := q.QueryContext(ctx, catalog)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("list tables: %v", err)
		}
		for _, p := range testTablePrefixes {
			if strings.HasPrefix(name, p) {
				out = append(out, name)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}
	return out
}

// Catalog queries for tablesToReset, one per engine.
const (
	postgresTablesQuery = "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()"
	mysqlTablesQuery    = "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()"
)

func openPostgres(t testing.TB, dsn string) (*sql.DB, sqlb.Dialect) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, tb := range tablesToReset(t, context.Background(), db, postgresTablesQuery) {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + tb + " CASCADE"); err != nil {
			t.Fatalf("reset postgres: %v", err)
		}
	}
	return db, sqlb.PostgresDialect{}
}

// openMySQL applies the settings sqlb's MySQL driver forces: parseTime, UTC,
// and clientFoundRows, so RowsAffected counts matched rows as on the other two
// engines.
func openMySQL(t testing.TB, dsn string) (*sql.DB, sqlb.Dialect) {
	t.Helper()
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ParseTime, cfg.Loc, cfg.ClientFoundRows = true, time.UTC, true
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(conn)
	t.Cleanup(func() { db.Close() })
	c, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("mysql: %v", err)
	}
	defer c.Close()
	ctx := context.Background()
	if _, err := c.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0"); err != nil {
		t.Fatal(err)
	}
	for _, tb := range tablesToReset(t, ctx, c, mysqlTablesQuery) {
		if _, err := c.ExecContext(ctx, "DROP TABLE IF EXISTS "+tb); err != nil {
			t.Fatalf("reset mysql: %v", err)
		}
	}
	if _, err := c.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1"); err != nil {
		t.Fatal(err)
	}
	return db, sqlb.MySQLDialect{}
}

// env is one engine's database plus the fakes a test inspects.
type env struct {
	engine string
	db     *sql.DB
	d      sqlb.Dialect
	clock  *clock
	mail   *mailbox
	sms    *smsbox
}

func newEnv(t testing.TB, engine string, db *sql.DB, d sqlb.Dialect) *env {
	return &env{engine: engine, db: db, d: d, clock: newClock(), mail: &mailbox{}, sms: &smsbox{}}
}

// withDB is the database option every test instance takes: the env's handle
// and dialect, plus the run's table prefix (EnvTablePrefix). One option, so
// a test that lists its own options still joins the prefixed run.
func (e *env) withDB() auth.Option {
	return auth.Options(auth.WithDB(e.db, e.d), auth.WithTablePrefix(tablePrefix()))
}

// newAuth wires plugins against the env's database and migrates it.
func (e *env) newAuth(t testing.TB, opts []auth.Option, plugins ...auth.Plugin) *auth.Auth {
	t.Helper()
	all := append([]auth.Option{
		e.withDB(), auth.WithBaseURL(testBaseURL), auth.WithClock(e.clock.Now),
		// Deliveries in the order they were issued, so "the last code sent
		// to X" is the code of the last send even when two sends to X are in
		// flight at once (an add, then a change). A test's own
		// WithBackground, later in the list, replaces it.
		auth.WithBackground(orderedBackground(t)),
		// An explicit store on the test clock: windows move with Advance, and
		// the one-process warning does not fire for every test.
		auth.WithRateStore(auth.NewMemoryRateStore(e.clock.Now)),
		auth.WithPlugins(plugins...),
	}, opts...)
	a, err := auth.New(all...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate on %s: %v", e.engine, err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// orderedQueueSize bounds the tasks one test can have waiting: far more than
// any test schedules; a full queue only makes the scheduling call wait.
const orderedQueueSize = 1024

// orderedBackground runs post-commit tasks one at a time on a goroutine of
// their own, in the order they were scheduled. It stays asynchronous, so a
// request never waits for a mail (the timing tests still hold), while the
// fake mailbox and SMS box record messages in issue order instead of in
// whichever order concurrent goroutines happened to finish, which made
// LastCode flaky under load. The queue closes after the Auth's own Close,
// because cleanups run last-registered first.
func orderedBackground(t testing.TB) auth.BackgroundFunc {
	type job struct {
		ctx  context.Context
		task func(context.Context)
	}
	q := make(chan job, orderedQueueSize)
	go func() {
		for j := range q {
			j.task(j.ctx)
		}
	}()
	t.Cleanup(func() { close(q) })
	return func(ctx context.Context, task func(context.Context)) { q <- job{ctx: ctx, task: task} }
}

// emailPlugin is the classic SaaS email setup with the env's mailbox.
func (e *env) emailPlugin(opts ...email.Option) *email.Plugin {
	return email.New(append([]email.Option{email.Login(), email.Recover(), email.WithMailer(e.mail)}, opts...)...)
}

func (e *env) passwordPlugin(opts ...password.Option) *password.Plugin {
	return password.New(append([]password.Option{password.Argon2(fastArgon2)}, opts...)...)
}

func (e *env) phonePlugin(opts ...phone.Option) *phone.Plugin {
	return phone.New(append([]phone.Option{phone.WithSMS(e.sms)}, opts...)...)
}

// clock is a settable clock, rounded to microseconds because Postgres and
// MySQL store no finer, and a value read back must equal the value written.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

// newClock starts at the real time: cookie expiries are computed from this
// clock and judged by the HTTP client's cookie jar against the real one, so a
// clock in the past would make the jar drop every cookie as expired.
func newClock() *clock { return &clock{t: time.Now().UTC().Truncate(time.Microsecond)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d).Truncate(time.Microsecond)
	c.mu.Unlock()
}

// mailbox records mail.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	m.sent = append(m.sent, mail)
	m.mu.Unlock()
	return nil
}

// To returns the mail sent to addr, after every delivery in flight finished.
func (m *mailbox) To(a *auth.Auth, addr string) []email.Mail {
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []email.Mail
	for _, x := range m.sent {
		if x.To == addr {
			out = append(out, x)
		}
	}
	return out
}

var tokenInLink = regexp.MustCompile(`token=([A-Za-z0-9_%-]+)`)

// LastToken returns the token in the newest link sent to addr.
func (m *mailbox) LastToken(t *testing.T, a *auth.Auth, addr string) auth.Token {
	t.Helper()
	list := m.To(a, addr)
	for i := len(list) - 1; i >= 0; i-- {
		if mm := tokenInLink.FindStringSubmatch(list[i].Text); mm != nil {
			return auth.Token(mm[1])
		}
	}
	t.Fatalf("no link sent to %s; mail: %+v", addr, list)
	return ""
}

// smsbox records texts.
type smsbox struct {
	mu   sync.Mutex
	sent map[string][]string
}

func (s *smsbox) Send(_ context.Context, to, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sent == nil {
		s.sent = map[string][]string{}
	}
	s.sent[to] = append(s.sent[to], text)
	return nil
}

// Count returns how many texts number received, after every delivery in
// flight finished.
func (s *smsbox) Count(a *auth.Auth, number string) int {
	a.WaitDeliveries()
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent[number])
}

var codeInText = regexp.MustCompile(`\b(\d{6})\b`)

// LastCode returns the newest code texted to number.
func (s *smsbox) LastCode(t *testing.T, a *auth.Auth, number string) string {
	t.Helper()
	a.WaitDeliveries()
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.sent[number]
	if len(list) == 0 {
		t.Fatalf("no text sent to %s", number)
	}
	m := codeInText.FindStringSubmatch(list[len(list)-1])
	if m == nil {
		t.Fatalf("no code in %q", list[len(list)-1])
	}
	return m[1]
}

// request returns a context that looks like an HTTP request from a browser
// with the given session token.
func request(a *auth.Auth, tok auth.Token) context.Context {
	req := auth.Request{
		Transport: auth.TransportHTTP,
		Client:    auth.Client{IP: "203.0.113.7", UserAgent: "test", Origin: testBaseURL},
	}
	if tok != "" {
		req.Credential, req.Token = auth.CredentialCookie, tok
	}
	return a.WithRequest(context.Background(), req)
}

// anon is a signed-out browser request.
func anon(a *auth.Auth) context.Context { return request(a, "") }

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// TestSQLiteDSN_OpensAPathWithAHash pins sqliteDSN against the "sqlite#01"
// subtest name: the database must be created at the exact path, "#"
// included, not at the truncated path before it.
func TestSQLiteDSN_OpensAPathWithAHash(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sqlite#01")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "auth.db")
	db, err := sql.Open("sqlite", sqliteDSN(path, sqlitePragmas))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE t (x INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the database is not at %s: %v", path, err)
	}
}

// TestOrderedBackground_RunsInScheduleOrder pins the harness runner the
// delivery tests rely on: tasks finish in the order they were scheduled even
// when an earlier one is slower.
func TestOrderedBackground_RunsInScheduleOrder(t *testing.T) {
	run := orderedBackground(t)
	var mu sync.Mutex
	var got []int
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		run(context.Background(), func(context.Context) {
			defer wg.Done()
			if i%2 == 0 {
				time.Sleep(time.Millisecond)
			}
			mu.Lock()
			got = append(got, i)
			mu.Unlock()
		})
	}
	wg.Wait()
	for i, v := range got {
		if v != i {
			t.Fatalf("task %d finished at position %d: %v", v, i, got)
		}
	}
}
