// Package authtest is the test harness for applications that embed the
// library: an Auth on a fresh database per test, a clock the test moves, a
// mailbox and an SMS box that record what the plugins send, a signed-in
// session as a cookie, a bearer header or a Go context, and a browser with
// a cookie jar over the app's handler.
//
// It exists because every app test otherwise writes the same eighty lines:
// open SQLite with the right pragmas, migrate, record mail, wait for
// deliveries, mark the Secure cookie for a plain test server, pull the token
// out of a link. Each of those was written in this repository's own examples
// several times before it was made public here.
//
// The package is part of the core module and imports no database driver: the
// test imports its own (`_ "modernc.org/sqlite"`) and New opens the database
// by driver name, so the module's dependency rule holds.
package authtest

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// BaseURL is the public URL every Env runs under unless WithBaseURL says
// otherwise: an https origin, so the __Host- cookie rules hold, on a name
// that resolves nowhere.
//
//ds:def id=authtest-baseurl-7kq3wm2d owner=@khanakia stability=stable
const BaseURL = "https://app.example.test"

// SQLiteDriver is the database/sql driver name New opens by default: the one
// modernc.org/sqlite registers. The test must import that driver, or New
// fails with sql's "unknown driver".
//
//ds:def id=authtest-sqlitedriver-2xn9pw4e owner=@khanakia stability=stable
const SQLiteDriver = "sqlite"

// sqliteDSN is the in-memory database New opens: one shared-cache database
// per Env, so every connection of the pool sees the same tables (a plain
// ":memory:" gives each connection its own empty database), with the pragmas
// the library needs: a busy timeout so two connections never answer
// SQLITE_BUSY (no foreign-key pragma: the library creates no foreign keys,
// ADR-0002). The counter keeps two Envs in one process apart.
const sqliteDSN = "file:authtest-%d?mode=memory&cache=shared&_pragma=busy_timeout(5000)"

// envCount numbers the in-memory databases; see sqliteDSN.
var envCount atomic.Int64

// Env is one test's wired library and the fakes around it.
//
//ds:def id=authtest-env-5mj8rt3q owner=@khanakia stability=stable
type Env struct {
	T testing.TB
	// Auth is wired, migrated and closed when the test ends.
	Auth *auth.Auth
	// DB and Dialect are what Auth runs on.
	DB      *sql.DB
	Dialect sqlb.Dialect
	// Clock is the clock Auth measures every expiry by; Advance it to expire
	// sessions, codes and links without sleeping.
	Clock *Clock
	// Mail records every mail the email plugin sends when the plugin is built
	// with email.WithMailer(env.Mail); SMS does the same for the phone plugin
	// with phone.WithSMS(env.SMS).
	Mail *Mailbox
	SMS  *SMSBox
	// BaseURL is the app's public URL as Auth knows it.
	BaseURL string
	// Faults fails a chosen database call when the Env was built with
	// WithFaults, and is nil otherwise.
	Faults *Faults
}

// settings is what Options write to before New builds the Env.
type settings struct {
	// optErrs collects the options given nil (auth.ErrNilOption); New
	// fails the test with them before anything else.
	optErrs auth.OptionErrors
	plugins func(e *Env) []auth.Plugin
	opts    []auth.Option
	db      *sql.DB
	dialect sqlb.Dialect
	driver  string
	dsn     string
	baseURL string
	faults  *Faults
}

// Option configures New.
type Option func(*settings)

// WithPlugins sets the plugin list. It is a function of the Env because the
// plugins take the recorders (env.Mail, env.SMS) and the Env exists first.
// New fails without it: a library with no sign-in method cannot start.
//
//ds:def id=authtest-withplugins-9rw2kx7n owner=@khanakia stability=stable
func WithPlugins(fn func(e *Env) []auth.Plugin) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("authtest.WithPlugins", fn) {
			return
		}
		s.plugins = fn
	}
}

// WithOptions adds options for auth.New after the harness's own (database,
// base URL, clock, rate store), so a test can add a session cache, a policy
// or a hook. An option that repeats one of the harness's replaces it.
//
//ds:def id=authtest-withoptions-3tc6qn8v owner=@khanakia stability=stable
func WithOptions(opts ...auth.Option) Option {
	return func(s *settings) {
		if auth.RefuseNilEach(&s.optErrs, "authtest.WithOptions", opts) {
			return
		}
		s.opts = append(s.opts, opts...)
	}
}

// WithDB runs the Env on an open database instead of SQLite in memory: a
// Postgres or MySQL the test suite reset itself. The Env does not close it.
//
//ds:def id=authtest-withdb-6hp4zm2k owner=@khanakia stability=stable
func WithDB(db *sql.DB, d sqlb.Dialect) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("authtest.WithDB", d) {
			return
		}
		s.db, s.dialect = db, d
	}
}

// WithSQLite opens SQLite through another driver or DSN, for a test that
// uses mattn/go-sqlite3 (whose pragma syntax differs) or wants a file in
// t.TempDir(). The dialect is SQLite's.
//
//ds:def id=authtest-withsqlite-8dk5vt3w owner=@khanakia stability=stable
func WithSQLite(driver, dsn string) Option {
	return func(s *settings) { s.driver, s.dsn = driver, dsn }
}

// WithBaseURL replaces BaseURL.
func WithBaseURL(u string) Option { return func(s *settings) { s.baseURL = u } }

// New builds the Env: it opens the database (SQLite in memory unless WithDB
// or WithSQLite), wires the plugins and options over a frozen clock and a
// memory rate store on that clock, migrates, and registers Close with the
// test's Cleanup. Any failure fails the test at once; a harness that
// returned errors would make every test start with four checks.
//
//ds:def id=authtest-new-4bm7xq9s owner=@khanakia stability=stable
func New(t testing.TB, opts ...Option) *Env {
	t.Helper()
	s := settings{driver: SQLiteDriver, baseURL: BaseURL}
	for _, o := range opts {
		o(&s)
	}
	if err := s.optErrs.OptionErr(); err != nil {
		t.Fatalf("authtest.New: %v", err)
	}
	if s.plugins == nil {
		t.Fatal("authtest.New: WithPlugins is required; the library has no sign-in method of its own")
	}
	e := &Env{T: t, Clock: NewClock(), Mail: &Mailbox{}, SMS: &SMSBox{}, BaseURL: s.baseURL, Faults: s.faults}
	e.Mail.env, e.SMS.env = e, e
	if s.db != nil {
		e.DB, e.Dialect = s.db, s.dialect
	} else {
		e.DB, e.Dialect = openSQLite(t, s.driver, s.dsn, s.faults)
	}
	all := append([]auth.Option{
		auth.WithDB(e.DB, e.Dialect), auth.WithBaseURL(e.BaseURL), auth.WithClock(e.Clock.Now),
		// An explicit rate store on the test clock, so a window moves with
		// Advance and the one-process warning does not fire per test.
		auth.WithRateStore(auth.NewMemoryRateStore(e.Clock.Now)),
		auth.WithPlugins(s.plugins(e)...),
	}, s.opts...)
	a, err := auth.New(all...)
	if err != nil {
		t.Fatalf("authtest.New: auth.New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatalf("authtest.New: migrate: %v", err)
	}
	e.Auth = a
	return e
}

// openSQLite opens the in-memory database, or dsn when given, through f
// when it is not nil.
func openSQLite(t testing.TB, driver, dsn string, f *Faults) (*sql.DB, sqlb.Dialect) {
	t.Helper()
	if dsn == "" {
		dsn = fmt.Sprintf(sqliteDSN, envCount.Add(1))
	}
	var db *sql.DB
	var err error
	if f != nil {
		db, err = faultDB(driver, dsn, f)
	} else {
		db, err = sql.Open(driver, dsn)
	}
	if err != nil {
		t.Fatalf("authtest.New: open %s: %v (import the driver in the test)", driver, err)
	}
	// A shared-cache memory database lives as long as one connection is
	// open; never let the pool close them all between two requests.
	db.SetConnMaxIdleTime(0)
	db.SetConnMaxLifetime(0)
	t.Cleanup(func() { _ = db.Close() })
	return db, sqlb.SQLiteDialect{}
}

// Identity is one identifier a test user is created with: a verified,
// primary identity of Kind holding Value, such as {email.KindEmail,
// "ada@example.test"}.
//
//ds:def id=authtest-identity-7pq2vn8k owner=@khanakia stability=stable
type Identity struct {
	Kind  auth.IdentifierKindName
	Value string
}

// CreateUser creates a user with the given verified, primary identities,
// through the real core API, so every plugin hook runs. It is the fixture
// most tests start with; a test of sign-up itself goes through the plugin's
// operation instead.
//
//ds:def id=authtest-createuser-6rk3xw2m owner=@khanakia stability=stable
func (e *Env) CreateUser(name string, ids ...Identity) auth.User {
	e.T.Helper()
	ctx := context.Background()
	u, err := e.Auth.CreateUser(ctx, auth.NewUser{Name: name})
	if err != nil {
		e.T.Fatalf("authtest: create user: %v", err)
	}
	for _, id := range ids {
		if _, err := e.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: id.Kind, Raw: id.Value, Verified: true, Primary: true}); err != nil {
			e.T.Fatalf("authtest: create %s identity %q: %v", id.Kind, id.Value, err)
		}
	}
	return u
}

// Clock is a settable clock for auth.WithClock. Instants are rounded to the
// microsecond because Postgres and MySQL store no finer, and a test that
// compares a stored time with Now would otherwise differ in the nanoseconds.
//
//ds:def id=authtest-clock-3zx8nq5v owner=@khanakia stability=stable
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock stopped at the current time, in UTC.
func NewClock() *Clock { return &Clock{now: time.Now().UTC().Truncate(time.Microsecond)} }

// Now returns the clock's time. It does not move by itself.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d).Truncate(time.Microsecond)
	c.mu.Unlock()
}

// Set moves the clock to t, in UTC.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t.UTC().Truncate(time.Microsecond)
	c.mu.Unlock()
}

// DefaultUserName is the name NewUser gives a fixture that names none, as
// better-auth's test utils default theirs.
//
//ds:def id=authtest-defaultusername-4hq8zn2w owner=@khanakia stability=stable
const DefaultUserName = "Test User"

// UserFixture is a user built in memory and not yet saved, as better-auth's
// ctx.test.createUser returns one: the test reads or edits its fields, then
// SaveUser writes it through the real core API. The ID is already final, so
// a test can refer to the user (in another fixture, an expected value)
// before it exists.
//
//ds:def id=authtest-userfixture-9kd2wq7m owner=@khanakia stability=stable
type UserFixture struct {
	ID         string
	Name       string
	Image      string
	CreatedAt  time.Time
	Identities []Identity
}

// NewUser builds a UserFixture without touching the database: an id from the
// Auth's generator (auth.WithIDs), DefaultUserName unless the test passes a
// name, the Env's clock as the creation time, and the given verified,
// primary identities. Nothing is checked until SaveUser, which is where
// every rule (uniqueness, hooks) runs.
func (e *Env) NewUser(name string, ids ...Identity) UserFixture {
	e.T.Helper()
	id, err := e.Auth.NewID(auth.IDPrefixUser)
	if err != nil {
		e.T.Fatalf("authtest: user id: %v", err)
	}
	if name == "" {
		name = DefaultUserName
	}
	return UserFixture{ID: id, Name: name, CreatedAt: e.Clock.Now(), Identities: ids}
}

// SaveUser writes f through the real core API (CreateUser, then each
// identity), so every plugin hook runs, and returns the stored user. A taken
// id or identity fails the test.
func (e *Env) SaveUser(f UserFixture) auth.User {
	e.T.Helper()
	ctx := context.Background()
	u, err := e.Auth.CreateUser(ctx, auth.NewUser{ID: f.ID, Name: f.Name, Image: f.Image, CreatedAt: f.CreatedAt})
	if err != nil {
		e.T.Fatalf("authtest: save user %s: %v", f.ID, err)
	}
	for _, id := range f.Identities {
		if _, err := e.Auth.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: id.Kind, Raw: id.Value, Verified: true, Primary: true}); err != nil {
			e.T.Fatalf("authtest: save %s identity %q: %v", id.Kind, id.Value, err)
		}
	}
	return u
}

// DeleteUser deletes user id through the core (a.DeleteUser), so its
// identities, sessions and every plugin's rows go with it, as better-auth's
// deleteUser does. An unknown id fails the test.
func (e *Env) DeleteUser(id string) {
	e.T.Helper()
	if err := e.Auth.DeleteUser(context.Background(), id); err != nil {
		e.T.Fatalf("authtest: delete user %s: %v", id, err)
	}
}
