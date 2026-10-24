package authtest

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
)

// ErrFault is the error an injected database failure returns. A test
// compares against it to prove the failure reached the caller rather than
// being eaten.
//
//ds:def id=authtest-errfault-3wq8mz5k owner=@khanakia stability=stable
var ErrFault = errors.New("authtest: injected database fault")

// MaxFaultSteps bounds a SweepFaults run. No operation in the library makes
// this many database calls; reaching it means the sweep never saw the
// operation finish without a fault, which is a loop in the test, not a slow
// operation.
//
//ds:def id=authtest-maxfaultsteps-6tn2hv9q owner=@khanakia stability=stable
const MaxFaultSteps = 200

// Faults counts database calls and fails the one numbered at: armed, the
// at-th call of any kind (exec, query, prepare, begin, commit) returns
// ErrFault; disarmed, every call passes. It is the switch behind the
// connector Connector returns.
//
// Why a driver and not a mock: the library talks to *sql.DB through sqlb,
// and the only honest way to reach a "the database failed here" branch is to
// make a real database fail at that exact call. Counting calls instead of
// matching SQL text keeps a test independent of the queries' wording.
//
//ds:def id=authtest-faults-8kv3qd7n owner=@khanakia stability=stable
type Faults struct {
	mu    sync.Mutex
	armed bool
	n, at int
	hit   bool
}

// NewFaults returns a disarmed counter.
func NewFaults() *Faults { return &Faults{} }

// Arm starts counting from zero and fails call number at.
func (f *Faults) Arm(at int) {
	f.mu.Lock()
	f.armed, f.n, f.at, f.hit = true, 0, at, false
	f.mu.Unlock()
}

// Disarm stops counting and reports whether the armed call was reached.
func (f *Faults) Disarm() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed = false
	return f.hit
}

// step counts one call and fails it when it is the armed one.
func (f *Faults) step() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.armed {
		return nil
	}
	f.n++
	if f.n == f.at {
		f.hit = true
		return ErrFault
	}
	return nil
}

// Connector wraps base so every call on its connections passes through f
// first. Any database/sql driver works; DSNConnector adapts a driver that
// has no connector of its own. Open the result with sql.OpenDB.
func (f *Faults) Connector(base driver.Connector) driver.Connector {
	return faultConnector{base: base, f: f}
}

// DSNConnector is a driver.Connector that opens dsn with d, for a driver
// that offers only Open (modernc.org/sqlite, for one). The driver of an
// open *sql.DB is db.Driver(), so a test needs no import beyond the one
// that registers the driver.
func DSNConnector(d driver.Driver, dsn string) driver.Connector { return dsnConnector{d: d, dsn: dsn} }

// dsnConnector is DSNConnector's connector.
type dsnConnector struct {
	d   driver.Driver
	dsn string
}

func (c dsnConnector) Connect(context.Context) (driver.Conn, error) { return c.d.Open(c.dsn) }
func (c dsnConnector) Driver() driver.Driver                        { return c.d }

// faultConnector opens base's connections wrapped in faultConn.
type faultConnector struct {
	base driver.Connector
	f    *Faults
}

func (c faultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &faultConn{Conn: conn, f: c.f}, nil
}

func (c faultConnector) Driver() driver.Driver { return c.base.Driver() }

// faultConn forwards to the wrapped connection, through Faults.step first.
// It implements the context interfaces database/sql prefers, so every
// statement passes through step exactly once: a connection that lacks
// ExecerContext or QueryerContext answers driver.ErrSkip without counting,
// and database/sql then prepares the statement, which counts.
type faultConn struct {
	driver.Conn
	f *Faults
}

// errNoBeginTx is a wrapped connection without ConnBeginTx; Begin, its only
// alternative, is deprecated and ignores the context.
var errNoBeginTx = errors.New("authtest: the wrapped connection does not implement driver.ConnBeginTx")

func (c *faultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	ex, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	if err := c.f.step(); err != nil {
		return nil, err
	}
	return ex.ExecContext(ctx, q, args)
}

func (c *faultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	qu, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	if err := c.f.step(); err != nil {
		return nil, err
	}
	return qu.QueryContext(ctx, q, args)
}

func (c *faultConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	if err := c.f.step(); err != nil {
		return nil, err
	}
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, q)
	}
	return c.Conn.Prepare(q)
}

func (c *faultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	b, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, errNoBeginTx
	}
	if err := c.f.step(); err != nil {
		return nil, err
	}
	tx, err := b.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &faultTx{Tx: tx, f: c.f}, nil
}

// faultTx fails Commit on its turn; Rollback always runs, because a rollback
// that fails would leave the pool's connection in a state no real failure
// produces.
type faultTx struct {
	driver.Tx
	f *Faults
}

func (t *faultTx) Commit() error {
	if err := t.f.step(); err != nil {
		_ = t.Tx.Rollback()
		return err
	}
	return t.Tx.Commit()
}

// WithFaults runs the Env's SQLite through f (Faults.Connector): every
// database call the Env makes, migrations included, passes f's counter,
// which stays disarmed until the test arms it. Env.Faults is f. It applies
// to the SQLite New opens (WithSQLite included), not to WithDB.
//
//ds:def id=authtest-withfaults-5rm9xc2p owner=@khanakia stability=stable
func WithFaults(f *Faults) Option { return func(s *settings) { s.faults = f } }

// faultDB opens driverName's driver through f, on dsn.
func faultDB(driverName, dsn string, f *Faults) (*sql.DB, error) {
	probe, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, err
	}
	d := probe.Driver()
	_ = probe.Close() // sql.Open connects lazily; the probe held nothing
	return sql.OpenDB(f.Connector(DSNConnector(d, dsn))), nil
}

// SweepT is what SweepFaults needs of a test: *testing.T satisfies it, and
// so does a recorder in the harness's own tests.
type SweepT interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
}

// SweepFaults proves that an operation surfaces every database failure it
// can meet. It runs the operation once per database call it makes, each
// time on a fresh state from fresh with a different call failing, until a
// run finishes without reaching the armed call.
//
// fresh builds a new database and returns it with its Faults (for an Env:
// New with WithFaults); setup prepares the state the operation needs, with
// faults off, and returns the operation. Every faulted run must return an
// error: a nil error after a fault means a failure was swallowed, and the
// operation reported success for work that did not happen. swallowOK names
// the steps where swallowing is the documented behaviour (a best-effort
// "last used" update, say), so an intentional one is written down at the
// test rather than silently allowed.
//
//ds:def id=authtest-sweepfaults-2pz7wk4d owner=@khanakia stability=stable
func SweepFaults[E any](t SweepT, fresh func() (E, *Faults), setup func(e E) func(ctx context.Context) error, swallowOK ...int) {
	t.Helper()
	allowed := map[int]bool{}
	for _, s := range swallowOK {
		allowed[s] = true
	}
	for k := 1; k <= MaxFaultSteps; k++ {
		e, f := fresh()
		op := setup(e)
		f.Arm(k)
		err := op(context.Background())
		if !f.Disarm() {
			if err != nil {
				t.Fatalf("run with no fault reached (step %d) failed: %v", k, err)
				return
			}
			if k == 1 {
				t.Fatalf("the operation made no database call; the sweep proves nothing")
				return
			}
			t.Logf("swept %d database calls", k-1)
			return
		}
		if err == nil && !allowed[k] {
			t.Errorf("fault at database call %d was swallowed: the operation returned no error", k)
		}
	}
	t.Fatalf("no run finished within %d database calls", MaxFaultSteps)
}
