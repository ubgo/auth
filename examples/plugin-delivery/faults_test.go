package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ubgo/sqlb"
	"modernc.org/sqlite"
)

// dialect is the SQL dialect of the test database.
var dialect = sqlb.SQLiteDialect{}

// errFault is what an injected database failure returns, so a test can tell
// it from any other error.
var errFault = errors.New("plugin-delivery: injected database fault")

// maxFaultSteps bounds a sweep: no operation makes this many database calls,
// so reaching it means the operation never finished without a fault.
const maxFaultSteps = 200

// faults counts database calls and fails the one numbered at. Armed, the
// at-th call of any kind (exec, query, prepare, begin, commit) returns
// errFault; disarmed, every call passes.
//
// Why a driver and not a mock: the plugin talks to *sql.DB through the core,
// and the only honest way to reach its "the database failed here" branches is
// to make a real database fail at that exact call. Counting calls instead of
// matching SQL keeps the test independent of the queries' wording.
//
//ds:def id=faults-mcqs6jyk
type faults struct {
	mu    sync.Mutex
	armed bool
	n, at int
	hit   bool
}

func (f *faults) arm(at int) {
	f.mu.Lock()
	f.armed, f.n, f.at, f.hit = true, 0, at, false
	f.mu.Unlock()
}

// disarm stops counting and reports whether the armed call was reached.
func (f *faults) disarm() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.armed = false
	return f.hit
}

//ds:def id=faults-step-8m4cqp4s
func (f *faults) step() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.armed {
		return nil
	}
	f.n++
	if f.n == f.at {
		f.hit = true
		return errFault
	}
	return nil
}

// faultConnector opens SQLite connections wrapped so every call goes through
// faults.step first.
type faultConnector struct {
	dsn string
	f   *faults
}

// Connect opens one wrapped connection.
func (c faultConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &faultConn{Conn: conn, f: c.f}, nil
}

// Driver is the underlying SQLite driver.
func (c faultConnector) Driver() driver.Driver { return &sqlite.Driver{} }

// faultConn forwards to the SQLite connection through the context interfaces
// database/sql prefers, so every statement passes through step exactly once.
type faultConn struct {
	driver.Conn
	f *faults
}

// inner narrows the wrapped connection to one of the context interfaces,
// which the SQLite driver implements; a failed assertion would mean the
// driver changed, and the panic says so.
func inner[T any](c driver.Conn) T {
	v, ok := c.(T)
	if !ok {
		panic("plugin-delivery: sqlite connection lacks a context interface the fault driver needs")
	}
	return v
}

//ds:def id=faultconn-execcontext-8ffryhwv
func (c *faultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.f.step(); err != nil {
		return nil, err
	}
	return inner[driver.ExecerContext](c.Conn).ExecContext(ctx, q, args)
}

func (c *faultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if err := c.f.step(); err != nil {
		return nil, err
	}
	return inner[driver.QueryerContext](c.Conn).QueryContext(ctx, q, args)
}

func (c *faultConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	if err := c.f.step(); err != nil {
		return nil, err
	}
	return inner[driver.ConnPrepareContext](c.Conn).PrepareContext(ctx, q)
}

func (c *faultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if err := c.f.step(); err != nil {
		return nil, err
	}
	tx, err := inner[driver.ConnBeginTx](c.Conn).BeginTx(ctx, opts)
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
	f *faults
}

// Commit fails on its turn, rolling back first.
func (t *faultTx) Commit() error {
	if err := t.f.step(); err != nil {
		_ = t.Tx.Rollback()
		return err
	}
	return t.Tx.Commit()
}

// openFaultDB opens a fresh SQLite file whose every call can be made to fail.
func openFaultDB(t *testing.T) (*sql.DB, *faults) {
	t.Helper()
	f := &faults{}
	dsn := "file:" + filepath.Join(t.TempDir(), dbFile) + sqlitePragmas
	db := sql.OpenDB(faultConnector{dsn: dsn, f: f})
	t.Cleanup(func() { _ = db.Close() })
	return db, f
}

// sweepFaults proves that an operation surfaces every database failure it
// can meet. It runs the operation once per database call it makes, each time
// on a fresh database with a different call failing, until a run finishes
// without reaching the armed call. setup builds the state the operation
// needs, with faults off, and returns the operation. Every faulted run must
// return an error: a nil error after a fault means the operation reported
// success for work that did not happen.
//
//ds:def id=sweepfaults-xx3u9wd8
func sweepFaults(t *testing.T, setup func(t *testing.T, db *sql.DB) func(ctx context.Context) error) {
	t.Helper()
	for k := 1; k <= maxFaultSteps; k++ {
		db, f := openFaultDB(t)
		op := setup(t, db)
		f.arm(k)
		err := op(context.Background())
		if !f.disarm() {
			if err != nil {
				t.Fatalf("run with no fault reached (step %d) failed: %v", k, err)
			}
			if k == 1 {
				t.Fatal("the operation made no database call; the sweep proves nothing")
			}
			t.Logf("swept %d database calls", k-1)
			return
		}
		if err == nil {
			t.Errorf("fault at database call %d was swallowed: the operation returned no error", k)
		}
	}
	t.Fatalf("no run finished within %d database calls", maxFaultSteps)
}
