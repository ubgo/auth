package authtest

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// fakeDriver opens fakeConn, or ctxConn when ctx is set, and fails Open
// when openErr is set. It stands in for a real driver so the fault
// connector's paths, the context ones and the fallbacks, run with no
// database.
type fakeDriver struct {
	ctx     bool
	openErr error
}

func (d fakeDriver) Open(string) (driver.Conn, error) {
	if d.openErr != nil {
		return nil, d.openErr
	}
	if d.ctx {
		return &ctxConn{}, nil
	}
	return &fakeConn{}, nil
}

// fakeConn implements only driver.Conn: no context interface.
type fakeConn struct{}

func (*fakeConn) Prepare(string) (driver.Stmt, error) { return fakeStmt{}, nil }
func (*fakeConn) Close() error                        { return nil }
func (*fakeConn) Begin() (driver.Tx, error)           { return fakeTx{}, nil }

// ctxConn adds every context interface.
type ctxConn struct{ fakeConn }

func (*ctxConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (*ctxConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return fakeRows{}, nil
}
func (*ctxConn) PrepareContext(context.Context, string) (driver.Stmt, error) { return fakeStmt{}, nil }
func (*ctxConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return fakeTx{}, nil
}

type fakeStmt struct{}

func (fakeStmt) Close() error                               { return nil }
func (fakeStmt) NumInput() int                              { return -1 }
func (fakeStmt) Exec([]driver.Value) (driver.Result, error) { return driver.RowsAffected(1), nil }
func (fakeStmt) Query([]driver.Value) (driver.Rows, error)  { return fakeRows{}, nil }

type fakeRows struct{}

func (fakeRows) Columns() []string         { return nil }
func (fakeRows) Close() error              { return nil }
func (fakeRows) Next([]driver.Value) error { return io.EOF }

type fakeTx struct{}

func (fakeTx) Commit() error   { return nil }
func (fakeTx) Rollback() error { return nil }

// faultyDB opens a fake database through a fresh Faults.
func faultyDB(t *testing.T, d fakeDriver) (*sql.DB, *Faults) {
	t.Helper()
	f := NewFaults()
	db := sql.OpenDB(f.Connector(DSNConnector(d, "")))
	t.Cleanup(func() { _ = db.Close() })
	return db, f
}

// TestFaults_FailsTheArmedCallOfEveryKind: the armed call fails with
// ErrFault whatever its kind, the calls before it pass, Disarm reports
// whether it was reached, and a disarmed counter fails nothing.
func TestFaults_FailsTheArmedCallOfEveryKind(t *testing.T) {
	ctx := context.Background()
	db, f := faultyDB(t, fakeDriver{ctx: true})
	calls := map[string]func() error{
		"exec":  func() error { _, err := db.ExecContext(ctx, "x"); return err },
		"query": func() error { _, err := db.QueryContext(ctx, "x"); return err },
		"prepare": func() error {
			st, err := db.PrepareContext(ctx, "x")
			if err == nil {
				_ = st.Close()
			}
			return err
		},
		"begin": func() error { _, err := db.BeginTx(ctx, nil); return err },
		"commit": func() error {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			return tx.Commit()
		},
	}
	for name, call := range calls {
		at := 1
		if name == "commit" {
			at = 2
		}
		f.Arm(at)
		if err := call(); !errors.Is(err, ErrFault) {
			t.Errorf("%s at call %d: %v, want ErrFault", name, at, err)
		}
		if !f.Disarm() {
			t.Errorf("%s: Disarm did not report the armed call", name)
		}
		if err := call(); err != nil {
			t.Errorf("%s disarmed: %v", name, err)
		}
	}
	f.Arm(5)
	if _, err := db.ExecContext(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if f.Disarm() {
		t.Fatal("Disarm reported a call that was never reached")
	}
}

// TestFaults_ConnectionsWithoutContextInterfaces: a driver with no
// ExecerContext or QueryerContext is counted once per statement, through
// the prepare database/sql falls back to; one with no ConnBeginTx refuses a
// transaction by name; a driver that cannot open is reported.
func TestFaults_ConnectionsWithoutContextInterfaces(t *testing.T) {
	ctx := context.Background()
	db, f := faultyDB(t, fakeDriver{})
	f.Arm(1)
	if _, err := db.ExecContext(ctx, "x"); !errors.Is(err, ErrFault) {
		t.Fatalf("exec through prepare: %v", err)
	}
	f.Arm(2)
	if _, err := db.ExecContext(ctx, "x"); err != nil {
		t.Fatalf("one exec must be one call: %v", err)
	}
	if f.Disarm() {
		t.Fatal("an exec was counted twice")
	}
	f.Arm(1)
	if _, err := db.QueryContext(ctx, "x"); !errors.Is(err, ErrFault) {
		t.Fatalf("query through prepare: %v", err)
	}
	f.Disarm()
	if _, err := db.BeginTx(ctx, nil); !errors.Is(err, errNoBeginTx) {
		t.Fatalf("begin without ConnBeginTx: %v", err)
	}
	broken, _ := faultyDB(t, fakeDriver{openErr: errors.New("no database")})
	if err := broken.PingContext(ctx); err == nil || !strings.Contains(err.Error(), "no database") {
		t.Fatalf("open failure: %v", err)
	}
	if _, err := faultDB("authtest-no-such-driver", "", NewFaults()); err == nil {
		t.Fatal("an unregistered driver opened")
	}
}

// sweepRecorder records what SweepFaults reports.
type sweepRecorder struct{ errs, fatals, logs []string }

func (r *sweepRecorder) Helper() {}
func (r *sweepRecorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *sweepRecorder) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}
func (r *sweepRecorder) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

// TestSweepFaults_CatchesEverySwallowedFault: an operation that returns
// every fault passes after one run per call; one that swallows a fault is
// reported at that step unless swallowOK names it; one that makes no call,
// fails with no fault, or never finishes is a fatal error.
func TestSweepFaults_CatchesEverySwallowedFault(t *testing.T) {
	ctx := context.Background()
	fresh := func() (*sql.DB, *Faults) { return faultyDB(t, fakeDriver{ctx: true}) }
	calls := func(n int, swallow int) func(db *sql.DB) func(context.Context) error {
		return func(db *sql.DB) func(context.Context) error {
			return func(context.Context) error {
				for i := 1; i <= n; i++ {
					if _, err := db.ExecContext(ctx, "x"); err != nil && i != swallow {
						return err
					}
				}
				return nil
			}
		}
	}
	for name, c := range map[string]struct {
		setup       func(db *sql.DB) func(context.Context) error
		swallowOK   []int
		errs, fatal int
		log         string
	}{
		"every fault surfaces":   {setup: calls(3, 0), log: "swept 3 database calls"},
		"a swallowed fault":      {setup: calls(3, 2), errs: 1},
		"a swallow written down": {setup: calls(3, 2), swallowOK: []int{2}, log: "swept 3"},
		"no database call":       {setup: calls(0, 0), fatal: 1},
		"never finishes":         {setup: calls(MaxFaultSteps+1, 0), fatal: 1},
		"fails with no fault":    {setup: func(*sql.DB) func(context.Context) error { return func(context.Context) error { return io.EOF } }, fatal: 1},
	} {
		r := &sweepRecorder{}
		SweepFaults(r, fresh, c.setup, c.swallowOK...)
		if len(r.errs) != c.errs || len(r.fatals) != c.fatal {
			t.Errorf("%s: errors %q fatals %q", name, r.errs, r.fatals)
		}
		if c.log != "" && (len(r.logs) != 1 || !strings.Contains(r.logs[0], c.log)) {
			t.Errorf("%s: logs %q, want %q", name, r.logs, c.log)
		}
	}
}
