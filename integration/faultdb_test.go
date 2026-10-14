package integration

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"path/filepath"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/sqlb"
	"modernc.org/sqlite"
)

// errFault is the error an injected database failure returns. Tests compare
// against it to prove the failure reached the caller rather than being eaten.
var errFault = authtest.ErrFault

// maxFaultSteps bounds a sweep; see authtest.MaxFaultSteps.
const maxFaultSteps = authtest.MaxFaultSteps

// faults is the public fault counter (authtest.Faults) under the names the
// suite has always used, so the driver lives in one place, the one plugin
// authors import, and this suite keeps testing it.
type faults struct{ *authtest.Faults }

func (f faults) arm(at int)   { f.Arm(at) }
func (f faults) disarm() bool { return f.Disarm() }

// faultEnv is an env whose database fails on demand.
type faultEnv struct {
	*env
	f faults
}

func newFaultEnv(t *testing.T) *faultEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	dsn := sqliteDSN(path, sqlitePragmas)
	f := faults{authtest.NewFaults()}
	db := sql.OpenDB(f.Connector(authtest.DSNConnector(&sqlite.Driver{}, dsn)))
	t.Cleanup(func() { db.Close() })
	return &faultEnv{env: newEnv(t, auth.EngineSQLite, db, sqlb.SQLiteDialect{}), f: f}
}

// sweepFaults runs authtest.SweepFaults on a fresh faultEnv per step.
func sweepFaults(t *testing.T, setup func(t *testing.T, e *faultEnv) func(ctx context.Context) error, swallowOK ...int) {
	t.Helper()
	authtest.SweepFaults(t,
		func() (*faultEnv, *authtest.Faults) { e := newFaultEnv(t); return e, e.f.Faults },
		func(e *faultEnv) func(context.Context) error { return setup(t, e) },
		swallowOK...)
}

// inner narrows a wrapped SQLite connection to a context interface, for the
// suite's own wrapping drivers. The SQLite driver implements all of them; a
// failed assertion would mean the driver changed, and the panic names that
// rather than letting a test pass through a slower path.
func inner[T any](c driver.Conn) T {
	v, ok := c.(T)
	if !ok {
		panic("integration: sqlite connection lacks a context interface the test driver needs")
	}
	return v
}
