package authgin

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// sessionUserID is the user every session lookup on sessionDB finds.
const sessionUserID = "usr_signed_in"

// sessionAuth returns an Auth whose every session lookup finds a live session
// of sessionUserID, so the adapter's signed-in paths run without a database.
//
// This module has no SQL driver on purpose (a real one would reach the go.sum
// of every app that imports the adapter), and the adapter code under test
// never looks at SQL. The same file is copied into each contrib module because
// modules cannot share test code; keep the copies identical.
func sessionAuth(t *testing.T, plugins ...auth.Plugin) *auth.Auth {
	t.Helper()
	// The dialect is the core's default, read from an Auth with no database:
	// sessionDB ignores the SQL text, and naming a dialect here would make
	// sqlb a direct requirement of this module.
	probe, err := auth.New(auth.WithPlugins(plugins...))
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(sessionDB{})
	t.Cleanup(func() { db.Close() })
	a, err := auth.New(auth.WithBaseURL(sessionBaseURL), auth.WithDB(db, probe.Dialect()), auth.WithPlugins(plugins...))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// sessionBaseURL is the app origin of sessionAuth; a cookie-authenticated
// mutation must send it as its Origin.
const sessionBaseURL = "https://app.example.com"

// sessionDB is a database/sql connector whose every query returns one live
// session row joined to its user, and whose every exec and transaction
// succeeds. The row's column order is auth.SessionBindings then
// auth.UserBindings, which is what the core's session lookup selects; a new
// column there fails these tests with a scan error, never silently.
type sessionDB struct{}

func (sessionDB) Connect(context.Context) (driver.Conn, error) { return sessionConn{}, nil }
func (sessionDB) Driver() driver.Driver                        { return nil }

type sessionConn struct{}

var errSessionDBPrepare = errors.New("sessionDB: prepared statements are not served")

func (sessionConn) Prepare(string) (driver.Stmt, error) { return nil, errSessionDBPrepare }
func (sessionConn) Close() error                        { return nil }
func (sessionConn) Begin() (driver.Tx, error)           { return sessionTx{}, nil }
func (sessionConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &sessionRows{}, nil
}
func (sessionConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

type sessionTx struct{}

func (sessionTx) Commit() error   { return nil }
func (sessionTx) Rollback() error { return nil }

type sessionRows struct{ done bool }

func (*sessionRows) Columns() []string { return make([]string, len(sessionRow())) }
func (*sessionRows) Close() error      { return nil }
func (r *sessionRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, sessionRow())
	return nil
}

func sessionRow() []driver.Value {
	now := time.Now().UTC()
	return []driver.Value{
		"ses_1", sessionUserID, now.Add(time.Hour), now, "203.0.113.7", "test", now, false, nil, false, int64(0), int64(0), nil, nil, nil, nil, nil, // session: ..., max expiry, revoked at, data, reauthenticated at, tasks
		sessionUserID, "Ada", "", now, now, nil, // user: ..., sessions valid after
	}
}
