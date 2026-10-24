package main

import (
	"context"
	"database/sql/driver"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth/plugin/twofactor"
)

// The single-use guarantee of a TOTP code: verify reads the factor, matches
// the code to a step, then records the step with an UPDATE conditioned on
// the step it read being older. A second request that spent the same code
// in between makes that UPDATE match nothing, and the code must be refused,
// not accepted twice. The window sits between two of verify's own database
// calls, so the test opens it deterministically: a connection wrapper runs
// the other request's spend, on the same connection and transaction, the
// moment verify sends its UPDATE.

// spendRace wraps a connector; once armed for a table, the next UPDATE of
// that table's last_step first runs steal.
type spendRace struct {
	base driver.Connector

	mu    sync.Mutex
	table string // the factor table whose spend is raced; "" when disarmed
	steal string
	args  []driver.NamedValue
	fired bool
}

func (c *spendRace) arm(table, steal string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.table, c.steal, c.fired = table, steal, false
	c.args = c.args[:0]
	for i, a := range args {
		c.args = append(c.args, driver.NamedValue{Ordinal: i + 1, Value: a})
	}
}

// take returns the steal once when q is the armed table's spend.
func (c *spendRace) take(q string) (string, []driver.NamedValue, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.table == "" || !strings.HasPrefix(q, `UPDATE "`+c.table+`" `) || !strings.Contains(q, twofactor.ColLastStep) {
		return "", nil, false
	}
	c.table, c.fired = "", true
	return c.steal, c.args, true
}

func (c *spendRace) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &spendConn{Conn: conn, race: c}, nil
}

func (c *spendRace) Driver() driver.Driver { return c.base.Driver() }

// spendConn forwards to the wrapped connection.
type spendConn struct {
	driver.Conn
	race *spendRace
}

func (c *spendConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	ex := c.Conn.(driver.ExecerContext)
	if steal, sargs, ok := c.race.take(q); ok {
		if _, err := ex.ExecContext(ctx, steal, sargs); err != nil {
			return nil, err
		}
	}
	return ex.ExecContext(ctx, q, args)
}

func (c *spendConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

func (c *spendConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

// spentLater is a step far past any real one: what the other request's
// spend leaves in last_step, so the raced UPDATE's condition fails.
const spentLater = int64(1) << 40

// TestFactors_CodeSpentElsewhereIsRefused: a code that another request
// spent after verify read the factor is refused, for the first factor's
// row and for an added app's row alike, and the session stays pending.
func TestFactors_CodeSpentElsewhereIsRefused(t *testing.T) {
	race := &spendRace{}
	w := newWorld(t, worldConfig{wrap: func(base driver.Connector) driver.Connector { race.base = base; return race }})

	// The first factor: an authenticator app in auth_two_factor.
	al := w.signUp(alice)
	w.enrolTOTP(al)
	ptok := w.pending(al)
	code := w.totpNow(al)
	race.arm(twofactor.TableNameFactor, "UPDATE "+twofactor.TableNameFactor+" SET "+twofactor.ColLastStep+" = ? WHERE "+twofactor.ColUserID+" = ?", spentLater, al.id)
	w.refuse(http.MethodPost, "/auth/twofactor/verify", ptok, fields{"code": code}, twofactor.ErrCodeInvalid.Code)
	if !race.fired {
		t.Fatal("verify never recorded its step; the race window was not opened")
	}
	w.must(http.MethodGet, "/auth/twofactor/status", ptok, nil, http.StatusOK)
	w.must(http.MethodGet, "/me", ptok, nil, http.StatusUnauthorized)

	// An added app: a row of auth_two_factor_method.
	bb := w.signUp(bob)
	w.addKey(bb, nil)
	var enr twofactor.EnrollResult
	mustJSON(t, w.must(http.MethodPost, "/auth/twofactor/enroll", bb.tok, obj{"method": "totp", "proof": obj{"code": bb.recovery()}}, http.StatusOK), &enr)
	bb.secret = enr.Secret
	w.must(http.MethodPost, "/auth/twofactor/confirm", bb.tok, fields{"method": "totp", "code": w.totpNow(bb)}, http.StatusOK)
	btok := w.pending(bb)
	code = w.totpNow(bb)
	race.arm(twofactor.TableNameMethod, "UPDATE "+twofactor.TableNameMethod+" SET "+twofactor.ColLastStep+" = ? WHERE "+twofactor.ColUserID+" = ?", spentLater, bb.id)
	w.refuse(http.MethodPost, "/auth/twofactor/verify", btok, fields{"method": "totp", "code": code}, twofactor.ErrCodeInvalid.Code)
	if !race.fired {
		t.Fatal("verify never recorded the added app's step; the race window was not opened")
	}
	w.must(http.MethodGet, "/me", btok, nil, http.StatusUnauthorized)
}
