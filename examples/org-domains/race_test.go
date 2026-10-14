package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/sqlb"
)

// decideRace wraps a connector; once armed, the next UPDATE of the
// membership-request table first runs steal on the same connection: another
// admin's decision landing between this one's read of the request and its
// write.
type decideRace struct {
	base driver.Connector

	mu    sync.Mutex
	steal string
	arg   string
	fired bool
}

func (c *decideRace) arm(q, arg string) {
	c.mu.Lock()
	c.steal, c.arg, c.fired = q, arg, false
	c.mu.Unlock()
}

func (c *decideRace) take() (string, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.steal == "" {
		return "", "", false
	}
	q, a := c.steal, c.arg
	c.steal, c.fired = "", true
	return q, a, true
}

func (c *decideRace) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &decideConn{Conn: conn, race: c}, nil
}

func (c *decideRace) Driver() driver.Driver { return c.base.Driver() }

// decideConn forwards to the wrapped SQLite connection.
type decideConn struct {
	driver.Conn
	race *decideRace
}

func (c *decideConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	exec := c.Conn.(driver.ExecerContext)
	if strings.HasPrefix(q, "UPDATE") && strings.Contains(q, organization.TableNameDomainRequest) {
		if steal, arg, ok := c.race.take(); ok {
			if _, err := exec.ExecContext(ctx, steal, []driver.NamedValue{{Ordinal: 1, Value: arg}}); err != nil {
				return nil, err
			}
		}
	}
	return exec.ExecContext(ctx, q, args)
}

func (c *decideConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

func (c *decideConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

// decideRaceDSN is a private in-memory database shared by the pool's
// connections.
const decideRaceDSN = "file:org-domains-decide-race?mode=memory&cache=shared&_pragma=busy_timeout(5000)"

// TestDomains_RequestDecidedConcurrently: an approval whose request another
// admin rejected after it was read is refused, and the requester is not left
// a member by the approval's half-done work.
func TestDomains_RequestDecidedConcurrently(t *testing.T) {
	probe, err := sql.Open("sqlite", decideRaceDSN)
	if err != nil {
		t.Fatal(err)
	}
	race := &decideRace{base: authtest.DSNConnector(probe.Driver(), decideRaceDSN)}
	_ = probe.Close() // only its driver was needed
	db := sql.OpenDB(race)
	t.Cleanup(func() { _ = db.Close() })

	w := newWorldWith(t, nil, []authtest.Option{authtest.WithDB(db, sqlb.SQLiteDialect{})}, nil)
	d := w.addDomain(t, "acme.com", organization.EnrollSuggestion, "")
	dave := w.user("Dave", "dave@acme.com")
	r, err := w.org.AcceptSuggestion(w.ctx(dave), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	race.arm("UPDATE "+w.e.Auth.TableName(organization.TableDomainRequest)+" SET "+organization.ColRequestStatus+" = '"+string(organization.RequestRejected)+"' WHERE "+organization.ColRequestID+" = ?", r.ID)
	err = w.org.ApproveMembershipRequest(w.ctx(w.alice), r.ID)
	race.mu.Lock()
	fired := race.fired
	race.mu.Unlock()
	if !fired {
		t.Fatal("the approval never wrote its decision; the race window was not opened")
	}
	if !errors.Is(err, organization.ErrRequestInvalid) {
		t.Fatalf("approving a request rejected meanwhile: %v", err)
	}
	if _, err := w.org.RoleOf(context.Background(), w.acme.ID, dave.Session.UserID); !errors.Is(err, organization.ErrNotMember) {
		t.Fatalf("the lost approval left dave a member: %v", err)
	}
}

// TestDomains_ApprovalAfterCreatorRoleChanged: a domain granting admin,
// then a deploy that makes admin the creator role. An owner, who no longer
// holds the creator role, cannot approve someone into it.
func TestDomains_ApprovalAfterCreatorRoleChanged(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	shared := []authtest.Option{authtest.WithDB(db, sqlb.SQLiteDialect{})}

	before := newWorldWith(t, nil, shared, nil)
	d := before.addDomain(t, "acme.com", organization.EnrollSuggestion, organization.RoleAdmin)
	dave := before.user("Dave", "dave@acme.com")
	r, err := before.org.AcceptSuggestion(before.ctx(dave), d.ID)
	if err != nil {
		t.Fatal(err)
	}

	// The same database under the new configuration.
	after := buildWorld(t, nil, shared, []organization.Option{organization.CreatorRole(organization.RoleAdmin)})
	owner := after.e.SignIn(before.alice.Session.UserID)
	err = after.org.ApproveMembershipRequest(owner.Context(context.Background()), r.ID)
	if !errors.Is(err, organization.ErrForbidden) {
		t.Fatalf("an owner approving into the new creator role: %v", err)
	}
	if _, err := after.org.RoleOf(context.Background(), before.acme.ID, dave.Session.UserID); !errors.Is(err, organization.ErrNotMember) {
		t.Fatalf("dave joined anyway: %v", err)
	}
}
