package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/webhook"
	"github.com/ubgo/sqlb"
)

// The never-send-twice guarantee: a send reads its delivery, then claims it
// with an UPDATE conditioned on the attempts count it read. A second sender
// (the post-commit send and a Maintain run, or two Maintain runs) that
// claimed the row in between makes that UPDATE match nothing, and the send
// must stop without a POST. The window sits between two of the send's own
// database calls, so the test opens it deterministically: a connection
// wrapper runs the other sender's claim on the same database the moment the
// send reads its endpoint, which is the read between the two.

// claimRace wraps a connector; once armed, the next query that reads the
// endpoint table first runs steal on the same connection.
type claimRace struct {
	base driver.Connector

	mu    sync.Mutex
	steal string // the other sender's UPDATE; "" when disarmed
	arg   string
	fired bool
}

func (c *claimRace) arm(update, id string) {
	c.mu.Lock()
	c.steal, c.arg, c.fired = update, id, false
	c.mu.Unlock()
}

// take returns the armed statement once and disarms.
func (c *claimRace) take() (string, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.steal == "" {
		return "", "", false
	}
	q, a := c.steal, c.arg
	c.steal, c.fired = "", true
	return q, a, true
}

func (c *claimRace) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &raceConn{Conn: conn, race: c}, nil
}

func (c *claimRace) Driver() driver.Driver { return c.base.Driver() }

// raceConn forwards to the wrapped SQLite connection.
type raceConn struct {
	driver.Conn
	race *claimRace
}

func (c *raceConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func (c *raceConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT") && strings.Contains(q, webhook.TableNameEndpoint) {
		if steal, id, ok := c.race.take(); ok {
			if _, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, steal, []driver.NamedValue{{Ordinal: 1, Value: id}}); err != nil {
				return nil, err
			}
		}
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

func (c *raceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

// claimRaceDSN is a private in-memory database shared by the pool's
// connections, with the busy timeout the library needs.
const claimRaceDSN = "file:webhook-claim-race?mode=memory&cache=shared&_pragma=busy_timeout(5000)"

// TestWebhooks_ClaimedElsewhereIsNeverSentTwice: a send whose delivery was
// claimed by another sender after it read the row sends nothing and leaves
// the other sender's claim as it is.
func TestWebhooks_ClaimedElsewhereIsNeverSentTwice(t *testing.T) {
	probe, err := sql.Open("sqlite", claimRaceDSN)
	if err != nil {
		t.Fatal(err)
	}
	race := &claimRace{base: authtest.DSNConnector(probe.Driver(), claimRaceDSN)}
	_ = probe.Close() // only its driver was needed
	db := sql.OpenDB(race)
	t.Cleanup(func() { _ = db.Close() })

	q := &queue{}
	hooks := webhook.New(webhook.AllowPrivateNetworks())
	e := authtest.New(t,
		authtest.WithDB(db, sqlb.SQLiteDialect{}),
		authtest.WithOptions(auth.WithSecret(testSecret), auth.WithBackground(q.run)),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins(hooks) }))
	t.Cleanup(q.drain)
	s := newSink(t)
	s.now = e.Clock.Now
	ctx := context.Background()
	_, secret, err := hooks.CreateEndpoint(ctx, webhook.EndpointInput{URL: s.srv.URL + receiverPath})
	if err != nil {
		t.Fatal(err)
	}
	s.setSecret(secret)
	if err := hooks.Publish(ctx, "app.thing.done", map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	page, err := hooks.Deliveries(ctx, webhook.DeliveryQuery{})
	if err != nil || len(page.Deliveries) != 1 {
		t.Fatalf("deliveries = %+v, %v", page, err)
	}
	d := page.Deliveries[0]

	// The other sender's claim: one more attempt on the row, exactly what
	// the plugin's own claim writes.
	race.arm("UPDATE "+e.Auth.TableName(webhook.TableDelivery)+" SET "+webhook.ColAttempts+" = "+webhook.ColAttempts+" + 1 WHERE "+webhook.ColID+" = ?", d.ID)
	q.drain() // the held post-commit send: reads the row, loses the claim
	race.mu.Lock()
	fired := race.fired
	race.mu.Unlock()
	if !fired {
		t.Fatal("the send never read its endpoint; the race window was not opened")
	}
	if accepted, refused := s.count(); accepted+refused != 0 {
		t.Fatalf("a delivery claimed by another sender was sent again: %d requests", accepted+refused)
	}
	got, err := hooks.Delivery(ctx, d.ID)
	if err != nil || got.Status != webhook.StatusPending || got.Attempts != 1 || got.LastStatus != 0 {
		t.Fatalf("after losing the claim: %+v, %v", got, err)
	}
}
