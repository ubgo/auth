package auth

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/sqlb"
)

// failingDropper is a server-side cache whose DropUser fails.
type failingDropper struct{ SessionCache }

func (failingDropper) DropUser(context.Context, string) error { return errors.New("cache down") }

// TestEvictCachedSessions_DropsEveryEntryOfTheUserOnly: outside a
// transaction the drop runs at once, takes every entry of the user and
// leaves another user's; a cache that cannot find entries by user, or no
// cache at all, reports false; a failing drop is logged, never returned.
func TestEvictCachedSessions_DropsEveryEntryOfTheUserOnly(t *testing.T) {
	ctx := context.Background()
	mem := NewMemorySessionCache(8)
	a, err := New(WithPlugins(scriptSignIn{}), WithSessionCache(mem, 0))
	if err != nil {
		t.Fatal(err)
	}
	now := a.now()
	until := now.Add(time.Minute)
	keys := map[string]CacheKey{}
	for tok, user := range map[string]string{"t1": "u1", "t2": "u1", "t3": "u2"} {
		keys[tok] = CacheKey{TokenHash: HashToken(Token(tok))}
		if _, err := mem.Put(ctx, keys[tok], Session{ID: "s" + tok, UserID: user, ExpiresAt: until}, User{ID: user}, until); err != nil {
			t.Fatal(err)
		}
	}
	if !a.EvictCachedSessions(ctx, "u1") {
		t.Fatal("the memory cache can evict by user")
	}
	for tok, want := range map[string]bool{"t1": false, "t2": false, "t3": true} {
		if _, _, ok, _ := mem.Get(ctx, keys[tok], now); ok != want {
			t.Errorf("entry %s present = %v, want %v", tok, ok, want)
		}
	}

	for name, opts := range map[string][]Option{
		"no cache":       nil,
		"snapshot cache": {WithSessionCache(NewSnapshotCache(sessKey), 0)},
		"compact cache":  {WithSessionCache(NewCompactSessionCache(sessKey), 0)},
	} {
		b, err := New(append(opts, WithPlugins(scriptSignIn{}))...)
		if err != nil {
			t.Fatal(err)
		}
		if b.EvictCachedSessions(ctx, "u1") {
			t.Errorf("%s: EvictCachedSessions = true, but nothing can be evicted", name)
		}
	}

	var buf bytes.Buffer
	f, err := New(WithPlugins(scriptSignIn{}), WithSessionCache(failingDropper{NewMemorySessionCache(1)}, 0),
		WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	if err != nil {
		t.Fatal(err)
	}
	if !f.EvictCachedSessions(ctx, "u1") {
		t.Fatal("a dropper reports true")
	}
	if !strings.Contains(buf.String(), "session cache eviction failed") || !strings.Contains(buf.String(), "cache down") {
		t.Fatalf("the failure was not logged: %q", buf.String())
	}
}

// outboxMail is a kind plugin for the outbox tests: it owns the kind "mail"
// and records or fails its deliveries.
type outboxMail struct {
	mu   sync.Mutex
	sent []string
	err  error
}

func (*outboxMail) Name() string  { return "mail" }
func (*outboxMail) SignsIn() bool { return true }
func (*outboxMail) Identifiers() []IdentifierKind {
	return []IdentifierKind{{Name: "mail", Unique: true, UniqueOnlyVerified: true, CanLogin: true, Normalize: func(s string) (string, error) { return s, nil }}}
}
func (m *outboxMail) Deliver(_ context.Context, to Identity, msg Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, to.Value+" "+msg.Link)
	return nil
}

// outboxAuth is an Auth with the outbox on the script database.
func outboxAuth(t *testing.T, s *script, d sqlb.Dialect, m *outboxMail, opts ...Option) *Auth {
	t.Helper()
	db := sql.OpenDB(s)
	t.Cleanup(func() { db.Close() })
	a, err := New(append([]Option{WithDB(db, d), WithPlugins(m), WithDeliveryOutbox(sessKey)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestWithDeliveryOutbox_Refusals: the outbox needs a database and a key,
// and is off unless asked for.
func TestWithDeliveryOutbox_Refusals(t *testing.T) {
	m := &outboxMail{}
	if _, err := New(WithPlugins(m), WithDeliveryOutbox(sessKey)); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("no database: %v", err)
	}
	db := sql.OpenDB(&script{})
	t.Cleanup(func() { db.Close() })
	if _, err := New(WithDB(db, sqlb.SQLiteDialect{}), WithPlugins(m), WithDeliveryOutbox()); !errors.Is(err, ErrNoKeys) {
		t.Errorf("no key and no secret: %v", err)
	}
	if _, err := New(WithDB(db, sqlb.SQLiteDialect{}), WithPlugins(m), WithDeliveryOutbox([]byte("short"))); !errors.Is(err, ErrBadOperation) {
		t.Errorf("a short key: %v", err)
	}
	if _, err := New(WithDB(db, sqlb.SQLiteDialect{}), WithPlugins(m), WithSecret(bytes.Repeat([]byte{7}, 32)), WithDeliveryOutbox()); err != nil {
		t.Errorf("a derived key: %v", err)
	}
	off, err := New(WithDB(db, sqlb.SQLiteDialect{}), WithPlugins(m))
	if err != nil {
		t.Fatal(err)
	}
	if off.DeliveryOutbox() {
		t.Error("the outbox is on without the option")
	}
	if _, err := off.SendOutbox(context.Background()); !errors.Is(err, ErrBadOperation) {
		t.Errorf("SendOutbox without the option: %v", err)
	}
	ms, _ := off.Migrations()
	for _, mg := range ms {
		if mg.Name == outboxMigrationName {
			t.Error("the outbox table is migrated without the option")
		}
	}
}

// TestRetryAfter_DoublesUpToTheCap pins the backoff.
func TestRetryAfter_DoublesUpToTheCap(t *testing.T) {
	for attempts, want := range map[int]time.Duration{1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 7: time.Hour, 100: time.Hour} {
		if got := retryAfter(attempts); got != want {
			t.Errorf("retryAfter(%d) = %v, want %v", attempts, got, want)
		}
	}
}

// TestOutbox_MigrationPerEngine: the table under its real name, in each
// engine's types.
func TestOutbox_MigrationPerEngine(t *testing.T) {
	for d, want := range map[sqlb.Dialect]string{
		sqlb.PostgresDialect{}: "created_at TIMESTAMPTZ NOT NULL)",
		sqlb.MySQLDialect{}:    "COLLATE=utf8mb4_bin",
		sqlb.SQLiteDialect{}:   "payload TEXT NOT NULL",
	} {
		a := outboxAuth(t, &script{}, d, &outboxMail{}, WithTablePrefix("p_"))
		ms, err := a.Migrations()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, m := range ms {
			if m.Name == outboxMigrationName {
				found = true
				if st := m.Statements[0]; !strings.HasPrefix(st, "CREATE TABLE IF NOT EXISTS p_auth_delivery_outbox (") || !strings.Contains(st, want) {
					t.Errorf("%s: %s", a.Engine(), st)
				}
			}
		}
		if !found || !a.DeliveryOutbox() {
			t.Errorf("%s: no outbox migration", a.Engine())
		}
	}
}

// outboxRows answers the due-rows query with rows.
func outboxRows(rows ...[]driver.Value) scriptAnswer {
	return scriptAnswer{match: "FROM auth_delivery_outbox WHERE", cols: []string{"id", "payload", "attempts"}, rows: rows}
}

// TestDeliver_WritesTheOutboxRowAndClearsItAfterTheSend: Deliver writes the
// sealed row (no link in clear) before the commit and deletes it once the
// deliverer accepted the message, or releases it for a retry when it did
// not; a failed write fails Deliver.
func TestDeliver_WritesTheOutboxRowAndClearsItAfterTheSend(t *testing.T) {
	ctx := context.Background()
	to := Identity{Kind: "mail", Value: "ada@example.com"}
	msg := Message{Purpose: PurposeVerify, Link: "https://app.example/verify?token=SECRET"}
	s := &script{}
	m := &outboxMail{}
	a := outboxAuth(t, s, sqlb.PostgresDialect{}, m)
	if err := a.Deliver(ctx, to, msg); err != nil {
		t.Fatal(err)
	}
	a.WaitDeliveries()
	log := s.statements()
	ins, del := indexOf(log, "INSERT INTO auth_delivery_outbox"), indexOf(log, "DELETE FROM auth_delivery_outbox WHERE id = $1")
	if ins < 0 || del < ins || len(m.sent) != 1 {
		t.Fatalf("statements %q, sent %q", log, m.sent)
	}
	for _, q := range log {
		if strings.Contains(q, "SECRET") {
			t.Fatal("a statement carries the link in clear")
		}
	}

	s2 := &script{}
	failing := &outboxMail{err: errors.New("smtp down")}
	b := outboxAuth(t, s2, sqlb.SQLiteDialect{}, failing)
	if err := b.Deliver(ctx, to, msg); err != nil {
		t.Fatal(err)
	}
	b.WaitDeliveries()
	if log := s2.statements(); indexOf(log, "UPDATE auth_delivery_outbox SET next_attempt_at = ? WHERE id = ?") < 0 || indexOf(log, "DELETE FROM auth_delivery_outbox") >= 0 {
		t.Fatalf("a failed send must release the row for a retry: %q", log)
	}

	var buf bytes.Buffer
	s3 := &script{failOn: "DELETE FROM auth_delivery_outbox"}
	c := outboxAuth(t, s3, sqlb.SQLiteDialect{}, &outboxMail{}, WithLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	if err := c.Deliver(ctx, to, msg); err != nil {
		t.Fatal(err)
	}
	c.WaitDeliveries()
	if !strings.Contains(buf.String(), "auth: delivery outbox") {
		t.Fatalf("a failed delete is not logged: %q", buf.String())
	}

	d := outboxAuth(t, &script{failOn: "INSERT INTO auth_delivery_outbox"}, sqlb.SQLiteDialect{}, &outboxMail{})
	if err := d.Deliver(ctx, to, msg); !errors.Is(err, errScript) {
		t.Fatalf("a failed outbox write: %v", err)
	}
	e := outboxAuth(t, &script{}, sqlb.SQLiteDialect{}, &outboxMail{}, WithIDs(func(string) (string, error) { return "", errScript }))
	if err := e.Deliver(ctx, to, msg); !errors.Is(err, errScript) {
		t.Fatalf("a failed id: %v", err)
	}
	if err := e.Deliver(Quiet(ctx), to, msg); err != nil {
		t.Fatalf("a quiet delivery writes nothing: %v", err)
	}
}

// TestSendOutbox_SendsClaimsAndReportsEveryFailure: due rows are claimed,
// sent and deleted; a row that no longer opens, decodes or has a deliverer
// fails and is released; each database failure is returned.
func TestSendOutbox_SendsClaimsAndReportsEveryFailure(t *testing.T) {
	ctx := context.Background()
	s := &script{}
	m := &outboxMail{}
	a := outboxAuth(t, s, sqlb.MySQLDialect{}, m)
	seal := func(v any) string {
		plain, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return a.outbox.Seal(plain, outboxAAD)
	}
	good := seal(outboxPayload{To: Identity{Kind: "mail", Value: "ada@example.com"}, Message: Message{Link: "L"}})
	s.answers = []scriptAnswer{outboxRows(
		[]driver.Value{"dlv_1", good, int64(1)},
		[]driver.Value{"dlv_2", "not sealed", int64(2)},
		[]driver.Value{"dlv_3", a.outbox.Seal([]byte("{not json"), outboxAAD), int64(1)},
		[]driver.Value{"dlv_4", seal(outboxPayload{To: Identity{Kind: "fax"}}), int64(1)},
	)}
	res, err := a.SendOutbox(ctx)
	if err != nil || res != (OutboxResult{Sent: 1, Failed: 3}) || len(m.sent) != 1 || m.sent[0] != "ada@example.com L" {
		t.Fatalf("SendOutbox = %+v, %v; sent %q", res, err, m.sent)
	}
	log := s.statements()
	if indexOf(log, "LIMIT 100") < 0 || indexOf(log, "SET attempts = attempts + 1") < 0 {
		t.Fatalf("statements %q", log)
	}

	for name, sc := range map[string]*script{
		"the read":  {answers: []scriptAnswer{{match: "FROM auth_delivery_outbox WHERE", err: errScript}}},
		"a scan":    {answers: []scriptAnswer{{match: "FROM auth_delivery_outbox WHERE", cols: []string{"id"}, rows: [][]driver.Value{{"dlv_1"}}}}},
		"the rows":  {answers: []scriptAnswer{{match: "FROM auth_delivery_outbox WHERE", cols: []string{"id", "payload", "attempts"}, nextErr: errScript}}},
		"the claim": {failOn: "SET attempts", answers: []scriptAnswer{outboxRows([]driver.Value{"dlv_1", good, int64(1)})}},
		"the end":   {failOn: "DELETE FROM auth_delivery_outbox", answers: []scriptAnswer{outboxRows([]driver.Value{"dlv_1", good, int64(1)})}},
	} {
		b := outboxAuth(t, sc, sqlb.SQLiteDialect{}, &outboxMail{})
		if _, err := b.SendOutbox(ctx); err == nil {
			t.Errorf("%s failed and SendOutbox did not", name)
		}
	}
}

// TestSweepOutbox_OnlyWhenTheLedgerHasTheTable: no ledger row is no key in
// the result; with one, old rows are deleted; a failure is returned.
func TestSweepOutbox_OnlyWhenTheLedgerHasTheTable(t *testing.T) {
	ctx := context.Background()
	ledger := func(n int64) scriptAnswer {
		return scriptAnswer{match: "auth_migrations", cols: []string{"n"}, rows: [][]driver.Value{{n}}}
	}
	a := outboxAuth(t, &script{answers: []scriptAnswer{ledger(0)}}, sqlb.SQLiteDialect{}, &outboxMail{})
	if n, err := a.sweepOutbox(ctx, time.Now()); n != -1 || err != nil {
		t.Fatalf("no table: %d %v", n, err)
	}
	s := &script{answers: []scriptAnswer{ledger(1)}}
	b := outboxAuth(t, s, sqlb.SQLiteDialect{}, &outboxMail{})
	if n, err := b.sweepOutbox(ctx, time.Now()); n != 1 || err != nil || indexOf(s.statements(), "DELETE FROM auth_delivery_outbox WHERE created_at < ?") < 0 {
		t.Fatalf("with the table: %d %v %q", n, err, s.statements())
	}
	c := outboxAuth(t, &script{answers: []scriptAnswer{ledger(1)}, failOn: "DELETE FROM auth_delivery_outbox"}, sqlb.SQLiteDialect{}, &outboxMail{})
	if _, err := c.sweepOutbox(ctx, time.Now()); !errors.Is(err, errScript) {
		t.Fatalf("a failed delete: %v", err)
	}
	d := outboxAuth(t, &script{answers: []scriptAnswer{{match: "auth_migrations", err: errScript}}}, sqlb.SQLiteDialect{}, &outboxMail{})
	if _, err := d.sweepOutbox(ctx, time.Now()); !errors.Is(err, errScript) {
		t.Fatalf("a failed ledger read: %v", err)
	}
}
