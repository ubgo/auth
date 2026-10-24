package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"
)

// The database rate store's table. Counters live in the app's own database,
// so every app instance shares them with no new infrastructure.
const (
	TableNameRateLimit = "auth_rate_limit"
	colRateKeyHash     = "key_hash"
	colRateHits        = "hits"
	colRateExpiresAt   = "expires_at"
)

// rateSweepEvery is how many hits pass between two deletions of finished
// windows. Counted per process; the sweep is idempotent, so two instances
// sweeping at once is harmless.
const rateSweepEvery = 1000

// WithDBRateStore counts rate limits in the auth database, in the table
// auth_rate_limit, which Migrate creates. It is the store to pick when an app
// runs more than one instance and has no shared cache: every instance sees the
// same counters.
//
//ds:def id=opt-withdbratestore-9gffdmh4 owner=@khanakia stability=stable
func WithDBRateStore() Option { return func(s *settings) { s.dbRateStore = true } }

// dbRateStore is a fixed-window counter in a table: one row per key and
// window, incremented with one upsert.
//
// It always writes on the database handle, never on a transaction in ctx: the
// pipeline counts before any transaction opens, and a count must survive the
// failure it counts.
type dbRateStore struct {
	a    *Auth
	hits atomic.Int64
}

// Hit adds one to key's counter for the window that contains now.
func (s *dbRateStore) Hit(ctx context.Context, key string, window time.Duration) (int, error) {
	now := s.a.now()
	slot := now.UnixNano() / int64(window)
	expires := time.Unix(0, (slot+1)*int64(window)).UTC()
	sum := sha256.Sum256([]byte(key + "|" + strconv.FormatInt(slot, 10)))
	hash := sum[:]

	table := s.a.TableName(TableRateLimit)
	var upsert string
	switch s.a.Engine() {
	case EngineMySQL:
		upsert = "INSERT INTO " + table + " (" + colRateKeyHash + ", " + colRateHits + ", " + colRateExpiresAt +
			") VALUES (?, 1, ?) ON DUPLICATE KEY UPDATE " + colRateHits + " = " + colRateHits + " + 1"
	default:
		upsert = placeholders(s.a.Engine(), "INSERT INTO "+table+" ("+colRateKeyHash+", "+colRateHits+", "+colRateExpiresAt+
			") VALUES (?, 1, ?) ON CONFLICT ("+colRateKeyHash+") DO UPDATE SET "+colRateHits+" = "+table+"."+colRateHits+" + 1")
	}
	if _, err := s.a.db.ExecContext(ctx, upsert, hash, expires); err != nil {
		return 0, fmt.Errorf("auth: rate count: %w", err)
	}
	var n int
	sel := placeholders(s.a.Engine(), "SELECT "+colRateHits+" FROM "+table+" WHERE "+colRateKeyHash+" = ?")
	if err := s.a.db.QueryRowContext(ctx, sel, hash).Scan(&n); err != nil {
		return 0, fmt.Errorf("auth: rate read: %w", err)
	}
	if s.hits.Add(1)%rateSweepEvery == 0 {
		if _, err := s.Sweep(ctx); err != nil {
			s.a.logger.Warn("auth: rate sweep failed", "error", err)
		}
	}
	return n, nil
}

// Sweep deletes finished windows and returns how many. Hit calls it now and
// then; Auth.Sweep calls it whenever the table exists.
func (s *dbRateStore) Sweep(ctx context.Context) (int64, error) {
	del := placeholders(s.a.Engine(), "DELETE FROM "+s.a.TableName(TableRateLimit)+" WHERE "+colRateExpiresAt+" < ?")
	res, err := s.a.db.ExecContext(ctx, del, s.a.now())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// rateLimitMigrationName names the migration that creates auth_rate_limit;
// the ledger row with this name is how Sweep knows the table exists.
const rateLimitMigrationName = "0002_rate_limit"

// rateTableMigrated reports whether the ledger records the rate-limit table.
//
// Why the ledger and not a.dbRates: the table outlives the option. An app
// that ran WithDBRateStore once, or whose web process uses it while its sweep
// job builds a plain Auth, still has rows that only a sweep ever deletes.
func (a *Auth) rateTableMigrated(ctx context.Context) (bool, error) {
	return a.ledgerHas(ctx, rateLimitMigrationName)
}

// rateLimitMigration creates the table of the database rate store, under its
// real name.
func (a *Auth) rateLimitMigration(engine string) Migration {
	t := a.typesFor(engine)
	return Migration{Owner: CorePluginName, Name: rateLimitMigrationName, Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + a.TableName(TableRateLimit) + " (" +
			colRateKeyHash + " " + t.Hash + " NOT NULL PRIMARY KEY, " +
			colRateHits + " " + t.Int + " NOT NULL, " +
			colRateExpiresAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
	}}
}
