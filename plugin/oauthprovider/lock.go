package oauthprovider

import (
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Locking reads, for the few places where a transaction must judge a row by
// what another transaction has committed rather than by its own snapshot.
//
// Why a clause of this package rather than sqlb's pg.ForUpdate or
// mysql.ForUpdate: those are typed to their dialect, and the core builds
// statements on the dialect it is given at run time (sqlb.AnySelect), so
// neither fits; sqlb's EngineClause refuses a runtime dialect by design.
// forUpdate is typed to the runtime dialect and checks the engine when it
// renders instead.

// kwForUpdate is the locking-read suffix Postgres and MySQL share.
const kwForUpdate = "FOR UPDATE"

// forUpdateConstruct names forUpdate in sqlb's unsupported-dialect error.
const forUpdateConstruct = "oauthprovider.forUpdate"

// forUpdate is SELECT … FOR UPDATE on Postgres and MySQL. Under any other
// dialect it fails the statement at Build (sqlb.ErrUnsupportedDialect)
// rather than rendering a lock the engine does not take: lockedRead never
// adds it there.
type forUpdate struct{}

// Slot puts the clause last, where both engines expect FOR UPDATE.
func (forUpdate) Slot() sqlb.Slot { return sqlb.SlotTail }

// ClauseOf types the clause to a SELECT on the runtime dialect.
func (forUpdate) ClauseOf(sqlb.Dialect, sqlb.SelectKind) {}

// WriteSQL renders FOR UPDATE, or records the dialect as unsupported.
func (forUpdate) WriteSQL(b *strings.Builder, a *sqlb.Args) {
	switch sqlb.DialectName(a.Dialect()) {
	case sqlb.DialectPostgres, sqlb.DialectMySQL:
		b.WriteString(kwForUpdate)
	default:
		a.Unsupported(forUpdateConstruct)
	}
}

// lockedRead makes sel a locking read where the engine needs one to see the
// latest committed row: FOR UPDATE on Postgres and MySQL. A locking read
// reads the newest committed version and holds the row until the
// transaction ends, whatever the isolation level; a plain read under
// MySQL's default REPEATABLE READ returns the transaction's first snapshot
// instead, which can predate a write another transaction has since
// committed.
//
// SQLite gets sel unchanged: it has no FOR UPDATE and needs none, since it
// has one writer and a transaction that writes sees every commit before it
// (a deferred transaction that read an older snapshot fails its first write
// with SQLITE_BUSY instead of reading stale data).
func (p *Plugin) lockedRead(sel *sqlb.AnySelect) *sqlb.AnySelect {
	if p.core.Engine() == auth.EngineSQLite {
		return sel
	}
	return sel.Clause(forUpdate{})
}
