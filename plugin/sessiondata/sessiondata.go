// Package sessiondata keeps per-session app data in a table of its own,
// keyed by session id, for an app that wants the data out of the session
// record: a value too big for a cookie, a value the session store (Redis,
// memory) should not hold, or a table the app joins and reports on.
//
// It is the second of the two shapes the owner decided on (2026-10-03). The
// first is Session.Data in the core: the same JSON, carried by every store
// inside the session, read with no query (auth.SessionData). This plugin
// offers the same typed API — Get and Set on the request's session — over a
// row per session, and keeps the rows in step with the sessions through the
// core's SessionLifecycle: a sign-out, a revoke, "sign out everywhere" and a
// deleted user remove the row, a second-factor promotion moves it to the
// new session, and Sweep removes the rows of sessions that reached their
// hard stop. There is no foreign key and no cascade (ADR-0002).
//
// What it costs: Get is one query per call, where Session.Data is none. What
// it gives: the data never travels in a token or a cache entry, the bound is
// the same (auth.MaxSessionDataSize) but the row is in SQL whatever the
// session store, and the table is the app's to read.
package sessiondata

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity: migration owner and table
// owner.
const PluginName = "sessiondata"

// The data table: one row per session that has data.
const (
	//ds:def id=tablenamesessiondata-5kq8mw2x owner=@khanakia stability=stable
	TableNameData  = "auth_session_data"
	TableAliasData = "sd"

	// ColSessionID is the session the row belongs to, and the primary key:
	// a session has one row, replaced on every Set.
	ColSessionID = "session_id"
	// ColUserID is the session's user, so "sign out everywhere" and
	// DeleteUser remove a user's rows without listing their sessions
	// (auth.UserTable).
	ColUserID = "user_id"
	// ColData is the app's JSON, the engine's document type.
	ColData = "data"
	// ColExpiresAt is the session's hard stop (Session.MaxExpiresAt, or its
	// expiry when it has none), after which Sweep removes the row. A
	// session that ended idle before its hard stop leaves its row until
	// then: the core sees no "end" for an expiry, in any store.
	ColExpiresAt = "expires_at"
	// ColUpdatedAt is when the data was last written.
	ColUpdatedAt = "updated_at"

	// migrationTable creates the table (2026-10-03).
	migrationTable = "0001_session_data"
	// indexUserSuffix, after the table's real name, names the index the
	// per-user deletes use.
	indexUserSuffix = "_user_idx"
)

// Typed columns of the data table, for an app that reads or joins it.
var (
	TableData = sqlb.Table{Name: TableNameData, Alias: TableAliasData}

	DataSessionID = sqlb.Col[string](TableData, ColSessionID)
	DataUserID    = sqlb.Col[string](TableData, ColUserID)
	DataValue     = sqlb.Col[auth.AppData](TableData, ColData)
	DataExpiresAt = sqlb.Col[time.Time](TableData, ColExpiresAt)
	DataUpdatedAt = sqlb.Col[time.Time](TableData, ColUpdatedAt)
)

// Initial computes the data a new session starts with, from the session as
// it will be stored; nil records nothing. It runs inside the transaction
// that creates the session, after the row exists, and an error fails the
// sign-in.
//
//ds:def id=sessiondata-initial-7mw3kq9r owner=@khanakia stability=stable
type Initial func(ctx context.Context, s auth.Session) (any, error)

// Plugin keeps per-session app data in its own table. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	core    *auth.Auth
	initial Initial
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; options are applied in order by New.
type Option func(*Plugin)

// WithInitial records fn's value for every session the core creates: the
// workspace the user was last in, the device the sign-in came from. A
// pending second-factor session gets its row at the first factor, and the
// promotion moves it to the full session, so fn runs once per sign-in.
func WithInitial(fn Initial) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sessiondata.WithInitial", fn) {
			return
		}
		p.initial = fn
	}
}

var (
	_ auth.Initializer      = (*Plugin)(nil)
	_ auth.TableOwner       = (*Plugin)(nil)
	_ auth.UserTableOwner   = (*Plugin)(nil)
	_ auth.TypedMigrator    = (*Plugin)(nil)
	_ auth.SessionLifecycle = (*Plugin)(nil)
	_ auth.Sweeper          = (*Plugin)(nil)
	_ auth.DataHooker       = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns PluginName, the key the core registers this plugin under.
func (p *Plugin) Name() string { return PluginName }

// Init captures the core handle every statement goes through.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	return nil
}

// Tables declares the data table, so New can check its alias and an app can
// rename it.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableData} }

// UserTables tells DeleteUser which rows are a user's: every row of the
// table, by user id.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableData, Column: ColUserID}}
}

// TypedMigrations creates the table for engine, and refuses an engine the core
// cannot write for. MySQL has no CREATE INDEX IF NOT EXISTS, so there the
// index is declared inside the CREATE TABLE.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.core.TableName(TableData)
	index := table + indexUserSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColSessionID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColData + " " + t.Doc + " NOT NULL, " +
		ColExpiresAt + " " + t.Timestamp + " NOT NULL, " +
		ColUpdatedAt + " " + t.Timestamp + " NOT NULL"
	var st []string
	if engine == auth.EngineMySQL {
		st = []string{create + ", INDEX " + index + " (" + ColUserID + "))" + t.TableSuffix}
	} else {
		st = []string{create + ")" + t.TableSuffix, "CREATE INDEX IF NOT EXISTS " + index + " ON " + table + " (" + ColUserID + ")"}
	}
	return []auth.Migration{{Owner: PluginName, Name: migrationTable, Statements: st}}, nil
}

// DataHooks record the initial data, when WithInitial was given, once the
// session row exists. The full session a PendingSecondFactor operation
// creates at a promotion is skipped: the pending session's row moves to it
// (SessionReplaced), so the value computed at the first factor is kept and
// the function runs once per sign-in.
func (p *Plugin) DataHooks() auth.DataHooks {
	if p.initial == nil {
		return auth.DataHooks{}
	}
	return auth.DataHooks{Session: auth.TableHooks[auth.Session]{
		AfterCreate: func(ctx context.Context, _ sqlb.DBTX, s *auth.Session) error {
			if op, ok := auth.OperationOf(ctx); ok && op.Require == auth.PendingSecondFactor {
				return nil
			}
			v, err := p.initial(ctx, *s)
			if err != nil {
				return err
			}
			if v == nil {
				return nil
			}
			return p.SetFor(ctx, *s, v)
		},
	}}
}

// Get reads the data of the request's session in ctx as T, with one query.
// ok is false for a signed-out request, a context that is not a request, an
// API-key request and a session with no row; an error means the row is not
// a T, or the database failed.
//
//ds:def id=sessiondata-get-2nq7xk4m owner=@khanakia stability=stable
func Get[T any](ctx context.Context, p *Plugin) (v T, ok bool, err error) {
	s, ok := auth.CurrentSession(ctx)
	if !ok || s.APIKeyID != "" {
		return v, false, nil
	}
	return GetFor[T](ctx, p, s.ID)
}

// GetFor reads the data of session sessionID as T, for an app that holds a
// session from a list or a hook rather than a request.
func GetFor[T any](ctx context.Context, p *Plugin, sessionID string) (v T, ok bool, err error) {
	if p.core == nil {
		return v, false, auth.ErrOperationNotWired
	}
	var d auth.AppData
	q := p.core.Select().Columns(sqlb.Bind(DataValue, &d)).From(TableData).Where(sqlb.Eq(DataSessionID, sessionID)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return v, false, nil
		}
		return v, false, fmt.Errorf("sessiondata: read: %w", err)
	}
	return auth.DecodeSessionData[T](d)
}

// Set replaces the data of the request's session in ctx with v, encoded as
// JSON; nil deletes the row. It refuses a signed-out request with
// auth.ErrSignedOut, an API-key request with auth.ErrSessionDataUnavailable
// and a value over auth.MaxSessionDataSize with auth.ErrSessionDataTooLarge.
// Of two concurrent writes the last wins.
//
//ds:def id=sessiondata-set-9rk3wq6t owner=@khanakia stability=stable
func (p *Plugin) Set(ctx context.Context, v any) error {
	s, ok := auth.CurrentSession(ctx)
	if !ok {
		return auth.ErrSignedOut
	}
	if s.APIKeyID != "" {
		return auth.ErrSessionDataUnavailable
	}
	return p.SetFor(ctx, s, v)
}

// SetFor is Set for any session: one from a list, or the one a hook is
// handed. The row's expiry is the session's hard stop.
func (p *Plugin) SetFor(ctx context.Context, s auth.Session, v any) error {
	if p.core == nil {
		return auth.ErrOperationNotWired
	}
	d, err := auth.EncodeSessionData(v)
	if err != nil {
		return err
	}
	dialect := p.core.Dialect()
	if d == nil {
		_, err := p.core.Exec(ctx, sqlb.NewDelete(dialect).From(TableData).Where(sqlb.Eq(DataSessionID, s.ID)))
		return err
	}
	now := p.core.Now()
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		n, err := p.core.Exec(ctx, sqlb.NewUpdate(dialect).Table(TableData).
			Set(sqlb.Set(DataValue, d), sqlb.Set(DataUpdatedAt, now), sqlb.Set(DataExpiresAt, hardStop(s))).
			Where(sqlb.Eq(DataSessionID, s.ID)))
		if err != nil || n == 1 {
			return err
		}
		_, err = p.core.Exec(ctx, sqlb.NewInsert(dialect).Into(TableData).Row(
			sqlb.Set(DataSessionID, s.ID), sqlb.Set(DataUserID, s.UserID), sqlb.Set(DataValue, d),
			sqlb.Set(DataExpiresAt, hardStop(s)), sqlb.Set(DataUpdatedAt, now)))
		return err
	})
}

// hardStop is when the session can no longer be live whatever happens: its
// MaxExpiresAt, or its expiry for a session with none (pending,
// impersonation, a fixed lifetime).
func hardStop(s auth.Session) time.Time {
	if s.MaxExpiresAt != nil {
		return *s.MaxExpiresAt
	}
	return s.ExpiresAt
}

// SessionEnded deletes the session's row. The user id is in the WHERE, as in
// the store's Delete, so an id of another user's session matches nothing.
func (p *Plugin) SessionEnded(ctx context.Context, userID, id string) error {
	_, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableData).
		Where(sqlb.Eq(DataSessionID, id), sqlb.Eq(DataUserID, userID)))
	return err
}

// UserSessionsEnded deletes every row of the user but the excepted session's.
func (p *Plugin) UserSessionsEnded(ctx context.Context, userID, exceptID string) error {
	where := []sqlb.Predicate{sqlb.Eq(DataUserID, userID)}
	if exceptID != "" {
		where = append(where, sqlb.NotEq(DataSessionID, exceptID))
	}
	_, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableData).Where(where...))
	return err
}

// SessionReplaced moves the pending session's row to the full session, with
// the full session's hard stop, so what was recorded at the first factor is
// there after the second. A row the full session already has (an app hook
// of its own wrote one) gives way to it: the pending row is the sign-in's
// state so far. No pending row, nothing to move.
func (p *Plugin) SessionReplaced(ctx context.Context, old, new auth.Session) error {
	var d auth.AppData
	var updated time.Time
	q := p.core.Select().Columns(sqlb.Bind(DataValue, &d), sqlb.Bind(DataUpdatedAt, &updated)).From(TableData).
		Where(sqlb.Eq(DataSessionID, old.ID), sqlb.Eq(DataUserID, old.UserID)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("sessiondata: read pending row: %w", err)
	}
	dialect := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(dialect).From(TableData).Where(sqlb.In(DataSessionID, old.ID, new.ID))); err != nil {
		return err
	}
	_, err := p.core.Exec(ctx, sqlb.NewInsert(dialect).Into(TableData).Row(
		sqlb.Set(DataSessionID, new.ID), sqlb.Set(DataUserID, new.UserID), sqlb.Set(DataValue, d),
		sqlb.Set(DataExpiresAt, hardStop(new)), sqlb.Set(DataUpdatedAt, updated)))
	return err
}

// Sweep deletes the rows of sessions whose hard stop is before cutoff, for
// auth sweep.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableData).Where(sqlb.LessEq(DataExpiresAt, cutoff)))
}
