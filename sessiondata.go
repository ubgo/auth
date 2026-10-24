package auth

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ubgo/sqlb"
)

// Per-session app data (owner decision, 2026-10-03): a session carries JSON
// the app chose, typed in Go, stored by every session store beside the
// session. A device name, the active workspace, a feature flag resolved at
// sign-in: anything that is about this session rather than about the user.
// What is about the user goes on auth_user (WithUserColumns).
//
// The data travels with the session wherever the session goes: the row (or
// the Redis hash, or the memory map), the stateless token, the client's
// snapshot and every cache entry, so a request reads it with no extra query.
// That is also why its size is bounded (MaxSessionDataSize): a stateless
// token and a snapshot are cookies, and a cookie has 4 KiB.
//
// plugin/sessiondata offers the same typed API over a table of its own, for
// an app that wants the data out of the session record.

// AppData is JSON the app attached to a session: the encoded value, or nil
// for none. It is a named type so the stores can save it as text on every
// engine (driver.Valuer, sql.Scanner) and so the Redis store and the sealed
// caches carry it as JSON inside the session's JSON (json.Marshaler,
// json.Unmarshaler) without re-encoding. Write it through EncodeSessionData
// or SetSessionData, which check the size and that it is JSON; read it
// through SessionData or DecodeSessionData.
//
//ds:def id=core-appdata-7hq2kx4m owner=@khanakia stability=stable
type AppData []byte

// MaxSessionDataSize bounds the encoded data of one session, in bytes. It
// is the largest size that still fits beside the session in a sealed cookie
// (a stateless token, a client snapshot) under the 4 KiB browsers allow per
// cookie: a device record or a handful of preferences fit, a document does
// not. One bound for every store, so switching stores never changes what an
// app may keep.
//
//ds:def id=maxsessiondatasize-9wk3rq2d owner=@khanakia stability=stable
const MaxSessionDataSize = 2048

// Errors of the session data API.
var (
	// ErrSessionDataTooLarge: the encoded value exceeds MaxSessionDataSize.
	// A programming error, not a client's, so a plain error.
	ErrSessionDataTooLarge = errors.New("auth: session data exceeds MaxSessionDataSize")
	// ErrSessionDataInvalid: the value does not encode as JSON (a channel, a
	// function, a cycle), or a hook set bytes that are not JSON.
	ErrSessionDataInvalid = errors.New("auth: session data is not JSON")
	// ErrSessionDataUnavailable is answered by SetSessionData for a request
	// signed in with an API key: such a request has no session row to hold
	// data, and a key is not a device.
	ErrSessionDataUnavailable = NewError("auth.session_data_unavailable", http.StatusConflict, "This request has no session to hold data.")
)

// Value stores the data as text, or NULL for none. Text rather than bytes
// because the column is the engines' document type (SQLTypes.Doc), and a
// []byte parameter would be sent as binary on Postgres.
func (d AppData) Value() (driver.Value, error) {
	if len(d) == 0 {
		return nil, nil
	}
	return string(d), nil
}

// Scan reads NULL, text or bytes, which is what the three drivers return for
// a document column. The bytes are copied: a driver may reuse its buffer.
func (d *AppData) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*d = nil
	case string:
		*d = AppData(v)
	case []byte:
		*d = bytes.Clone(v)
	default:
		return fmt.Errorf("auth: scan session data from %T", src)
	}
	return nil
}

// MarshalJSON writes the data as it is, since it is JSON already, or null for
// none. It never fails: a value reaches an AppData only through normalized.
func (d AppData) MarshalJSON() ([]byte, error) {
	if len(d) == 0 {
		return []byte(jsonNull), nil
	}
	return d, nil
}

// UnmarshalJSON keeps the raw JSON, mapping null back to none.
func (d *AppData) UnmarshalJSON(b []byte) error {
	if string(b) == jsonNull {
		*d = nil
		return nil
	}
	*d = bytes.Clone(b)
	return nil
}

// jsonNull is the JSON spelling of "no data".
const jsonNull = "null"

// normalized is what every data write passes: nothing, or compact JSON
// within the bound. Compact, because a store that keeps the session as JSON
// (Redis, the sealed caches) compacts whatever it is given, and the
// conformance suite holds every store to the same bytes; so the core
// compacts first and no store can differ. A hook that sets Session.Data by
// hand goes through it too, at the insert, so a store never holds a value a
// reader cannot decode.
func (d AppData) normalized() (AppData, error) {
	if len(d) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, d); err != nil {
		return nil, ErrSessionDataInvalid
	}
	if buf.Len() > MaxSessionDataSize {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrSessionDataTooLarge, buf.Len(), MaxSessionDataSize)
	}
	return AppData(buf.Bytes()), nil
}

// EncodeSessionData turns v into the data a session carries, refusing a
// value that does not encode or that exceeds MaxSessionDataSize; nil v is
// no data. It is the one way to produce an AppData from a Go value: a
// Session.BeforeCreate hook uses it to set the data a session starts with,
// SetSessionData uses it for the current session.
//
//ds:def id=core-encodesessiondata-4nx8wq3t owner=@khanakia stability=stable
func EncodeSessionData(v any) (AppData, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSessionDataInvalid, err)
	}
	return AppData(b).normalized()
}

// DecodeSessionData reads a session's data as T. ok is false when the
// session carries none; an error means the data is not a T, which happens
// when the app changed its type without a migration of the live sessions.
//
//ds:def id=core-decodesessiondata-2mq7xk8r owner=@khanakia stability=stable
func DecodeSessionData[T any](d AppData) (v T, ok bool, err error) {
	if len(d) == 0 {
		return v, false, nil
	}
	if err := json.Unmarshal(d, &v); err != nil {
		return v, false, fmt.Errorf("auth: decode session data: %w", err)
	}
	return v, true, nil
}

// SessionData reads the data of the request's session in ctx as T, with no
// query: the session was resolved once for the request and the data came
// with it, from the store, the token or the cache. ok is false for a
// signed-out request, a context that is not a request, and a session with
// no data.
//
//ds:def id=core-sessiondata-6rk9wn2p owner=@khanakia stability=stable
func SessionData[T any](ctx context.Context) (v T, ok bool, err error) {
	s, ok := CurrentSession(ctx)
	if !ok {
		return v, false, nil
	}
	return DecodeSessionData[T](s.Data)
}

// SetSessionData replaces the data of the request's session in ctx with v,
// encoded as JSON, and makes the rest of the request see it. The write goes
// to the store (the Session.BeforeUpdate and AfterUpdate hooks run around
// it, in the transaction), or in stateless mode into a new token the
// transport hands to the client; a cache entry for the session is dropped,
// so the next request reads the new value. Nil v clears the data.
//
// It refuses a signed-out request with ErrSignedOut and an API-key request
// with ErrSessionDataUnavailable, and a value over MaxSessionDataSize with
// ErrSessionDataTooLarge, before anything is written.
//
//ds:def id=core-setsessiondata-8pz4mw6k owner=@khanakia stability=stable
func SetSessionData(ctx context.Context, a *Auth, v any) error {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || st.session.SecondFactorPending {
		return ErrSignedOut
	}
	if st.session.APIKeyID != "" {
		return ErrSessionDataUnavailable
	}
	d, err := EncodeSessionData(v)
	if err != nil {
		return err
	}
	old := *st.session
	s := old
	s.Data = d
	if a.stateless != nil {
		// The token is the session: the new data exists once the client
		// holds the new token, which the transport issues with the response.
		tok, err := a.stateless.seal(s)
		if err != nil {
			return err
		}
		st.effects.ReplaceSessionOf(s, tok)
	} else {
		err = a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			if err := runHooks(ctx, a, tx, pickSession, stageBeforeUpdate, &old, &s); err != nil {
				return err
			}
			if err := a.sessions.SetData(ctx, s.ID, s.Data); err != nil {
				return fmt.Errorf("auth: set session data: %w", err)
			}
			return runHooks(ctx, a, tx, pickSession, stageAfterUpdate, &old, &s)
		})
		if err != nil {
			return err
		}
	}
	*st.session = s
	return a.dropCached(ctx, st)
}

// dropCached forgets the request's cache entry and tells the transport to
// clear the client's copy, after a change to the session that a cached
// lookup would not see. Nothing to do without a cache.
func (a *Auth) dropCached(ctx context.Context, st *requestState) error {
	if a.cache == nil {
		return nil
	}
	if err := a.cache.Drop(ctx, CacheKey{TokenHash: HashToken(st.req.Token), Client: st.req.CachedSession}); err != nil {
		return fmt.Errorf("auth: session cache: %w", err)
	}
	st.effects.ClearCache()
	return nil
}

// SetData of the SQL store: one UPDATE of the live row.
func (s sqlSessionStore) SetData(ctx context.Context, id string, data AppData) error {
	_, err := s.a.Exec(ctx, sqlb.NewUpdate(s.a.cfg.Dialect).Table(TableSession).
		Set(sqlb.Set(SessionAppData, data)).Where(sqlb.Eq(SessionID, id), sqlb.IsNull(SessionRevokedAt)))
	return err
}

// SetData of the memory store replaces the session's data in place; an
// unknown id changes nothing.
func (m *memorySessionStore) SetData(_ context.Context, id string, data AppData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.byID[id]
	if !ok {
		return nil
	}
	s := m.byHash[key]
	s.Data = data
	m.byHash[key] = s
	return nil
}

// SessionLifecycle is a plugin told when a session ends before its expiry,
// or is replaced, so what the plugin keeps per session can go with it. It
// exists because the library creates no foreign keys and no cascades
// (ADR-0002): a table keyed by session id is cleaned in Go, and these are the
// moments to do it. Every method runs inside the transaction that ends the
// session and before the store is told, so a plugin's error leaves the
// session and its rows untouched, whatever the store; a store's failure
// afterwards rolls the plugin's SQL back with it.
//
// Expiry is not an end the core sees: a session that ran out is simply not
// found, and its rows are deleted by the plugin's own Sweeper. An end in
// stateless mode is only the cookie being cleared, except "sign out
// everywhere", which the core still reports.
//
//ds:def id=core-sessionlifecycle-3vt6nq8z owner=@khanakia stability=stable
type SessionLifecycle interface {
	// SessionEnded is one session of userID ending by id: sign-out, revoke,
	// an admin ending it, a device's other account being ended.
	SessionEnded(ctx context.Context, userID, id string) error
	// UserSessionsEnded is every session of userID ending but exceptID,
	// which is "" for all: sign-out everywhere, a password reset, a ban.
	UserSessionsEnded(ctx context.Context, userID, exceptID string) error
	// SessionReplaced is a pending second-factor session (old) becoming the
	// full session (new) at PromoteSession: a new id, the same sign-in.
	// What the plugin kept for old belongs to new now.
	SessionReplaced(ctx context.Context, old, new Session) error
}

// sessionEnded tells every SessionLifecycle plugin that one session ended.
func (a *Auth) sessionEnded(ctx context.Context, userID, id string) error {
	for _, p := range a.plugins {
		if l, ok := p.(SessionLifecycle); ok {
			if err := l.SessionEnded(ctx, userID, id); err != nil {
				return fmt.Errorf("auth: plugin %q on session end: %w", p.Name(), err)
			}
		}
	}
	return nil
}

// userSessionsEnded tells every SessionLifecycle plugin that a user's
// sessions ended.
func (a *Auth) userSessionsEnded(ctx context.Context, userID, exceptID string) error {
	for _, p := range a.plugins {
		if l, ok := p.(SessionLifecycle); ok {
			if err := l.UserSessionsEnded(ctx, userID, exceptID); err != nil {
				return fmt.Errorf("auth: plugin %q on sessions end: %w", p.Name(), err)
			}
		}
	}
	return nil
}

// sessionReplaced tells every SessionLifecycle plugin about a promotion.
func (a *Auth) sessionReplaced(ctx context.Context, old, new Session) error {
	for _, p := range a.plugins {
		if l, ok := p.(SessionLifecycle); ok {
			if err := l.SessionReplaced(ctx, old, new); err != nil {
				return fmt.Errorf("auth: plugin %q on session promotion: %w", p.Name(), err)
			}
		}
	}
	return nil
}
