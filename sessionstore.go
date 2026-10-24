package auth

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/sqlb"
)

// SessionStore persists sessions. The core keeps every rule — lifetimes,
// sliding expiry, the pending second factor, impersonation, data hooks — and
// a store only saves and finds. A store never sees a raw token, only its
// SHA-256 hash, so a store cannot leak a usable credential. A store keeps
// every field of the Session it is given, Data included: the conformance
// suite fails a store that drops one.
//
// The SQL store (the default) writes through Auth.Exec, so it joins the
// transaction of ctx and a rolled-back sign-up leaves no session. Any other
// store does not: a rollback can leave it a session whose token never reached
// the client, because effects are dropped on rollback; that session expires by
// itself and nobody holds its token. github.com/ubgo/auth/sessiontest checks
// every method's contract; a custom store runs it before it ships.
//
//ds:def id=core-sessionstore-jxm3haq9 owner=@khanakia stability=stable
type SessionStore interface {
	// Insert saves a new session under its token hash.
	Insert(ctx context.Context, s Session, tokenHash []byte) error
	// Find returns the session whose token hashes to tokenHash and that is
	// still live at now (ExpiresAt after now), or ErrSessionNotFound.
	Find(ctx context.Context, tokenHash []byte, now time.Time) (Session, error)
	// Touch moves the expiry of session id forward to expiresAt, and records
	// lastSeenAt, only if its current expiry is earlier; it reports whether
	// it moved. Of concurrent refreshes the first wins and the rest report
	// false.
	Touch(ctx context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error)
	// List returns userID's live, non-pending sessions: newest first, ties by
	// id descending, the same order on every store.
	List(ctx context.Context, userID string, now time.Time) ([]Session, error)
	// Delete ends session id of userID; another user's id matches nothing.
	Delete(ctx context.Context, userID, id string) error
	// DeleteUser ends every session of userID except exceptID ("" = all).
	DeleteUser(ctx context.Context, userID, exceptID string) error
	// Sweep deletes sessions expired before now and reports how many; a
	// store that expires entries by itself returns 0, nil.
	Sweep(ctx context.Context, now time.Time) (int64, error)
	// SetData replaces the app data (Session.Data) of session id; nil
	// clears it. An unknown id is no error. Every other field, the expiry
	// above all, stays as it is.
	SetData(ctx context.Context, id string, data AppData) error
}

// SessionUserFinder is a SessionStore that can also load the session's user,
// with every plugin's SessionChecker predicates applied, in its own query.
// The SQL store implements it: one statement joins auth_session to auth_user,
// which is what a request costs. A store without it costs two: Find, then
// the user by primary key with the predicates on auth_user alone — so such a
// store cannot serve a SessionChecker that names auth_session columns, and
// New refuses one.
//
//ds:def id=core-sessionuserfinder-mpexgk37 owner=@khanakia stability=stable
type SessionUserFinder interface {
	SessionStore
	// FindWithUser is Find plus the user, refused (ErrSessionNotFound) when
	// the user fails any of checks.
	FindWithUser(ctx context.Context, tokenHash []byte, now time.Time, checks []sqlb.Predicate) (Session, User, error)
}

// ErrSessionNotFound is what a SessionStore returns for a token hash it does
// not hold or a session that expired. The core turns it into ErrSignedOut;
// stores return this one so the core can tell "not there" from "the store
// failed", which must be a 500 and not a silent sign-out.
var ErrSessionNotFound = errors.New("auth: session not found")

// WithSessionStore replaces the SQL session store. See SessionStore for what
// a replacement gives up (transactions) and NewMemorySessionStore for the
// one that ships in the core.
//
//ds:def id=opt-withsessionstore-55bdhhma owner=@khanakia stability=stable
func WithSessionStore(s SessionStore) Option {
	return func(st *settings) {
		if st.optErrs.RefuseNil("auth.WithSessionStore", s) {
			return
		}
		st.sessions = s
	}
}

// sqlSessionStore is the default store: the auth_session table, through the
// core's own statements, so it joins the transaction in ctx. archive is
// WithSessionArchive: Delete and DeleteUser then mark rows revoked instead
// of removing them, and every lookup leaves revoked rows out.
type sqlSessionStore struct {
	a       *Auth
	archive bool
}

// WithSessionArchive keeps a revoked session's row, marked with the time it
// was ended (Session.RevokedAt), instead of deleting it: sign-out, "sign out
// everywhere", revoking by id and a password reset all leave an audit trail
// that RevokedSessions reads and Sweep removes after the retention. A revoked
// row is never found by a lookup, so nothing changes for the user; only the
// SQL store supports it, and New refuses the option with another store or
// with stateless sessions, which have no row to keep.
//
//ds:def id=opt-withsessionarchive-5rk3nq8w owner=@khanakia stability=stable
func WithSessionArchive() Option { return func(s *settings) { s.archive = true } }

// Insert saves the session row; the hash is the only credential stored.
func (s sqlSessionStore) Insert(ctx context.Context, sess Session, tokenHash []byte) error {
	_, err := s.a.Exec(ctx, sqlb.NewInsert(s.a.cfg.Dialect).Into(TableSession).Row(
		sqlb.Set(SessionID, sess.ID), sqlb.Set(SessionUserID, sess.UserID), sqlb.Set(SessionTokenHash, tokenHash),
		sqlb.Set(SessionExpiresAt, sess.ExpiresAt), sqlb.Set(SessionLastSeenAt, sess.LastSeenAt),
		sqlb.Set(SessionIP, sess.IP), sqlb.Set(SessionUserAgent, sess.UserAgent), sqlb.Set(SessionCreatedAt, sess.CreatedAt),
		sqlb.Set(SessionFactorPending, sess.SecondFactorPending), sqlb.Set(SessionImpersonator, sess.ImpersonatedBy), sqlb.Set(SessionTransient, sess.Transient),
		sqlb.Set(SessionIdleSeconds, sess.IdleSeconds), sqlb.Set(SessionRefreshSeconds, sess.RefreshSeconds), sqlb.Set(SessionMaxExpiresAt, sess.MaxExpiresAt),
		sqlb.Set(SessionAppData, sess.Data), sqlb.Set(SessionReauthenticatedAt, sess.ReauthenticatedAt),
		sqlb.Set(SessionPendingTasks, sess.Tasks),
	))
	return err
}

// live is the condition every lookup shares: this token, not yet expired.
// Expiry is part of the SQL, so an expired session is not found at all rather
// than found and then compared in Go, where a caller could forget.
func live(tokenHash []byte, now time.Time) []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.Eq(SessionTokenHash, tokenHash), sqlb.Greater(SessionExpiresAt, now), sqlb.IsNull(SessionRevokedAt)}
}

// Find returns the live session under tokenHash.
func (s sqlSessionStore) Find(ctx context.Context, tokenHash []byte, now time.Time) (Session, error) {
	var sess Session
	q := s.a.Select().Columns(SessionBindings(&sess)...).From(TableSession).Where(live(tokenHash, now)...).Limit(1)
	return sess, s.notFound(s.a.One(ctx, q))
}

// FindWithUser is the single-query lookup: the session joined to its user,
// with the plugins' conditions in the same WHERE, so a banned user fails on
// the next request and not when a cache expires.
func (s sqlSessionStore) FindWithUser(ctx context.Context, tokenHash []byte, now time.Time, checks []sqlb.Predicate) (Session, User, error) {
	var sess Session
	var u User
	q := s.a.Select().
		Columns(sqlb.Bindings(SessionBindings(&sess), UserBindings(&u))...).
		From(TableSession).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: TableUser, On: []sqlb.Predicate{sqlb.EqExpr(UserID, SessionUserID)}}).
		Where(append(live(tokenHash, now), checks...)...).Limit(1)
	return sess, u, s.notFound(s.a.One(ctx, q))
}

// notFound maps sqlb's "no row" to the store contract's error.
func (sqlSessionStore) notFound(err error) error {
	if errors.Is(err, sqlb.ErrNoRows) {
		return ErrSessionNotFound
	}
	return err
}

// Touch moves the expiry forward only when it is earlier: concurrent
// refreshes are then harmless, the first moves it and the rest match nothing.
func (s sqlSessionStore) Touch(ctx context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error) {
	n, err := s.a.Exec(ctx, sqlb.NewUpdate(s.a.cfg.Dialect).Table(TableSession).
		Set(sqlb.Set(SessionExpiresAt, expiresAt), sqlb.Set(SessionLastSeenAt, lastSeenAt)).
		Where(sqlb.Eq(SessionID, id), sqlb.Less(SessionExpiresAt, expiresAt), sqlb.IsNull(SessionRevokedAt)))
	return n == 1, err
}

// List returns the user's live, non-pending sessions, newest first.
func (s sqlSessionStore) List(ctx context.Context, userID string, now time.Time) ([]Session, error) {
	var row Session
	q := s.a.Select().Columns(SessionBindings(&row)...).From(TableSession).
		Where(sqlb.Eq(SessionUserID, userID), sqlb.Greater(SessionExpiresAt, now), sqlb.Eq(SessionFactorPending, false), sqlb.IsNull(SessionRevokedAt)).
		Order(sqlb.OrderBy(SessionCreatedAt, sqlb.SortDesc), sqlb.OrderBy(SessionID, sqlb.SortDesc))
	var out []Session
	err := s.a.Each(ctx, q, func() error { out = append(out, row); return nil })
	return out, err
}

// Delete ends one session of userID; the user id in the WHERE is what keeps
// revoking by id safe.
func (s sqlSessionStore) Delete(ctx context.Context, userID, id string) error {
	return s.end(ctx, sqlb.Eq(SessionID, id), sqlb.Eq(SessionUserID, userID))
}

// DeleteUser ends every session of userID but exceptID.
func (s sqlSessionStore) DeleteUser(ctx context.Context, userID, exceptID string) error {
	where := []sqlb.Predicate{sqlb.Eq(SessionUserID, userID)}
	if exceptID != "" {
		where = append(where, sqlb.NotEq(SessionID, exceptID))
	}
	return s.end(ctx, where...)
}

// end removes the matching sessions, or under the archive marks the live
// ones revoked at the store's clock; a row already revoked keeps its time.
func (s sqlSessionStore) end(ctx context.Context, where ...sqlb.Predicate) error {
	if !s.archive {
		_, err := s.a.Exec(ctx, sqlb.NewDelete(s.a.cfg.Dialect).From(TableSession).Where(where...))
		return err
	}
	now := s.a.now()
	_, err := s.a.Exec(ctx, sqlb.NewUpdate(s.a.cfg.Dialect).Table(TableSession).Set(sqlb.Set(SessionRevokedAt, &now)).
		Where(append(where, sqlb.IsNull(SessionRevokedAt))...))
	return err
}

// RevokedSessions lists the sessions of userID that were ended before their
// expiry and kept by WithSessionArchive, newest revocation first, ties by
// id; empty without the option, since nothing is kept then. It is the audit
// trail: when each device was signed out, and by which path a support
// person can tell from the time.
//
//ds:def id=core-revokedsessions-7mk4xq2t owner=@khanakia stability=stable
func (a *Auth) RevokedSessions(ctx context.Context, userID string) ([]Session, error) {
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	var row Session
	q := a.Select().Columns(SessionBindings(&row)...).From(TableSession).
		Where(sqlb.Eq(SessionUserID, userID), sqlb.IsNotNull(SessionRevokedAt)).
		Order(sqlb.OrderBy(SessionRevokedAt, sqlb.SortDesc), sqlb.OrderBy(SessionID, sqlb.SortDesc))
	var out []Session
	err := a.Each(ctx, q, func() error { out = append(out, row); return nil })
	return out, err
}

// Sweep deletes expired rows.
func (s sqlSessionStore) Sweep(ctx context.Context, now time.Time) (int64, error) {
	return s.a.Exec(ctx, sqlb.NewDelete(s.a.cfg.Dialect).From(TableSession).Where(sqlb.Less(SessionExpiresAt, now)))
}

// memorySessionStore keeps sessions in a map, guarded by one mutex.
type memorySessionStore struct {
	mu sync.Mutex
	// byHash holds every session under the hex of its token hash; byID maps
	// a session id to that key, for Delete and Touch.
	byHash map[string]Session
	byID   map[string]string
	// prev holds each session's replaced token (RotateToken) under the hex
	// of its hash, and prevByID the key of a session's entry in prev, so a
	// second rotation or an end drops the first.
	prev     map[string]rotated
	prevByID map[string]string
}

// NewMemorySessionStore returns a SessionStore that lives in this process's
// memory: nothing survives a restart, and two instances never see each
// other's sessions. It is for tests and for a single-process app that accepts
// that every deploy signs everyone out. It joins no transaction; see
// SessionStore.
func NewMemorySessionStore() SessionStore {
	return &memorySessionStore{byHash: map[string]Session{}, byID: map[string]string{}, prev: map[string]rotated{}, prevByID: map[string]string{}}
}

// Insert saves the session, replacing any under the same hash.
func (m *memorySessionStore) Insert(_ context.Context, s Session, tokenHash []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hex.EncodeToString(tokenHash)
	m.byHash[key] = s
	m.byID[s.ID] = key
	return nil
}

// Find returns the live session under tokenHash.
func (m *memorySessionStore) Find(_ context.Context, tokenHash []byte, now time.Time) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byHash[hex.EncodeToString(tokenHash)]
	if !ok || !s.ExpiresAt.After(now) {
		return Session{}, ErrSessionNotFound
	}
	return s, nil
}

// Touch moves the expiry forward when it is earlier.
func (m *memorySessionStore) Touch(_ context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.byID[id]
	if !ok {
		return false, nil
	}
	s := m.byHash[key]
	if !s.ExpiresAt.Before(expiresAt) {
		return false, nil
	}
	s.ExpiresAt, s.LastSeenAt = expiresAt, lastSeenAt
	m.byHash[key] = s
	return true, nil
}

// List returns the user's live, non-pending sessions, newest first.
func (m *memorySessionStore) List(_ context.Context, userID string, now time.Time) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Session
	for _, s := range m.byHash {
		if s.UserID == userID && s.ExpiresAt.After(now) && !s.SecondFactorPending {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(x, y Session) int {
		if c := y.CreatedAt.Compare(x.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(y.ID, x.ID)
	})
	return out, nil
}

// Delete ends one session of userID.
func (m *memorySessionStore) Delete(_ context.Context, userID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if key, ok := m.byID[id]; ok && m.byHash[key].UserID == userID {
		m.remove(id, key)
	}
	return nil
}

// DeleteUser ends every session of userID but exceptID.
func (m *memorySessionStore) DeleteUser(_ context.Context, userID, exceptID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, s := range m.byHash {
		if s.UserID == userID && s.ID != exceptID {
			m.remove(s.ID, key)
		}
	}
	return nil
}

// Sweep drops expired sessions.
func (m *memorySessionStore) Sweep(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for key, s := range m.byHash {
		if !s.ExpiresAt.After(now) {
			m.remove(s.ID, key)
			n++
		}
	}
	return n, nil
}

// remove forgets one session; the caller holds mu.
func (m *memorySessionStore) remove(id, key string) {
	delete(m.byHash, key)
	delete(m.byID, id)
	if prev, ok := m.prevByID[id]; ok {
		delete(m.prev, prev)
		delete(m.prevByID, id)
	}
}

// SessionStore returns the store sessions live in: the SQL store unless
// WithSessionStore replaced it, and nil in stateless mode. It exists so an
// app or a test can run sessiontest over the configured store, or wrap it.
func (a *Auth) SessionStore() SessionStore { return a.sessions }
