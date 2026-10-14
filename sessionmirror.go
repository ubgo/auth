package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// MirrorSessionStore keeps every session in two stores at once, as
// better-auth's storeSessionInDatabase does with secondary storage: the
// primary is authoritative (typically the database, through
// SQLSessionStore) and the secondary is the fast copy read first
// (typically Redis). Pass the result to WithSessionStore.
//
// The consistency rule, chosen so that a failing secondary can cost speed
// but never let an ended session in:
//
//   - Find reads the secondary first and falls back to the primary on a
//     miss or a secondary failure (logged); the secondary never has the last
//     word on a miss, so a copy it lost or never got costs one primary read.
//   - Insert and Touch write the primary, which decides the result, then the
//     secondary; a secondary failure is logged, never fails the request: a
//     missing or older copy only sends a later Find to the primary.
//   - Delete and DeleteUser end the session in the secondary FIRST and fail
//     the call when it fails: a copy left there would keep a revoked
//     session working. Ending it in the primary second means a primary
//     failure leaves it ended only in the copy, which is a fallback, not a
//     sign-in.
//   - SetData writes the primary, then the secondary, and fails the call
//     when the secondary fails, because a stale copy would answer with the
//     old data; a primary that joins no transaction then already holds the
//     new data, and the caller sees the error.
//   - SetReauthenticatedAt (SessionReauthStore) writes the primary, then the
//     secondary, and fails the call when the secondary fails, as SetData
//     does: Find reads the copy first, so a copy that missed it would answer
//     "not fresh" right after the user was told the session is fresh. A
//     stale copy never lets anything in; it only fails honestly. Either side
//     without SessionReauthStore makes it ErrReauthUnsupported.
//   - List reads the primary alone (the copy may lack a session); Sweep runs
//     on both and reports the primary's count, a secondary failure logged.
//
// A mirror does not implement SessionUserFinder, so a request costs a Find
// and the user by primary key, and New refuses a SessionChecker that names
// auth_session columns. WithSessionArchive applies to an SQLSessionStore on
// either side. The mirror logs through the Auth's logger; New binds it.
//
//ds:def id=core-mirrorsessionstore-4tq9xk2w owner=@khanakia stability=stable
func MirrorSessionStore(primary, secondary SessionStore) SessionStore {
	return mirrorSessionStore{primary: primary, secondary: secondary, logger: slog.Default()}
}

// mirrorSessionStore is MirrorSessionStore. A value, so binding returns a
// new one and a store handed to two Auths is bound to each separately.
type mirrorSessionStore struct {
	primary, secondary SessionStore
	logger             *slog.Logger
}

// Names of the mirror's operations in its log lines, a closed set.
const (
	mirrorOpFind   = "find"
	mirrorOpInsert = "insert"
	mirrorOpTouch  = "touch"
	mirrorOpSweep  = "sweep"
)

// secondaryFailed logs a secondary failure the rule above tolerates.
func (m mirrorSessionStore) secondaryFailed(ctx context.Context, op string, err error) {
	m.logger.WarnContext(ctx, "auth: session mirror: the secondary store failed; the primary answers", "op", op, "err", err)
}

// Find reads the secondary, then the primary.
func (m mirrorSessionStore) Find(ctx context.Context, tokenHash []byte, now time.Time) (Session, error) {
	s, err := m.secondary.Find(ctx, tokenHash, now)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, ErrSessionNotFound) {
		m.secondaryFailed(ctx, mirrorOpFind, err)
	}
	return m.primary.Find(ctx, tokenHash, now)
}

// Insert writes the primary, then the copy.
func (m mirrorSessionStore) Insert(ctx context.Context, s Session, tokenHash []byte) error {
	if err := m.primary.Insert(ctx, s, tokenHash); err != nil {
		return err
	}
	if err := m.secondary.Insert(ctx, s, tokenHash); err != nil {
		m.secondaryFailed(ctx, mirrorOpInsert, err)
	}
	return nil
}

// Touch slides the primary, which answers, then the copy.
func (m mirrorSessionStore) Touch(ctx context.Context, id string, expiresAt, lastSeenAt time.Time) (bool, error) {
	moved, err := m.primary.Touch(ctx, id, expiresAt, lastSeenAt)
	if err != nil {
		return false, err
	}
	if _, err := m.secondary.Touch(ctx, id, expiresAt, lastSeenAt); err != nil {
		m.secondaryFailed(ctx, mirrorOpTouch, err)
	}
	return moved, nil
}

// List reads the primary.
func (m mirrorSessionStore) List(ctx context.Context, userID string, now time.Time) ([]Session, error) {
	return m.primary.List(ctx, userID, now)
}

// Delete ends the copy first, then the primary.
func (m mirrorSessionStore) Delete(ctx context.Context, userID, id string) error {
	if err := m.secondary.Delete(ctx, userID, id); err != nil {
		return fmt.Errorf("auth: session mirror: secondary: %w", err)
	}
	return m.primary.Delete(ctx, userID, id)
}

// DeleteUser ends the copies first, then the primary's.
func (m mirrorSessionStore) DeleteUser(ctx context.Context, userID, exceptID string) error {
	if err := m.secondary.DeleteUser(ctx, userID, exceptID); err != nil {
		return fmt.Errorf("auth: session mirror: secondary: %w", err)
	}
	return m.primary.DeleteUser(ctx, userID, exceptID)
}

// Sweep sweeps both and reports the primary's count.
func (m mirrorSessionStore) Sweep(ctx context.Context, now time.Time) (int64, error) {
	n, err := m.primary.Sweep(ctx, now)
	if err != nil {
		return 0, err
	}
	if _, err := m.secondary.Sweep(ctx, now); err != nil {
		m.secondaryFailed(ctx, mirrorOpSweep, err)
	}
	return n, nil
}

// SetData writes the primary, then the copy; both must succeed.
func (m mirrorSessionStore) SetData(ctx context.Context, id string, data AppData) error {
	if err := m.primary.SetData(ctx, id, data); err != nil {
		return err
	}
	if err := m.secondary.SetData(ctx, id, data); err != nil {
		return fmt.Errorf("auth: session mirror: secondary: %w", err)
	}
	return nil
}

// SetReauthenticatedAt writes the primary, then the copy; both must succeed
// (see MirrorSessionStore).
func (m mirrorSessionStore) SetReauthenticatedAt(ctx context.Context, id string, at time.Time) error {
	primary, ok1 := m.primary.(SessionReauthStore)
	secondary, ok2 := m.secondary.(SessionReauthStore)
	if !ok1 || !ok2 {
		return ErrReauthUnsupported
	}
	if err := primary.SetReauthenticatedAt(ctx, id, at); err != nil {
		return err
	}
	if err := secondary.SetReauthenticatedAt(ctx, id, at); err != nil {
		return fmt.Errorf("auth: session mirror: secondary: %w", err)
	}
	return nil
}

// bindStore binds both sides and takes the Auth's logger.
func (m mirrorSessionStore) bindStore(a *Auth, archive bool) (SessionStore, error) {
	if m.primary == nil || m.secondary == nil {
		return nil, fmt.Errorf("%w: MirrorSessionStore needs two stores", ErrBadOperation)
	}
	p, err := bindSessionStore(a, m.primary, archive)
	if err != nil {
		return nil, err
	}
	s, err := bindSessionStore(a, m.secondary, archive)
	if err != nil {
		return nil, err
	}
	if storeUsesSQL(p) && storeUsesSQL(s) {
		// Both sides would write the same auth_session row twice.
		return nil, fmt.Errorf("%w: MirrorSessionStore has the SQL store on both sides", ErrBadOperation)
	}
	return mirrorSessionStore{primary: p, secondary: s, logger: a.logger}, nil
}

// usesSQL reports whether either side is the SQL store.
func (m mirrorSessionStore) usesSQL() bool {
	return storeUsesSQL(m.primary) || storeUsesSQL(m.secondary)
}

// sessionStoreBinder is a store that needs the Auth it serves: the SQL
// store placeholder, and a composite store holding one.
type sessionStoreBinder interface {
	bindStore(a *Auth, archive bool) (SessionStore, error)
}

// bindSessionStore returns s bound to a, or s itself when it needs nothing.
func bindSessionStore(a *Auth, s SessionStore, archive bool) (SessionStore, error) {
	if b, ok := s.(sessionStoreBinder); ok {
		return b.bindStore(a, archive)
	}
	return s, nil
}

// storeUsesSQL reports whether a bound store is, or contains, the SQL store,
// which is what WithSessionArchive needs.
func storeUsesSQL(s SessionStore) bool {
	switch st := s.(type) {
	case sqlSessionStore:
		return true
	case mirrorSessionStore:
		return st.usesSQL()
	default:
		return false
	}
}

// SQLSessionStore names the default SQL store (the auth_session table)
// before New exists, so it can be one side of a MirrorSessionStore: New
// binds it to the Auth it is passed to, with that Auth's transaction and
// WithSessionArchive. Passed to WithSessionStore alone it is the default.
// Used before New binds it, every method answers ErrUnboundSessionStore.
//
//ds:def id=core-sqlsessionstore-8mz4rv6q owner=@khanakia stability=stable
func SQLSessionStore() SessionStore { return sqlStorePlaceholder{} }

// ErrUnboundSessionStore is what SQLSessionStore's value answers when it is
// called directly instead of through the Auth that New bound it to.
var ErrUnboundSessionStore = errors.New("auth: SQLSessionStore is bound by auth.New; use the store Auth.SessionStore returns")

// sqlStorePlaceholder is SQLSessionStore before New: it has no Auth, so it
// can only refuse.
type sqlStorePlaceholder struct{}

// bindStore is the SQL store of a.
func (sqlStorePlaceholder) bindStore(a *Auth, archive bool) (SessionStore, error) {
	return sqlSessionStore{a: a, archive: archive}, nil
}

// Insert refuses: the placeholder is not bound.
func (sqlStorePlaceholder) Insert(context.Context, Session, []byte) error {
	return ErrUnboundSessionStore
}

// Find refuses: the placeholder is not bound.
func (sqlStorePlaceholder) Find(context.Context, []byte, time.Time) (Session, error) {
	return Session{}, ErrUnboundSessionStore
}

// Touch refuses: the placeholder is not bound.
func (sqlStorePlaceholder) Touch(context.Context, string, time.Time, time.Time) (bool, error) {
	return false, ErrUnboundSessionStore
}

// List refuses: the placeholder is not bound.
func (sqlStorePlaceholder) List(context.Context, string, time.Time) ([]Session, error) {
	return nil, ErrUnboundSessionStore
}

// Delete refuses: the placeholder is not bound.
func (sqlStorePlaceholder) Delete(context.Context, string, string) error {
	return ErrUnboundSessionStore
}

// DeleteUser refuses: the placeholder is not bound.
func (sqlStorePlaceholder) DeleteUser(context.Context, string, string) error {
	return ErrUnboundSessionStore
}

// Sweep refuses: the placeholder is not bound.
func (sqlStorePlaceholder) Sweep(context.Context, time.Time) (int64, error) {
	return 0, ErrUnboundSessionStore
}

// SetData refuses: the placeholder is not bound.
func (sqlStorePlaceholder) SetData(context.Context, string, AppData) error {
	return ErrUnboundSessionStore
}
