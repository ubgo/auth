package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ubgo/sqlb"
)

// Bounds of TokenRotation.Grace.
const (
	// DefaultTokenRotationGrace is how long a rotated-away token keeps
	// working when TokenRotation.Grace is 0: long enough for the requests a
	// page or an app had in flight when the new token was issued (other
	// tabs, parallel API calls) to land.
	//
	//ds:def id=defaulttokenrotationgrace-5qm8wx3k owner=@khanakia stability=stable
	DefaultTokenRotationGrace = time.Minute
	// MaxTokenRotationGrace is the longest grace New accepts. Every second
	// of grace is a second in which a stolen token works beside the real
	// one without being noticed, so a longer window is a misconfiguration.
	//
	//ds:def id=maxtokenrotationgrace-9vk2nq7t owner=@khanakia stability=stable
	MaxTokenRotationGrace = 10 * time.Minute
)

// TokenRotation configures WithTokenRotation.
//
//ds:def id=core-tokenrotation-4hx9mk2w owner=@khanakia stability=stable
type TokenRotation struct {
	// Grace is how long the token a rotation replaced is still accepted;
	// 0 means DefaultTokenRotationGrace, and more than
	// MaxTokenRotationGrace or a negative value is refused by New.
	Grace time.Duration
}

// WithTokenRotation gives a session a new token every time its expiry slides
// (once per refresh interval, SessionConfig.RefreshAfter), and treats the
// replaced token, presented after the grace window, as stolen: the session is
// revoked at once (every device holding it is signed out) and a
// SecuritySessionTokenReuse event is emitted. Within the grace window the old
// token still works, so concurrent requests and tabs are not signed out.
//
// It catches a copied token as soon as the real user and the thief have both
// used the session across a rotation: whichever of the two presents the
// replaced token later ends the session for both. A response that never
// reached the client (a dropped connection right after a rotation) looks the
// same and signs that client out once the grace passes; that is the price of
// the detection, the same as SuperTokens' refresh-token rotation.
//
// The new token reaches the client like any refreshed session: a new cookie,
// or Set-Auth-Token in bearer mode, on whichever response did the rotation.
// Only the request pipeline rotates; ResolveSession and the multi-session
// device list slide the expiry without changing the token, because their
// callers have no way to hand a new token on.
//
// It needs a store with the SessionTokenRotator upgrade (the SQL and memory
// stores and contrib/redis have it) and refuses stateless sessions, whose
// token is the session and has nothing to compare against. Off by default.
//
//ds:def id=opt-withtokenrotation-7wq3mx8n owner=@khanakia stability=stable
func WithTokenRotation(r TokenRotation) Option {
	return func(s *settings) { s.tokenRotation = &r }
}

// SessionTokenRotator is the optional upgrade of a SessionStore that
// WithTokenRotation needs: it moves a session to a new token hash while
// remembering the one it replaced, and finds a session by that replaced
// hash. The SQL, memory and contrib/redis stores implement it; New refuses
// WithTokenRotation with a store that does not, and nothing changes for such
// a store without the option. sessiontest.Run checks it when a store has it.
//
//ds:def id=core-sessiontokenrotator-3nw8kq5x owner=@khanakia stability=stable
type SessionTokenRotator interface {
	// RotateToken moves session id from oldHash to newHash, only while
	// oldHash is still its current token hash and it is not ended: of
	// concurrent rotations the first wins and the rest report false. It
	// records oldHash as the previous hash, accepted until graceUntil
	// (forgetting any earlier previous hash), and sets the expiry and
	// last-seen as Touch would. Every other field stays as it is.
	RotateToken(ctx context.Context, id string, oldHash, newHash []byte, graceUntil, expiresAt, lastSeenAt time.Time) (bool, error)
	// FindRotated returns the live session (ExpiresAt after now, not ended)
	// whose previous hash is tokenHash, with the time until which that
	// token is accepted, or ErrSessionNotFound. The grace is not checked:
	// a token found after it is the one the core treats as stolen.
	FindRotated(ctx context.Context, tokenHash []byte, now time.Time) (Session, time.Time, error)
}

// tokenRotation is the resolved WithTokenRotation setting.
type tokenRotation struct {
	grace time.Duration
	store SessionTokenRotator
}

// wireTokenRotation resolves WithTokenRotation once the session store is
// settled, refusing a grace out of range, stateless sessions and a store
// without the upgrade.
func (a *Auth) wireTokenRotation(r *TokenRotation) error {
	if r == nil {
		return nil
	}
	switch {
	case r.Grace < 0 || r.Grace > MaxTokenRotationGrace:
		return fmt.Errorf("%w: WithTokenRotation Grace %v is outside 0..%v", ErrBadOperation, r.Grace, MaxTokenRotationGrace)
	case a.stateless != nil:
		return fmt.Errorf("%w: WithTokenRotation needs stored sessions; a stateless token is the session", ErrBadOperation)
	}
	store, ok := a.sessions.(SessionTokenRotator)
	if !ok {
		return fmt.Errorf("%w: WithTokenRotation needs a session store with SessionTokenRotator; %T has none", ErrBadOperation, a.sessions)
	}
	grace := r.Grace
	if grace == 0 {
		grace = DefaultTokenRotationGrace
	}
	a.rotation = &tokenRotation{grace: grace, store: store}
	return nil
}

// rotate slides session s to expiresAt under a new token, for a lookup that
// may rotate. It reports the new token, or "" when a concurrent request
// rotated first (the caller keeps the token it has, now in its grace).
func (a *Auth) rotate(ctx context.Context, s Session, t Token, expiresAt, now time.Time) (Token, error) {
	next := NewToken()
	moved, err := a.rotation.store.RotateToken(ctx, s.ID, HashToken(t), HashToken(next), now.Add(a.rotation.grace), expiresAt, now)
	if err != nil {
		return "", fmt.Errorf("auth: rotate session token: %w", err)
	}
	if !moved {
		return "", nil
	}
	return next, nil
}

// rotatedUserFinder is the SQL store's single-query form of FindRotated,
// with the SessionChecker predicates on the same join FindWithUser uses.
type rotatedUserFinder interface {
	findRotatedWithUser(ctx context.Context, tokenHash []byte, now time.Time, checks []sqlb.Predicate) (Session, User, time.Time, error)
}

// lookupRotated looks a token the store did not find up among the replaced
// ones. Within the grace window it answers the session as Find would; after
// it, the token is treated as stolen: the session is revoked and the call
// is signed out. Not found is ErrSessionNotFound, as from Find.
func (a *Auth) lookupRotated(ctx context.Context, t Token, now time.Time) (Session, User, error) {
	var s Session
	var u User
	var until time.Time
	var err error
	if f, ok := a.sessions.(rotatedUserFinder); ok {
		s, u, until, err = f.findRotatedWithUser(ctx, HashToken(t), now, a.sessionPredicates())
	} else {
		s, until, err = a.rotation.store.FindRotated(ctx, HashToken(t), now)
		if err == nil {
			u, err = a.checkedUser(ctx, s.UserID)
		}
	}
	if err != nil {
		return Session{}, User{}, err
	}
	if now.Before(until) {
		return s, u, nil
	}
	if err := a.EndSession(ctx, s.UserID, s.ID, SessionEndTokenReuse); err != nil {
		return Session{}, User{}, fmt.Errorf("auth: revoke reused session: %w", err)
	}
	e := SecurityEvent{
		Kind: SecuritySessionTokenReuse, Severity: SeverityAlert, Outcome: RateOutcomeBlocked, UserID: s.UserID,
		Attrs: map[string]string{AttrSessionID: s.ID},
	}
	if st := stateFrom(ctx); st != nil {
		e.IP = st.req.Client.IP
	}
	a.EmitSecurity(e)
	a.logger.WarnContext(ctx, "auth: a rotated session token was reused after its grace; the session was revoked", "user", s.UserID, "session", s.ID)
	return Session{}, User{}, ErrSessionNotFound
}

// RotateToken of the SQL store: one UPDATE, conditional on the old hash.
func (s sqlSessionStore) RotateToken(ctx context.Context, id string, oldHash, newHash []byte, graceUntil, expiresAt, lastSeenAt time.Time) (bool, error) {
	n, err := s.a.Exec(ctx, sqlb.NewUpdate(s.a.cfg.Dialect).Table(TableSession).
		Set(sqlb.Set(SessionTokenHash, newHash), sqlb.Set(SessionPreviousTokenHash, oldHash), sqlb.Set(SessionPreviousValidUntil, &graceUntil),
			sqlb.Set(SessionExpiresAt, expiresAt), sqlb.Set(SessionLastSeenAt, lastSeenAt)).
		Where(sqlb.Eq(SessionID, id), sqlb.Eq(SessionTokenHash, oldHash), sqlb.IsNull(SessionRevokedAt)))
	return n == 1, err
}

// rotatedWhere is FindRotated's condition: the previous hash, live.
func rotatedWhere(tokenHash []byte, now time.Time) []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.Eq(SessionPreviousTokenHash, tokenHash), sqlb.Greater(SessionExpiresAt, now), sqlb.IsNull(SessionRevokedAt)}
}

// FindRotated of the SQL store.
func (s sqlSessionStore) FindRotated(ctx context.Context, tokenHash []byte, now time.Time) (Session, time.Time, error) {
	var sess Session
	var until *time.Time
	q := s.a.Select().Columns(append(SessionBindings(&sess), sqlb.Bind(SessionPreviousValidUntil, &until))...).
		From(TableSession).Where(rotatedWhere(tokenHash, now)...).Limit(1)
	if err := s.notFound(s.a.One(ctx, q)); err != nil {
		return Session{}, time.Time{}, err
	}
	return sess, graceOf(until), nil
}

// findRotatedWithUser is FindRotated joined to the user, with checks.
func (s sqlSessionStore) findRotatedWithUser(ctx context.Context, tokenHash []byte, now time.Time, checks []sqlb.Predicate) (Session, User, time.Time, error) {
	var sess Session
	var u User
	var until *time.Time
	q := s.a.Select().
		Columns(sqlb.Bindings(SessionBindings(&sess), UserBindings(&u), []sqlb.Binding{sqlb.Bind(SessionPreviousValidUntil, &until)})...).
		From(TableSession).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: TableUser, On: []sqlb.Predicate{sqlb.EqExpr(UserID, SessionUserID)}}).
		Where(append(rotatedWhere(tokenHash, now), checks...)...).Limit(1)
	if err := s.notFound(s.a.One(ctx, q)); err != nil {
		return Session{}, User{}, time.Time{}, err
	}
	return sess, u, graceOf(until), nil
}

// graceOf reads the stored grace end; a row with a previous hash always has
// one, and a missing one is no grace at all, which fails closed.
func graceOf(until *time.Time) time.Time {
	if until == nil {
		return time.Time{}
	}
	return *until
}

// rotated is the memory store's record of a replaced token: whose it was
// and until when it is accepted.
type rotated struct {
	id    string
	until time.Time
}

// RotateToken of the memory store.
func (m *memorySessionStore) RotateToken(_ context.Context, id string, oldHash, newHash []byte, graceUntil, expiresAt, lastSeenAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	oldKey := hex.EncodeToString(oldHash)
	if key, ok := m.byID[id]; !ok || key != oldKey {
		return false, nil
	}
	s := m.byHash[oldKey]
	s.ExpiresAt, s.LastSeenAt = expiresAt, lastSeenAt
	delete(m.byHash, oldKey)
	newKey := hex.EncodeToString(newHash)
	m.byHash[newKey], m.byID[id] = s, newKey
	if prev, ok := m.prevByID[id]; ok {
		delete(m.prev, prev)
	}
	m.prev[oldKey], m.prevByID[id] = rotated{id: id, until: graceUntil}, oldKey
	return true, nil
}

// FindRotated of the memory store.
func (m *memorySessionStore) FindRotated(_ context.Context, tokenHash []byte, now time.Time) (Session, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.prev[hex.EncodeToString(tokenHash)]
	if !ok {
		return Session{}, time.Time{}, ErrSessionNotFound
	}
	s, ok := m.byHash[m.byID[r.id]]
	if !ok || !s.ExpiresAt.After(now) {
		return Session{}, time.Time{}, ErrSessionNotFound
	}
	return s, r.until, nil
}

var (
	_ SessionTokenRotator = sqlSessionStore{}
	_ SessionTokenRotator = (*memorySessionStore)(nil)
	_ rotatedUserFinder   = sqlSessionStore{}
)
