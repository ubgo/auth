package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ubgo/sqlb"
)

// SessionEndReason says why a session ended before the user would have let it
// expire (or, for SessionEndExpired, that it ran out). The set is closed so a
// plugin can switch on it and a webhook consumer can rely on the strings;
// a path that fits none of them uses SessionEndUnspecified rather than a
// string of its own.
type SessionEndReason string

// Reasons a session ends.
const (
	// SessionEndUnspecified: the caller used DeleteSession or
	// DeleteUserSessions, which carry no reason. Prefer EndSession.
	SessionEndUnspecified SessionEndReason = "unspecified"
	// SessionEndSignOut: the signed-in user ended their own current session.
	SessionEndSignOut SessionEndReason = "sign_out"
	// SessionEndRevoked: the user ended one of their sessions by id.
	SessionEndRevoked SessionEndReason = "revoked"
	// SessionEndRevokedOthers: the user ended all their sessions but the
	// current one.
	SessionEndRevokedOthers SessionEndReason = "revoked_others"
	// SessionEndRevokedAll: the user ended every session they have
	// ("sign out everywhere").
	SessionEndRevokedAll SessionEndReason = "revoked_all"
	// SessionEndAdmin: an administrator ended the session or all of a user's.
	SessionEndAdmin SessionEndReason = "admin_revoked"
	// SessionEndImpersonationStopped: an admin stopped impersonating, which
	// ends the impersonation session.
	SessionEndImpersonationStopped SessionEndReason = "impersonation_stopped"
	// SessionEndBanned: the user was banned or deactivated.
	SessionEndBanned SessionEndReason = "banned"
	// SessionEndPasswordChanged: the user changed their password.
	SessionEndPasswordChanged SessionEndReason = "password_changed"
	// SessionEndPasswordReset: the password was reset from a mailed token.
	SessionEndPasswordReset SessionEndReason = "password_reset"
	// SessionEndPasswordSet: a password was set on an account that had none.
	SessionEndPasswordSet SessionEndReason = "password_set"
	// SessionEndCredentialChanged: another credential change that ends
	// sessions created before it (a second factor turned on, an email
	// change undone).
	SessionEndCredentialChanged SessionEndReason = "credential_changed"
	// SessionEndTokenReuse: a rotated session token came back after its
	// grace, which is treated as theft (WithSessionTokenRotation).
	SessionEndTokenReuse SessionEndReason = "token_reuse"
	// SessionEndProviderLogout: a federated logout (OIDC end-session, SAML
	// single logout) ended the session.
	SessionEndProviderLogout SessionEndReason = "provider_logout"
	// SessionEndUserDeleted: the user was deleted.
	SessionEndUserDeleted SessionEndReason = "user_deleted"
	// SessionEndExpired: the session ran out and the sweep removed it. It
	// had stopped working already; the event lets a plugin clean up.
	SessionEndExpired SessionEndReason = "expired"
)

// SessionEndReasonValues lists every reason, for a consumer that validates or
// documents them.
var SessionEndReasonValues = []SessionEndReason{
	SessionEndUnspecified, SessionEndSignOut, SessionEndRevoked, SessionEndRevokedOthers, SessionEndRevokedAll,
	SessionEndAdmin, SessionEndImpersonationStopped, SessionEndBanned, SessionEndPasswordChanged, SessionEndPasswordReset,
	SessionEndPasswordSet, SessionEndCredentialChanged, SessionEndTokenReuse, SessionEndProviderLogout,
	SessionEndUserDeleted, SessionEndExpired,
}

// SessionEnd is what DataHooks.SessionEnded receives: one session that is
// ending and why. Session never carries the raw token.
//
// In stateless mode (WithStatelessSessions) the server holds no row, so only
// the ends the core itself performs are reported: the request's own session
// (sign-out, revoke by id) and, for "sign out everywhere", one SessionEnd with
// an empty Session.ID and the user's id, meaning "every session of this
// user". Expiry is never reported there.
type SessionEnd struct {
	Session Session
	Reason  SessionEndReason
}

// sessionEndBatch is how many expired sessions one sweep transaction removes
// and reports, so a store with millions of stale rows is never read whole.
const sessionEndBatch = 500

// wantsSessionEnd reports whether any plugin listens for session ends, so the
// paths that must read the sessions first (a List before the delete) cost
// nothing when nobody listens.
func (a *Auth) wantsSessionEnd() bool {
	for _, dh := range a.dataHooks {
		if dh.SessionEnded != nil {
			return true
		}
	}
	return false
}

// hookMode says what an ending does with a hook failure.
type hookMode int

const (
	// hookStrict: a hook error is returned as a *sessionHookError so
	// endAlways can roll the attempt back and end without hooks.
	hookStrict hookMode = iota
	// hookLenient: a hook error is reported and the ending goes on, for a
	// caller already inside a transaction, where the attempt cannot be
	// rolled back by itself.
	hookLenient
	// hookOff: the hooks do not run (the retry after a failure).
	hookOff
)

// sessionHookError is a SessionEnded hook's failure, kept apart from the
// store and database errors so only it triggers the retry without hooks.
type sessionHookError struct{ err error }

func (e *sessionHookError) Error() string { return "auth: session ended hook: " + e.err.Error() }
func (e *sessionHookError) Unwrap() error { return e.err }

// endAlways runs one ending, fn, so that a failing hook never keeps the
// session alive: in its own transaction the failed attempt is rolled back and
// fn runs again with hookOff, and the lost hook is reported. Inside a caller's
// transaction fn runs once in hookLenient mode.
func (a *Auth) endAlways(ctx context.Context, fn func(ctx context.Context, m hookMode) error) error {
	if txFrom(ctx) != nil {
		return fn(ctx, hookLenient)
	}
	err := fn(ctx, hookStrict)
	var he *sessionHookError
	if !errors.As(err, &he) {
		return err
	}
	return fn(ctx, hookOff)
}

// reportLostHook records that a SessionEnded hook failed for a session that
// ended anyway: the security stream gets SecuritySessionEndHookFailed and the
// log gets a warning.
func (a *Auth) reportLostHook(ctx context.Context, s Session, reason SessionEndReason, err error) {
	e := SecurityEvent{
		Kind: SecuritySessionEndHookFailed, Severity: SeverityWarn, Outcome: RateOutcomeLogged, UserID: s.UserID,
		Attrs: map[string]string{AttrSessionID: s.ID, AttrReason: string(reason), AttrError: err.Error()},
	}
	if st := stateFrom(ctx); st != nil {
		e.IP = st.req.Client.IP
	}
	a.EmitSecurity(e)
	a.logger.WarnContext(ctx, "auth: a session-ended hook failed; the session ended without it", "user", s.UserID, "session", s.ID, "reason", string(reason), "error", err)
}

// fireSessionEnded runs every SessionEnded hook for each ending session, in
// plugin order, stopping at the first error. In hookStrict the error is
// returned (as *sessionHookError) for endAlways; in hookLenient it is
// reported and the ending goes on; hookOff runs nothing.
func (a *Auth) fireSessionEnded(ctx context.Context, tx sqlb.DBTX, mode hookMode, reason SessionEndReason, ended ...Session) error {
	if mode == hookOff {
		return nil
	}
	for _, s := range ended {
		e := SessionEnd{Session: s, Reason: reason}
		for _, dh := range a.dataHooks {
			if dh.SessionEnded == nil {
				continue
			}
			_, end := a.dataHookSpan(ctx, "session_ended", "session")
			err := dh.SessionEnded(ctx, tx, e)
			end(err)
			if err == nil {
				continue
			}
			if mode == hookLenient {
				a.reportLostHook(ctx, s, reason, err)
				continue
			}
			a.reportLostHook(ctx, s, reason, err)
			return &sessionHookError{err: err}
		}
	}
	return nil
}

// endingSession finds the live session id of userID for the hook, or
// reports false when there is none (another user's id, an unknown id, a
// pending second-factor session), in which case nothing ends and nothing is
// reported.
func (a *Auth) endingSession(ctx context.Context, userID, id string) (Session, bool, error) {
	list, err := a.sessions.List(ctx, userID, a.now())
	if err != nil {
		return Session{}, false, err
	}
	for _, s := range list {
		if s.ID == id {
			return s, true, nil
		}
	}
	return Session{}, false, nil
}

// endingUserSessions lists the live sessions of userID that an end with
// exceptID spares not, for the hook.
func (a *Auth) endingUserSessions(ctx context.Context, userID, exceptID string) ([]Session, error) {
	list, err := a.sessions.List(ctx, userID, a.now())
	if err != nil {
		return nil, err
	}
	out := list[:0:0]
	for _, s := range list {
		if s.ID != exceptID {
			out = append(out, s)
		}
	}
	return out, nil
}

// expiredSweeper is the optional SessionStore upgrade that lets Sweep report
// expired sessions: it deletes up to limit sessions expired before now and
// returns them (revoked and pending ones included, which Sweep skips when it
// reports). The SQL and memory stores implement it. A store that expires
// sessions by itself (Redis TTL, storage) or wraps another (mirror) does not,
// and its expiries are not reported: nothing in the core ever sees them.
type expiredSweeper interface {
	SweepExpired(ctx context.Context, now time.Time, limit int) ([]Session, error)
}

// sweepSessions is Sweep's session step: the store's own sweep, or, when a
// plugin listens and the store can name what it removes, batches of expired
// sessions each deleted and reported in one transaction.
func (a *Auth) sweepSessions(ctx context.Context, now time.Time) (int64, error) {
	es, ok := a.sessions.(expiredSweeper)
	if !ok || !a.wantsSessionEnd() {
		return a.sessions.Sweep(ctx, now)
	}
	var total int64
	mode := hookStrict
	for {
		var batch []Session
		err := a.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
			var err error
			if batch, err = es.SweepExpired(ctx, now, sessionEndBatch); err != nil {
				return err
			}
			live := make([]Session, 0, len(batch))
			for _, s := range batch {
				if s.RevokedAt == nil && !s.SecondFactorPending {
					live = append(live, s)
				}
			}
			return a.fireSessionEnded(ctx, tx, mode, SessionEndExpired, live...)
		})
		var he *sessionHookError
		if errors.As(err, &he) {
			// The sweep removes expired rows whatever a hook says: run the
			// batch again, without the hooks.
			mode = hookOff
			continue
		}
		if err != nil {
			return total, fmt.Errorf("auth: sweep expired sessions: %w", err)
		}
		mode = hookStrict
		total += int64(len(batch))
		if len(batch) < sessionEndBatch {
			return total, nil
		}
	}
}

// SweepExpired of the SQL store: one SELECT of up to limit expired rows, one
// DELETE of exactly those ids, so the rows reported are the rows removed.
func (s sqlSessionStore) SweepExpired(ctx context.Context, now time.Time, limit int) ([]Session, error) {
	var row Session
	q := s.a.Select().Columns(SessionBindings(&row)...).From(TableSession).
		Where(sqlb.Less(SessionExpiresAt, now)).Order(sqlb.OrderBy(SessionID, sqlb.SortAsc)).Limit(limit)
	var out []Session
	if err := s.a.Each(ctx, q, func() error { out = append(out, row); return nil }); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	ids := make([]string, len(out))
	for i, r := range out {
		ids[i] = r.ID
	}
	_, err := s.a.Exec(ctx, sqlb.NewDelete(s.a.cfg.Dialect).From(TableSession).Where(sqlb.In(SessionID, ids...)))
	return out, err
}

// SweepExpired of the memory store.
func (m *memorySessionStore) SweepExpired(_ context.Context, now time.Time, limit int) ([]Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Session
	for key, s := range m.byHash {
		if len(out) == limit {
			break
		}
		if !s.ExpiresAt.After(now) {
			out = append(out, s)
			m.remove(s.ID, key)
		}
	}
	return out, nil
}
