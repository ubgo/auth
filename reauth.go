package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ubgo/sqlb"
)

// Re-authentication: the user proves "it is still me" on the session they
// already hold, and that session becomes fresh again for FreshSignIn
// operations, without a new session, a new row or a new cookie.
//
// Why it exists: freshness used to be the session's creation time, so the
// only way to become fresh was a new sign-in, which creates a second session.
// The old one stays alive (the device shows twice in the sessions list), and
// with a second factor on, the new one starts pending and replaces the
// client's token, so abandoning the code step signs the user out.
//
// The rule it keeps: re-authentication asks for exactly what signing in with
// the same method would ask. A method proves the user (password.reauthenticate,
// passkey.reauthenticate-finish) and calls Reauthenticate; the core asks the
// SecondFactor plugins the sign-in question, with SignInAttempt.Reauthentication
// set. When no second factor is due the session is fresh at once. When one is,
// the answer carries a single-use ticket bound to this session, and the second
// factor's own operation (twofactor.reauthenticate) checks its code and calls
// CompleteReauthentication with that ticket. A password alone never refreshes a
// session whose user signs in with two factors, so a stolen cookie plus a leaked
// password is not enough to change the password, the address or the factors.

// PurposeReauth is the verification purpose of a re-authentication ticket:
// the first factor was proved on session Identifier, the second is due. It
// lives PendingSessionTTL, as a pending sign-in does.
//
//ds:def id=core-purposereauth-4kq8wz2m owner=@khanakia stability=stable
const PurposeReauth Purpose = "core.reauth"

// Errors of re-authentication.
var (
	// ErrReauthUnsupported is returned when the session store cannot record a
	// re-authentication (a custom SessionStore without the
	// SessionReauthStore upgrade). Signing in again still works.
	ErrReauthUnsupported = NewError("auth.reauthentication_unsupported", http.StatusNotImplemented, "Confirming your identity is not available here. Sign in again to continue.")
	// ErrReauthTicketInvalid is returned by the second step for a ticket that
	// is wrong, spent, expired or issued to another session: the user starts
	// again from the first factor.
	ErrReauthTicketInvalid = NewError("auth.reauthentication_ticket_invalid", http.StatusBadRequest, "Confirm your password or passkey again.")
)

// errReauthProof refuses a ReauthAttempt that claims one factor and two.
var errReauthProof = errors.New("auth: ReauthAttempt: SingleFactor and MultiFactor are exclusive")

// SessionReauthStore is the optional upgrade of a SessionStore that can record
// a re-authentication. The SQL, memory, storage-backed, mirror and
// contrib/redis stores implement it; a custom store without it answers ErrReauthUnsupported to
// every re-authentication, and its users sign in again as before.
//
//ds:def id=core-sessionreauthstore-7nd3qp5x owner=@khanakia stability=stable
type SessionReauthStore interface {
	// SetReauthenticatedAt records at as session id's ReauthenticatedAt. An
	// unknown or ended id is no error. Every other field, the expiry and the
	// token above all, stays as it is.
	SetReauthenticatedAt(ctx context.Context, id string, at time.Time) error
}

// ReauthAttempt says what the method that called Reauthenticate proved. The
// zero value is a one-factor proof (a password): the SecondFactor plugins
// decide, as they do at sign-in.
//
//ds:def id=core-reauthattempt-2vx9mk4d owner=@khanakia stability=stable
type ReauthAttempt struct {
	// SingleFactor is set by a method that can prove two factors but proved
	// one this time (a passkey whose authenticator did not verify the user),
	// as SessionOptions.SingleFactor is at sign-in.
	SingleFactor bool
	// MultiFactor is set by a method that proved two factors on its own (a
	// user-verified passkey), as CreateMultiFactorSession is at sign-in: no
	// second factor is asked. Exclusive with SingleFactor.
	MultiFactor bool
}

// Reauthentication is the answer of a re-authentication step.
//
//ds:def id=core-reauthentication-8hw2nq6t owner=@khanakia stability=stable
type Reauthentication struct {
	// Fresh is true when the session is fresh now: FreshSignIn operations
	// pass until FreshUntil.
	Fresh bool `json:"fresh"`
	// FreshUntil is when the session stops being fresh (the
	// re-authentication time plus WithFreshWindow); nil when not Fresh.
	FreshUntil *time.Time `json:"freshUntil,omitempty"`
	// SecondFactorRequired is true when the user's second factor is due
	// before the session is fresh: the client sends Ticket with the code to
	// the second factor's re-authentication operation.
	SecondFactorRequired bool `json:"secondFactorRequired"`
	// Ticket is the single-use proof of the first step, bound to this
	// session and valid for PendingSessionTTL; "" unless
	// SecondFactorRequired.
	Ticket WireToken `json:"ticket,omitempty"`
}

// Reauthenticate is called by a sign-in method's re-authentication operation
// after it proved the call's user: it refreshes the call's session, or, when
// the user's second factor is due (asked exactly as at sign-in, with
// SignInAttempt.Reauthentication set), answers with a ticket for the second
// step. It never creates a session or issues a new token; in stateless mode
// the same session is resealed with the new time, as a sliding refresh does.
//
// Refused: no session or a pending one (ErrSignedOut), an API key
// (ErrAPIKeyRefused), an impersonation (ErrImpersonationRefused), a store
// without SessionReauthStore (ErrReauthUnsupported).
//
//ds:def id=core-reauthenticate-5tm8xr3q owner=@khanakia stability=stable
func (a *Auth) Reauthenticate(ctx context.Context, c *Call, in ReauthAttempt) (Reauthentication, error) {
	if in.SingleFactor && in.MultiFactor {
		return Reauthentication{}, errReauthProof
	}
	if err := a.reauthAllowed(c); err != nil {
		return Reauthentication{}, err
	}
	if !in.MultiFactor {
		attempt := a.signInAttempt(ctx, c.Session.UserID, c.Client, in.SingleFactor)
		attempt.Reauthentication = true
		due, err := a.secondFactorRequiredFor(ctx, attempt)
		if err != nil {
			return Reauthentication{}, err
		}
		if due {
			tok, err := a.IssueVerification(ctx, PurposeReauth, c.Session.ID, a.cfg.PendingSessionTTL, "")
			if err != nil {
				return Reauthentication{}, err
			}
			a.emitReauth(c, ReauthStepSecondFactor)
			return Reauthentication{SecondFactorRequired: true, Ticket: tok.Wire()}, nil
		}
	}
	return a.markFresh(ctx, c)
}

// CompleteReauthentication is called by a second factor's re-authentication
// operation after it checked its code: it spends ticket, which must come from
// Reauthenticate on this same session, and refreshes the session. A wrong,
// spent or expired ticket, or one issued to another session, is
// ErrReauthTicketInvalid; the session requirements are Reauthenticate's.
//
//ds:def id=core-completereauthentication-3gx7wn9k owner=@khanakia stability=stable
func (a *Auth) CompleteReauthentication(ctx context.Context, c *Call, ticket Token) (Reauthentication, error) {
	if err := a.reauthAllowed(c); err != nil {
		return Reauthentication{}, err
	}
	v, err := a.ConsumeVerification(ctx, PurposeReauth, ticket)
	if errors.Is(err, ErrTokenInvalid) {
		return Reauthentication{}, ErrReauthTicketInvalid
	}
	if err != nil {
		return Reauthentication{}, err
	}
	// A ticket proves the first factor on one session only: another
	// session's ticket (a second tab, a captured value) proves nothing here.
	if subtle.ConstantTimeCompare([]byte(v.Identifier), []byte(c.Session.ID)) != 1 {
		return Reauthentication{}, ErrReauthTicketInvalid
	}
	return a.markFresh(ctx, c)
}

// ReportReauthFailure tells the security stream that a re-authentication
// proof was refused (a wrong password, code or passkey). The operations call
// it beside returning their error; the audit log records the refusal by
// itself, as it does every mutation.
func (a *Auth) ReportReauthFailure(c *Call) {
	a.EmitSecurity(securityOfCall(c, SecurityEvent{
		Kind: SecurityReauthentication, Severity: SeverityWarn, Outcome: RateOutcomeBlocked,
		Attrs: map[string]string{AttrReauthStep: ReauthStepFailed},
	}))
}

// CanReauthenticate reports whether the call may re-authenticate, with the
// refusal Reauthenticate would give: ErrSignedOut for no session or a pending
// one, ErrAPIKeyRefused, ErrImpersonationRefused, ErrReauthUnsupported. A
// re-authentication operation calls it first, before it reads c.User or
// checks a credential, so a refused caller costs no hash and an operation
// whose SignedIn requirement was removed by mistake refuses instead of
// panicking on a nil user.
func (a *Auth) CanReauthenticate(c *Call) error { return a.reauthAllowed(c) }

// reauthAllowed is what every re-authentication step needs: a full session
// of the user's own, and a store that can record the time.
func (a *Auth) reauthAllowed(c *Call) error {
	switch {
	case c == nil || c.Session == nil || c.User == nil || c.Session.SecondFactorPending:
		return ErrSignedOut
	case c.Session.APIKeyID != "":
		return ErrAPIKeyRefused
	case c.Session.ImpersonatedBy != nil:
		// An admin acting as the user must not unlock what FreshSignIn
		// guards, by any route.
		return ErrImpersonationRefused
	}
	if a.stateless == nil {
		if _, ok := a.sessions.(SessionReauthStore); !ok {
			return ErrReauthUnsupported
		}
	}
	return nil
}

// markFresh records now as the session's re-authentication time: in the
// store, between the session's update hooks, or in stateless mode in a
// resealed token the transport hands to the client. The request sees the new
// time at once, and a cache entry is dropped so the next request does too.
func (a *Auth) markFresh(ctx context.Context, c *Call) (Reauthentication, error) {
	now := a.now()
	old := *c.Session
	s := old
	s.ReauthenticatedAt = &now
	if a.stateless != nil {
		tok, err := a.stateless.seal(s)
		if err != nil {
			return Reauthentication{}, err
		}
		c.Effects.ReplaceSessionOf(s, tok)
	} else {
		store, _ := a.sessions.(SessionReauthStore) // reauthAllowed checked it
		err := a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			if err := runHooks(ctx, a, tx, pickSession, stageBeforeUpdate, &old, &s); err != nil {
				return err
			}
			if err := store.SetReauthenticatedAt(ctx, s.ID, now); err != nil {
				return fmt.Errorf("auth: set reauthenticated_at: %w", err)
			}
			return runHooks(ctx, a, tx, pickSession, stageAfterUpdate, &old, &s)
		})
		if err != nil {
			return Reauthentication{}, err
		}
	}
	// c.Session is the request state's session (the pipeline hands the same
	// pointer), so the rest of the request sees the new time.
	*c.Session = s
	if st := stateFrom(ctx); st != nil {
		if err := a.dropCached(ctx, st); err != nil {
			return Reauthentication{}, err
		}
	}
	a.emitReauth(c, ReauthStepFresh)
	until := now.Add(a.cfg.FreshWindow)
	return Reauthentication{Fresh: true, FreshUntil: &until}, nil
}

// emitReauth reports a successful step to the security stream.
func (a *Auth) emitReauth(c *Call, step string) {
	a.EmitSecurity(securityOfCall(c, SecurityEvent{
		Kind: SecurityReauthentication, Severity: SeverityInfo, Outcome: RateOutcomeLogged,
		Attrs: map[string]string{AttrReauthStep: step},
	}))
}

// FreshAt is when the session last proved its user: the later of its creation
// and its last re-authentication. A FreshSignIn operation needs it within
// the fresh window.
func (s Session) FreshAt() time.Time {
	if s.ReauthenticatedAt != nil && s.ReauthenticatedAt.After(s.CreatedAt) {
		return *s.ReauthenticatedAt
	}
	return s.CreatedAt
}

// SetReauthenticatedAt of the SQL store: one UPDATE of the live row.
func (s sqlSessionStore) SetReauthenticatedAt(ctx context.Context, id string, at time.Time) error {
	_, err := s.a.Exec(ctx, sqlb.NewUpdate(s.a.cfg.Dialect).Table(TableSession).
		Set(sqlb.Set(SessionReauthenticatedAt, &at)).Where(sqlb.Eq(SessionID, id), sqlb.IsNull(SessionRevokedAt)))
	return err
}

// SetReauthenticatedAt of the memory store sets the time in place; an
// unknown id changes nothing.
func (m *memorySessionStore) SetReauthenticatedAt(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, ok := m.byID[id]
	if !ok {
		return nil
	}
	s := m.byHash[key]
	s.ReauthenticatedAt = &at
	m.byHash[key] = s
	return nil
}
