package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ubgo/sqlb"
)

// SessionConfig holds the session lifetimes.
//
// Two limits, because either alone is wrong: a session that never expires is a
// stolen laptop that never stops working, and one that expires an hour after
// sign-in annoys every user. IdleTimeout slides while the user is active;
// MaxLifetime is the hard stop after which they sign in again.
//
//ds:def id=core-sessionconfig-2hscd7v9 owner=@khanakia stability=stable
type SessionConfig struct {
	IdleTimeout time.Duration
	MaxLifetime time.Duration
	// RefreshAfter limits how often an active session's expiry is written, so
	// the middleware does not write to the database on every request.
	RefreshAfter time.Duration
	// TransientIdleTimeout replaces IdleTimeout for a session made without
	// "remember me" (SessionOptions.Transient). Zero means
	// DefaultTransientIdleTimeout.
	TransientIdleTimeout time.Duration
}

// NoSessionRefresh, as RefreshAfter, stops the sliding expiry: a session then
// ends exactly IdleTimeout after it was created, however active the user. It
// is MaxSessionLifetime because no session can be seen that long after its
// last use: its hard stop comes first.
//
//ds:def id=core-nosessionrefresh-6ht3cwz9 owner=@khanakia stability=stable
const NoSessionRefresh = MaxSessionLifetime

// DefaultTransientIdleTimeout: a session the user did not ask to remember
// ends after half a day without use, besides ending with the browser.
//
//ds:def id=core-defaulttransientidle-7mhdjdth owner=@khanakia stability=stable
const DefaultTransientIdleTimeout = 12 * time.Hour

// SessionOptions are the per-sign-in choices a sign-in method passes to
// CreateSessionWithOptions.
type SessionOptions struct {
	// Transient is "remember me" unticked.
	Transient bool
	// SingleFactor reports that this sign-in proved one factor whatever its
	// operation, such as a passkey whose authenticator did not verify the
	// user (possession only). It reaches SecondFactorForSignIn plugins as
	// SignInAttempt.SingleFactor, so a policy that skips the factor for the
	// method's other sign-ins can still ask for it here.
	SingleFactor bool
}

// DefaultSessionConfig: 7 days idle, 30 days at most, refreshed at most daily.
//
//ds:def id=core-defaultsessionconfig-nsrfps74 owner=@khanakia stability=stable
var DefaultSessionConfig = SessionConfig{
	IdleTimeout:  7 * 24 * time.Hour,
	MaxLifetime:  30 * 24 * time.Hour,
	RefreshAfter: 24 * time.Hour,
}

// resolve fills every zero duration from DefaultSessionConfig and refuses a
// negative one.
//
// Why: a WithSession that set only IdleTimeout left MaxLifetime at zero, and
// a zero hard stop ended every session at its first request after sign-in.
// Zero means "the default" here as it does for SessionLifetime,
// TransientIdleTimeout and AccountDeletion.LinkTTL; a negative duration is a
// mistake rather than a choice, so it fails the start.
func (c *SessionConfig) resolve() error {
	def := DefaultSessionConfig
	for _, f := range []struct {
		name string
		v    *time.Duration
		def  time.Duration
	}{
		{"IdleTimeout", &c.IdleTimeout, def.IdleTimeout},
		{"MaxLifetime", &c.MaxLifetime, def.MaxLifetime},
		{"RefreshAfter", &c.RefreshAfter, def.RefreshAfter},
		{"TransientIdleTimeout", &c.TransientIdleTimeout, DefaultTransientIdleTimeout},
	} {
		switch {
		case *f.v < 0:
			return fmt.Errorf("%w: SessionConfig.%s is %v", ErrBadSessionConfig, f.name, *f.v)
		case *f.v == 0:
			*f.v = f.def
		}
	}
	return nil
}

// CreateSession starts a session for userID and returns it with its raw token.
// The token exists only in the return value and, through the IssueSession
// effect, in the client; the database stores its hash.
//
// Sign-in plugins call this and never write auth_session themselves, so the
// session rules live in one place.
//
// When a SecondFactor plugin requires a second factor for the user, the
// session is created pending: it lasts PendingSessionTTL, signs nobody in, and
// PromoteSession replaces it once the factor is passed. Sign-in plugins need
// no code for this; they report Session.SecondFactorPending to the client.
//
//ds:def id=core-createsession-qp23u2q5 owner=@khanakia stability=stable
func (a *Auth) CreateSession(ctx context.Context, userID string, client Client) (Session, Token, error) {
	return a.CreateSessionWithOptions(ctx, userID, client, SessionOptions{})
}

// CreateSessionWithOptions is CreateSession with the sign-in's choices, such
// as "remember me". Hand the result to the client with Effects.IssueSessionOf,
// which carries the choice to the cookie.
func (a *Auth) CreateSessionWithOptions(ctx context.Context, userID string, client Client, o SessionOptions) (Session, Token, error) {
	pending, err := a.secondFactorRequired(ctx, userID, client, o.SingleFactor)
	if err != nil {
		return Session{}, "", err
	}
	return a.createSessionFull(ctx, userID, client, sessionSeed{pending: pending, transient: o.Transient})
}

// CreateMultiFactorSession starts a full session without asking SecondFactor
// plugins, for a sign-in method that is itself multi-factor: a passkey with
// user verification proves possession of the device and the user's PIN or
// biometric in one step. A method that proves one factor must call
// CreateSession instead, or a user who turned on two-factor loses it.
func (a *Auth) CreateMultiFactorSession(ctx context.Context, userID string, client Client) (Session, Token, error) {
	return a.createSession(ctx, userID, client, false)
}

// MaxImpersonationTTL caps an impersonation session: long enough to reproduce
// a problem, short enough that a forgotten one ends by itself.
//
//ds:def id=maximpersonationttl-3f39wbus owner=@khanakia stability=stable
const MaxImpersonationTTL = time.Hour

// CreateImpersonationSession starts a session as userID for the admin adminID,
// lasting ttl (at most MaxImpersonationTTL). The row records adminID, so the
// user's session list shows the impersonation. Only an admin plugin should
// call it, after its own authorization.
func (a *Auth) CreateImpersonationSession(ctx context.Context, userID, adminID string, client Client, ttl time.Duration) (Session, Token, error) {
	if ttl <= 0 || ttl > MaxImpersonationTTL {
		ttl = MaxImpersonationTTL
	}
	s, tok, err := a.createSessionWith(ctx, userID, client, false, &adminID, ttl)
	return s, tok, err
}

// PendingSessionTTL is how long a user has to pass the second factor, unless
// WithPendingSessionTTL says otherwise.
//
//ds:def id=pendingsessionttl-p4sajtqx owner=@khanakia stability=stable
const PendingSessionTTL = 10 * time.Minute

// SecondFactor is a plugin that can require a second factor at sign-in, such
// as a TOTP plugin for users who enrolled.
//
//ds:def id=core-secondfactor-h5jajc6c owner=@khanakia stability=stable
type SecondFactor interface {
	SecondFactorRequired(ctx context.Context, userID string) (bool, error)
}

// SignInAttempt describes the sign-in a session is being created for, as a
// SecondFactorForSignIn plugin sees it. It is a struct so fields can be added
// without breaking implementers.
type SignInAttempt struct {
	UserID string
	// Client is the request's client (IP, user agent, origin).
	Client Client
	// Operation is the operation signing the user in, such as
	// "password.sign-in" or "oauth.callback"; "" for a direct Go call to
	// CreateSession outside any operation.
	Operation EndpointID
	// Method is the name of the plugin that registered Operation, such as
	// "password", "oauth" or "sso": the sign-in method. "" when Operation is.
	Method string
	// SingleFactor is set by a method that proved one factor on this
	// sign-in although the operation can also prove two (a passkey without
	// user verification), through SessionOptions.SingleFactor. False tells a
	// policy nothing beyond Operation and Method.
	SingleFactor bool
	// Reauthentication is true when the user is not signing in but proving
	// who they are on the session they hold (Auth.Reauthenticate). A policy
	// that decides by Operation already sees the re-authentication
	// operation; the flag is for one that decides by Method alone.
	Reauthentication bool
}

// SecondFactorForSignIn is an optional upgrade of SecondFactor: a plugin that
// implements it is asked with the whole SignInAttempt instead of the user id
// alone, so its policy can depend on how the user signed in (skip the factor
// after an SSO sign-in whose identity provider already enforced one) or from
// where. CreateSession calls it in place of SecondFactorRequired.
type SecondFactorForSignIn interface {
	SecondFactorRequiredForSignIn(ctx context.Context, in SignInAttempt) (bool, error)
}

// signInAttempt fills a SignInAttempt from the operation running in ctx.
func (a *Auth) signInAttempt(ctx context.Context, userID string, client Client, singleFactor bool) SignInAttempt {
	in := SignInAttempt{UserID: userID, Client: client, SingleFactor: singleFactor}
	if info, ok := OperationOf(ctx); ok {
		in.Operation = info.ID
		if op, ok := a.Operation(info.ID); ok {
			in.Method = op.Plugin()
		}
	}
	return in
}

func (a *Auth) secondFactorRequired(ctx context.Context, userID string, client Client, singleFactor bool) (bool, error) {
	return a.secondFactorRequiredFor(ctx, a.signInAttempt(ctx, userID, client, singleFactor))
}

// secondFactorRequiredFor asks every SecondFactor plugin about in: the
// sign-in question, which re-authentication asks too.
func (a *Auth) secondFactorRequiredFor(ctx context.Context, in SignInAttempt) (bool, error) {
	for _, p := range a.plugins {
		var req bool
		var err error
		switch sf := p.(type) {
		case SecondFactorForSignIn:
			req, err = sf.SecondFactorRequiredForSignIn(ctx, in)
		case SecondFactor:
			req, err = sf.SecondFactorRequired(ctx, in.UserID)
		default:
			continue
		}
		if err != nil {
			return false, err
		}
		if req {
			return true, nil
		}
	}
	return false, nil
}

// PromoteSession replaces the call's pending session with a full one, after a
// second factor was passed. The token changes too, so a token captured before
// the second factor is worthless after it. The app data the pending session
// carried moves to the full one, and SessionLifecycle plugins are told of
// the replacement rather than of an end. Only a PendingSecondFactor
// operation can call it.
//
//ds:def id=core-promotesession-vvab635r owner=@khanakia stability=stable
func (a *Auth) PromoteSession(ctx context.Context, c *Call) (Session, error) {
	if c.Session == nil || !c.Session.SecondFactorPending {
		return Session{}, ErrSignedOut
	}
	var out Session
	err := a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		if err := a.endSession(ctx, *c.Session); err != nil {
			return err
		}
		s, tok, err := a.createSessionFull(ctx, c.Session.UserID, c.Client, sessionSeed{transient: c.Session.Transient, data: c.Session.Data, promoted: true})
		if err != nil {
			return err
		}
		if err := a.sessionReplaced(ctx, *c.Session, s); err != nil {
			return err
		}
		c.Effects.ReplaceSessionOf(s, tok)
		out = s
		return nil
	})
	return out, err
}

func (a *Auth) createSession(ctx context.Context, userID string, client Client, pending bool) (Session, Token, error) {
	return a.createSessionWith(ctx, userID, client, pending, nil, 0)
}

// createSessionWith is createSession with an impersonator and a fixed
// lifetime; ttl 0 means the configured lifetimes.
func (a *Auth) createSessionWith(ctx context.Context, userID string, client Client, pending bool, impersonator *string, ttl time.Duration) (Session, Token, error) {
	return a.createSessionFull(ctx, userID, client, sessionSeed{pending: pending, impersonator: impersonator, ttl: ttl})
}

// sessionSeed is what differs between the sessions createSessionFull makes:
// the rest (id, times, client, lifetime) is computed the same way for all.
type sessionSeed struct {
	pending      bool
	impersonator *string
	// ttl is a fixed lifetime; 0 means the configured lifetimes.
	ttl       time.Duration
	transient bool
	// data is the app data the session starts with: at a promotion, the
	// pending session's. A sign-in starts with none; a Session.BeforeCreate
	// hook sets it.
	data AppData
	// promoted marks the full session that replaces a pending one after the
	// second factor: the sign-in was judged when the pending session was made.
	promoted bool
	// continued marks a session that replaces one the user already signed
	// in with, after a session task was completed: tasks is then what is
	// left, the SessionTasker plugins are not asked again, and no
	// unknown-device mail goes out for a sign-in that already sent one.
	continued bool
	tasks     SessionTasks
}

func (a *Auth) createSessionFull(ctx context.Context, userID string, client Client, seed sessionSeed) (Session, Token, error) {
	// A sign-in the user did not make (an impersonation), one that already
	// passed (a promotion) and an import judge nothing.
	if a.geo != nil && !seed.promoted && seed.impersonator == nil && !isQuiet(ctx) {
		if err := a.geo.checkTravel(ctx, userID, client); err != nil {
			return Session{}, "", err
		}
	}
	// Tasks are decided for the full session the user signs in with: not
	// for a pending one (its promotion is asked), not for an impersonation
	// (the admin is not the user who must set anything up).
	tasks := seed.tasks
	if !seed.continued && !seed.pending && seed.impersonator == nil && len(a.taskers) > 0 {
		var err error
		if tasks, err = a.sessionTasksFor(ctx, a.signInAttempt(ctx, userID, client, false)); err != nil {
			return Session{}, "", err
		}
	}
	id, err := a.ids(IDPrefixSession)
	if err != nil {
		return Session{}, "", err
	}
	now := a.now()
	s := Session{
		ID: id, UserID: userID, CreatedAt: now, LastSeenAt: now,
		UserAgent:           client.UserAgent,
		SecondFactorPending: seed.pending, ImpersonatedBy: seed.impersonator, Transient: seed.transient,
		Data: seed.data, Tasks: tasks,
	}
	if a.trackIP {
		s.IP = client.IP
	}
	switch {
	case seed.pending:
		s.ExpiresAt = now.Add(a.cfg.PendingSessionTTL)
	case seed.ttl > 0:
		s.ExpiresAt = now.Add(seed.ttl)
	default:
		// A full session carries the lifetime chosen for it, so every later
		// refresh slides by the session's own values, not the defaults.
		lt := a.lifetimeFor(ctx, userID, client, seed.transient)
		maxAt := now.Add(lt.Max)
		s.IdleSeconds, s.RefreshSeconds, s.MaxExpiresAt = int64(lt.Idle/time.Second), int64(lt.RefreshAfter/time.Second), &maxAt
		s.ExpiresAt = s.expiryAt(a.cfg.Session, now)
	}
	// before checks that the user exists, runs the BeforeCreate hooks and
	// checks what they left in Data: a hook sets it by hand, and the bound
	// and the JSON check hold for it as for SetSessionData, before any store
	// sees it. The existence check is what the session table's foreign key
	// used to do (ADR-0002): a session for a user that does not exist would
	// otherwise be stored and sign nobody in, and a store outside the
	// database never had the constraint at all.
	before := func(ctx context.Context, tx sqlbTx) (err error) {
		if _, err := a.User(ctx, userID); err != nil {
			return fmt.Errorf("auth: create session: %w", err)
		}
		if err := runHooks(ctx, a, tx, pickSession, stageBeforeCreate, nil, &s); err != nil {
			return err
		}
		// A data hook shapes the row, never its access: the tasks are the
		// SessionTasker plugins' decision, so a hook cannot drop one.
		s.Tasks = tasks
		s.Data, err = s.Data.normalized()
		return err
	}
	var tok Token
	if a.stateless != nil {
		// The token is the session; it exists once the hooks have seen the
		// final row, so it is sealed after them.
		err = a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			if err := before(ctx, tx); err != nil {
				return err
			}
			if tok, err = a.stateless.seal(s); err != nil {
				return err
			}
			return runHooks(ctx, a, tx, pickSession, stageAfterCreate, nil, &s)
		})
	} else {
		tok = NewToken()
		err = a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			if err := before(ctx, tx); err != nil {
				return err
			}
			if err := a.sessions.Insert(ctx, s, HashToken(tok)); err != nil {
				return fmt.Errorf("auth: insert session: %w", err)
			}
			if len(s.Tasks) > 0 {
				if err := a.checkStoredTasks(ctx, s, tok); err != nil {
					return err
				}
			}
			return runHooks(ctx, a, tx, pickSession, stageAfterCreate, nil, &s)
		})
	}
	if err != nil {
		return Session{}, "", err
	}
	a.afterSignIn(ctx, s, client, seed)
	return s, tok, nil
}

// ResolveSession turns a raw token into its session and user, and slides the
// expiry of an active session.
//
// Expiry is checked by the store, so an expired session is not found at all
// rather than found and then compared in Go, where a caller could forget.
// Plugins' SessionChecker conditions apply on the same lookup, so a banned
// user fails on the next request, not when a cache expires; and a session
// created before the user's SessionsValidAfter is refused in every mode.
//
// refreshed reports whether the expiry moved, so the transport can send the
// cookie again with the new expiry. In stateless mode a refresh makes a new
// token, which only the request pipeline delivers (as an issue-session
// effect); a direct caller keeps using the old token until it expires.
// ErrSignedOut covers an unknown, expired and revoked token alike, and a
// session still waiting for its second factor.
//
// A session with tasks pending (Session.Tasks) is returned as it is: its
// user is proven, and a flow that hands the token on (a popup, a handoff)
// needs it. It is usable only for the operations its tasks allow, so a
// caller deciding access itself checks Tasks, as CurrentUser does.
//
//ds:def id=core-resolvesession-qg4k2agf owner=@khanakia stability=stable
func (a *Auth) ResolveSession(ctx context.Context, t Token) (sess *Session, user *User, refreshed bool, err error) {
	s, u, reissue, err := a.resolveSessionFor(ctx, t, true)
	if err == nil && s.SecondFactorPending {
		return nil, nil, false, ErrSignedOut
	}
	return s, u, reissue != "", err
}

// resolveSession is ResolveSession that also returns a pending session, for
// the request state, which hands one only to PendingSecondFactor operations.
// reissue is the token the client must hold from now on, or "" when the one
// it sent is still the right one.
func (a *Auth) resolveSession(ctx context.Context, t Token) (sess *Session, user *User, reissue Token, err error) {
	return a.resolveSessionFor(ctx, t, true)
}

// refreshDue reports whether a session seen now would slide its expiry: it
// is active, not pending or impersonated, and RefreshAfter has passed since
// it was last seen.
func (a *Auth) refreshDue(s Session) bool {
	return !s.SecondFactorPending && s.ImpersonatedBy == nil && a.now().Sub(s.LastSeenAt) >= s.Lifetime(a.cfg.Session).RefreshAfter
}

// resolveSessionFor is resolveSession with the choice of sliding the expiry:
// refresh false looks up only, for a read under WithDeferredSessionRefresh,
// and the caller reports needsRefresh instead.
func (a *Auth) resolveSessionFor(ctx context.Context, t Token, refresh bool) (sess *Session, user *User, reissue Token, err error) {
	r, err := a.lookupSession(ctx, t, refresh, false, false)
	return r.session, r.user, r.reissue, err
}

// lookedUp is what lookupSession found.
type lookedUp struct {
	session *Session
	user    *User
	// reissue is the token the client must hold from now on, or "".
	reissue Token
	// fromToken is true when the user is the stateless token's copy rather
	// than a read (WithStatelessRefreshWithoutRead), so a FreshSignIn
	// operation looks it up again.
	fromToken bool
	// inGrace is true when the token is one a rotation replaced, still in
	// its grace window (WithTokenRotation): such a lookup is never cached,
	// or the cache would keep answering for the token past its grace.
	inGrace bool
	// rotated is true when this lookup gave the session a new token
	// (WithTokenRotation): reissue then replaces the token the client sent.
	rotated bool
}

// lookupSession is the one session lookup. fullRead refuses the stateless
// token's copy of the user and loads it, for a FreshSignIn operation.
// rotate lets a slide give the session a new token under WithTokenRotation;
// only the request pipeline passes it, because only it hands the new token
// to the client.
func (a *Auth) lookupSession(ctx context.Context, t Token, refresh, fullRead, rotate bool) (lookedUp, error) {
	if a.db == nil {
		return lookedUp{}, ErrNoDatabase
	}
	now := a.now()
	var s Session
	var u User
	var err error
	// read is the stateless token's user copy as it will be resealed: the
	// one the token carried, or a new one after a full read.
	var read *statelessRead
	fromToken, reread := false, false
	switch {
	case a.stateless != nil:
		var carried *statelessRead
		s, carried, err = a.stateless.openWith(t)
		if err == nil && !s.ExpiresAt.After(now) {
			err = ErrSessionNotFound
		}
		if err == nil {
			err = a.checkRevoked(ctx, s.ID, now)
		}
		switch {
		case err != nil:
		case !fullRead && a.stateless.usableRead(carried, now):
			u, read, fromToken = carried.User, carried, true
		default:
			u, err = a.checkedUser(ctx, s.UserID)
			if err == nil && a.stateless.readEvery > 0 {
				read, reread = &statelessRead{User: u, At: now}, true
			}
		}
	case a.finder != nil:
		s, u, err = a.finder.FindWithUser(ctx, HashToken(t), now, a.sessionPredicates())
	default:
		s, err = a.sessions.Find(ctx, HashToken(t), now)
		if err == nil {
			u, err = a.checkedUser(ctx, s.UserID)
		}
	}
	// A token the store does not hold may be one a rotation replaced: still
	// good within its grace, and a theft after it (lookupRotated revokes).
	// A token in its grace never slides: the session already moved on to
	// the token the rotation issued.
	inGrace, rotated := false, false
	if a.rotation != nil && errors.Is(err, ErrSessionNotFound) {
		s, u, err = a.lookupRotated(ctx, t, now)
		inGrace = err == nil
	}
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return lookedUp{}, ErrSignedOut
		}
		return lookedUp{}, fmt.Errorf("auth: look up session: %w", err)
	}
	if u.SessionsValidAfter != nil && s.CreatedAt.Before(*u.SessionsValidAfter) {
		return lookedUp{}, ErrSignedOut
	}
	var reissue Token
	// A pending or impersonation session never slides: its short life is the
	// point.
	slide := refresh && !inGrace && a.refreshDue(s)
	if slide {
		exp := s.expiryAt(a.cfg.Session, now)
		switch {
		case a.stateless != nil:
			s.ExpiresAt, s.LastSeenAt = exp, now
		case rotate && a.rotation != nil:
			next, err := a.rotate(ctx, s, t, exp, now)
			if err != nil {
				return lookedUp{}, err
			}
			if next != "" {
				s.ExpiresAt, s.LastSeenAt, reissue, rotated = exp, now, next, true
			}
		default:
			moved, err := a.sessions.Touch(ctx, s.ID, exp, now)
			if err != nil {
				return lookedUp{}, fmt.Errorf("auth: refresh session: %w", err)
			}
			if moved {
				s.ExpiresAt, s.LastSeenAt, reissue = exp, now, t
			}
		}
	}
	// A stateless token is resealed when it slid, carrying the user copy it
	// had, and after a full read under WithStatelessRefreshWithoutRead,
	// carrying the new copy; a read-only lookup (refresh false) leaves the
	// token alone and the next request reads again.
	if a.stateless != nil && (slide || reread && refresh) {
		if reissue, err = a.stateless.sealWith(s, read); err != nil {
			return lookedUp{}, err
		}
	}
	return lookedUp{session: &s, user: &u, reissue: reissue, fromToken: fromToken, inGrace: inGrace, rotated: rotated}, nil
}

// checkedUser loads the user of a session with every SessionChecker condition
// applied, for the modes whose lookup does not join auth_user. A user the
// conditions refuse is ErrSessionNotFound: the same answer as no session, so
// a banned user learns nothing from the difference.
func (a *Auth) checkedUser(ctx context.Context, userID string) (User, error) {
	var u User
	q := a.Select().Columns(UserBindings(&u)...).From(TableUser).
		Where(append([]sqlb.Predicate{sqlb.Eq(UserID, userID)}, a.sessionPredicates()...)...).Limit(1)
	err := a.One(ctx, q)
	if errors.Is(err, sqlb.ErrNoRows) {
		return User{}, ErrSessionNotFound
	}
	return u, err
}

// Sessions lists a user's live sessions, newest first; sessions created in
// the same instant come in descending id order, so the list is the same on
// every store and every call. In stateless mode only the request's own
// session is known: it is returned when ctx carries it for userID, otherwise
// ErrSessionsUnavailable.
//
//ds:def id=core-sessions-ra92ahrn owner=@khanakia stability=stable
func (a *Auth) Sessions(ctx context.Context, userID string) ([]Session, error) {
	if a.stateless != nil {
		if s, ok := currentSession(ctx, userID); ok {
			return []Session{s}, nil
		}
		return nil, ErrSessionsUnavailable
	}
	return a.sessions.List(ctx, userID, a.now())
}

// DeleteSession ends one session of userID. Deleting a session of another user
// matches nothing, which is how revoking by id stays safe. In stateless mode
// there is nothing to delete: the request's own session ends when the
// transport clears its token, and any other id is ErrSessionsUnavailable;
// under WithSessionRevocations the session's id also goes on the list, so
// the token stops opening at once, not only on this device.
// SessionLifecycle plugins are told first, in the same transaction, so a
// plugin that refuses leaves the session in place in every store; so are the
// DataHooks.SessionEnded hooks, with SessionEndUnspecified (use EndSession to
// say why). The user's SessionCache entries are evicted after the commit
// (EvictCachedSessions): the cache is keyed by token, which the server does
// not keep, so the user's other devices miss once too.
func (a *Auth) DeleteSession(ctx context.Context, userID, id string) error {
	return a.EndSession(ctx, userID, id, SessionEndUnspecified)
}

// EndSession is DeleteSession with the reason the session ends, which
// DataHooks.SessionEnded receives. Every core and plugin path that ends one
// session calls it, so a listener sees them all.
//
//ds:def id=core-endsession-4h8cwq2m owner=@khanakia stability=stable
func (a *Auth) EndSession(ctx context.Context, userID, id string, reason SessionEndReason) error {
	return a.endAlways(ctx, func(ctx context.Context, m hookMode) error {
		if a.stateless != nil {
			s, ok := currentSession(ctx, userID)
			if !ok || s.ID != id {
				return ErrSessionsUnavailable
			}
			err := a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
				if err := a.sessionEnded(ctx, userID, id); err != nil {
					return err
				}
				return a.fireSessionEnded(ctx, tx, m, reason, s)
			})
			if err != nil {
				return err
			}
			a.EvictCachedSessions(ctx, userID)
			return a.revokeStateless(ctx, s)
		}
		return a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			if err := a.sessionEnded(ctx, userID, id); err != nil {
				return err
			}
			if m != hookOff && a.wantsSessionEnd() {
				s, ok, err := a.endingSession(ctx, userID, id)
				if err != nil {
					return err
				}
				if ok {
					if err := a.fireSessionEnded(ctx, tx, m, reason, s); err != nil {
						return err
					}
				}
			}
			a.EvictCachedSessions(ctx, userID)
			return a.sessions.Delete(ctx, userID, id)
		})
	})
}

// endSession removes one session from the store with no lifecycle notice,
// for PromoteSession, which reports a replacement instead of an end. In
// stateless mode there is nothing to remove; under WithSessionRevocations
// the pending session's id goes on the list, so a token captured before the
// second factor stops opening even as a pending session.
func (a *Auth) endSession(ctx context.Context, s Session) error {
	if a.stateless != nil {
		return a.revokeStateless(ctx, s)
	}
	return a.sessions.Delete(ctx, s.UserID, s.ID)
}

// DeleteUserSessions ends every session of userID except exceptID, which may be
// empty to end them all. A password reset and an "undo email change" call it
// with no exception, because they are often the answer to a stolen account.
//
// With no exception it also sets the user's SessionsValidAfter to now, in
// every mode: that is what ends stateless sessions, which have no row to
// delete, and it costs one update. With an exception it cannot, since the
// excepted session would end too, so stateless mode refuses that call with
// ErrSessionsUnavailable. Either way the user's SessionCache entries are
// evicted after the commit (EvictCachedSessions), so the end reaches a
// cached device on its next request.
//
//ds:def id=core-deleteusersessions-xu9nyyx4 owner=@khanakia stability=stable
func (a *Auth) DeleteUserSessions(ctx context.Context, userID, exceptID string) error {
	return a.EndUserSessions(ctx, userID, exceptID, SessionEndUnspecified)
}

// EndUserSessions is DeleteUserSessions with the reason the sessions end,
// which DataHooks.SessionEnded receives once per session. Every core and
// plugin path that ends a user's sessions calls it.
//
//ds:def id=core-endusersessions-9d3tzr5k owner=@khanakia stability=stable
func (a *Auth) EndUserSessions(ctx context.Context, userID, exceptID string, reason SessionEndReason) error {
	if exceptID != "" && a.stateless != nil {
		return ErrSessionsUnavailable
	}
	return a.endAlways(ctx, func(ctx context.Context, m hookMode) error {
		return a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			if exceptID == "" {
				now := a.now()
				if _, err := a.Exec(ctx, sqlb.NewUpdate(a.cfg.Dialect).Table(TableUser).
					Set(sqlb.Set(UserSessionsValidAfter, &now)).Where(sqlb.Eq(UserID, userID))); err != nil {
					return fmt.Errorf("auth: mark sessions invalid: %w", err)
				}
			}
			if err := a.userSessionsEnded(ctx, userID, exceptID); err != nil {
				return err
			}
			if err := a.fireUserSessionsEnded(ctx, tx, m, userID, exceptID, reason); err != nil {
				return err
			}
			a.EvictCachedSessions(ctx, userID)
			if a.stateless != nil {
				return nil
			}
			return a.sessions.DeleteUser(ctx, userID, exceptID)
		})
	})
}

// fireUserSessionsEnded reports every live session of userID but exceptID to
// the SessionEnded hooks. Stateless mode has no list: it reports one end with
// an empty session id, the user's id and nothing else.
func (a *Auth) fireUserSessionsEnded(ctx context.Context, tx sqlbTx, m hookMode, userID, exceptID string, reason SessionEndReason) error {
	if m == hookOff || !a.wantsSessionEnd() {
		return nil
	}
	if a.stateless != nil {
		return a.fireSessionEnded(ctx, tx, m, reason, Session{UserID: userID})
	}
	list, err := a.endingUserSessions(ctx, userID, exceptID)
	if err != nil {
		return err
	}
	return a.fireSessionEnded(ctx, tx, m, reason, list...)
}

// RotateSessionToken gives the call's own session a new raw token: same row,
// id, creation time, expiry and lifetimes, so nothing about its freshness
// changes, and the token the client sent stops working at once, its cache
// entry dropped with it. An admin plugin uses it before impersonating, so
// the admin's own token can be kept in the flow cookie and reissued when the
// impersonation ends while a stolen impersonation cookie alone gains
// nothing. In stateless mode the session is sealed again. The caller hands
// the new token to the client itself (IssueSessionOf or BindFlow).
//
//ds:def id=core-rotatesessiontoken-5vn8qx3t owner=@khanakia stability=stable
func (a *Auth) RotateSessionToken(ctx context.Context, c *Call) (Token, error) {
	if c.Session == nil {
		return "", ErrSignedOut
	}
	if a.stateless != nil {
		return a.stateless.seal(*c.Session)
	}
	tok := NewToken()
	err := a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
		if err := a.sessions.Delete(ctx, c.Session.UserID, c.Session.ID); err != nil {
			return fmt.Errorf("auth: rotate session: %w", err)
		}
		if err := a.sessions.Insert(ctx, *c.Session, HashToken(tok)); err != nil {
			return fmt.Errorf("auth: rotate session: %w", err)
		}
		return a.forgetSession(ctx, c)
	})
	if err != nil {
		return "", err
	}
	return tok, nil
}

// Core operation ids.
const (
	EndpointSession       EndpointID = "core.session"
	EndpointSignOut       EndpointID = "core.sign-out"
	EndpointSignOutAll    EndpointID = "core.sign-out-all"
	EndpointSessions      EndpointID = "core.sessions"
	EndpointRevokeSession EndpointID = "core.sessions-revoke"
	EndpointProfile       EndpointID = "core.profile"
	// EndpointRefreshSession slides the expiry on request, under
	// WithDeferredSessionRefresh; see that option.
	EndpointRefreshSession EndpointID = "core.session-refresh"
)

// ProfileRequest changes the signed-in user's display fields; an omitted
// field is kept.
type ProfileRequest struct {
	Name  *string `json:"name,omitempty"`
	Image *string `json:"image,omitempty"`
	// Fields sets the app columns WithProfileFields lists; any other name,
	// or a value of the wrong type, is ErrFieldInvalid and nothing is
	// written.
	Fields Fields `json:"fields,omitempty"`
}

// UserView is the part of a user the core returns to a client. A separate type
// so a field added to User for internal use never reaches a response.
type UserView struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
}

// ViewOf returns the client-facing view of u.
func ViewOf(u User) UserView { return UserView{ID: u.ID, Name: u.Name, Image: u.Image} }

// SessionResult is the output of core.session.
type SessionResult struct {
	User      UserView  `json:"user"`
	ExpiresAt time.Time `json:"expiresAt"`
	// Extras is what WithSessionExtras computed, or absent.
	Extras any `json:"extras,omitempty"`
	// NeedsRefresh is true, under WithDeferredSessionRefresh, when the
	// expiry is due to slide and this read did not slide it: the client
	// POSTs /session/refresh. Absent otherwise.
	NeedsRefresh bool `json:"needsRefresh,omitempty"`
	// Tasks are the session tasks the user must complete before the
	// session is usable (TaskSetupMFA, or a task an app plugin declares);
	// absent for an ordinary session. Until they are done every other
	// operation answers auth.session_task_pending.
	Tasks SessionTasks `json:"tasks,omitempty"`
}

// SessionView is one row of core.sessions.
type SessionView struct {
	ID      string `json:"id"`
	Current bool   `json:"current"`
	// Impersonated is true for a session an admin opened as this user.
	Impersonated bool      `json:"impersonated"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"userAgent"`
	CreatedAt    time.Time `json:"createdAt"`
	LastSeenAt   time.Time `json:"lastSeenAt"`
}

// SessionsResult is the output of core.sessions.
type SessionsResult struct {
	Sessions []SessionView `json:"sessions"`
}

// RevokeSessionRequest is the input of core.sessions-revoke.
type RevokeSessionRequest struct {
	ID string `json:"id"`
}

// Done is the output of operations that return nothing but success.
type Done struct {
	OK bool `json:"ok"`
}

// coreOps holds the core's operations so the Go API can call them.
type coreOps struct {
	session    *Op[struct{}, SessionResult]
	signOut    *Op[struct{}, Done]
	signOutAll *Op[struct{}, Done]
	sessions   *Op[struct{}, SessionsResult]
	revoke     *Op[RevokeSessionRequest, Done]
	profile    *Op[ProfileRequest, UserView]
	// deleteAccount and confirmDelete are self-service deletion; see
	// account.go.
	deleteAccount *Op[struct{}, DeleteAccountResult]
	confirmDelete *Op[ConfirmDeleteAccountRequest, Done]
	// The multi-session operations, served only under WithMultiSession;
	// see multisession.go.
	deviceSessions *Op[struct{}, DeviceSessionsResult]
	switchDevice   *Op[DeviceSessionRequest, Done]
	revokeDevice   *Op[DeviceSessionRequest, Done]
	// refresh slides the expiry on request; see WithDeferredSessionRefresh.
	refresh *Op[struct{}, SessionResult]
}

func newCoreOps(a *Auth) *coreOps {
	return &coreOps{
		session: Define(OpInfo{ID: EndpointSession, Kind: Query, Require: SignedIn, Path: "/session"},
			func(ctx context.Context, c *Call, _ struct{}) (SessionResult, error) {
				out := SessionResult{User: ViewOf(*c.User), ExpiresAt: c.Session.ExpiresAt, NeedsRefresh: stateFrom(ctx).needsRefresh, Tasks: c.Session.Tasks}
				if a.sessionExtras != nil {
					extras, err := a.sessionExtras(ctx, c)
					if err != nil {
						return SessionResult{}, err
					}
					out.Extras = extras
				}
				return out, nil
			}),
		signOut: Define(OpInfo{ID: EndpointSignOut, Kind: Mutation, Require: SignedIn, Path: "/sign-out"},
			func(ctx context.Context, c *Call, _ struct{}) (Done, error) {
				if err := a.EndSession(ctx, c.User.ID, c.Session.ID, SessionEndSignOut); err != nil {
					return Done{}, err
				}
				if err := a.signOutDevice(ctx, c); err != nil {
					return Done{}, err
				}
				if err := a.forgetSession(ctx, c); err != nil {
					return Done{}, err
				}
				c.Effects.ClearSession()
				return Done{OK: true}, nil
			}),
		signOutAll: Define(OpInfo{ID: EndpointSignOutAll, Kind: Mutation, Require: SignedIn, Path: "/sign-out-all"},
			func(ctx context.Context, c *Call, _ struct{}) (Done, error) {
				if err := a.EndUserSessions(ctx, c.User.ID, "", SessionEndRevokedAll); err != nil {
					return Done{}, err
				}
				if err := a.forgetSession(ctx, c); err != nil {
					return Done{}, err
				}
				c.Effects.ClearSession()
				return Done{OK: true}, nil
			}),
		sessions: Define(OpInfo{ID: EndpointSessions, Kind: Query, Require: SignedIn, Path: "/sessions"},
			func(ctx context.Context, c *Call, _ struct{}) (SessionsResult, error) {
				list, err := a.Sessions(ctx, c.User.ID)
				if err != nil {
					return SessionsResult{}, err
				}
				out := SessionsResult{Sessions: make([]SessionView, 0, len(list))}
				for _, s := range list {
					out.Sessions = append(out.Sessions, SessionView{
						ID: s.ID, Current: s.ID == c.Session.ID, Impersonated: s.ImpersonatedBy != nil, IP: s.IP, UserAgent: s.UserAgent,
						CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt,
					})
				}
				return out, nil
			}),
		revoke: Define(OpInfo{ID: EndpointRevokeSession, Kind: Mutation, Require: SignedIn, Path: "/sessions/revoke"},
			func(ctx context.Context, c *Call, in RevokeSessionRequest) (Done, error) {
				if err := a.EndSession(ctx, c.User.ID, in.ID, revokeReason(c, in.ID)); err != nil {
					return Done{}, err
				}
				if in.ID == c.Session.ID {
					if err := a.forgetSession(ctx, c); err != nil {
						return Done{}, err
					}
					c.Effects.ClearSession()
				}
				return Done{OK: true}, nil
			}),
		profile: Define(OpInfo{ID: EndpointProfile, Kind: Mutation, Require: SignedIn, Path: "/profile"},
			func(ctx context.Context, c *Call, in ProfileRequest) (UserView, error) {
				// The fields are checked before anything is written, so a
				// bad one refuses the whole update.
				sets, err := decodeFieldsFrom(a.profileFields, in.Fields)
				if err != nil {
					return UserView{}, err
				}
				u, err := a.UpdateUser(ctx, c.User.ID, UserUpdate{Name: in.Name, Image: in.Image})
				if err != nil {
					return UserView{}, err
				}
				if len(sets) > 0 {
					if err := a.writeFields(ctx, c.User.ID, sets); err != nil {
						return UserView{}, err
					}
				}
				return ViewOf(u), nil
			}),
		// FreshSignIn: deleting an account is at least as serious as changing
		// its password, and a laptop left open must not be able to do it.
		deleteAccount: Define(OpInfo{ID: EndpointDeleteAccount, Kind: Mutation, Require: FreshSignIn, Path: "/account/delete"},
			func(ctx context.Context, c *Call, _ struct{}) (DeleteAccountResult, error) {
				return a.deleteAccount(ctx, c)
			}),
		// Public: the link is opened wherever the mail was read, which may
		// be a browser with no session; the single-use token is the proof.
		confirmDelete: Define(OpInfo{ID: EndpointConfirmDeleteAccount, Kind: Mutation, Require: Public, Path: "/account/delete/confirm"},
			a.confirmDeleteAccount),
		deviceSessions: Define(OpInfo{ID: EndpointDeviceSessions, Kind: Query, Require: SignedIn, Path: deviceSessionsPath},
			func(ctx context.Context, c *Call, _ struct{}) (DeviceSessionsResult, error) {
				return a.listDeviceSessions(ctx, c)
			}),
		switchDevice: Define(OpInfo{ID: EndpointSwitchDeviceSession, Kind: Mutation, Require: SignedIn, Path: switchDeviceSessionPath}, a.switchDeviceSession),
		revokeDevice: Define(OpInfo{ID: EndpointRevokeDeviceSession, Kind: Mutation, Require: SignedIn, Path: revokeDeviceSessionPath}, a.revokeDeviceSession),
		// A mutation, so the pipeline resolved the session with mayRefresh
		// and the slide, when due, already happened in the lookup; the
		// result is the session as it stands now.
		refresh: Define(OpInfo{ID: EndpointRefreshSession, Kind: Mutation, Require: SignedIn, Path: refreshSessionPath},
			func(ctx context.Context, c *Call, _ struct{}) (SessionResult, error) {
				return SessionResult{User: ViewOf(*c.User), ExpiresAt: c.Session.ExpiresAt, Tasks: c.Session.Tasks}, nil
			}),
	}
}

// list returns the core operations a deployment serves. The deletion ones
// exist only under WithAccountDeletion, and the multi-session ones only
// under WithMultiSession, so a deployment without the option has no route
// it did not ask for.
func (o *coreOps) list(multi, deferRefresh, deletion bool) []Operation {
	ops := []Operation{o.session, o.signOut, o.signOutAll, o.sessions, o.revoke, o.profile}
	if deletion {
		ops = append(ops, o.deleteAccount, o.confirmDelete)
	}
	if multi {
		ops = append(ops, o.deviceSessions, o.switchDevice, o.revokeDevice)
	}
	if deferRefresh {
		ops = append(ops, o.refresh)
	}
	return ops
}

// refreshSessionPath is the route of EndpointRefreshSession.
const refreshSessionPath = "/session/refresh"

// WithDeferredSessionRefresh makes every read leave the session's expiry
// alone: a query (GET /session, a middleware lookup, any Query operation)
// only reports NeedsRefresh in the session result when the slide is due, and
// the client asks for it with POST /session/refresh (RefreshSession), or by
// any mutation, which still slides as before. For a deployment that serves
// reads from a replica, or that wants GET to be a pure read. Without the
// option every lookup slides when due, as before.
//
//ds:def id=opt-withdeferredsessionrefresh-4qn7xm2k owner=@khanakia stability=stable
func WithDeferredSessionRefresh() Option { return func(s *settings) { s.deferRefresh = true } }

// RefreshSession slides the signed-in session's expiry when it is due,
// through the same operation POST /session/refresh runs; it exists only
// under WithDeferredSessionRefresh.
func (a *Auth) RefreshSession(ctx context.Context) (SessionResult, error) {
	return a.core.refresh.Call(ctx, struct{}{})
}

// Session returns the signed-in user's session view, with the extras
// WithSessionExtras computes, through the same operation GET /session runs.
func (a *Auth) Session(ctx context.Context) (SessionResult, error) {
	return a.core.session.Call(ctx, struct{}{})
}

// ListSessions returns the signed-in user's sessions, marking the current
// one, through the same operation the HTTP route runs.
func (a *Auth) ListSessions(ctx context.Context) (SessionsResult, error) {
	return a.core.sessions.Call(ctx, struct{}{})
}

// RevokeSession ends one of the signed-in user's sessions.
func (a *Auth) RevokeSession(ctx context.Context, id string) error {
	_, err := a.core.revoke.Call(ctx, RevokeSessionRequest{ID: id})
	return err
}

// UpdateProfile changes the signed-in user's name or image, through the same
// operation the HTTP route runs.
func (a *Auth) UpdateProfile(ctx context.Context, in ProfileRequest) (UserView, error) {
	return a.core.profile.Call(ctx, in)
}

// SignOut ends the session of the request in ctx, through the same operation
// the HTTP route runs.
func (a *Auth) SignOut(ctx context.Context) error {
	_, err := a.core.signOut.Call(ctx, struct{}{})
	return err
}

// SignOutAll ends every session of the signed-in user.
func (a *Auth) SignOutAll(ctx context.Context) error {
	_, err := a.core.signOutAll.Call(ctx, struct{}{})
	return err
}

// revokeReason is why a revoke-by-id ends a session: the caller's own current
// session is a sign-out, any other is a revoke.
func revokeReason(c *Call, id string) SessionEndReason {
	if c.Session != nil && c.Session.ID == id {
		return SessionEndSignOut
	}
	return SessionEndRevoked
}
