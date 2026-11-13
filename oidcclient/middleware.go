package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Middleware timing values (values, not policies: see DESIGN.md).
const (
	// slideStep is the granularity of the idle window: LastSeenAt moves at
	// most once a minute, so a busy session does not rewrite its cookie or
	// row on every request.
	slideStep = time.Minute
	// recentRecheckTTL is how long a finished re-check answers requests that
	// still carry the session it started from. Two tabs whose requests do
	// not overlap in time (the second leaves the browser before the first
	// one's new cookie arrives) would otherwise spend the same refresh
	// token twice, which a strict server reads as theft and answers by
	// revoking the whole token family: both tabs signed out.
	recentRecheckTTL = 10 * time.Second
	// recheckTimeout bounds one re-check, which runs detached from the
	// request that started it (see recheckGroup.do).
	recheckTimeout = 30 * time.Second
)

// recheckResult is what one re-check decided, shared by every request of
// the session that waited for it.
type recheckResult struct {
	// session is the session after an Allow, already saved; sealed is its
	// cookie value, which every sharing request writes.
	session Session
	sealed  string
	// ref is set when the re-check refused: the session ended (ended) or
	// could not be kept.
	ref   *Refusal
	ended bool
	// outage is set when the login server could not be asked: the caller
	// applies the outage grace from the session's CheckedAt.
	outage error
}

// recheckGroup runs at most one re-check per session at a time in this
// process (single-flight), and keeps each finished one for
// recentRecheckTTL. It belongs to one Client; nothing is package-level.
type recheckGroup struct {
	mu        sync.Mutex
	inflight  map[string]*recheckCall
	recent    map[string]recentRecheck
	lastPurge time.Time
}

// recheckCall is one re-check in flight; done closes when res is set.
type recheckCall struct {
	done chan struct{}
	res  recheckResult
}

// recentRecheck is a finished re-check of the session as it stood at
// from (its CheckedAt then), finished at at.
type recentRecheck struct {
	from time.Time
	at   time.Time
	res  recheckResult
}

// do returns the result of run for s, sharing a call in flight for the
// same session ID, or a recent one that started from the same CheckedAt.
// run gets a context detached from the request's cancellation (bounded by
// recheckTimeout): a refresh the server has already rotated must be saved
// even when the browser that asked for it has gone, or the session would
// hold a spent refresh token.
func (g *recheckGroup) do(ctx context.Context, s Session, now func() time.Time, run func(context.Context) recheckResult) recheckResult {
	g.mu.Lock()
	t := now()
	if rr, ok := g.recent[s.ID]; ok && rr.from.Equal(s.CheckedAt) && !t.Before(rr.at) && t.Sub(rr.at) < recentRecheckTTL {
		g.mu.Unlock()
		return rr.res
	}
	if call, ok := g.inflight[s.ID]; ok {
		g.mu.Unlock()
		select {
		case <-call.done:
			return call.res
		case <-ctx.Done():
			return recheckResult{ref: &Refusal{Kind: RefusalUnavailable, Reason: ReasonServerDown, Err: ctx.Err()}}
		}
	}
	if g.inflight == nil {
		g.inflight, g.recent = map[string]*recheckCall{}, map[string]recentRecheck{}
	}
	call := &recheckCall{done: make(chan struct{})}
	g.inflight[s.ID] = call
	g.mu.Unlock()

	finished := false
	defer func() {
		// Runs on a panic in run too, so waiters are released (with a
		// failure) instead of blocking forever; the panic goes on up.
		g.mu.Lock()
		delete(g.inflight, s.ID)
		if finished {
			at := now()
			g.recent[s.ID] = recentRecheck{from: s.CheckedAt, at: at, res: call.res}
			if at.Sub(g.lastPurge) >= recentRecheckTTL {
				for id, rr := range g.recent {
					if at.Sub(rr.at) >= recentRecheckTTL {
						delete(g.recent, id)
					}
				}
				g.lastPurge = at
			}
		} else {
			call.res = recheckResult{ref: &Refusal{Kind: RefusalFailed, Reason: ReasonHookFailed, Err: errors.New("oidcclient: re-check panicked")}}
		}
		g.mu.Unlock()
		close(call.done)
	}()
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recheckTimeout)
	defer cancel()
	call.res = run(rctx)
	finished = true
	return call.res
}

// openSession reads the session cookie, opens it and loads the session.
// had reports whether the request carried a session cookie at all. A
// cookie that does not open (tampered, sealed under a retired key, under
// another cookie name) or names no live session is ErrNoSession; a sealer
// or store that fails is another error.
func (c *Client) openSession(ctx context.Context, r *http.Request) (s Session, had bool, err error) {
	name := c.set.cookie.Name
	sealed := readChunked(r, name)
	if sealed == "" {
		return Session{}, false, ErrNoSession
	}
	plain, err := c.set.sealer.Open(ctx, sealed, name)
	if errors.Is(err, ErrSealedCorrupt) {
		return Session{}, true, fmt.Errorf("%w: %w", ErrNoSession, err)
	}
	if err != nil {
		return Session{}, true, fmt.Errorf("oidcclient: open session cookie: %w", err)
	}
	s, err = c.set.store.Load(ctx, plain)
	if err != nil {
		if errors.Is(err, ErrNoSession) {
			return Session{}, true, err
		}
		return Session{}, true, fmt.Errorf("oidcclient: load session: %w", err)
	}
	// A session of another login server (an app that changed Issuer, or a
	// store shared by two Clients) is not this Client's to honour.
	if strings.TrimSuffix(s.User.Issuer, "/") != strings.TrimSuffix(c.cfg.Issuer, "/") || s.ID == "" {
		return Session{}, true, fmt.Errorf("%w: session of another issuer", ErrNoSession)
	}
	return s, true, nil
}

// persist sets s.ExpiresAt, saves s and seals what the store returned,
// refusing a value that would not fit the cookie limit, without writing
// any cookie: a re-check shared by several requests persists once, and
// each request writes the cookie.
func (c *Client) persist(ctx context.Context, s *Session) (string, error) {
	s.ExpiresAt = s.LastSeenAt.Add(c.set.lifetimes.Idle)
	if abs := s.CreatedAt.Add(c.set.lifetimes.Absolute); abs.Before(s.ExpiresAt) {
		s.ExpiresAt = abs
	}
	b, err := c.set.store.Save(ctx, *s)
	if err != nil {
		return "", fmt.Errorf("oidcclient: save session: %w", err)
	}
	sealed, err := c.set.sealer.Seal(ctx, b, c.set.cookie.Name)
	if err != nil {
		return "", fmt.Errorf("oidcclient: seal session: %w", err)
	}
	if len(sealed) > maxSessionCookies*maxCookieValue {
		return "", fmt.Errorf("%w: %d bytes sealed, at most %d fit; keep fewer Claims in the UserMapper or use a server-side SessionStore",
			ErrSessionTooLarge, len(sealed), maxSessionCookies*maxCookieValue)
	}
	return sealed, nil
}

// saveSession persists s and writes its cookie.
func (c *Client) saveSession(ctx context.Context, w http.ResponseWriter, r *http.Request, s *Session) error {
	sealed, err := c.persist(ctx, s)
	if err != nil {
		return err
	}
	return cookieWriter{opts: c.set.cookie}.writeChunked(w, r, sealed, s.ExpiresAt, c.set.now())
}

// deleteSession forgets s in the store; a failure is logged, because the
// caller is already refusing and the cookie is cleared either way.
func (c *Client) deleteSession(ctx context.Context, s Session) {
	if err := c.set.store.Delete(ctx, s); err != nil {
		c.set.logger.ErrorContext(ctx, "oidcclient: delete session", "session", s.ID, "error", err)
	}
}

// fresh reports whether the login server's last "yes" still stands. A
// CheckedAt in the future (a clock that went back) is not fresh.
func (c *Client) fresh(s Session, now time.Time) bool {
	return !now.Before(s.CheckedAt) && now.Sub(s.CheckedAt) < c.set.interval
}

// recheck asks the Rechecker about s and turns its answer into a saved
// session or a refusal. It runs once per flight, so the UserMapper and the
// store see one re-check however many requests wait for it.
func (c *Client) recheck(ctx context.Context, s Session) recheckResult {
	res, err := c.set.rechecker.Recheck(ctx, RecheckRequest{Session: s, Provider: c.provider})
	end := func(ref Refusal) recheckResult {
		c.deleteSession(ctx, s)
		return recheckResult{ref: &ref, ended: true}
	}
	switch {
	case err != nil && !errors.Is(err, ErrProviderRefused) && errors.Is(err, ErrProviderUnavailable):
		return recheckResult{outage: err}
	case err != nil:
		return end(Refusal{Kind: RefusalLoginRequired, Reason: ReasonServerRefused, Err: err})
	case res.Decision != Allow:
		return end(Refusal{Kind: RefusalLoginRequired, Reason: ReasonServerRefused, Err: errors.New("oidcclient: the Rechecker said Deny")})
	}
	now := c.set.now()
	ns := s
	ns.CheckedAt, ns.LastSeenAt = now, now
	if rf := res.Refreshed; rf != nil {
		ns.Tokens = rf.Tokens()
		if id := rf.Identity(); id != nil {
			if id.Issuer != s.User.Issuer || id.Subject != s.User.Subject {
				return end(Refusal{Kind: RefusalLoginRequired, Reason: ReasonServerRefused, Err: errors.New("oidcclient: the refreshed ID token names another person")})
			}
			prev := s.User
			u, err := c.mapUser(ctx, MapUserRequest{Reason: MapRefresh, Identity: *id, Previous: &prev, AccessToken: ns.Tokens.AccessToken, Provider: c.provider})
			if err != nil {
				return end(hookRefusal(err))
			}
			ns.User = u
			if id.ProviderSessionID != "" {
				ns.ProviderSessionID = id.ProviderSessionID
			}
		}
	}
	sealed, err := c.persist(ctx, &ns)
	if err != nil {
		// The refresh token may already be spent at the server, so the old
		// session cannot be re-checked again: end it.
		return end(Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: err})
	}
	c.observe(ctx, Event{Kind: EventRefresh, SessionID: ns.ID, Subject: ns.User.Subject})
	return recheckResult{session: ns, sealed: sealed}
}

// authenticate is the decision Require and Optional share: load the
// session, apply the Lifetimes, re-check when stale (single-flight, with
// the outage grace), slide the idle window, run the Authorizer. It writes
// the session cookies the decision changed and returns the session (zero
// when there is none) with the refusal, or nil to let the request through.
func (c *Client) authenticate(w http.ResponseWriter, r *http.Request) (Session, *Refusal) {
	ctx := r.Context()
	cw := cookieWriter{opts: c.set.cookie}
	s, had, err := c.openSession(ctx, r)
	switch {
	case errors.Is(err, ErrNoSession):
		if had {
			cw.clearChunked(w, r)
		}
		return Session{}, &Refusal{Kind: RefusalLoginRequired, Reason: ReasonNoSession, Err: err}
	case err != nil:
		return Session{}, &Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: err}
	}
	now := c.set.now()
	if !now.Before(s.CreatedAt.Add(c.set.lifetimes.Absolute)) {
		c.deleteSession(ctx, s)
		cw.clearChunked(w, r)
		return s, &Refusal{Kind: RefusalLoginRequired, Reason: ReasonAbsoluteExpired}
	}
	if !now.Before(s.LastSeenAt.Add(c.set.lifetimes.Idle)) {
		c.deleteSession(ctx, s)
		cw.clearChunked(w, r)
		return s, &Refusal{Kind: RefusalLoginRequired, Reason: ReasonIdleExpired}
	}
	if !c.fresh(s, now) {
		res := c.rechecks.do(ctx, s, c.set.now, func(rctx context.Context) recheckResult { return c.recheck(rctx, s) })
		switch {
		case res.ref != nil:
			if res.ended {
				cw.clearChunked(w, r)
			}
			return s, res.ref
		case res.outage != nil:
			if c.set.grace <= 0 || now.Before(s.CheckedAt) || now.Sub(s.CheckedAt) > c.set.grace {
				return s, &Refusal{Kind: RefusalUnavailable, Reason: ReasonServerDown, Err: res.outage}
			}
			c.observe(ctx, Event{Kind: EventGrace, SessionID: s.ID, Subject: s.User.Subject, Err: res.outage})
		default:
			s = res.session
			if err := cw.writeChunked(w, r, res.sealed, s.ExpiresAt, now); err != nil {
				return s, &Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: err}
			}
		}
	}
	if now.Sub(s.LastSeenAt) >= slideStep {
		s.LastSeenAt = now
		if err := c.saveSession(ctx, w, r, &s); err != nil {
			return s, &Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: err}
		}
	}
	if a := c.set.authorizer; a != nil {
		d, err := a(ctx, AuthorizeRequest{User: s.User, Request: r})
		switch {
		case err != nil:
			ref := hookRefusal(err)
			return s, &ref
		case d != Allow:
			return s, &Refusal{Kind: RefusalNoAccess, Reason: ReasonNotAuthorized, Err: errors.New("oidcclient: the Authorizer said Deny")}
		}
	}
	return s, nil
}

// loginURL is the login route with r's same-site path and query as
// return_to, or the bare login route when r's target is not one.
func (c *Client) loginURL(r *http.Request) string {
	ret := r.URL.RequestURI()
	if !isSameSitePath(ret) {
		return c.set.paths.Login
	}
	return c.set.paths.Login + "?" + url.Values{ParamReturnTo: {ret}}.Encode()
}

// refuse reports and answers a refused request. s is the session the
// refusal concerns, or nil.
func (c *Client) refuse(w http.ResponseWriter, r *http.Request, ref Refusal, s *Session) {
	ctx := r.Context()
	if ref.Kind == RefusalLoginRequired && ref.LoginURL == "" {
		ref.LoginURL = c.loginURL(r)
	}
	c.observeRefusal(ctx, ref, s)
	noStore(w)
	c.set.responder.Respond(w, r, ref)
}

// observeRefusal logs a refusal at the level its kind deserves and tells
// the Observer. The cause is logged, never a token: errors here carry
// endpoints and reasons only.
func (c *Client) observeRefusal(ctx context.Context, ref Refusal, s *Session) {
	e := Event{Kind: EventRefuse, Reason: ref.Reason, Err: ref.Err}
	if s != nil {
		e.SessionID, e.Subject = s.ID, s.User.Subject
	}
	switch {
	case ref.Kind == RefusalFailed && ref.Reason == ReasonBadCallback:
		// A callback that does not verify is the browser's or an
		// attacker's doing, not the app failing: worth a warning, not a page.
		c.set.logger.WarnContext(ctx, "oidcclient: callback refused", "reason", ref.Reason, "error", ref.Err)
	case ref.Kind == RefusalFailed:
		c.set.logger.ErrorContext(ctx, "oidcclient: request refused", "reason", ref.Reason, "session", e.SessionID, "error", ref.Err)
	case ref.Kind == RefusalUnavailable:
		c.set.logger.WarnContext(ctx, "oidcclient: request refused", "reason", ref.Reason, "session", e.SessionID, "error", ref.Err)
	default:
		c.set.logger.DebugContext(ctx, "oidcclient: request refused", "reason", ref.Reason, "session", e.SessionID, "error", ref.Err)
	}
	c.observe(ctx, e)
}

// observe tells the Observer, when there is one, stamping the time.
func (c *Client) observe(ctx context.Context, e Event) {
	if c.set.observer == nil {
		return
	}
	if e.At.IsZero() {
		e.At = c.set.now()
	}
	c.set.observer.Observe(ctx, e)
}

// sessionRef is s as a pointer for refuse, nil for the zero Session.
func sessionRef(s Session) *Session {
	if s.ID == "" {
		return nil
	}
	return &s
}

// serveRequire implements Require for one request.
func (c *Client) serveRequire(next http.Handler, w http.ResponseWriter, r *http.Request) {
	s, ref := c.authenticate(w, r)
	if ref != nil {
		c.refuse(w, r, *ref, sessionRef(s))
		return
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, s.User)))
}

// serveOptional implements Optional for one request: the same decision,
// but a refusal only means the request goes on without a User. A request
// without any session is not reported: on a public page it is the normal
// case, not a refusal.
func (c *Client) serveOptional(next http.Handler, w http.ResponseWriter, r *http.Request) {
	s, ref := c.authenticate(w, r)
	if ref != nil {
		if ref.Reason != ReasonNoSession {
			c.observeRefusal(r.Context(), *ref, sessionRef(s))
		}
		next.ServeHTTP(w, r)
		return
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, s.User)))
}
