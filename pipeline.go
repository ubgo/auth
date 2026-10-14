package auth

import (
	"context"
	"net/url"
	"time"
)

// OperationHook runs before and after chosen operations, on every transport.
//
// After receives the result as any because one hook can match operations
// with different output types; a hook that needs the concrete type asserts it
// for the operations it named in Match.
//
// Match lists the operations by id; an empty Match means every operation. A
// Before error stops the call and becomes its error. An After error also fails
// the call, and the call's effects are then dropped, so a hook can veto a
// sign-in after the fact without a cookie leaking out.
//
//ds:def id=core-operationhook-e9d2av55 owner=@khanakia stability=stable
type OperationHook struct {
	Match  []EndpointID
	Before func(ctx context.Context, c *Call) error
	After  func(ctx context.Context, c *Call, result any) error
	// Finally runs once per call after the call's transaction has ended,
	// commit or rollback, before the observer, on every outcome, with the
	// error the caller gets (nil on success). It returns nothing and cannot
	// change the answer: it is for recording what happened (an audit row
	// for a failed sign-in, a counter), never for deciding. It runs for a
	// refusal before the input was decoded too (rate limit, origin,
	// requirement), with c.Input nil then.
	Finally func(ctx context.Context, c *Call, err error)
}

func (h OperationHook) matches(id EndpointID) bool {
	if len(h.Match) == 0 {
		return true
	}
	for _, m := range h.Match {
		if m == id {
			return true
		}
	}
	return false
}

// DefaultFreshWindow is how recent a session must be for a FreshSignIn
// operation. Ten minutes is long enough to finish a settings change and short
// enough that a laptop left open overnight cannot change the password.
//
//ds:def id=defaultfreshwindow-5mt8jqw7 owner=@khanakia stability=stable
const DefaultFreshWindow = 10 * time.Minute

// prepared is an operation ready to run: its logic bound to the decoded
// input, and the account the input names, for ByIdentifier limits.
type prepared[T any] struct {
	rateID string
	// input is the decoded input as any, for Call.Input.
	input any
	run   func(ctx context.Context, c *Call) (T, error)
}

// execute is the pipeline. Every entry point — a transport's Invoke and a Go
// caller's Call — goes through it, and there is no other way to run an
// operation's logic.
//
// Order, and why:
//  1. rate limit by IP — first, so a flood costs one counter increment
//  2. origin check — before any lookup, so a cross-site request learns
//     nothing, not even whether its session is valid
//  3. session — resolved once per request, then shared
//  4. requirement — public, signed in, or freshly signed in
//  5. the input is decoded and the per-account rate limit counted, outside
//     any transaction, so a failed call cannot roll its own count back
//  6. a mutation opens one transaction for everything below, when there is
//     a database; data hooks and plugin writes all join it
//  7. before hooks, then the operation, then after hooks
//  8. effects reach the request, and messages go out, only after commit —
//     the outermost commit, when the call runs inside an app's own Tx
//
// The observer, when there is one, sees the call end whatever step refused
// it, with the time it took.
//
// It is generic over the result so a Go caller's typed Call gets its Out back
// with no assertion; a transport's Invoke instantiates it with any.
func execute[T any](ctx context.Context, a *Auth, op Operation, prepare func() (prepared[T], error)) (T, error) {
	if a.observer == nil && a.tracer == nil {
		return executeCall(ctx, a, op, prepare)
	}
	ev := OperationEvent{Op: op.Info(), Plugin: op.Plugin(), Transport: TransportGo}
	if st := stateFrom(ctx); st != nil {
		ev.Transport = st.req.Transport
	}
	ctx, end := a.startSpan(ctx, operationSpan(ev.Op, ev.Plugin, ev.Transport))
	var start time.Time
	if a.observer != nil {
		start = a.now()
	}
	out, err := executeCall(ctx, a, op, prepare)
	end(err)
	if a.observer != nil {
		ev.Duration, ev.Err = a.now().Sub(start), err
		a.observer.Operation(ctx, ev)
	}
	return out, err
}

// executeCall is execute without the observer and the operation span; see
// execute for the order.
func executeCall[T any](ctx context.Context, a *Auth, op Operation, prepare func() (prepared[T], error)) (out T, err error) {
	var zero T
	c := &Call{
		Auth:        a,
		Op:          op.Info(),
		Plugin:      op.Plugin(),
		Transport:   TransportGo,
		Credential:  CredentialNone,
		Effects:     &Effects{},
		annotations: &annotationSet{},
	}
	st := stateFrom(ctx)
	c.ctx = ctx
	if st != nil {
		c.Transport, c.Client, c.Credential, c.header, c.Flow = st.req.Transport, st.req.Client, st.req.Credential, st.req.Header, st.req.Flow
	}
	// A cross-site form relays fields and nothing else: whatever credential
	// or flow cookie rode along is not believed, so a page another site
	// posted to cannot act with the browser's session.
	crossSiteForm := c.Op.CrossSiteForm
	if crossSiteForm {
		c.Credential, c.Flow = CredentialNone, ""
	}
	// Finally hooks see the final answer, whatever step produced it; the
	// deferred call reads the named results after every return below.
	defer func() {
		for _, h := range a.hooksFor(c.Op.ID) {
			if h.Finally != nil {
				h.Finally(ctx, c, err)
			}
		}
	}()

	if err := a.limiter.check(ctx, c, ByIP, c.Client.IP); err != nil {
		return zero, err
	}
	if err := a.checkOrigin(c); err != nil {
		return zero, err
	}
	// Country rules come before the credentials are read, so a refusal says
	// nothing about whether a guess was right.
	if err := a.geo.checkSignIn(ctx, c); err != nil {
		return zero, err
	}
	if err := a.risk.checkRequest(ctx, c); err != nil {
		return zero, err
	}
	if st != nil && !crossSiteForm {
		// A mutation may slide the expiry; under deferred refresh a query
		// only reports that it is due. The first resolver of the request
		// decides, which is this call unless middleware resolved earlier.
		st.mayRefresh = c.Op.Kind == Mutation || !a.deferRefresh
		resolve := st.resolve
		if c.Op.Require == FreshSignIn {
			resolve = st.resolveFresh
		}
		if err := resolve(ctx, a); err != nil {
			return zero, err
		}
		if st.session != nil && a.sessionVisibleTo(st.session, c.Op) {
			c.Session, c.User = st.session, st.user
		}
	}
	if err := a.checkRequirement(c); err != nil {
		return zero, err
	}
	// Decode, then count per account, both before any transaction: a count
	// taken inside the transaction would be rolled back by the very failure
	// it is meant to count, such as a wrong password.
	p, err := prepare()
	if err != nil {
		return zero, err
	}
	c.Input = p.input
	if err := a.limiter.check(ctx, c, ByIdentifier, p.rateID); err != nil {
		return zero, err
	}
	run := p.run

	// Data hooks run inside body with no Call; OperationOf lets them see
	// which operation is writing.
	ctx = context.WithValue(ctx, opKey{}, c.Op)
	// The call too, for the session this operation may create: impossible
	// travel asks the rate challenger about it.
	ctx = context.WithValue(ctx, callKey{}, c)
	body := func(ctx context.Context) error {
		hooks := a.hooksFor(c.Op.ID)
		for _, h := range hooks {
			if h.Before != nil && !c.answered {
				if err := a.runHook(ctx, c, h, HookBefore, func(ctx context.Context) error { return h.Before(ctx, c) }); err != nil {
					return err
				}
			}
		}
		// run returns a Before hook's Respond value in place of running the
		// operation; such an answer skips the After hooks too, as
		// better-auth's short-circuit does.
		short := c.answered
		res, err := run(ctx, c)
		if err != nil {
			return err
		}
		for _, h := range hooks {
			if short {
				break
			}
			if h.After != nil {
				if err := a.runHook(ctx, c, h, HookAfter, func(ctx context.Context) error { return h.After(ctx, c, res) }); err != nil {
					return err
				}
			}
		}
		// Inside the transaction, so a sign-in refused for the device cap
		// rolls its session back.
		if err := a.checkDeviceCap(c); err != nil {
			return err
		}
		out = res
		return nil
	}
	if c.Op.Kind == Mutation && a.db != nil {
		err = a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error { return body(ctx) })
	} else {
		err = body(ctx)
	}
	if err != nil {
		if st != nil && c.redirectOnError != "" {
			// The operation asked for a redirect on failure: the browser is
			// sent to the app's error page with the code, and nothing else
			// the failed call recorded reaches the request.
			st.effects.add(Effect{Kind: EffectRedirect, URL: errorRedirectURL(c.redirectOnError, err)})
		}
		return zero, err
	}
	if st != nil {
		// Effects reach the request only once the data they describe is
		// committed. A call inside an app's own a.Tx has not committed
		// anything yet: were its IssueSession merged now and the outer
		// transaction rolled back, the response would replace a valid cookie
		// with one for a session that does not exist. AfterCommit runs at
		// once when no transaction is open (this call's own Tx has already
		// committed), and never for a rollback.
		a.AfterCommit(ctx, func(context.Context) { st.effects.merge(c.Effects) })
	}
	return out, nil
}

// checkOrigin refuses a mutation that carries a session cookie from an origin
// that is not trusted. It is the CSRF defence, and it fails closed: a missing
// Origin on such a call is refused, because a browser that sends a cookie on
// a cross-site POST also sends an Origin, so a missing one is not an innocent
// case worth accommodating.
//
// Under WithFetchMetadata a mutation the browser marks cross-site is refused
// the same way without a cookie, which closes login CSRF: the sign-in that
// has no cookie yet. A trusted origin passes either check, so an admin app on
// another site keeps working. WithoutCSRFCheck skips both.
func (a *Auth) checkOrigin(c *Call) error {
	if a.noCSRFCheck || c.Op.Kind != Mutation || c.Op.CrossSiteForm {
		// A cross-site form arrives from another site by definition; it
		// carries no credential (the pipeline dropped it), so there is
		// nothing for the check to protect.
		return nil
	}
	crossSite := a.fetchMetadata && c.Client.FetchSite == FetchSiteCrossSite
	if c.Credential != CredentialCookie && !crossSite {
		return nil
	}
	if a.TrustsOrigin(c.Client.Origin) {
		return nil
	}
	return ErrOriginNotTrusted
}

// sessionVisibleTo reports whether op sees the request's session s. A pending
// second-factor session is visible only to the operations that finish it,
// or that serve both steps; a session with tasks pending is hidden from a
// Public operation its tasks do not allow, so a sign-in page or a public
// read treats the caller as signed out. To every other operation the caller
// with such a session is signed out, or (tasks) refused by
// checkSessionTasks.
func (a *Auth) sessionVisibleTo(s *Session, op OpInfo) bool {
	switch {
	case s.SecondFactorPending:
		return op.Require == PendingSecondFactor || op.Require == SignedInOrPending
	case len(s.Tasks) > 0 && op.Require == Public:
		return a.taskAllows(s.Tasks, op.ID)
	}
	return true
}

func (a *Auth) checkRequirement(c *Call) error {
	if c.Op.Require != Public {
		if err := a.checkSessionTasks(c); err != nil {
			return err
		}
	}
	switch c.Op.Require {
	case Public:
		return nil
	case SignedIn:
		if c.Session == nil || c.Session.SecondFactorPending {
			return ErrSignedOut
		}
		if c.Session.APIKeyID != "" {
			return ErrAPIKeyRefused
		}
		return nil
	case PendingSecondFactor:
		if c.Session == nil || !c.Session.SecondFactorPending {
			return ErrSignedOut
		}
		return nil
	case SignedInOrPending:
		if c.Session == nil {
			return ErrSignedOut
		}
		if c.Session.APIKeyID != "" {
			return ErrAPIKeyRefused
		}
		return nil
	case FreshSignIn:
		if c.Session == nil || c.Session.SecondFactorPending {
			return ErrSignedOut
		}
		if c.Session.APIKeyID != "" {
			return ErrAPIKeyRefused
		}
		// An admin acting as a user may look, never change what proves the
		// user is them: password, addresses, factors, passkeys.
		if c.Session.ImpersonatedBy != nil {
			return ErrImpersonationRefused
		}
		// Fresh since the sign-in or the last re-authentication
		// (Reauthenticate), whichever is later.
		if a.now().Sub(c.Session.FreshAt()) > a.cfg.FreshWindow {
			return ErrFreshSessionRequired
		}
		return nil
	default:
		// An unknown requirement is refused at auth.New; reaching this means
		// a value was changed after wiring. Fail closed.
		return ErrSignedOut
	}
}

func (a *Auth) hooksFor(id EndpointID) []registeredHook {
	var out []registeredHook
	for _, h := range a.opHooks {
		if h.matches(id) {
			out = append(out, h)
		}
	}
	return out
}

// registeredHook is an OperationHook with where it came from: a plugin's name
// or HookSourceApp, which is what a hook span and a wiring error show.
type registeredHook struct {
	OperationHook
	source string
}

// runHook runs one stage of one hook inside its span. A hook's error is the
// span's outcome and then the call's.
func (a *Auth) runHook(ctx context.Context, c *Call, h registeredHook, stage HookStage, fn func(context.Context) error) error {
	ctx, end := a.startSpan(ctx, hookSpan(c, stage, h.source))
	err := fn(ctx)
	end(err)
	return err
}

// originOf reduces a URL to "scheme://host", the form browsers send in the
// Origin header. It returns "" for anything that is not an absolute URL.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// OriginOf is originOf for transports, which need the same reduction to turn a
// Referer header into an origin.
func OriginOf(raw string) string { return originOf(raw) }

// TrustsOrigin reports whether origin ("scheme://host") may send
// cookie-authenticated writes: the BaseURL's origin, a trusted origin, one an
// OriginTruster plugin added, a subdomain of a wildcard pattern
// ("https://*.example.com"), or one the WithTrustedOriginFunc function
// accepts. A server-rendered form uses it to refuse a cross-site POST,
// including a sign-in, where no session cookie exists yet for the pipeline's
// own check to look at. An empty origin is never trusted.
//
//ds:def id=core-trustsorigin-pvpqhgyd owner=@khanakia stability=stable
func (a *Auth) TrustsOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	if _, ok := a.trustedOrigins[origin]; ok {
		return true
	}
	for _, p := range a.originPatterns {
		if p.matches(origin) {
			return true
		}
	}
	return a.originFunc != nil && a.originFunc(origin)
}
