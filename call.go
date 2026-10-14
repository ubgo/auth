package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// Transport names the entry point a call arrived through.
type Transport string

// Entry points. A hook that must not be skipped by a direct Go call can check
// Call.Transport and refuse TransportGo explicitly.
const (
	TransportGo   Transport = "go"
	TransportHTTP Transport = "http"
)

// Credential names how the client presented its session token.
type Credential string

// How a token can arrive. The origin check applies only to CredentialCookie,
// because a browser attaches a cookie on its own and never a bearer header.
const (
	CredentialNone   Credential = "none"
	CredentialCookie Credential = "cookie"
	CredentialBearer Credential = "bearer"
)

// Client describes the other end of a request. Every field comes from the
// client and is information only: none of them may decide anything about
// security except Origin, which is compared against a fixed allow-list.
type Client struct {
	IP        string
	UserAgent string
	// Origin is the scheme and host the request claims to come from, taken
	// from the Origin header or, when it is missing, from the Referer.
	Origin string
	// Locale is the language the client prefers, as a BCP 47 tag such as
	// "de-CH", or "". Messages sent during the request carry it.
	Locale string
	// FetchSite is the request's Sec-Fetch-Site header as the browser sent
	// it ("same-origin", "same-site", "cross-site", "none"), or "" when the
	// client sent none. Browsers set it and scripts cannot change it, which
	// is what makes WithFetchMetadata a defence; a value an app made up
	// would defend nothing.
	FetchSite string
}

// FetchSiteCrossSite is the Sec-Fetch-Site value of a request from another
// site, the one WithFetchMetadata refuses for a mutation.
//
//ds:def id=fetchsitecrosssite-8kq3wn2v owner=@khanakia stability=stable
const FetchSiteCrossSite = "cross-site"

// WithFetchMetadata refuses a mutation whose request says Sec-Fetch-Site:
// cross-site and whose Origin is not trusted, whether or not it carries a
// cookie. The origin check alone protects cookie-authenticated calls; a
// sign-in has no cookie yet, so a form on another site could sign the victim
// into the attacker's account (login CSRF) and the origin check would not
// look. Browsers send the header on every request and no script can change
// it, so the check costs nothing and cannot be forged from a page. It is
// opt-in because a client that sends no header (an old browser, a native
// app, curl) is unaffected either way, and an app deciding to rely on it
// should know it did.
//
//ds:def id=opt-withfetchmetadata-5rn7kq8z owner=@khanakia stability=stable
func WithFetchMetadata() Option { return func(s *settings) { s.fetchMetadata = true } }

// TokenDelivery names how the client wants to receive a session token:
// in a cookie, or in the response for it to send back as a bearer token.
// It is asked for before any token exists, at sign-in, which is why it is
// not Credential: Credential says how a token WAS presented on this request,
// and the origin check and the session lookup depend on that meaning.
type TokenDelivery string

// How a client asks to receive its token. The session policy treats a bearer
// request like a bearer credential, so an app gets the app lifetime on the
// sign-in that has no token yet.
const (
	DeliveryCookie TokenDelivery = "cookie"
	DeliveryBearer TokenDelivery = "bearer"
)

// TokenDeliveryValues is the canonical iteration order over deliveries.
var TokenDeliveryValues = []TokenDelivery{DeliveryCookie, DeliveryBearer}

// Request is what a transport knows about one incoming request. A transport
// builds it once and passes it to Auth.WithRequest.
//
//ds:def id=core-request-e9s7echt owner=@khanakia stability=stable
type Request struct {
	Transport  Transport
	Client     Client
	Credential Credential
	// Delivery is how the client asked to receive a token issued during this
	// request (HTTP: the Auth-Token-Mode header). Empty means DeliveryCookie.
	Delivery TokenDelivery
	// Token is the raw session token, empty when Credential is CredentialNone.
	Token Token
	// Flow is the value the client holds from an earlier BindFlow effect, or
	// empty. HTTP transports keep it in a cookie of its own.
	Flow Token
	// CachedSession is the value the client holds from an earlier
	// EffectCacheSession, or empty. Only the snapshot cache uses one; a
	// transport passes whatever the client sent, and the cache decides.
	CachedSession string
	// Host is the host the request came to, as the transport determined it
	// (behind its trusted-proxy rule when it has one), such as
	// "preview-42.example.com" or "app.example.com:8443"; empty for a
	// transport without one. BaseURL(ctx) uses it only when WithAllowedHosts
	// allows it, so a made-up Host header changes nothing.
	Host string
	// Device is the token the client holds from an earlier
	// EffectRememberDevice, or empty (HTTP: a cookie of its own). A
	// second-factor plugin reads it through RequestDevice to skip the second
	// step on a remembered browser.
	Device Token
	// DeviceTokens are the other session tokens the device holds under
	// WithMultiSession (authhttp: one cookie per account), without Token.
	// The core lists and switches between them; a transport without the
	// feature leaves it empty.
	DeviceTokens []Token
	// Header reads a request header. Nil for transports without headers.
	Header func(name string) string
	// Cookie reads a plugin cookie (Call.Cookie) by the name the plugin
	// gave it, under whatever the transport names it on the wire; it
	// reports whether the client sent one. Nil for transports without
	// cookies.
	Cookie func(name string) (string, bool)
}

// requestState is attached to the context of one request. The session is
// resolved lazily and at most once, so an operation that never needs it costs
// no query, and a GraphQL request with ten fields costs one.
type requestState struct {
	req     Request
	effects *Effects
	// a is the Auth the request was attached to, so a transport holding only
	// the context can render errors in the request's language (ErrorInfoFor).
	a *Auth

	once    sync.Once
	session *Session
	user    *User
	// localeOnce and userLocale hold the signed-in user's stored locale
	// (WithUserLocale), read at most once per request and only when a
	// message or Locale asks for it.
	localeOnce sync.Once
	userLocale string
	// scopes are the API key's scopes, when the credential is a key.
	scopes []string
	err    error
	// fromCache is true when session came from the SessionCache and not the
	// store; a FreshSignIn operation then looks the session up again
	// (resolveFresh), because a cached copy may have been revoked.
	fromCache bool
	// fromToken is true when the user is the stateless token's copy rather
	// than a read (WithStatelessRefreshWithoutRead); a FreshSignIn
	// operation then loads it (resolveFresh), because the copy may predate a
	// ban or a "sign out everywhere".
	fromToken bool
	// mayRefresh is whether the first lookup may slide the expiry; under
	// WithDeferredSessionRefresh a read-only call leaves it alone and
	// reports needsRefresh instead. The pipeline sets it before resolving;
	// a lookup forced by middleware is a read.
	mayRefresh bool
	// needsRefresh is true when the lookup found the expiry due to slide
	// and did not, under WithDeferredSessionRefresh.
	needsRefresh bool
	// rejected is true when the request presented a session token and the
	// lookup found no session behind it at all: unknown, expired, revoked
	// or created before the user's SessionsValidAfter. A pending
	// second-factor session is a session, so it never sets this; neither
	// does a lookup that failed (st.err), which says nothing about the
	// token. RequestTokenRejected reads it.
	rejected bool
}

type requestKey struct{}

// WithRequest attaches a request to ctx. Transports call it once per request,
// before calling any operation or reading the current user.
//
//ds:def id=core-withrequest-zka2yc8d owner=@khanakia stability=stable
func (a *Auth) WithRequest(ctx context.Context, r Request) context.Context {
	if r.Credential == "" {
		r.Credential = CredentialNone
	}
	// A lookup forced by middleware is a read: it may slide the expiry
	// unless WithDeferredSessionRefresh says reads never do.
	return context.WithValue(ctx, requestKey{}, &requestState{req: r, effects: &Effects{}, a: a, mayRefresh: !a.deferRefresh})
}

func stateFrom(ctx context.Context) *requestState {
	st, _ := ctx.Value(requestKey{}).(*requestState)
	return st
}

// resolve looks the session up once. An unknown, expired or revoked token is
// not an error: the request is simply signed out. Any other failure, such as
// the database being unreachable, is returned so the transport can answer 500
// instead of pretending the user is signed out.
func (st *requestState) resolve(ctx context.Context, a *Auth) error {
	st.once.Do(func() {
		if st.req.Token == "" {
			return
		}
		if tr, ok := a.tokenResolver(st.req.Token); ok {
			if st.req.Credential != CredentialBearer {
				return
			}
			sess, user, scopes, err := a.resolvePrincipal(ctx, tr, st.req.Token)
			switch {
			case err == nil:
				st.session, st.user, st.scopes = sess, user, scopes
				return
			case !errors.Is(err, ErrSignedOut):
				st.err = err
				return
			}
			// Not the plugin's token: a random session token can start with
			// a plugin prefix once in millions, so fall through to sessions.
		}
		key := CacheKey{TokenHash: HashToken(st.req.Token), Client: st.req.CachedSession}
		if a.cache != nil {
			s, u, ok, err := a.cache.Get(ctx, key, a.now())
			if err != nil {
				st.err = fmt.Errorf("auth: session cache: %w", err)
				return
			}
			if ok {
				// A cached stateless session is still checked against the
				// revocation list: the list is the only thing that ends one
				// early, and a cache entry would otherwise outlive it.
				if a.stateless != nil {
					switch err := a.checkRevoked(ctx, s.ID, a.now()); {
					case errors.Is(err, ErrSessionNotFound):
						st.rejected = true
						return
					case err != nil:
						st.err = err
						return
					}
				}
				st.session, st.user, st.fromCache = &s, &u, true
				return
			}
		}
		r, err := a.lookupSession(ctx, st.req.Token, st.mayRefresh, false, true)
		sess, user, reissue := r.session, r.user, r.reissue
		switch {
		case err == nil:
			st.session, st.user, st.fromToken = sess, user, r.fromToken
			st.needsRefresh = reissue == "" && a.deferRefresh && !st.mayRefresh && a.refreshDue(*sess)
			if reissue != "" {
				// The expiry slid, so the client's cookie must learn the new
				// one; otherwise it would expire before the session does. In
				// stateless mode the token itself changed.
				st.effects.ReplaceSessionOf(*sess, reissue)
				key.TokenHash = HashToken(reissue)
			}
			if !r.inGrace {
				st.err = a.cacheSession(ctx, st, key, sess, user)
			}
		case errors.Is(err, ErrSignedOut):
			st.rejected = true
		default:
			st.err = err
		}
	})
	return st.err
}

// resolveFresh is resolve for a FreshSignIn operation: the session must come
// from the store, never from the cache, because the cache is where a revoked
// session lives on for up to its TTL, and a password change or an account
// deletion must not run on one. A session already resolved from the store is
// kept; one that came from the cache is looked up again, and the cache entry
// is dropped when the store no longer has it. A stateless session whose user
// was the token's copy (WithStatelessRefreshWithoutRead) is looked up again
// with the user loaded, for the same reason.
func (st *requestState) resolveFresh(ctx context.Context, a *Auth) error {
	if err := st.resolve(ctx, a); err != nil || !st.fromCache && !st.fromToken {
		return err
	}
	r, err := a.lookupSession(ctx, st.req.Token, st.mayRefresh, true, true)
	switch {
	case err == nil:
		wasCached := st.fromCache
		st.session, st.user, st.fromCache, st.fromToken = r.session, r.user, false, false
		if r.reissue != "" {
			st.effects.ReplaceSessionOf(*r.session, r.reissue)
		}
		// A rotation replaced the token a cache entry is keyed by: dropped,
		// so the replaced token cannot keep answering from the cache past
		// its grace, where the store would treat it as stolen.
		if wasCached && r.rotated {
			if err := a.cache.Drop(ctx, CacheKey{TokenHash: HashToken(st.req.Token), Client: st.req.CachedSession}); err != nil {
				return fmt.Errorf("auth: session cache: %w", err)
			}
		}
		return nil
	case errors.Is(err, ErrSignedOut):
		wasCached := st.fromCache
		st.session, st.user, st.fromCache, st.fromToken = nil, nil, false, false
		st.rejected = true
		if !wasCached {
			return nil
		}
		if err := a.cache.Drop(ctx, CacheKey{TokenHash: HashToken(st.req.Token), Client: st.req.CachedSession}); err != nil {
			return fmt.Errorf("auth: session cache: %w", err)
		}
		st.effects.ClearCache()
		return nil
	default:
		return err
	}
}

// cacheSession remembers a looked-up session for the next requests, when a
// cache is configured. A pending second-factor session is never cached: it
// must be promoted or expire, and a cached copy could outlive both. Neither
// is a session with tasks pending, which CompleteSessionTask replaces.
func (a *Auth) cacheSession(ctx context.Context, st *requestState, key CacheKey, s *Session, u *User) error {
	if a.cache == nil || s.SecondFactorPending || len(s.Tasks) > 0 {
		return nil
	}
	until := a.now().Add(a.cacheTTL)
	if until.After(s.ExpiresAt) {
		until = s.ExpiresAt
	}
	v, err := a.cache.Put(ctx, key, *s, *u, until)
	if err != nil {
		return fmt.Errorf("auth: session cache: %w", err)
	}
	if v != "" {
		st.effects.CacheSession(v, until)
	}
	return nil
}

// forgetSession drops the request's session from the cache, when there is
// one, and asks the transport to clear the client's copy. Sign-out, sign-out
// everywhere and revoking the current session call it, because deleting the
// session is not enough while a cache would keep answering for it. Its
// callers are SignedIn operations, whose session came from the request in
// ctx, so the request state is there.
func (a *Auth) forgetSession(ctx context.Context, c *Call) error {
	if a.cache == nil {
		return nil
	}
	st := stateFrom(ctx)
	if err := a.cache.Drop(ctx, CacheKey{TokenHash: HashToken(st.req.Token), Client: st.req.CachedSession}); err != nil {
		return fmt.Errorf("auth: session cache: %w", err)
	}
	c.Effects.ClearCache()
	return nil
}

// Resolve forces the session lookup for the request in ctx and reports a
// failure other than "signed out". Middleware calls it so a broken database
// becomes a 500 at the edge rather than a silent sign-out.
func (a *Auth) Resolve(ctx context.Context) error {
	st := stateFrom(ctx)
	if st == nil {
		return nil
	}
	return st.resolve(ctx, a)
}

// RequestEffects returns the effects that succeeded operations recorded during
// the request in ctx, for the transport to apply. It returns nil outside a
// request.
func RequestEffects(ctx context.Context) []Effect {
	st := stateFrom(ctx)
	if st == nil {
		return nil
	}
	return st.effects.List()
}

// RequestCredential reports how the request in ctx presented its token, so a
// transport can apply an issued session the same way it arrived.
func RequestCredential(ctx context.Context) Credential {
	st := stateFrom(ctx)
	if st == nil {
		return CredentialNone
	}
	return st.req.Credential
}

// RequestTokenRejected reports whether the request in ctx presented a
// session token that names no session: unknown, expired, revoked, or created
// before the user's SessionsValidAfter. A transport tells a client that keeps
// its own token (bearer mode) to forget it, because no call will ever accept
// it again. It is false for a pending second-factor session, which is alive
// and still needed to finish the sign-in; for a request without a token; for
// a lookup that failed with an error other than "signed out"; and before
// anything resolved the session (an operation that needs one, Resolve, or
// CurrentUser after middleware). Like CurrentUser it never queries by itself.
//
//ds:def id=core-requesttokenrejected-k3v8qd2m owner=@khanakia stability=stable
func RequestTokenRejected(ctx context.Context) bool {
	st := stateFrom(ctx)
	return st != nil && st.rejected
}

// CurrentUser returns the signed-in user of the request in ctx.
//
// It returns false both for a signed-out request and for a context that is not
// a request at all, and for a session that is not usable yet: a pending
// second factor, or session tasks pending (CurrentSessionTasks names them). It never queries the database by itself: the session must
// have been resolved by middleware or by an operation, which keeps a helper
// called in a loop from turning into a query per call.
//
//ds:def id=core-currentuser-g6e2yzqp owner=@khanakia stability=stable
func CurrentUser(ctx context.Context) (User, bool) {
	st := stateFrom(ctx)
	if st == nil || st.user == nil || st.session == nil || !st.session.usable() {
		return User{}, false
	}
	return *st.user, true
}

// CurrentSession returns the session of the request in ctx, under the same
// rules as CurrentUser.
//
//ds:def id=core-currentsession-muwuze9v owner=@khanakia stability=stable
func CurrentSession(ctx context.Context) (Session, bool) {
	st := stateFrom(ctx)
	if st == nil || st.session == nil || !st.session.usable() {
		return Session{}, false
	}
	return *st.session, true
}

// Call is what an operation sees of the call that invoked it.
//
// The same Call shape reaches an operation whether it was invoked over HTTP,
// GraphQL or directly from Go, which is what lets one operation serve every
// entry point. Effects is private to this call: its contents reach the request
// only if the operation and every after hook succeed.
//
//ds:def id=core-call-5mhhdsyk owner=@khanakia stability=stable
type Call struct {
	Auth       *Auth
	Op         OpInfo
	Plugin     string
	Transport  Transport
	Client     Client
	Credential Credential
	// Session and User are nil for a signed-out call.
	Session *Session
	User    *User
	Effects *Effects
	// Flow is the client's flow binding; see Request.Flow.
	Flow Token
	// Input is the operation's decoded input, for hooks: a Before hook that
	// restricts sign-up to one mail domain asserts it to the operation's
	// input type. It is a copy; assigning to it changes nothing the
	// operation sees. A Before hook that means to change the input calls
	// SetInput, which is checked against the operation's input type. It is
	// nil until the input is decoded, which is after the rate, origin and
	// session checks.
	Input any

	header func(name string) string
	// ctx is the call's context, for the pipeline's own checks after the
	// operation ran (checkDeviceCap); operations receive ctx as a parameter.
	ctx context.Context
	// redirectOnError is where a failed call sends the browser; see
	// RedirectOnError.
	redirectOnError string
	// inputSet and answered record SetInput and Respond from a Before hook;
	// answer is the value Respond gave.
	inputSet, answered bool
	answer             any
	// annotations are facts the operation recorded for its hooks; see
	// Annotate. A pointer, created with the call by the pipeline, so a copy
	// of the Call (session extras run on one) shares them, and the lock in
	// it is never copied.
	annotations *annotationSet
}

// annotationSet is a Call's annotations; mu guards m, because an
// operation may hand its Call to goroutines of its own.
type annotationSet struct {
	mu sync.Mutex
	m  map[string]string
}

// Annotation keys the library's own plugins record.
const (
	// AnnotationOrganization is the id of the organization an operation
	// acted on, which the operation resolves itself (from the active
	// organization, a team's or an invitation's) and the audit log records.
	//ds:def id=core-annotationorganization-7w3kq9xm owner=@khanakia stability=stable
	AnnotationOrganization = "organization"
)

// Annotate records a fact about this call for its After and Finally hooks,
// such as the organization an operation resolved and acted on, which its
// input does not carry. Last write wins. The value lives on this Call, not
// in the transaction, so a Finally hook still reads it after a failure
// rolled the writes back. Values are plain strings on purpose: a hook reads
// them into a log, so nothing that is not meant to be logged should go in,
// and a secret never should. An operation called from inside another gets
// its own Call, so it cannot overwrite the outer call's annotations.
//
//ds:def id=core-call-annotate-5p8wv2kq owner=@khanakia stability=stable
func (c *Call) Annotate(key, value string) {
	if c.annotations == nil {
		// A Call the pipeline did not build (a test's literal): no other
		// goroutine can hold it yet.
		c.annotations = &annotationSet{}
	}
	c.annotations.mu.Lock()
	defer c.annotations.mu.Unlock()
	if c.annotations.m == nil {
		c.annotations.m = map[string]string{}
	}
	c.annotations.m[key] = value
}

// Annotation returns the value Annotate recorded under key, or "".
//
//ds:def id=core-call-annotation-3m6xq8wn owner=@khanakia stability=stable
func (c *Call) Annotation(key string) string {
	if c.annotations == nil {
		return ""
	}
	c.annotations.mu.Lock()
	defer c.annotations.mu.Unlock()
	return c.annotations.m[key]
}

// SetInput replaces the input the operation runs with, from a Before hook,
// as better-auth's before hook returning { context } does: normalising a
// field, filling a default the app decides. v must have the operation's
// input type (the type its Input holds), or the call fails with
// ErrBadOperation before the operation runs, so a wrong type is a loud
// error and never a zero input. Later hooks see the new value in Input.
//
// What it does not redo: the per-account rate limit (ByIdentifier) was
// counted on the decoded input before any hook ran, so a hook cannot move a
// caller onto another account's budget or off its own.
//
//ds:def id=core-call-setinput-3nq7kd2w owner=@khanakia stability=stable
func (c *Call) SetInput(v any) { c.Input, c.inputSet = v, true }

// Respond answers the call from a Before hook with out, as better-auth's
// before hook returning a response (ctx.json) does: the remaining Before
// hooks, the operation and every After hook are skipped, the effects the
// hooks recorded still apply, and a mutation's transaction still commits.
// out must have the operation's output type, or the call fails with
// ErrBadOperation, so a Go caller never gets a zero result it did not ask
// for. A hook that refuses returns an error instead; Respond is for a
// success the app produces itself (a canned answer in a maintenance window,
// a result served from the app's own cache). Called from an After hook or
// the operation it changes nothing.
//
//ds:def id=core-call-respond-8hw2mz5v owner=@khanakia stability=stable
func (c *Call) Respond(out any) { c.answer, c.answered = out, true }

// RedirectOnError makes a failure of this call, from here on, answer with a
// redirect to url carrying the error code ("?error=<code>", or "&error="
// when url has a query) instead of a JSON error, for a browser flow such as
// an OAuth callback whose user is on the app's page, not in a script. The
// error is still returned to a Go caller; the transport sees the redirect in
// RequestEffects and applies it. Nothing else the failed call recorded
// reaches the request.
//
// An empty url takes WithErrorURL's page, as better-auth's callbacks fall
// back to onAPIError.errorURL; with neither, the call answers JSON as
// before.
//
//ds:def id=core-redirectonerror-8wq4tk2n owner=@khanakia stability=stable
func (c *Call) RedirectOnError(url string) {
	if url == "" {
		url = c.Auth.cfg.ErrorURL
	}
	c.redirectOnError = url
}

// WithErrorURL is the page a failed browser flow (an OAuth callback, a
// magic link) lands on when the flow names none, with the error code in the
// query ("?error=oauth.denied"), as better-auth's onAPIError.errorURL is.
// It must pass TrustsReturnURL (a same-site path, or a URL on a trusted
// origin), or New refuses it, so no failure can send the browser off-site.
// authhttp.ErrorPage serves a page for it to point at. Without it a flow
// with no error page of its own answers its failure as JSON.
//
//ds:def id=opt-witherrorurl-6nd2kq8w owner=@khanakia stability=stable
func WithErrorURL(url string) Option { return func(s *settings) { s.cfg.ErrorURL = url } }

// errorQueryParam is the query parameter a redirect-on-error carries.
const errorQueryParam = "error"

// errorRedirectURL appends the error's code to url.
func errorRedirectURL(target string, err error) string {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + errorQueryParam + "=" + url.QueryEscape(ErrorOf(err).Code)
}

// Header reads a request header, or returns "" when the call has no transport
// headers, such as a direct Go call.
func (c *Call) Header(name string) string {
	if c.header == nil {
		return ""
	}
	return c.header(name)
}

// opKey carries the running operation's OpInfo in the pipeline's context.
type opKey struct{}

// OperationOf returns the operation whose pipeline is running in ctx: what a
// data hook, which has no Call, needs to know how a row came to be written,
// such as which sign-in method created a session. False outside an operation
// (a direct Go call to the core API, a job). It is set before the hooks and
// the operation run, inside the transaction.
//
//ds:def id=core-operationof-3hk8wq2m owner=@khanakia stability=stable
func OperationOf(ctx context.Context) (OpInfo, bool) {
	info, ok := ctx.Value(opKey{}).(OpInfo)
	return info, ok
}

// RequestHeader reads a header of the request in ctx, or "" outside a request
// or for a transport without headers. It lets a data hook, which has no Call,
// read what the client sent with the call that caused the write.
func RequestHeader(ctx context.Context, name string) string {
	st := stateFrom(ctx)
	if st == nil || st.req.Header == nil {
		return ""
	}
	return st.req.Header(name)
}

// ProvenSignIn is the result of Call.SignInProven.
type ProvenSignIn struct {
	User User
	// Session has SecondFactorPending set when a SecondFactor plugin requires
	// a second factor; report that to the client rather than a sign-in.
	Session Session
	// Token is the new session's token. It is never written to JSON: the
	// transport delivers it through the IssueSession effect, so an operation
	// may return a ProvenSignIn as its output as it is.
	Token Token `json:"-"`
	// Created is true when this call created the user.
	Created bool
}

// SignInProven signs in the verified owner of the identifier (kind, raw),
// whose control the calling operation has just proven by checking a code or a
// link it sent there. With no verified owner and create set, it creates a user
// holding that identifier, verified and primary. It records the session on
// c.Effects (IssueSessionOf), so the transport sets the cookie or bearer
// token, and it creates the session through CreateSession, so a user's second
// factor still applies.
//
// It exists because every "prove you control this address" sign-in — an
// emailed code, an SMS code, a magic link — ends in these same steps, and a
// copy per plugin is where one of them forgets that only a VERIFIED owner may
// be signed in: an unverified row is a stranger's claim, never an account.
//
// With no verified owner and create false it returns ErrIdentityNotFound. The
// caller must map that to the same error a wrong code or link gets
// (ErrCodeInvalid, ErrTokenInvalid), so the answer does not tell a stranger
// which identifiers have accounts. ctx carries the tenant scope that
// FindIdentity and CreateIdentity use, and the operation's transaction, so a
// failure after the user is created leaves no user behind.
func (c *Call) SignInProven(ctx context.Context, kind IdentifierKindName, raw string, create bool) (ProvenSignIn, error) {
	var newUser *NewUser
	if create {
		newUser = &NewUser{}
	}
	return c.SignInProvenAs(ctx, kind, raw, newUser)
}

// SignInProvenAs is SignInProven with the profile a created user gets:
// newUser nil means "do not create" (ErrIdentityNotFound for an unknown
// identifier), and a non-nil value is used only when this call creates the
// user, so a first sign-in by code or link can carry the name the person
// typed. An existing user's profile is never touched: the input of a sign-in
// is not a place to edit an account from.
func (c *Call) SignInProvenAs(ctx context.Context, kind IdentifierKindName, raw string, newUser *NewUser) (ProvenSignIn, error) {
	a := c.Auth
	var out ProvenSignIn
	owner, err := a.FindIdentity(ctx, kind, raw, true)
	switch {
	case err == nil:
		if out.User, err = a.User(ctx, owner.UserID); err != nil {
			return ProvenSignIn{}, err
		}
	case errors.Is(err, ErrIdentityNotFound) && newUser != nil:
		if out.User, err = a.CreateUser(ctx, *newUser); err != nil {
			return ProvenSignIn{}, err
		}
		if _, err := a.CreateIdentity(ctx, NewIdentity{UserID: out.User.ID, Kind: kind, Raw: raw, Verified: true, Primary: true}); err != nil {
			return ProvenSignIn{}, err
		}
		out.Created = true
	default:
		return ProvenSignIn{}, err
	}
	if out.Session, out.Token, err = a.CreateSession(ctx, out.User.ID, c.Client); err != nil {
		return ProvenSignIn{}, err
	}
	c.Effects.IssueSessionOf(out.Session, out.Token)
	return out, nil
}
