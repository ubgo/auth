package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config is what every Client needs and has no safe default: which login
// server, which client, where the app lives, and the key its cookies are
// sealed with. Everything with a default is an Option.
type Config struct {
	// Issuer is the login server's issuer URL, exactly as its ID tokens'
	// iss and its discovery document say (a trailing slash aside). https,
	// or http on a loopback host for local development.
	Issuer string
	// ClientID is this app's client id at the login server; every ID token
	// must name it in aud (and in azp, when azp is present).
	ClientID string
	// ClientSecret authenticates the client with client_secret_basic. Leave
	// it empty only together with WithClientAuth (PublicClient for none).
	ClientSecret Secret
	// AppURL is the app's public origin, scheme and host only
	// ("https://admin.example.com"), as the browser sees it behind any
	// proxy. The redirect URI is AppURL + Paths.Callback; the back-channel
	// logout URI to register is AppURL + Paths.Backchannel. https, or http on
	// a loopback host.
	AppURL string
	// SessionSecret derives the key cookies are sealed with
	// (NewSecretSealer): at least MinSecretSize random bytes, kept secret
	// and the same on every instance. Leave it empty only together with
	// WithSealer.
	SessionSecret Secret
	// PreviousSessionSecrets still open cookies sealed before a rotation;
	// see NewSecretSealer.
	PreviousSessionSecrets []Secret
}

// Client is the relying party: the four routes, the middleware, and the
// re-check machinery, for one client at one login server. It is safe for
// concurrent use and holds no package-level state; an app may run several
// (two login servers, two clients) side by side under different Paths and
// cookie names.
type Client struct {
	cfg      Config
	set      settings
	provider *Provider
	// appOrigin is Config.AppURL normalised to scheme://host[:port], the
	// form a browser's Origin header takes; the redirect URI and the
	// post-logout URI are built on it.
	appOrigin string
	// rechecks is the per-session single-flight of re-checks.
	rechecks recheckGroup
	// replay remembers accepted logout tokens' jti.
	replay replayCache
}

// Defaults that are values, not policies.
const (
	// defaultHTTPTimeout bounds one request to the login server.
	defaultHTTPTimeout = 10 * time.Second
)

// New checks cfg and the options and returns a Client. It makes no network
// call: the discovery document is fetched on first use, so an app starts
// while the login server is down. Every mistake it can find is returned
// together, wrapping ErrInvalidConfig or ErrNilOption.
func New(cfg Config, opts ...Option) (*Client, error) {
	s := settings{
		store: CookieStore(), rechecker: RecheckByRefresh(), interval: DefaultRecheckInterval, grace: DefaultOutageGrace,
		responder: DefaultResponder(), returns: ReturnToRequested(), paths: PathsUnder(DefaultRoutePrefix),
		postLogout: siteRoot, scopes: DefaultScopes(), now: time.Now,
	}
	for _, o := range opts {
		o(&s)
	}
	if err := s.complete(&cfg); err != nil {
		return nil, err
	}
	c := &Client{cfg: cfg, set: s, appOrigin: originOf(cfg.AppURL)}
	c.provider = &Provider{c: c}
	if s.discovery != nil {
		m := *s.discovery
		c.provider.meta = &m
		c.provider.warnNoRevocation(m)
	}
	return c, nil
}

// complete validates cfg and s together and fills the defaults that depend
// on cfg (the sealer, the client authentication, the HTTP client).
func (s *settings) complete(cfg *Config) error {
	if err := checkOrigin("Issuer", cfg.Issuer, true); err != nil {
		s.errs = errors.Join(s.errs, err)
	}
	if err := checkOrigin("AppURL", cfg.AppURL, false); err != nil {
		s.errs = errors.Join(s.errs, err)
	}
	if cfg.ClientID == "" {
		s.refuse("Config.ClientID is empty")
	}
	switch {
	case cfg.ClientSecret.IsZero() && s.clientAuth == nil:
		s.refuse("set Config.ClientSecret, or WithClientAuth (PublicClient for a client without one)")
	case !cfg.ClientSecret.IsZero() && s.clientAuth != nil:
		s.refuse("Config.ClientSecret and WithClientAuth both set")
	case s.clientAuth == nil:
		s.clientAuth = ClientSecretBasic(cfg.ClientID, cfg.ClientSecret)
	}
	switch {
	case cfg.SessionSecret.IsZero() && s.sealer == nil:
		s.refuse("set Config.SessionSecret, or WithSealer")
	case !cfg.SessionSecret.IsZero() && s.sealer != nil:
		s.refuse("Config.SessionSecret and WithSealer both set")
	case s.sealer == nil:
		prev := make([][]byte, len(cfg.PreviousSessionSecrets))
		for i, p := range cfg.PreviousSessionSecrets {
			prev[i] = []byte(p.Reveal())
		}
		sl, err := NewSecretSealer([]byte(cfg.SessionSecret.Reveal()), prev...)
		if err != nil {
			s.errs = errors.Join(s.errs, err)
		}
		s.sealer = sl
	}
	if s.lifetimes.Idle == 0 {
		s.lifetimes.Idle = DefaultIdleLifetime
	}
	if s.lifetimes.Absolute == 0 {
		s.lifetimes.Absolute = DefaultAbsoluteLifetime
	}
	if s.lifetimes.Idle < 0 || s.lifetimes.Absolute < 0 || s.lifetimes.Idle > s.lifetimes.Absolute {
		s.refuse("Lifetimes %+v: both must be positive and Idle at most Absolute", s.lifetimes)
	}
	if err := s.cookie.validate(); err != nil {
		s.errs = errors.Join(s.errs, err)
	}
	if !s.paths.valid() {
		s.refuse("Paths %+v: each must be a distinct same-site path", s.paths)
	}
	if _, ok := s.rechecker.(backchannelOnly); ok {
		if _, revokes := s.store.(SessionRevoker); !revokes {
			s.refuse("RecheckBackchannelOnly needs a SessionStore that implements SessionRevoker")
		}
	}
	if s.discovery != nil {
		if err := s.discovery.validate(cfg.Issuer); err != nil {
			s.errs = errors.Join(s.errs, err)
		}
	}
	if s.httpClient == nil {
		s.httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	noRedirects := *s.httpClient
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.httpClient = &noRedirects
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s.errs
}

// schemeHTTPS and schemeHTTP are the only schemes an origin may use; http
// only on a loopback host.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
	hostLocal   = "localhost"
)

// checkOrigin checks a Config URL: absolute, https (http on a loopback
// host), no query or fragment, and, unless pathAllowed (an issuer may have
// a path, as Keycloak's realms do), no path either.
func checkOrigin(field, raw string, pathAllowed bool) error {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("%w: Config.%s %q is not an absolute URL", ErrInvalidConfig, field, raw)
	}
	if !pathAllowed && strings.TrimSuffix(u.Path, "/") != "" {
		return fmt.Errorf("%w: Config.%s %q must be an origin, without a path", ErrInvalidConfig, field, raw)
	}
	switch {
	case u.Scheme == schemeHTTPS:
		return nil
	case u.Scheme == schemeHTTP && isLoopbackHost(u.Hostname()):
		return nil
	}
	return fmt.Errorf("%w: Config.%s %q must be https (http only on a loopback host)", ErrInvalidConfig, field, raw)
}

// originOf returns an AppURL (already checked by checkOrigin) as the
// origin a browser sends: lower-case scheme and host, the default port
// dropped, no trailing slash.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" && !(u.Scheme == schemeHTTPS && p == portHTTPS) && !(u.Scheme == schemeHTTP && p == portHTTP) {
		host += ":" + p
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

// Default ports a browser leaves out of an Origin.
const (
	portHTTPS = "443"
	portHTTP  = "80"
)

// isLoopbackHost reports whether host is localhost or a loopback address.
func isLoopbackHost(host string) bool {
	if host == hostLocal {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Handler serves the four routes at Paths: GET Login, GET Callback, POST
// Logout and POST Backchannel. Any other path is 404, so it can be mounted
// at "/" of its own mux or under its prefix.
func (c *Client) Handler() http.Handler {
	routes := map[string]http.HandlerFunc{
		c.set.paths.Login: c.serveLogin, c.set.paths.Callback: c.serveCallback,
		c.set.paths.Logout: c.serveLogout, c.set.paths.Backchannel: c.serveBackchannel,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// LoginHandler starts a sign-in: it writes the sealed flow cookie (state,
// nonce, PKCE verifier, return path) and redirects to the authorization
// endpoint. GET; the return_to query parameter goes through the
// ReturnPolicy.
func (c *Client) LoginHandler() http.Handler { return http.HandlerFunc(c.serveLogin) }

// CallbackHandler completes a sign-in: state equal to the flow cookie's
// (constant time), iss when sent (RFC 9207), the code exchanged with the
// PKCE verifier, the ID token verified, the UserMapper run, the session
// saved, the browser sent to the return path. Every failure is refused with
// RefusalFailed or RefusalNoAccess, and no session is written.
func (c *Client) CallbackHandler() http.Handler { return http.HandlerFunc(c.serveCallback) }

// LogoutHandler signs out: it deletes the session, revokes its refresh
// token at the revocation endpoint (RFC 7009, best effort: a failure is
// logged and observed as EventRevokeFailed, never blocks the sign-out),
// then sends the browser to the login server's end-session endpoint with the ID token as
// id_token_hint and the post-logout path, or straight to that path when the
// server has none. POST only, and only from this origin (Origin or
// Sec-Fetch-Site), so another site cannot sign people out.
func (c *Client) LogoutHandler() http.Handler { return http.HandlerFunc(c.serveLogout) }

// BackchannelHandler receives OpenID Connect Back-Channel Logout tokens:
// a POSTed logout_token signed by the issuer under an allowed algorithm,
// with iss, aud equal to the client id, iat, a short exp, the back-channel
// logout event, sub or sid, and no nonce. It ends the matching sessions
// through the store's SessionRevoker and answers 200; a token that does not
// verify is 400, a store without SessionRevoker is 501.
func (c *Client) BackchannelHandler() http.Handler { return http.HandlerFunc(c.serveBackchannel) }

// Require lets a request through only with a live, fresh, authorized
// session, and puts its User in the request context (UserFrom). In order:
// load the session (none: login required), apply Lifetimes (past either:
// login required), re-check when the last "yes" is older than the recheck
// interval (single-flight per session; Deny: login required; unreachable:
// the outage grace, then unavailable), run the UserMapper on a new
// Identity, run the Authorizer, then serve next. Every refusal goes to the
// Responder.
func (c *Client) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { c.serveRequire(next, w, r) })
}

// Optional is Require for pages anyone may see that show more to a
// signed-in person ("signed in as", a personal menu): it makes the same
// decision (load, Lifetimes, re-check with the outage grace, the
// Authorizer) and writes the same cookies, but never refuses. When Require
// would have let the request through, UserFrom returns the User; otherwise
// the request goes on without one, and a session the login server refused
// is ended exactly as under Require. The Responder is never called.
func (c *Client) Optional(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { c.serveOptional(next, w, r) })
}

// Provider returns the handle that calls the login server as this client,
// for the app's own calls (introspection, userinfo) with the same
// credentials, HTTP client and floors.
func (c *Client) Provider() *Provider { return c.provider }

// userKey is the context key UserFrom reads; unexported, so only Require
// and Optional can set it.
type userKey struct{}

// UserFrom returns the User that Require (or Optional) let through for
// this request's context, and false otherwise.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey{}).(User)
	return u, ok
}
