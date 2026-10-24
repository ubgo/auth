// Package authgate is a login gate, not user accounts: sign in with any
// OAuth 2.0 or OpenID Connect provider and keep the person's profile in a
// sealed cookie, with no database, no user table and no auth.New.
//
// It is for an internal tool behind company login, a prototype, a tool that
// acts on the person's GitHub or Google account, or a serverless function
// with nowhere to keep rows. Everything the rest of this library stores (users,
// identities, sessions, devices) does not exist here, and so neither does
// anything built on it: no per-device sign-out, no passwords, no bans, no
// admin, no linking of two providers to one person. Revocation is coarse on
// purpose: every cookie carries an absolute expiry and the SessionVersion it
// was issued under, so bumping the version (or rotating the secret without
// keeping the old one) signs everyone out at once. An app that needs any of
// the missing parts uses auth.New with plugin/oauth instead, and the
// providers it configured here carry over unchanged.
//
// The providers are plugin/oauth's own (oauth.Google, oauth.GitHub, the
// presets, oauth.OIDC with discovery), so PKCE, state, the RFC 9207 issuer
// check and ID-token verification are the code the full library runs. The
// state is bound to the browser by a sealed __Host- flow cookie, the same
// login-CSRF defence authhttp's flow cookie gives, without a stored row.
package authgate

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// Cookie names. __Host- makes the browser refuse the cookie unless it is
// Secure, has Path=/ and no Domain, so a sibling subdomain cannot plant or
// overwrite it. They differ from authhttp's so a gate and a full Auth can run
// side by side on one host.
//
//ds:def id=authgate-cookienames-3vx8kq2m owner=@khanakia stability=stable
const (
	// SessionCookieName holds the sealed profile.
	SessionCookieName = "__Host-authgate_session"
	// FlowCookieName holds the sealed state, PKCE verifier and return path
	// of one sign-in between start and callback.
	FlowCookieName = "__Host-authgate_flow"
)

// Defaults and limits.
//
//ds:def id=authgate-defaults-7pm2wn4q owner=@khanakia stability=stable
const (
	// DefaultPrefix is where Handler expects to be mounted.
	DefaultPrefix = "/auth"
	// DefaultSessionLifetime is the absolute lifetime of a sign-in: a week.
	// It is never extended; the person signs in again
	// after it, which is also when an Allow rule change or a changed provider
	// profile reaches the cookie.
	DefaultSessionLifetime = 7 * 24 * time.Hour
	// FlowLifetime bounds the time a person may spend at the provider,
	// plugin/oauth's DefaultStateTTL.
	FlowLifetime = oauth.DefaultStateTTL
	// MaxCookieSize is the largest Set-Cookie value (name, value and
	// attributes) the gate writes: RFC 6265 section 6.1 asks browsers to
	// accept at least 4096 bytes per cookie, and most stop there. A session
	// that would not fit (provider tokens kept with KeepTokens are the usual
	// cause) is refused with ErrCookieTooLarge rather than written and
	// silently dropped by the browser.
	MaxCookieSize = 4096
	// MaxReturnToLength bounds the returnTo path a start accepts, so the flow
	// cookie that carries it stays far below MaxCookieSize.
	MaxReturnToLength = 1024
)

// Route segments under the prefix: /{provider}/start, /{provider}/callback,
// /sign-out and /session.
const (
	stepStart    = "start"
	stepCallback = "callback"
	pathSignOut  = "/sign-out"
	pathSession  = "/session"
	// rootPath is where a flow lands when it named no returnTo.
	rootPath = "/"
)

// Query and form parameters. The callback's names are the OAuth 2.0 ones
// (RFC 6749 section 4.1.2, RFC 9207); returnTo is plugin/oauth's spelling.
const (
	paramReturnTo = "returnTo"
	paramCode     = "code"
	paramState    = "state"
	paramError    = "error"
	paramIssuer   = "iss"
	// paramUser is the user field a form-post provider (Apple) sends beside
	// the code on first consent; see oauth.PostedProfile.
	paramUser = "user"
	// paramDeviceID is VK ID's device_id, which its token request needs;
	// handed to the exchange through oauth.WithCallbackValues.
	paramDeviceID = "device_id"
)

// Errors a request can answer. The state, denial and provider failures reuse
// plugin/oauth's, so a client sees the same codes either way.
//
//ds:def id=authgate-errors-6tq3vm8w owner=@khanakia stability=stable
var (
	// ErrNotAllowed is a sign-in or a cookie whose profile no Allow rule
	// accepts.
	ErrNotAllowed = auth.NewError("authgate.not_allowed", http.StatusForbidden, "This account is not allowed here.")
	// ErrCookieTooLarge is a sign-in whose sealed session would exceed
	// MaxCookieSize. Nothing is written; the log says how large it was.
	ErrCookieTooLarge = auth.NewError("authgate.cookie_too_large", http.StatusInternalServerError, "The sign-in could not be saved. Contact the site's owner.")
	// ErrBadReturnTo is a returnTo that is not a path on this site.
	ErrBadReturnTo = auth.NewError("authgate.bad_return_to", http.StatusBadRequest, "The return address must be a path on this site.")
	// ErrUnknownProvider is a route naming a provider the gate was not given.
	ErrUnknownProvider = auth.NewError("authgate.unknown_provider", http.StatusNotFound, "This sign-in method is not offered here.")
	// ErrCrossSite is a sign-out posted from another site.
	ErrCrossSite = auth.NewError("authgate.cross_site", http.StatusForbidden, "This request came from another site.")
)

// Configuration errors New returns.
var (
	// ErrNoProviders is New without WithProviders.
	ErrNoProviders = errors.New("authgate: no providers; pass WithProviders")
	// ErrNoRule is New without any Allow rule. Letting every account at the
	// provider in is a real choice for a GitHub tool and a breach for a
	// company dashboard, so it must be said out loud with AllowAnyone.
	ErrNoRule = errors.New("authgate: no Allow rule; pass Allow, AllowEmailDomain, AllowEmails or AllowAnyone")
	// ErrBaseURL is a missing or malformed WithBaseURL: an http or https
	// origin with no path, query or fragment.
	ErrBaseURL = errors.New("authgate: WithBaseURL must be an http or https origin such as https://tools.example.com")
	// ErrDuplicateProvider is two providers with one name, which would share
	// one callback route.
	ErrDuplicateProvider = errors.New("authgate: two providers share a name")
	// ErrBadOption is an option given an unusable value (a non-positive
	// lifetime, an empty domain, a path that is not one).
	ErrBadOption = errors.New("authgate: bad option")
)

// Gate is a configured login gate. It is safe for concurrent use and holds no
// state beyond its configuration: every sign-in lives in the browser's
// cookies, so any number of instances with the same options serve the same
// people.
type Gate struct {
	// optErrs collects the options given nil (auth.ErrNilOption); New
	// returns them before optionErr.
	optErrs      auth.OptionErrors
	providers    map[string]oauth.Provider
	order        []string
	ring         *auth.KeyRing
	baseURL      string
	prefix       string
	rules        []func(Profile) bool
	allowAnyone  bool
	keepTokens   bool
	lifetime     time.Duration
	version      uint64
	signInPage   string
	hc           *http.Client
	logger       *slog.Logger
	now          func() time.Time
	errorHandler func(w http.ResponseWriter, r *http.Request, err error)
	// secrets lives only between the options and New, which derives the
	// ring from it and drops it.
	secrets [][]byte
	// optionErr is the first error an option recorded; New returns it.
	optionErr error
}

// Option configures a Gate.
type Option func(*Gate)

// WithProviders sets the providers people may sign in with: any
// oauth.Provider, such as oauth.Google, oauth.GitHub, a preset or oauth.OIDC.
// Each is checked by oauth.ValidateProvider, the check plugin/oauth runs.
func WithProviders(ps ...oauth.Provider) Option {
	return func(g *Gate) {
		if auth.RefuseNilEach(&g.optErrs, "authgate.WithProviders", ps) {
			return
		}
		for _, p := range ps {
			if _, dup := g.providers[p.Name()]; dup {
				g.fail(fmt.Errorf("%w: %q", ErrDuplicateProvider, p.Name()))
				continue
			}
			g.providers[p.Name()] = p
			g.order = append(g.order, p.Name())
		}
	}
}

// WithSecret sets the secret the cookie keys are derived from, by the same
// HKDF rule as auth.WithSecret under the label auth.KeyLabelAuthGate. It is
// required and at least auth.MinSecretSize bytes. Rotation: pass the new
// secret first and the old ones after; cookies sealed under an old one still
// open until they expire. Dropping a secret signs out everyone it sealed.
func WithSecret(current []byte, previous ...[]byte) Option {
	return func(g *Gate) { g.secrets = append([][]byte{current}, previous...) }
}

// WithBaseURL sets the origin the gate is served at, such as
// "https://tools.example.com". The callback URL registered at each provider
// is this origin, the prefix, then /{provider}/callback. http is accepted
// for local development on localhost; the cookies stay Secure, which
// browsers honour on http://localhost.
func WithBaseURL(origin string) Option {
	return func(g *Gate) { g.baseURL = origin }
}

// Prefix sets the path Handler is mounted at; the default is DefaultPrefix.
func Prefix(path string) Option {
	return func(g *Gate) { g.prefix = strings.TrimSuffix(path, "/") }
}

// SessionLifetime sets how long a sign-in lasts from the moment it happened;
// the default is DefaultSessionLifetime. It is absolute: activity does not
// extend it.
func SessionLifetime(d time.Duration) Option {
	return func(g *Gate) {
		if d <= 0 {
			g.fail(fmt.Errorf("%w: SessionLifetime %v", ErrBadOption, d))
		}
		g.lifetime = d
	}
}

// SessionVersion stamps every cookie with n and accepts only cookies stamped
// with n. Raising it (from a deploy variable) signs everyone out at once:
// the gate's only revocation, because there is no store to delete one
// session from. The default is 0.
func SessionVersion(n uint64) Option {
	return func(g *Gate) { g.version = n }
}

// KeepTokens keeps the provider's access token, refresh token, expiry and
// granted scope in the sealed session cookie, for a tool that calls the
// provider's API as the person (Profile.Tokens). Off by default: a cookie
// that holds nothing but a profile leaks nothing an attacker can use at the
// provider. The ID token and the raw token answer are never kept. Tokens are
// what the provider issued at sign-in; nothing refreshes them into the
// cookie, so a tool whose access token expires before the session does asks
// the person to sign in again. Large tokens (Entra ID's can pass 2 KB) can
// push the cookie over MaxCookieSize, which refuses the sign-in with
// ErrCookieTooLarge.
func KeepTokens() Option {
	return func(g *Gate) { g.keepTokens = true }
}

// SignInPage is where RequireUser sends a browser that is not signed in,
// with ?returnTo= the page it asked for. Without it, a gate with exactly one
// provider sends the browser straight to that provider's start, and a gate
// with several answers 401.
func SignInPage(path string) Option {
	return func(g *Gate) {
		if !isLocalPath(path) {
			g.fail(fmt.Errorf("%w: SignInPage %q is not a path on this site", ErrBadOption, path))
		}
		g.signInPage = path
	}
}

// WithHTTPClient sets the client used to reach the providers; the default
// times out after oauth.DefaultHTTPTimeout.
func WithHTTPClient(hc *http.Client) Option {
	return func(g *Gate) { g.hc = hc }
}

// WithLogger sets where refused sign-ins and provider failures are logged;
// the default is slog.Default.
func WithLogger(l *slog.Logger) Option {
	return func(g *Gate) { g.logger = l }
}

// WithClock replaces time.Now. Tests move time with it.
func WithClock(now func() time.Time) Option {
	return func(g *Gate) {
		if g.optErrs.RefuseNil("authgate.WithClock", now) {
			return
		}
		g.now = now
	}
}

// ErrorHandler answers every error of Handler and RequireUser's 401 instead
// of the library's JSON error body, for an app that renders its own page.
// err is one of this package's errors, auth.ErrSignedOut, or plugin/oauth's
// ErrStateInvalid, ErrProviderDenied or ErrProviderFailed;
// auth.ErrorOf(err) gives its code and status.
func ErrorHandler(fn func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(g *Gate) {
		if g.optErrs.RefuseNil("authgate.ErrorHandler", fn) {
			return
		}
		g.errorHandler = fn
	}
}

// New builds a gate. It refuses a configuration nobody could sign in with or
// that would let in more than intended: no provider, a provider
// oauth.ValidateProvider refuses, no secret or a short one, no base URL, and
// no Allow rule.
func New(opts ...Option) (*Gate, error) {
	g := &Gate{
		providers: map[string]oauth.Provider{},
		prefix:    DefaultPrefix,
		lifetime:  DefaultSessionLifetime,
		hc:        &http.Client{Timeout: oauth.DefaultHTTPTimeout},
		logger:    slog.Default(),
		now:       time.Now,
	}
	for _, o := range opts {
		o(g)
	}
	if err := errors.Join(g.optErrs.OptionErr(), g.optionErr); err != nil {
		return nil, err
	}
	if len(g.order) == 0 {
		return nil, ErrNoProviders
	}
	for _, name := range g.order {
		if err := oauth.ValidateProvider(g.providers[name]); err != nil {
			return nil, fmt.Errorf("authgate: %w", err)
		}
	}
	if len(g.rules) == 0 && !g.allowAnyone {
		return nil, ErrNoRule
	}
	base, err := checkBaseURL(g.baseURL)
	if err != nil {
		return nil, err
	}
	g.baseURL = base
	if g.prefix != "" && !isLocalPath(g.prefix) {
		return nil, fmt.Errorf("%w: Prefix %q is not a path", ErrBadOption, g.prefix)
	}
	keys, err := auth.DeriveSecretKeys(auth.KeyLabelAuthGate, g.secrets...)
	if err != nil {
		return nil, fmt.Errorf("authgate: WithSecret: %w", err)
	}
	// NewKeyRing fails only for a key that is not SealKeySize bytes, and
	// DeriveSecretKeys returns exactly that size.
	if g.ring, err = auth.NewKeyRing(keys[0], keys[1:]...); err != nil {
		return nil, err
	}
	g.secrets = nil
	return g, nil
}

// fail records the first option error, so New reports it.
func (g *Gate) fail(err error) {
	if g.optionErr == nil {
		g.optionErr = err
	}
}

// CallbackURL is the redirect URI to register at the provider named name.
func (g *Gate) CallbackURL(name string) string {
	return g.baseURL + g.prefix + "/" + name + "/" + stepCallback
}

// StartURL is the path that begins a sign-in with the provider named name,
// returning to returnTo ("" for the site root) afterwards: the href of a
// "Sign in with …" link.
func (g *Gate) StartURL(name, returnTo string) string {
	u := g.prefix + "/" + name + "/" + stepStart
	if returnTo != "" {
		u += "?" + url.Values{paramReturnTo: {returnTo}}.Encode()
	}
	return u
}

// Providers lists the configured provider names in the order given.
func (g *Gate) Providers() []string { return append([]string(nil), g.order...) }

// checkBaseURL accepts an http or https origin and returns it without a
// trailing slash.
func checkBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != schemeHTTPS && u.Scheme != schemeHTTP) || u.Host == "" ||
		(u.Path != "" && u.Path != rootPath) || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", ErrBaseURL
	}
	return u.Scheme + "://" + u.Host, nil
}

// Schemes a base URL may use.
const (
	schemeHTTPS = "https"
	schemeHTTP  = "http"
)

// isLocalPath reports whether p is a path on this site: it starts with one
// slash, not two, and carries no backslash or line break, the same rule
// auth.TrustsReturnURL applies to a path. Anything else could send the
// browser to another site after sign-in.
func isLocalPath(p string) bool {
	return strings.HasPrefix(p, rootPath) && !strings.HasPrefix(p, "//") && !strings.ContainsAny(p, "\\\r\n")
}
