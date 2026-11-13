package oidcclient

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Option sets one policy of a Client. Options run in order inside New; a
// mistake an option can only find while it runs (a nil value, a reserved
// parameter) is collected and returned by New, naming the option.
type Option func(*settings)

// settings is what the options build; New validates it as a whole.
type settings struct {
	errs        error
	store       SessionStore
	sealer      Sealer
	mapper      UserMapper
	authorizer  Authorizer
	rechecker   Rechecker
	interval    time.Duration
	grace       time.Duration
	lifetimes   Lifetimes
	responder   Responder
	returns     ReturnPolicy
	cookie      CookieOptions
	paths       Paths
	postLogout  string
	scopes      []string
	authParams  map[string]string
	clientAuth  ClientAuth
	httpClient  *http.Client
	logger      *slog.Logger
	now         func() time.Time
	discovery   *ProviderMetadata
	observer    Observer
	intervalSet bool
}

// RefuseNil records ErrNilOption naming the option (its qualified name,
// "oidcclient.WithSealer") when v is nil or holds a nil func or pointer,
// and reports whether it did, so the option keeps its default. Every option
// taking a func, an interface or a pointer starts with it; the repository's
// TestGuard_OptionsRefuseNil checks the shape. It is a method of the
// unexported settings, so it is not part of the package's API.
func (s *settings) RefuseNil(name string, v any) bool {
	if v != nil {
		switch rv := reflect.ValueOf(v); rv.Kind() {
		case reflect.Func, reflect.Pointer, reflect.Map, reflect.Slice:
			if !rv.IsNil() {
				return false
			}
		default:
			return false
		}
	}
	s.errs = errors.Join(s.errs, fmt.Errorf("%w: %s(nil)", ErrNilOption, name))
	return true
}

// refuse records a configuration mistake an option found.
func (s *settings) refuse(format string, args ...any) {
	s.errs = errors.Join(s.errs, fmt.Errorf("%w: "+format, append([]any{ErrInvalidConfig}, args...)...))
}

// WithSessionStore keeps sessions in st instead of the stateless
// CookieStore: NewMemoryStore, or a Redis, SQL or app-owned store. A store
// that also implements SessionRevoker enables back-channel logout.
func WithSessionStore(st SessionStore) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithSessionStore", st) {
			return
		}
		s.store = st
	}
}

// WithSealer seals cookies with sl (a KMS-backed sealer, auth.RingSealer)
// instead of the one derived from Config.SessionSecret. New refuses both
// at once: two sources of the key would leave it unclear which one opens
// yesterday's cookies.
func WithSealer(sl Sealer) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithSealer", sl) {
			return
		}
		s.sealer = sl
	}
}

// WithUserMapper maps the verified Identity to the app's User at sign-in
// and at every refresh that brings a new ID token (the "OnLogin" hook).
// The default is DefaultUser.
func WithUserMapper(m UserMapper) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithUserMapper", m) {
			return
		}
		s.mapper = m
	}
}

// WithAuthorizer adds the app's own rule, run on every request after the
// session is known to be fresh. The default is none.
func WithAuthorizer(a Authorizer) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithAuthorizer", a) {
			return
		}
		s.authorizer = a
	}
}

// WithRechecker sets how the login server is asked again: RecheckByRefresh
// (the default), RecheckByIntrospection, RecheckByUserInfo,
// RecheckBackchannelOnly, or the app's own.
func WithRechecker(r Rechecker) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithRechecker", r) {
			return
		}
		s.rechecker = r
	}
}

// WithRecheckInterval sets how long the login server's last "yes" stands:
// the longest a person removed at the server can still use the app.
// RecheckEveryRequest (zero) asks on every request; a negative d is
// refused. The default is DefaultRecheckInterval.
func WithRecheckInterval(d time.Duration) Option {
	return func(s *settings) {
		if d < 0 {
			s.refuse("WithRecheckInterval(%v) is negative", d)
			return
		}
		s.interval, s.intervalSet = d, true
	}
}

// WithOutageGrace sets how long the last "yes" stands while the login
// server cannot be reached, counted from Session.CheckedAt. NoOutageGrace
// (zero) refuses at once; a negative d is refused. The default is
// DefaultOutageGrace. It never extends a session past its Lifetimes.
func WithOutageGrace(d time.Duration) Option {
	return func(s *settings) {
		if d < 0 {
			s.refuse("WithOutageGrace(%v) is negative", d)
			return
		}
		s.grace = d
	}
}

// WithLifetimes sets the idle and absolute session lifetimes. A zero field
// keeps its default.
func WithLifetimes(l Lifetimes) Option { return func(s *settings) { s.lifetimes = l } }

// WithResponder answers refused requests with r instead of
// DefaultResponder.
func WithResponder(r Responder) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithResponder", r) {
			return
		}
		s.responder = r
	}
}

// WithReturnPolicy picks where sign-in lands: ReturnToRequested (the
// default), ReturnToFixed, ReturnToAllowed, or the app's own. Its answer is
// still held to the same-site path floor.
func WithReturnPolicy(p ReturnPolicy) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithReturnPolicy", p) {
			return
		}
		s.returns = p
	}
}

// WithCookie sets the session cookie's name, domain and SameSite mode; New
// checks them against the browser's cookie-prefix rules.
func WithCookie(o CookieOptions) Option { return func(s *settings) { s.cookie = o } }

// WithPaths serves the routes at p instead of PathsUnder(DefaultRoutePrefix).
func WithPaths(p Paths) Option { return func(s *settings) { s.paths = p } }

// WithPostLogoutPath is where the browser lands after sign-out: sent to the
// login server as post_logout_redirect_uri (Config.AppURL + path, which
// must be registered there), or redirected to directly when the server has
// no end-session endpoint. It must be a same-site path; the default is "/".
func WithPostLogoutPath(path string) Option {
	return func(s *settings) {
		if !isSameSitePath(path) {
			s.refuse("WithPostLogoutPath(%q) is not a same-site path", path)
			return
		}
		s.postLogout = path
	}
}

// ScopeOpenID is always requested, whatever WithScopes says: without it
// there is no ID token and nothing to verify.
const ScopeOpenID = "openid"

// defaultScopes are requested unless WithScopes replaces them.
// offline_access asks for the refresh token RecheckByRefresh needs.
//
//ds:def id=defaultscopes-9z5zg4vd owner=@khanakia stability=stable
var defaultScopes = []string{ScopeOpenID, "email", "profile", "offline_access"}

// DefaultScopes returns the scopes requested when WithScopes is not given,
// as a fresh slice the caller may extend.
func DefaultScopes() []string { return slices.Clone(defaultScopes) }

// WithScopes replaces the requested scopes. "openid" is added when absent.
func WithScopes(scopes ...string) Option {
	return func(s *settings) {
		if !slices.Contains(scopes, ScopeOpenID) {
			scopes = append([]string{ScopeOpenID}, scopes...)
		}
		s.scopes = scopes
	}
}

// reservedAuthParams are the authorization-request parameters the flow
// sets itself; WithAuthParams may not name one, so no option can drop PKCE,
// the state or the nonce, or redirect the code elsewhere.
var reservedAuthParams = []string{"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge",
	"code_challenge_method", "nonce", "response_mode", "request", "request_uri"}

// WithAuthParams adds parameters to every authorization request: prompt,
// login_hint, acr_values, hd, or Google's access_type=offline. A reserved
// parameter (state, nonce, code_challenge, redirect_uri and the other
// protocol parameters) is refused by New.
func WithAuthParams(params map[string]string) Option {
	return func(s *settings) {
		for k := range params {
			if slices.Contains(reservedAuthParams, strings.ToLower(k)) {
				s.refuse("WithAuthParams may not set %q", k)
				return
			}
		}
		s.authParams = params
	}
}

// WithClientAuth authenticates the client with a instead of
// client_secret_basic: ClientSecretPost, PublicClient, or the app's own.
// New refuses it together with Config.ClientSecret.
func WithClientAuth(a ClientAuth) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithClientAuth", a) {
			return
		}
		s.clientAuth = a
	}
}

// WithHTTPClient sends every request to the login server through c: a
// proxy, mTLS, a test transport. The package uses a copy of c that never
// follows redirects, because an endpoint answering with a redirect could
// send the client's credentials elsewhere. The default times out after 10
// seconds.
func WithHTTPClient(c *http.Client) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithHTTPClient", c) {
			return
		}
		s.httpClient = c
	}
}

// WithLogger logs to l instead of slog.Default(). Secrets are never
// logged; failures are logged with their cause.
func WithLogger(l *slog.Logger) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithLogger", l) {
			return
		}
		s.logger = l
	}
}

// WithClock reads the time from now instead of time.Now, for tests of
// lifetimes, re-checks and grace. It is also the clock ID token expiry is
// checked against.
func WithClock(now func() time.Time) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithClock", now) {
			return
		}
		s.now = now
	}
}

// WithDiscovery uses m instead of fetching the discovery document: a
// server without discovery, or a test. m is held to the same checks as a
// fetched document.
func WithDiscovery(m ProviderMetadata) Option { return func(s *settings) { s.discovery = &m } }

// WithObserver reports logins, re-checks, refusals and logouts to o.
func WithObserver(o Observer) Option {
	return func(s *settings) {
		if s.RefuseNil("oidcclient.WithObserver", o) {
			return
		}
		s.observer = o
	}
}
