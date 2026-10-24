// Package oauthproxy lets preview and development deployments sign in with a
// provider through the one callback URL registered at the provider, better-
// auth's oauth-proxy plugin. A provider console takes a fixed list of
// callback URLs, and a preview deployment's URL is new every push; with this
// plugin the console lists only production's callback.
//
// The flow, with the same plugin and the same secret on every deployment:
//
//  1. On a preview, a provider wrapped by Wrap sends the browser to the
//     provider with production's callback as redirect_uri and, as state, a
//     sealed package naming the preview's own state and callback.
//  2. Production's callback finds the package (a Before hook on the oauth
//     plugin's callback operation), checks that the preview's origin is one
//     it trusts, and redirects the browser to the preview's callback with
//     the preview's state and the authorization code sealed for it.
//     Production exchanges nothing and writes nothing.
//  3. The preview's own oauth callback runs as always (flow cookie, state,
//     account linking, sign-up rules); the wrapped provider opens the sealed
//     code and exchanges it with the provider itself, with production's
//     redirect_uri and the PKCE verifier that never left the preview.
//
// What travels is an authorization code, not a profile: it is sealed
// (AES-256-GCM under a key derived from the shared secret, bound to the
// provider and the preview callback, valid MaxAge), and it is useless
// without the PKCE verifier only the preview holds. Whoever holds the
// secret can relay codes but cannot assert an identity to a deployment, as
// an encrypted-profile relay would allow. That design is available opt-in,
// with a warning at every start, as PassProfile.
package oauthproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// PluginName is the plugin's permanent identity.
const PluginName = "oauthproxy"

// Key labels: one key per purpose, so a sealed state can never be opened as
// a sealed code.
const (
	keyLabelState   = "oauthproxy-state"
	keyLabelCode    = "oauthproxy-code"
	keyLabelProfile = "oauthproxy-profile"
)

// Defaults and formats.
const (
	// DefaultMaxAge is how long a sealed state or code is accepted: a relay
	// takes a second; the provider sign-in between the two takes the state's
	// TTL, so the state gets StateMaxAge.
	//ds:def id=oauthproxy-defaultmaxage-4k8wq2nv owner=@khanakia stability=stable
	DefaultMaxAge = 60 * time.Second
	// StateMaxAge bounds a sealed state: the person signs in at the provider
	// between the start and production's callback, as long as the oauth
	// plugin's own state lives by default.
	//ds:def id=oauthproxy-statemaxage-7n2xk5qm owner=@khanakia stability=stable
	StateMaxAge = 10 * time.Minute
	// clockSkew is how far in the future an issue time may be, better-
	// auth's 10 seconds, for deployments whose clocks differ.
	clockSkew = 10 * time.Second
	// sealedPrefix marks a sealed value, so production tells a proxied
	// state from its own in one comparison, before any decryption.
	sealedPrefix = "oxp1."
	// profilePrefix marks a sealed profile (PassProfile); it does not start
	// with sealedPrefix, so a profile is never opened as a code.
	profilePrefix = "oxp1p."
	// version is the package format.
	version = 1
)

// Errors.
var (
	// ErrNoProductionURL is a configuration error: ProductionURL is required.
	ErrNoProductionURL = errors.New("oauthproxy: ProductionURL is required and must be an absolute http(s) URL")
	// ErrNoSecret is a configuration error: neither WithSecret nor
	// auth.WithSecret was given, so nothing can be sealed.
	ErrNoSecret = errors.New("oauthproxy: pass oauthproxy.WithSecret (the same on every deployment) or auth.WithSecret")
	// ErrNotWrapped is a configuration error: the plugin is registered but
	// no provider was wrapped, so it can do nothing on a preview.
	ErrNotWrapped = errors.New("oauthproxy: wrap at least one oauth provider with Plugin.Wrap")

	// ErrInvalidState is a sealed state that does not open, is too old, or
	// names an untrusted preview: production refuses to relay it.
	ErrInvalidState = auth.NewError("oauthproxy.invalid_state", http.StatusBadRequest, "The sign-in could not be completed. Start again.")
	// ErrInvalidCode is a relayed code that does not open or is too old: the
	// preview refuses to exchange it.
	ErrInvalidCode = auth.NewError("oauthproxy.invalid_code", http.StatusBadRequest, "The sign-in could not be completed. Start again.")
	// ErrMissingProfile is missing_profile: under PassProfile
	// the preview's callback arrived with neither a sealed profile nor an
	// error. The oauth callback logs it and answers oauth.provider_failed.
	ErrMissingProfile = errors.New("oauthproxy: missing_profile: the relayed callback carries no profile")
)

// RelayErrorInvalidCode is the error parameter production relays to the
// preview when, under PassProfile, its own code exchange failed: better-
// auth's invalid_code. The preview's oauth callback then answers
// oauth.provider_denied and redirects to the flow's error page.
//
//ds:def id=oauthproxy-relayerrorinvalidcode-p3r2kq7m owner=@khanakia stability=stable
const RelayErrorInvalidCode = "invalid_code"

// WarnPassProfile is logged at every start under PassProfile.
//
//ds:def id=oauthproxy-warnpassprofile-p3r2wn4x owner=@khanakia stability=stable
const WarnPassProfile = "oauthproxy: PassProfile is on: production exchanges the code and relays a sealed profile, so whoever holds the proxy secret can sign in as anyone on a deployment that accepts it"

// Plugin is the proxy plugin. Build it with New, wrap providers with Wrap,
// and register it beside the oauth plugin on every deployment.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs    auth.OptionErrors
	production *url.URL
	callbackOf func(previewCallback string) string
	secrets    [][]byte
	maxAge     time.Duration
	stateKeys  [][]byte
	codeKeys   [][]byte
	wrapped    []string
	// providers are the wrapped providers by name, which production
	// exchanges with under PassProfile.
	providers   map[string]*Proxied
	passProfile bool
	profileKeys [][]byte
	hc          *http.Client
	core        *auth.Auth
	now         func() time.Time
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin.
type Option func(*Plugin)

// ProductionURL is the deployment whose callback URL the provider has.
// Sign-ins on that origin are not proxied.
func ProductionURL(u string) Option {
	return func(p *Plugin) {
		if parsed, err := url.Parse(u); err == nil && parsed.IsAbs() && (parsed.Scheme == "https" || parsed.Scheme == "http") {
			p.production = parsed
		}
	}
}

// WithSecret sets the secret the proxy keys are derived from. It must be the
// same on every participating deployment; previous secrets still open values
// sealed under them. Without it the app's auth.WithSecret is used, which then
// must be shared too.
func WithSecret(current []byte, previous ...[]byte) Option {
	return func(p *Plugin) { p.secrets = append([][]byte{current}, previous...) }
}

// MaxAge overrides DefaultMaxAge for a relayed code.
func MaxAge(d time.Duration) Option { return func(p *Plugin) { p.maxAge = d } }

// PassProfile is the encrypted-profile design, opt-in: production
// exchanges the authorization code itself, with production's redirect_uri
// and a PKCE verifier the preview sealed into the state, and relays the
// profile and the provider's tokens to the preview sealed (AES-256-GCM,
// bound to the provider and the preview callback, valid MaxAge). The
// preview's own callback opens it and signs in as always (flow cookie and
// state checked first, single use with the state). Use it when only
// production can exchange a code (a client secret production alone holds).
//
// Risk, which is why it is off by default and Init logs WarnPassProfile at
// every start: a deployment that accepts a sealed profile trusts whoever
// holds the proxy secret to say who signed in. With the default relay, the
// secret lets someone relay codes but never assert an identity. Turn it on
// on every participating deployment; one without it refuses a state that
// asks production to exchange (invalid_state) and a relayed profile
// (invalid_code).
//
//ds:def id=oauthproxy-passprofile-p3r2mx8v owner=@khanakia stability=stable
func PassProfile() Option { return func(p *Plugin) { p.passProfile = true } }

// HTTPClient sets the client production exchanges codes with under
// PassProfile. Default: DefaultExchangeTimeout and no redirect followed,
// the oauth plugin's own rule for provider calls.
func HTTPClient(hc *http.Client) Option { return func(p *Plugin) { p.hc = hc } }

// DefaultExchangeTimeout bounds production's code exchange under
// PassProfile when HTTPClient is not given.
//
//ds:def id=oauthproxy-defaultexchangetimeout-p3r2tq5d owner=@khanakia stability=stable
const DefaultExchangeTimeout = 10 * time.Second

// errRedirect refuses a redirect from a token endpoint: a code exchange is
// one request, and following a redirect would resend the code elsewhere.
var errRedirect = errors.New("oauthproxy: the token endpoint answered with a redirect")

// refuseRedirect is the default client's CheckRedirect.
func refuseRedirect(*http.Request, []*http.Request) error { return errRedirect }

// ProductionCallback overrides how production's callback URL is found from
// the preview's: by default the preview callback's path on the production
// origin, which holds when every deployment mounts the routes alike.
func ProductionCallback(fn func(previewCallback string) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthproxy.ProductionCallback", fn) {
			return
		}
		p.callbackOf = fn
	}
}

// Compile-time proof of each capability.
var (
	_ auth.Validator       = (*Plugin)(nil)
	_ auth.Initializer     = (*Plugin)(nil)
	_ auth.Dependent       = (*Plugin)(nil)
	_ auth.OperationHooker = (*Plugin)(nil)
)

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{maxAge: DefaultMaxAge, now: time.Now, providers: map[string]*Proxied{}}
	for _, o := range opts {
		o(p)
	}
	if p.callbackOf == nil {
		p.callbackOf = p.sameOriginPath
	}
	if p.hc == nil {
		p.hc = &http.Client{Timeout: DefaultExchangeTimeout, CheckRedirect: refuseRedirect}
	}
	return p
}

// Name returns PluginName.
func (p *Plugin) Name() string { return PluginName }

// Requires names the oauth plugin, whose callback the plugin relays.
func (p *Plugin) Requires() []string { return []string{oauth.PluginName} }

// Validate refuses a configuration that cannot proxy.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.production == nil {
		return ErrNoProductionURL
	}
	if len(p.wrapped) == 0 {
		return ErrNotWrapped
	}
	if p.maxAge <= 0 {
		return errors.New("oauthproxy: MaxAge needs a positive duration")
	}
	var err error
	derive := c.DeriveKeys
	if len(p.secrets) > 0 {
		// The error names the option, because "secret 0 has 0 bytes" alone
		// does not say it is this plugin's secret rather than the app's.
		derive = func(label string) ([][]byte, error) {
			keys, err := auth.DeriveSecretKeys(label, p.secrets...)
			if err != nil {
				return nil, fmt.Errorf("oauthproxy.WithSecret: %w", err)
			}
			return keys, nil
		}
	}
	if p.stateKeys, err = derive(keyLabelState); err == nil {
		if p.codeKeys, err = derive(keyLabelCode); err == nil {
			p.profileKeys, err = derive(keyLabelProfile)
		}
	}
	if errors.Is(err, auth.ErrNoSecret) {
		return ErrNoSecret
	}
	return err
}

// Init captures the core handle and its clock.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	p.now = a.Now
	if p.passProfile {
		a.Logger().Warn(WarnPassProfile)
	}
	return nil
}

// OperationHooks adds the relay before the oauth callback of every wrapped
// provider.
func (p *Plugin) OperationHooks() []auth.OperationHook {
	match := make([]auth.EndpointID, 0, len(p.wrapped))
	for _, name := range p.wrapped {
		match = append(match, oauth.CallbackEndpoint(name))
	}
	return []auth.OperationHook{{Match: match, Before: p.relay}}
}

// statePackage is what a proxied state carries.
type statePackage struct {
	V        int    `json:"v"`
	Provider string `json:"p"`
	State    string `json:"s"`
	Callback string `json:"c"`
	IssuedAt int64  `json:"t"`
	// Verifier is the PKCE verifier production exchanges with, set only
	// under PassProfile.
	Verifier string `json:"x,omitempty"`
}

// profilePackage is what a relayed profile carries under PassProfile: the
// passthrough payload (user info, the provider's tokens and
// raw claims, all in oauth.Profile) with the provider and preview callback
// it is bound to and its issue time.
type profilePackage struct {
	V        int         `json:"v"`
	Provider string      `json:"p"`
	Profile  wireProfile `json:"f"`
	Callback string      `json:"c"`
	IssuedAt int64       `json:"t"`
}

// wireProfile is oauth.Profile as it is sealed. auth.Token marshals as
// "[redacted]" on purpose, so the tokens travel as plain strings inside the
// sealed package and become auth.Token again on the preview. TokenSet.Raw
// stays behind: it only feeds the provider's own profile read, which ran on
// production. TestWireProfile_CarriesEveryField fails when oauth.Profile or
// oauth.TokenSet gains a field this does not carry.
type wireProfile struct {
	Subject          string                     `json:"sub"`
	Email            string                     `json:"email,omitempty"`
	EmailVerified    bool                       `json:"ev,omitempty"`
	Name             string                     `json:"name,omitempty"`
	Image            string                     `json:"img,omitempty"`
	Claims           map[string]json.RawMessage `json:"claims,omitempty"`
	AccessToken      string                     `json:"at,omitempty"`
	RefreshToken     string                     `json:"rt,omitempty"`
	IDToken          string                     `json:"it,omitempty"`
	ExpiresAt        time.Time                  `json:"exp"`
	RefreshExpiresAt time.Time                  `json:"rexp"`
	RefreshParams    url.Values                 `json:"rp,omitempty"`
	Scope            string                     `json:"scope,omitempty"`
}

// toWire is the sealed form of prof.
func toWire(prof oauth.Profile) wireProfile {
	ts := prof.Tokens
	return wireProfile{Subject: prof.Subject, Email: prof.Email, EmailVerified: prof.EmailVerified, Name: prof.Name, Image: prof.Image,
		Claims: prof.Claims, AccessToken: ts.AccessToken.Reveal(), RefreshToken: ts.RefreshToken.Reveal(), IDToken: ts.IDToken.Reveal(),
		ExpiresAt: ts.ExpiresAt, RefreshExpiresAt: ts.RefreshExpiresAt, RefreshParams: ts.RefreshParams, Scope: ts.Scope}
}

// profile is the oauth.Profile w carries.
func (w wireProfile) profile() oauth.Profile {
	return oauth.Profile{Subject: w.Subject, Email: w.Email, EmailVerified: w.EmailVerified, Name: w.Name, Image: w.Image, Claims: w.Claims,
		Tokens: oauth.TokenSet{AccessToken: auth.Token(w.AccessToken), RefreshToken: auth.Token(w.RefreshToken), IDToken: auth.Token(w.IDToken),
			ExpiresAt: w.ExpiresAt, RefreshExpiresAt: w.RefreshExpiresAt, RefreshParams: w.RefreshParams, Scope: w.Scope}}
}

// profileAAD binds a sealed profile to its purpose, provider and callback.
func profileAAD(provider, callback string) string {
	return keyLabelProfile + "\n" + provider + "\n" + callback
}

// codePackage is what a relayed code carries.
type codePackage struct {
	V        int    `json:"v"`
	Provider string `json:"p"`
	Code     string `json:"k"`
	Callback string `json:"c"`
	IssuedAt int64  `json:"t"`
}

// errNoKey is a seal before Validate derived the keys.
var errNoKey = errors.New("oauthproxy: no key")

// seal encrypts v under keys[0] with aad, prefixed with sealedPrefix.
func seal(keys [][]byte, v any, aad string) (string, error) {
	return sealWith(keys, sealedPrefix, v, aad)
}

// sealWith is seal under another prefix.
func sealWith(keys [][]byte, prefix string, v any, aad string) (string, error) {
	if len(keys) == 0 {
		return "", errNoKey
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	s, err := auth.Seal(keys[0], b, aad)
	if err != nil {
		return "", err
	}
	// Seal's base64 alphabet has + and /, which a query keeps only escaped;
	// url.Values escapes them on the way out and unescapes them on the way in.
	return prefix + s, nil
}

// open reverses seal with any key, current first.
func open(keys [][]byte, sealed, aad string, v any) bool {
	return openWith(keys, sealedPrefix, sealed, aad, v)
}

// openWith is open for a value sealed under prefix.
func openWith(keys [][]byte, prefix, sealed, aad string, v any) bool {
	raw, ok := strings.CutPrefix(sealed, prefix)
	if !ok {
		return false
	}
	for _, k := range keys {
		if b, err := auth.Open(k, raw, aad); err == nil {
			return json.Unmarshal(b, v) == nil
		}
	}
	return false
}

// fresh reports whether an issue time is within maxAge, allowing clockSkew
// into the future.
func (p *Plugin) fresh(issued int64, maxAge time.Duration) bool {
	age := p.now().Sub(time.Unix(issued, 0))
	return age <= maxAge && age >= -clockSkew
}

// IsProduction reports whether a callback URL is on the production origin,
// where nothing is proxied.
func (p *Plugin) IsProduction(callback string) bool {
	u, err := url.Parse(callback)
	return err == nil && p.production != nil && strings.EqualFold(u.Scheme, p.production.Scheme) && strings.EqualFold(u.Host, p.production.Host)
}

// sameOriginPath is the default ProductionCallback: the preview callback's
// path and query on the production origin.
func (p *Plugin) sameOriginPath(previewCallback string) string {
	u, err := url.Parse(previewCallback)
	if err != nil {
		return previewCallback
	}
	u.Scheme, u.Host = p.production.Scheme, p.production.Host
	return u.String()
}

// relay is production's Before hook on a wrapped provider's callback: a
// state that is a proxy package is answered with a redirect to the preview
// carrying its own state and the sealed code; any other state is left to
// the oauth plugin.
func (p *Plugin) relay(ctx context.Context, c *auth.Call) error {
	in, ok := c.Input.(oauth.CallbackRequest)
	if !ok || !strings.HasPrefix(in.State, sealedPrefix) {
		return nil
	}
	var pkg statePackage
	if !open(p.stateKeys, in.State, keyLabelState, &pkg) || pkg.V != version || !p.fresh(pkg.IssuedAt, StateMaxAge) ||
		c.Op.ID != oauth.CallbackEndpoint(pkg.Provider) || !c.Auth.TrustsReturnURL(pkg.Callback) || !absolute(pkg.Callback) ||
		(pkg.Verifier != "" && !p.passProfile) {
		return ErrInvalidState
	}
	q := url.Values{"state": {pkg.State}}
	for k, v := range map[string]string{"error": in.Error, "error_description": in.ErrorDescription, "iss": in.Iss, "user": in.User, "device_id": in.DeviceID} {
		if v != "" {
			q.Set(k, v)
		}
	}
	switch {
	case in.Code != "" && pkg.Verifier != "":
		sealed, err := p.exchangeAndSeal(ctx, pkg, in.Code)
		if err != nil {
			return err
		}
		if sealed == "" {
			q.Set("error", RelayErrorInvalidCode)
		} else {
			q.Set("code", sealed)
		}
	case in.Code != "":
		code, err := seal(p.codeKeys, codePackage{V: version, Provider: pkg.Provider, Code: in.Code, Callback: pkg.Callback, IssuedAt: p.now().Unix()},
			keyLabelCode+"\n"+pkg.Provider+"\n"+pkg.Callback)
		if err != nil {
			return err
		}
		q.Set("code", code)
	}
	target := pkg.Callback + "?" + q.Encode()
	if strings.Contains(pkg.Callback, "?") {
		target = pkg.Callback + "&" + q.Encode()
	}
	c.Effects.Redirect(target)
	c.Respond(oauth.CallbackResult{RedirectTo: target})
	return nil
}

// absolute reports an absolute http(s) URL: a preview callback is always
// one, and a relative "trusted" path would send the browser back to
// production itself.
func absolute(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// exchangeAndSeal is production's PassProfile step: it exchanges the code
// with the provider (production's redirect_uri, the preview's sealed
// verifier) and seals the profile for the preview. A failed exchange is
// logged and answered "" (relayed as error=invalid_code);
// only a sealing failure is an error.
func (p *Plugin) exchangeAndSeal(ctx context.Context, pkg statePackage, code string) (string, error) {
	x := p.providers[pkg.Provider]
	prof, err := x.exchangeHere(ctx, p.hc, code, pkg.Verifier, p.callbackOf(pkg.Callback))
	if err != nil {
		p.core.Logger().Warn("oauthproxy: production exchange failed", "provider", pkg.Provider, "error", err)
		return "", nil
	}
	return sealWith(p.profileKeys, profilePrefix,
		profilePackage{V: version, Provider: pkg.Provider, Profile: toWire(prof), Callback: pkg.Callback, IssuedAt: p.now().Unix()},
		profileAAD(pkg.Provider, pkg.Callback))
}
