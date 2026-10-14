package oauthproxy

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// Proxied is a provider wrapped by Wrap. On the production origin it is the
// provider itself; elsewhere it sends the sign-in through production. It
// forwards the provider's optional capabilities (discovery, issuer check,
// request parameters, form posts, refresh, revoke, profile reads, logout);
// an ID-token sign-in and a provider-initiated flow are not proxied, so a
// wrapped provider does not offer them.
type Proxied struct {
	inner oauth.Provider
	p     *Plugin
}

// Wrap returns prov routed through production when the deployment is not
// production. Wrap every provider whose console lists only production's
// callback, on every deployment, before auth.New.
//
//ds:def id=oauthproxy-plugin-wrap-6q3vn8kw owner=@khanakia stability=stable
func (p *Plugin) Wrap(prov oauth.Provider) *Proxied {
	p.wrapped = append(p.wrapped, prov.Name())
	x := &Proxied{inner: prov, p: p}
	p.providers[prov.Name()] = x
	return x
}

// Compile-time proof of the forwarded capabilities.
var (
	_ oauth.Provider         = (*Proxied)(nil)
	_ oauth.Labeler          = (*Proxied)(nil)
	_ oauth.Discoverer       = (*Proxied)(nil)
	_ oauth.Loader           = (*Proxied)(nil)
	_ oauth.IssuerChecker    = (*Proxied)(nil)
	_ oauth.ParamsProvider   = (*Proxied)(nil)
	_ oauth.RequestAuthURLer = (*Proxied)(nil)
	_ oauth.PostedProfile    = (*Proxied)(nil)
	_ oauth.FormPoster       = (*Proxied)(nil)
	_ oauth.Refresher        = (*Proxied)(nil)
	_ oauth.Revoker          = (*Proxied)(nil)
	_ oauth.ProfileFetcher   = (*Proxied)(nil)
	_ oauth.Logouter         = (*Proxied)(nil)
)

// errNoRefresh is Refresh for a provider that cannot refresh.
var errNoRefresh = errors.New("oauthproxy: the provider has no refresh grant")

// Unwrap returns the wrapped provider.
func (x *Proxied) Unwrap() oauth.Provider { return x.inner }

// Name is the provider's name.
func (x *Proxied) Name() string { return x.inner.Name() }

// AuthCodeURL is the provider's URL; off production it carries production's
// callback and a sealed state naming this deployment's state and callback.
func (x *Proxied) AuthCodeURL(state, challenge, redirectURI string) string {
	return x.authURL(state, challenge, redirectURI, x.inner.AuthCodeURL)
}

// AuthCodeURLWithParams is AuthCodeURL with request parameters, when the
// provider takes them.
func (x *Proxied) AuthCodeURLWithParams(state, challenge, redirectURI string, rp oauth.RequestParams) string {
	pp, ok := x.inner.(oauth.ParamsProvider)
	if !ok {
		return x.AuthCodeURL(state, challenge, redirectURI)
	}
	return x.authURL(state, challenge, redirectURI, func(s, ch, r string) string { return pp.AuthCodeURLWithParams(s, ch, r, rp) })
}

// SkipHeader on the request that starts a sign-in turns proxying off for
// it, better-auth's x-skip-oauth-proxy: any non-empty value. For a preview
// whose callback the provider does list, or a test.
//
//ds:def id=oauthproxy-skipheader-7q4mn2xv owner=@khanakia stability=stable
const SkipHeader = "X-Skip-OAuth-Proxy"

// AuthCodeURLForRequest is the oauth plugin's start: AuthCodeURL (with the
// request's parameters when the provider takes them), unproxied when the
// request carries SkipHeader.
func (x *Proxied) AuthCodeURLForRequest(ctx context.Context, state, challenge, redirectURI string, rp oauth.RequestParams) string {
	params := rp.Prompt != "" || rp.LoginHint != "" || len(rp.Scopes) > 0
	if auth.RequestHeader(ctx, SkipHeader) != "" {
		if pp, ok := x.inner.(oauth.ParamsProvider); ok && params {
			return pp.AuthCodeURLWithParams(state, challenge, redirectURI, rp)
		}
		return x.inner.AuthCodeURL(state, challenge, redirectURI)
	}
	if params {
		return x.AuthCodeURLWithParams(state, challenge, redirectURI, rp)
	}
	return x.AuthCodeURL(state, challenge, redirectURI)
}

// authURL seals the state and swaps the callback off production. Under
// PassProfile the state also carries a fresh PKCE verifier for production's
// exchange, and the provider gets its challenge instead of the oauth
// plugin's, whose verifier never leaves this deployment. A sealing failure
// (no key, which Validate prevents) falls back to the plain URL, as
// better-auth continues without proxying, rather than an unusable link.
func (x *Proxied) authURL(state, challenge, redirectURI string, build func(state, challenge, redirectURI string) string) string {
	if x.p.IsProduction(redirectURI) {
		return build(state, challenge, redirectURI)
	}
	pkg := statePackage{V: version, Provider: x.inner.Name(), State: state, Callback: redirectURI, IssuedAt: x.p.now().Unix()}
	sent := challenge
	if x.p.passProfile {
		pkg.Verifier = auth.NewToken().Reveal()
		sent = oauth.PKCEChallenge(pkg.Verifier)
	}
	sealed, err := seal(x.p.stateKeys, pkg, keyLabelState)
	if err != nil {
		if x.p.core != nil {
			x.p.core.Logger().Warn("oauthproxy: sign-in not proxied", "provider", x.inner.Name(), "error", err)
		}
		return build(state, challenge, redirectURI)
	}
	return build(sealed, sent, x.p.callbackOf(redirectURI))
}

// Exchange trades the code; off production a sealed code is the one
// production relayed, opened and exchanged with production's callback.
func (x *Proxied) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (oauth.Profile, error) {
	if x.p.passProfile && !x.p.IsProduction(redirectURI) && (code == "" || strings.HasPrefix(code, profilePrefix)) {
		// A relayed profile. A start with SkipHeader still brings the
		// provider's own unsealed code, exchanged below.
		return x.openProfile(code, redirectURI)
	}
	if x.p.IsProduction(redirectURI) || !strings.HasPrefix(code, sealedPrefix) {
		// Production's own sign-in, or one started with SkipHeader: the
		// provider sent the code straight here, bound to this callback.
		return x.inner.Exchange(ctx, hc, code, verifier, redirectURI)
	}
	var pkg codePackage
	if !open(x.p.codeKeys, code, keyLabelCode+"\n"+x.inner.Name()+"\n"+redirectURI, &pkg) || pkg.V != version ||
		pkg.Provider != x.inner.Name() || pkg.Callback != redirectURI || !x.p.fresh(pkg.IssuedAt, x.p.maxAge) {
		return oauth.Profile{}, ErrInvalidCode
	}
	return x.inner.Exchange(ctx, hc, pkg.Code, verifier, x.p.callbackOf(redirectURI))
}

// Label is the provider's label, or "" (the oauth plugin then shows Name).
func (x *Proxied) Label() string {
	if l, ok := x.inner.(oauth.Labeler); ok {
		return l.Label()
	}
	return ""
}

// Discover runs the provider's discovery, if it has one.
func (x *Proxied) Discover(ctx context.Context, hc *http.Client) error {
	if d, ok := x.inner.(oauth.Discoverer); ok {
		return d.Discover(ctx, hc)
	}
	return nil
}

// Load runs the provider's loader, if it has one.
func (x *Proxied) Load(ctx context.Context, hc *http.Client) error {
	if l, ok := x.inner.(oauth.Loader); ok {
		return l.Load(ctx, hc)
	}
	return nil
}

// ExpectedIssuer is the provider's RFC 9207 issuer, or "" for none.
// Production relays iss, so the check runs on the preview unchanged.
func (x *Proxied) ExpectedIssuer() string {
	if ic, ok := x.inner.(oauth.IssuerChecker); ok {
		return ic.ExpectedIssuer()
	}
	return ""
}

// OptionalScopeList is the provider's optional scopes, or none.
func (x *Proxied) OptionalScopeList() []string {
	if pp, ok := x.inner.(oauth.ParamsProvider); ok {
		return pp.OptionalScopeList()
	}
	return nil
}

// ApplyPosted applies a form-post user field, if the provider reads one.
func (x *Proxied) ApplyPosted(raw string, prof *oauth.Profile) {
	if pp, ok := x.inner.(oauth.PostedProfile); ok {
		pp.ApplyPosted(raw, prof)
	}
}

// PostsBack reports whether the provider answers with a form post.
func (x *Proxied) PostsBack() bool {
	fp, ok := x.inner.(oauth.FormPoster)
	return ok && fp.PostsBack()
}

// Refresh refreshes with the provider, or fails for one that cannot.
func (x *Proxied) Refresh(ctx context.Context, hc *http.Client, rt auth.Token) (oauth.TokenSet, error) {
	if r, ok := x.inner.(oauth.Refresher); ok {
		return r.Refresh(ctx, hc, rt)
	}
	return oauth.TokenSet{}, errNoRefresh
}

// Revoke revokes at the provider, or does nothing for one with no endpoint.
func (x *Proxied) Revoke(ctx context.Context, hc *http.Client, ts oauth.TokenSet) error {
	if r, ok := x.inner.(oauth.Revoker); ok {
		return r.Revoke(ctx, hc, ts)
	}
	return nil
}

// FetchProfileWith reads the profile, or answers oauth.ErrProfileUnsupported.
func (x *Proxied) FetchProfileWith(ctx context.Context, hc *http.Client, ts oauth.TokenSet) (oauth.Profile, error) {
	if pf, ok := x.inner.(oauth.ProfileFetcher); ok {
		return pf.FetchProfileWith(ctx, hc, ts)
	}
	return oauth.Profile{}, oauth.ErrProfileUnsupported
}

// EndSession is the provider's logout URL, or "" for none.
func (x *Proxied) EndSession(ctx context.Context, hc *http.Client) (string, error) {
	if l, ok := x.inner.(oauth.Logouter); ok {
		return l.EndSession(ctx, hc)
	}
	return "", nil
}

// openProfile is the preview's exchange under PassProfile: the code is the
// profile production sealed for this provider and callback, accepted for
// MaxAge; a callback with no code is better-auth's missing_profile.
func (x *Proxied) openProfile(code, redirectURI string) (oauth.Profile, error) {
	if code == "" {
		return oauth.Profile{}, ErrMissingProfile
	}
	var pkg profilePackage
	if !openWith(x.p.profileKeys, profilePrefix, code, profileAAD(x.inner.Name(), redirectURI), &pkg) || pkg.V != version ||
		pkg.Provider != x.inner.Name() || pkg.Callback != redirectURI || !x.p.fresh(pkg.IssuedAt, x.p.maxAge) {
		return oauth.Profile{}, ErrInvalidCode
	}
	return pkg.Profile.profile(), nil
}

// exchangeHere is production's own exchange of a proxied code under
// PassProfile: discovery first, as the oauth plugin's start would have run
// it, then the provider's exchange.
func (x *Proxied) exchangeHere(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (oauth.Profile, error) {
	if err := x.Discover(ctx, hc); err != nil {
		return oauth.Profile{}, err
	}
	return x.inner.Exchange(ctx, hc, code, verifier, redirectURI)
}
