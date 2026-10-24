package oauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/ubgo/auth"
)

// InitiatedExchanger is a Provider that can complete a sign-in the provider
// started (AllowProviderInitiated): a code that arrives with no state and no
// PKCE verifier, trusted only through the verified ID token of its token
// response. *OAuth2 (with an IDToken key set) and *OIDCProvider implement it.
//
//ds:def id=initiatedexchanger-v6kq2wnt owner=@khanakia stability=stable
type InitiatedExchanger interface {
	Provider
	// ExchangeInitiated trades code for the person's profile without a
	// verifier. The token response must carry an ID token whose signature,
	// issuer, audience and lifetime verify and which carries no nonce, and
	// the profile's subject must be the token's.
	ExchangeInitiated(ctx context.Context, hc *http.Client, code, redirectURI string) (Profile, error)
}

// ErrProviderInitiatedConfig is a configuration error: AllowProviderInitiated
// or RestartProviderInitiated names a provider that is not configured, both
// name the same one, or AllowProviderInitiated names one that cannot verify
// an ID token (an *OAuth2 without IDToken, or a custom Provider that is not
// an InitiatedExchanger). Without a verified ID token nothing would vouch for
// a code no request of this app asked for.
var ErrProviderInitiatedConfig = errors.New("oauth: AllowProviderInitiated needs a configured provider that verifies ID tokens (an OIDC provider, or OAuth2 with IDToken)")

// claimSub is the OpenID Connect subject claim, compared between the ID
// token and the profile on a provider-initiated sign-in.
const claimSub = "sub"

// validateInitiated checks every provider AllowProviderInitiated and
// RestartProviderInitiated name: configured, not in both, and for the first,
// able to verify an ID token.
func (p *Plugin) validateInitiated() error {
	for _, name := range p.restart {
		if !slices.ContainsFunc(p.providers, func(prov Provider) bool { return prov.Name() == name }) {
			return fmt.Errorf("%w: RestartProviderInitiated: %q is not configured", ErrProviderInitiatedConfig, name)
		}
		if slices.Contains(p.initiated, name) {
			return fmt.Errorf("%w: %q is named by both AllowProviderInitiated and RestartProviderInitiated", ErrProviderInitiatedConfig, name)
		}
	}
	for _, name := range p.initiated {
		idx := slices.IndexFunc(p.providers, func(prov Provider) bool { return prov.Name() == name })
		if idx < 0 {
			return fmt.Errorf("%w: AllowProviderInitiated: %q is not configured", ErrProviderInitiatedConfig, name)
		}
		prov := p.providers[idx]
		_, ok := prov.(InitiatedExchanger)
		if o, plain := prov.(*OAuth2); plain && !o.IDToken.Enabled() {
			ok = false
		}
		if !ok {
			return fmt.Errorf("%w: AllowProviderInitiated: provider %q", ErrProviderInitiatedConfig, name)
		}
	}
	return nil
}

// ExchangeInitiated implements InitiatedExchanger: the code is exchanged
// with no verifier, the ID token verified with no nonce allowed, and the
// profile read as Exchange reads it, whose subject must be the token's.
func (o *OAuth2) ExchangeInitiated(ctx context.Context, hc *http.Client, code, redirectURI string) (Profile, error) {
	if !o.IDToken.Enabled() {
		return Profile{}, fmt.Errorf("%w: provider %q", ErrIDTokenUnsupported, o.ID)
	}
	ts, err := o.exchangeCode(ctx, hc, code, "", redirectURI)
	if err != nil {
		return Profile{}, err
	}
	claims, err := o.idTokens().verifyInitiated(ctx, hc, ts.IDToken.Reveal())
	if err != nil {
		return Profile{}, fmt.Errorf("%w: id_token: %v", ErrExchange, err)
	}
	if o.IDToken.ProfileFromToken {
		return withTokens(profileFromClaims(claims), ts)
	}
	p, err := o.profileFromTokens(ctx, hc, ts)
	if err != nil {
		return Profile{}, err
	}
	if sub := subjectOf(p); sub != claims.Subject {
		return Profile{}, fmt.Errorf("%w: profile subject %q is not the ID token's %q", ErrExchange, sub, claims.Subject)
	}
	return withTokens(p, ts)
}

// subjectOf is the sub a profile was read for: its sub claim when the
// profile kept its claims (a SubjectClaim may have made Subject another
// claim), else Subject.
func subjectOf(p Profile) string {
	if raw, ok := p.Claims[claimSub]; ok {
		return stringClaim(raw)
	}
	return p.Subject
}

// ExchangeInitiated discovers the issuer and exchanges through its
// endpoints; an issuer whose document has no jwks_uri cannot verify the ID
// token and fails.
func (o *OIDCProvider) ExchangeInitiated(ctx context.Context, hc *http.Client, code, redirectURI string) (Profile, error) {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return Profile{}, err
	}
	return c.ExchangeInitiated(ctx, hc, code, redirectURI)
}

// doInitiated completes a provider-initiated sign-in. The issuer is
// discovered first, so an RFC 9207 iss the issuer announces is checked here
// as on every callback. The resolution never links: a linked subject signs
// its user in, an unknown one creates a user (subject to NoSignUp,
// ExplicitSignUp, RequireVerifiedEmail and the hooks), and a matching
// address is ErrAccountExists. A browser already signed in is signed out
// first, after the person is known, so a refused sign-in leaves it as it
// was. It lands on the site root.
func (p *Plugin) doInitiated(ctx context.Context, c *auth.Call, prov InitiatedExchanger, in CallbackRequest) (CallbackResult, error) {
	if d, ok := prov.(Discoverer); ok {
		if err := d.Discover(ctx, p.hc); err != nil {
			c.Auth.Logger().Warn("oauth: discovery failed", "provider", prov.Name(), "error", err)
			return CallbackResult{}, ErrProviderFailed
		}
	}
	if ic, ok := prov.(IssuerChecker); ok {
		if want := ic.ExpectedIssuer(); want != "" && in.Iss != want {
			return CallbackResult{}, ErrStateInvalid
		}
	}
	profile, err := prov.ExchangeInitiated(ctx, p.hc, in.Code, p.callback(prov.Name()))
	if err != nil {
		c.Auth.Logger().Warn("oauth: provider-initiated exchange failed", "provider", prov.Name(), "error", err)
		return CallbackResult{}, ErrProviderFailed
	}
	out, err := p.resolveTx(ctx, c, prov.Name(), profile, flowMeta{initiated: true})
	if err != nil {
		return CallbackResult{}, err
	}
	if c.User != nil {
		if err := c.Auth.SignOut(ctx); err != nil {
			return CallbackResult{}, err
		}
	}
	if held, err := p.hold(ctx, c, &out, cmp.Or(p.errorURL, c.Auth.Config().ErrorURL, siteRoot)); held || err != nil {
		return out, err
	}
	sess, tok, err := c.Auth.CreateSession(ctx, out.User.ID, c.Client)
	if err != nil {
		return CallbackResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	c.Effects.Redirect(siteRoot)
	out.Token, out.RedirectTo, out.SecondFactorRequired = tok, siteRoot, sess.SecondFactorPending
	return out, nil
}

// doRestart answers a provider-initiated callback under
// RestartProviderInitiated: the code is dropped unread and an ordinary start
// runs in its place, landing on the site root, so the sign-in that follows
// carries a state bound to this browser like any other.
func (p *Plugin) doRestart(ctx context.Context, c *auth.Call, prov Provider) (CallbackResult, error) {
	res, err := p.doStart(ctx, c, prov, StartRequest{ReturnTo: siteRoot})
	if err != nil {
		return CallbackResult{}, err
	}
	return CallbackResult{RedirectTo: res.URL}, nil
}
