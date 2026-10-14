package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// minGeneratedLength is the shortest client id or secret a custom generator
// may return: 22 base64url characters are 128 bits.
const minGeneratedLength = 22

// ErrShortGenerated is a GenerateClientID or GenerateClientSecret function
// that returned fewer than 22 characters, or a client id shaped like a
// metadata document URL: a programming error, so registration fails.
var ErrShortGenerated = errors.New("oauthprovider: a generated client id or secret is at least 22 characters, and a client id is never an https URL")

// RedirectValidator decides a redirect URI at authorize, better-auth's
// validateRedirectUri: it gets the requested URI, the client's registered
// ones and the built-in exact-match result, and its answer replaces that
// result, both for issuing the code and for whether early errors may be
// sent to the URI. It relaxes RFC 9700's exact matching, so accept only
// hosts you control.
type RedirectValidator func(uri string, registered []string, defaultResult bool) bool

// AccessTokenClaimsInfo is what AccessTokenClaims receives.
type AccessTokenClaimsInfo struct {
	// User is the token's user; nil for a client_credentials token.
	User     *auth.User
	ClientID string
	Scopes   []string
	Resource string
	// ReferenceID is the post-login reference (PostLogin's
	// ConsentReferenceID), or "".
	ReferenceID string
}

// AccessTokenClaimsFunc adds claims to a JWT access token, better-auth's
// customAccessTokenClaims. A registered or provider claim it returns is
// ignored.
type AccessTokenClaimsFunc func(ctx context.Context, info AccessTokenClaimsInfo) map[string]any

// RequestURIResolverFunc returns the stored parameters of a pushed
// authorization request (RFC 9126), better-auth's requestUriResolver; nil
// values mean the request_uri is unknown or expired.
type RequestURIResolverFunc func(ctx context.Context, requestURI, clientID string) (url.Values, error)

// RequestURIResolver accepts request_uri at authorize: every parameter
// comes from the stored request, except client_id, which the authorization
// URL carries. Without it, request_uri is request_uri_not_supported.
func RequestURIResolver(fn RequestURIResolverFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.RequestURIResolver", fn) {
			return
		}
		p.requestURIResolver = fn
	}
}

// RegistrationRequirePKCE(false) lets confidential clients created by
// dynamic registration omit PKCE, better-auth's
// clientRegistrationRequirePKCE (default true). Public clients always need
// it.
func RegistrationRequirePKCE(on bool) Option { return func(p *Plugin) { p.dcrOptionalPKCE = !on } }

// RegistrationSecretExpiration gives secrets of dynamically registered
// confidential clients a lifetime, better-auth's
// clientRegistrationClientSecretExpiration; 0 (the default) never expires.
func RegistrationSecretExpiration(d time.Duration) Option {
	return func(p *Plugin) { p.dcrSecretTTL = d }
}

// RegistrationSecretExpiresAt ends the secrets of dynamically registered
// confidential clients at one instant, better-auth's
// clientRegistrationClientSecretExpiration given a Date; a time already
// past on the app's clock (auth.WithClock) is refused at auth.New
// (ErrBadTTL). With RegistrationSecretExpiration
// too, the earlier end wins.
func RegistrationSecretExpiresAt(t time.Time) Option {
	return func(p *Plugin) { p.dcrSecretAt = t }
}

// RegistrationDefaultScopes are the scopes a dynamically registered client
// gets when its registration names none, better-auth's
// clientRegistrationDefaultScopes; nil gives it every scope (Scopes).
func RegistrationDefaultScopes(scopes ...string) Option {
	return func(p *Plugin) { p.dcrDefaultScopes = scopes }
}

// RegistrationAllowedScopes widens what a registration may ask for beyond
// RegistrationDefaultScopes, better-auth's clientRegistrationAllowedScopes:
// a registration naming a scope outside both lists is invalid_scope. With
// neither option, any scope the provider supports may be registered.
func RegistrationAllowedScopes(scopes ...string) Option {
	return func(p *Plugin) { p.dcrAllowedScopes = scopes }
}

// registrationScopes applies the registration scope policy to a dynamic
// registration: the default scopes for none, and a requested set within
// defaults and allowed.
func (p *Plugin) registrationScopes(requested string) (string, error) {
	if p.dcrDefaultScopes == nil && p.dcrAllowedScopes == nil {
		return requested, nil
	}
	defaults := p.dcrDefaultScopes
	if defaults == nil {
		defaults = p.scopes
	}
	if strings.TrimSpace(requested) == "" {
		return strings.Join(defaults, listSeparator), nil
	}
	for _, s := range strings.Fields(requested) {
		if !slices.Contains(defaults, s) && !slices.Contains(p.dcrAllowedScopes, s) {
			return "", ErrInvalidScope
		}
	}
	return requested, nil
}

// TokenFieldsInfo is what TokenResponseFields receives.
type TokenFieldsInfo struct {
	GrantType string
	ClientID  string
	Scopes    []string
	// UserID is "" for a client's own token.
	UserID string
}

// TokenResponseFields adds members to the token response envelope (not to
// the token), better-auth's customTokenResponseFields; the standard members
// cannot be replaced, and an error from fn fails the request.
func TokenResponseFields(fn func(ctx context.Context, info TokenFieldsInfo) (map[string]any, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.TokenResponseFields", fn) {
			return
		}
		p.responseFields = fn
	}
}

// InitialAccessTokenFunc validates an RFC 7591 initial access token sent
// as a Bearer token to the registration endpoint, better-auth's
// validateInitialAccessToken: ok admits the registration (even when open
// registration is off), and referenceID becomes the client's ReferenceID.
type InitialAccessTokenFunc func(ctx context.Context, token string) (referenceID string, ok bool)

// ValidateInitialAccessToken installs an InitialAccessTokenFunc. Without
// one, a registration that presents a token is refused (invalid_token)
// rather than falling through to open registration.
func ValidateInitialAccessToken(fn InitialAccessTokenFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.ValidateInitialAccessToken", fn) {
			return
		}
		p.initialToken = fn
	}
}

// SignupPage is where prompt=create sends the browser, with the authorize
// parameters, better-auth's signup.page. Without it, prompt=create goes to
// LoginPage.
func SignupPage(u string) Option { return func(p *Plugin) { p.signupPage = u } }

// M2MAccessTokenTTL is the lifetime of a client_credentials access token,
// better-auth's m2mAccessTokenExpiresIn; 0 takes AccessTokenTTL.
func M2MAccessTokenTTL(d time.Duration) Option { return func(p *Plugin) { p.m2mTTL = d } }

// ScopeExpirations gives scopes shorter access-token lifetimes,
// better-auth's scopeExpirations: a token carrying several gets the
// earliest. A value longer than the default changes nothing.
func ScopeExpirations(ttls map[string]time.Duration) Option {
	return func(p *Plugin) { p.scopeTTLs = ttls }
}

// ValidateRedirectURI installs a RedirectValidator.
func ValidateRedirectURI(fn RedirectValidator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.ValidateRedirectURI", fn) {
			return
		}
		p.redirectValidator = fn
	}
}

// AccessTokenClaims installs an AccessTokenClaimsFunc.
func AccessTokenClaims(fn AccessTokenClaimsFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.AccessTokenClaims", fn) {
			return
		}
		p.accessClaims = fn
	}
}

// AdvertisedScopes replaces scopes_supported in discovery with a subset of
// Scopes, better-auth's advertisedMetadata.scopes_supported; the provider
// still serves every scope.
func AdvertisedScopes(scopes ...string) Option {
	return func(p *Plugin) { p.advertisedScopes = scopes }
}

// AdvertisedClaims replaces claims_supported in discovery,
// better-auth's advertisedMetadata.claims_supported.
func AdvertisedClaims(claims ...string) Option {
	return func(p *Plugin) { p.advertisedClaims = claims }
}

// GenerateClientID replaces the client id generator, better-auth's
// generateClientId. It must return at least 22 characters and never an
// https URL (ErrShortGenerated otherwise, at registration).
func GenerateClientID(fn func() string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.GenerateClientID", fn) {
			return
		}
		p.genClientID = fn
	}
}

// GenerateClientSecret replaces the random part of a client secret (after
// the ubos_ prefix), better-auth's generateClientSecret; at least 22
// characters from a cryptographic source.
func GenerateClientSecret(fn func() string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.GenerateClientSecret", fn) {
			return
		}
		p.genSecret = fn
	}
}

// validateOptions checks the options of this file for Validate.
func (p *Plugin) validateOptions() error {
	if p.refreshFormat != nil && (p.refreshFormat.Encode == nil || p.refreshFormat.Decode == nil) {
		return errors.New("oauthprovider: FormatRefreshToken needs Encode and Decode")
	}
	// Each refusal names the option that set the value, so the error says
	// which setting to fix; ErrBadScopes and ErrBadTTL stay the sentinels.
	for _, set := range []struct {
		option string
		scopes []string
	}{
		{"oauthprovider.AdvertisedScopes", p.advertisedScopes},
		{"oauthprovider.RegistrationDefaultScopes", p.dcrDefaultScopes},
		{"oauthprovider.RegistrationAllowedScopes", p.dcrAllowedScopes},
	} {
		for _, s := range set.scopes {
			if !slices.Contains(p.scopes, s) {
				return fmt.Errorf("%w: %s: %q is not in Scopes", ErrBadScopes, set.option, s)
			}
		}
	}
	for s, d := range p.scopeTTLs {
		if d <= 0 || !slices.Contains(p.scopes, s) {
			return fmt.Errorf("%w: oauthprovider.ScopeExpirations: scope %q lifetime %v", ErrBadTTL, s, d)
		}
	}
	if p.m2mTTL < 0 {
		return fmt.Errorf("%w: oauthprovider.M2MAccessTokenTTL(%v) is negative", ErrBadTTL, p.m2mTTL)
	}
	return nil
}

// newClientID is a generated client id: the custom generator's, checked,
// or the default.
func (p *Plugin) newClientID() (string, error) {
	if p.genClientID == nil {
		return p.core.NewID(clientIDPrefix)
	}
	id := p.genClientID()
	if len(id) < minGeneratedLength || isCIMDCandidate(id) || strings.ContainsAny(id, " \t\n") {
		return "", ErrShortGenerated
	}
	return id, nil
}

// newClientSecret is a client secret: the prefix and a random part.
func (p *Plugin) newClientSecret() (string, error) {
	if p.genSecret == nil {
		return PrefixClientSecret + auth.NewToken().Reveal(), nil
	}
	r := p.genSecret()
	if len(r) < minGeneratedLength {
		return "", ErrShortGenerated
	}
	return PrefixClientSecret + r, nil
}

// refreshTTLFor is the refresh-token lifetime: the provider's, or the
// resource's when shorter.
func (p *Plugin) refreshTTLFor(is issuance) time.Duration {
	ttl := p.refreshTTL
	if r := is.policy.RefreshTTL; r != nil && *r > 0 && time.Duration(*r)*time.Second < ttl {
		ttl = time.Duration(*r) * time.Second
	}
	return ttl
}

// accessTTLFor is an issuance's access-token lifetime: the M2M one for a
// client's own token, then the earliest of its scopes' expirations.
func (p *Plugin) accessTTLFor(is issuance) time.Duration {
	ttl := p.accessTTL
	if is.userID == "" && p.m2mTTL > 0 {
		ttl = p.m2mTTL
	}
	for _, s := range is.scopes {
		if d, ok := p.scopeTTLs[s]; ok && d < ttl {
			ttl = d
		}
	}
	if r := is.policy.AccessTTL; r != nil && *r > 0 && time.Duration(*r)*time.Second < ttl {
		ttl = time.Duration(*r) * time.Second
	}
	return ttl
}

// RefreshTokenFormat encodes refresh tokens on the wire, better-auth's
// formatRefreshToken (a JWE carrying the session id, say). Encode receives
// the random token and the session id, Decode answers the random token
// back; PrefixRefreshToken goes before the encoding, and the stored hash is
// always the random token's, so a format can be added or changed without
// touching stored rows, and a token Decode refuses is simply unknown.
type RefreshTokenFormat struct {
	Encode func(ctx context.Context, token, sessionID string) (string, error)
	Decode func(ctx context.Context, encoded string) (string, error)
}

// FormatRefreshToken installs a RefreshTokenFormat; both functions are
// required.
func FormatRefreshToken(f RefreshTokenFormat) Option {
	return func(p *Plugin) { p.refreshFormat = &f }
}

// encodeRefresh is the wire form of a random refresh token.
func (p *Plugin) encodeRefresh(ctx context.Context, raw, sessionID string) (string, error) {
	if p.refreshFormat == nil {
		return PrefixRefreshToken + raw, nil
	}
	enc, err := p.refreshFormat.Encode(ctx, raw, sessionID)
	if err != nil {
		return "", err
	}
	return PrefixRefreshToken + enc, nil
}

// refreshHash is the stored hash of a presented refresh token; false when
// it lacks the prefix or the format cannot decode it.
func (p *Plugin) refreshHash(ctx context.Context, presented string) ([]byte, bool) {
	rest, ok := strings.CutPrefix(presented, PrefixRefreshToken)
	if !ok || rest == "" {
		return nil, false
	}
	if p.refreshFormat != nil {
		raw, err := p.refreshFormat.Decode(ctx, rest)
		if err != nil || raw == "" {
			return nil, false
		}
		rest = raw
	}
	return p.hashSecret(SecretRefresh, PrefixRefreshToken+rest), true
}
