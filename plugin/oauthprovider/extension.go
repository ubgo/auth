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

// ExtensionGrant serves one extension grant_type at the token endpoint;
// the device authorization grant (RFC 8628) is one. The provider authenticates
// the client and checks it registered the grant type before calling Handle;
// Handle decides who the tokens are for, and the provider issues them through
// the same path as every other grant (refresh and ID token rules unchanged).
type ExtensionGrant struct {
	// Type is the grant_type, an absolute URI such as
	// "urn:ietf:params:oauth:grant-type:device_code".
	Type string
	// Handle validates the request and answers who the tokens are for. Its
	// errors reach the client: see ErrorNamespace.
	Handle func(ctx context.Context, client Client, in TokenRequest) (GrantDecision, error)
	// ErrorNamespace, when set, makes an *auth.Error whose code is
	// "<namespace>.<rest>" answer error "<rest>" on the wire, so a plugin's
	// own codes (device.authorization_pending) keep their RFC names.
	ErrorNamespace string
}

// GrantDecision is what an extension grant decided.
type GrantDecision struct {
	// UserID is who the tokens act for; "" is the client itself, as in
	// client_credentials (no refresh token, no ID token, no user scope).
	UserID string
	// SessionID is recorded on the token row; optional.
	SessionID string
	// Scopes are the granted scopes; each must be allowed for the client
	// (and the resource), or the request is invalid_scope.
	Scopes []string
	// Resource is the RFC 8707 resource, or "".
	Resource string
	// AuthTime is when the user authenticated, for the ID token.
	AuthTime *time.Time
	// AccessTokenClaims are this issuance's JWT access token claims: over
	// the extensions', under AccessTokenClaims and the resource's.
	AccessTokenClaims map[string]any
	// IDTokenClaims are added to the ID token, never replacing a claim.
	IDTokenClaims map[string]any
}

// ErrBadExtensionGrant is a WithGrant whose type is not an absolute URI,
// is a built-in grant, is registered twice, or has no handler.
var ErrBadExtensionGrant = errors.New("oauthprovider: an extension grant needs an absolute-URI type that is not built in, registered once, with a handler")

// extensionFamilyPrefix starts the token family of an extension grant.
const extensionFamilyPrefix = "oaf"

// WithGrant registers an extension grant and adds its type to the grant
// types the provider serves and advertises.
func WithGrant(g ExtensionGrant) Option {
	return func(p *Plugin) {
		p.extensions = append(p.extensions, g)
		p.extensionFrom = append(p.extensionFrom, "oauthprovider.WithGrant")
	}
}

// DeviceAuthorizationEndpoint advertises the RFC 8628 device authorization
// endpoint in discovery; the module serving it passes its URL.
func DeviceAuthorizationEndpoint(u string) Option {
	return func(p *Plugin) { p.deviceEndpoint = u }
}

// validateExtensions checks the extension grants for Validate.
func (p *Plugin) validateExtensions() error {
	seen := map[string]bool{}
	for i, g := range p.extensions {
		u, err := url.Parse(g.Type)
		if err != nil || u.Scheme == "" || g.Handle == nil || slices.Contains(DefaultGrantTypes, g.Type) || seen[g.Type] {
			return fmt.Errorf("%w: %s: %q", ErrBadExtensionGrant, p.extensionFrom[i], g.Type)
		}
		seen[g.Type] = true
	}
	if err := p.validateExt(); err != nil {
		return err
	}
	if p.deviceEndpoint != "" && !validWebURL(p.deviceEndpoint) {
		return fmt.Errorf("oauthprovider: DeviceAuthorizationEndpoint %q is not an absolute http(s) URL", p.deviceEndpoint)
	}
	return nil
}

// extension returns the extension grant of a type.
func (p *Plugin) extension(grantType string) (ExtensionGrant, bool) {
	for _, g := range p.extensions {
		if g.Type == grantType {
			return g, true
		}
	}
	return ExtensionGrant{}, false
}

// servedGrants is every grant type the provider serves: the built-in ones
// configured, then the extensions.
func (p *Plugin) servedGrants() []string {
	out := slices.Clone(p.grantTypes)
	for _, g := range p.extensions {
		out = append(out, g.Type)
	}
	return out
}

// extensionGrant runs an extension grant for an authenticated client.
func (p *Plugin) extensionGrant(ctx context.Context, g ExtensionGrant, client clientRow, in TokenRequest) (TokenResponse, error) {
	d, err := g.Handle(ctx, client.client(), in)
	if err != nil {
		return TokenResponse{}, err
	}
	scopes, err := p.CheckScopes(ctx, client.client(), dedupe(d.Scopes), d.Resource)
	if err != nil {
		return TokenResponse{}, err
	}
	if d.UserID == "" {
		for _, s := range scopes {
			if slices.Contains(userScopes, s) {
				return TokenResponse{}, ErrInvalidScope
			}
		}
	} else if err := p.userExists(ctx, d.UserID); err != nil {
		return TokenResponse{}, err
	}
	family, err := p.core.NewID(extensionFamilyPrefix)
	if err != nil {
		return TokenResponse{}, err
	}
	return p.issue(ctx, issuance{grantType: g.Type, client: client, userID: d.UserID, sessionID: d.SessionID, scopes: scopes, family: family, authTime: d.AuthTime, resource: d.Resource, accessClaims: d.AccessTokenClaims, idClaims: d.IDTokenClaims})
}

// AuthenticateClient checks a client's credentials as the token endpoint
// does, for a module that serves an endpoint of its own (a device
// authorization endpoint). audience is the absolute URL a private_key_jwt
// assertion must name (that endpoint's URL; the issuer is accepted too).
// Every failure is ErrInvalidClient.
func (p *Plugin) AuthenticateClient(ctx context.Context, cred ClientCredentials, audience string) (Client, error) {
	r, err := p.authenticateClient(ctx, cred, audience)
	if err != nil {
		return Client{}, err
	}
	return r.client(), nil
}

// CheckScopes decides the scopes a client may be granted for resource
// ("" for none), for a module that issues through WithGrant: ErrInvalidScope
// for a scope the provider or the client does not allow; for a resource,
// ErrInvalidTarget when it is unknown, disabled or (EnforcePerClientResources)
// not linked to the client, and the scopes narrowed to its allowlist
// (ErrInvalidScope when none is left). It answers the effective scopes.
func (p *Plugin) CheckScopes(ctx context.Context, client Client, scopes []string, resource string) ([]string, error) {
	if len(scopes) == 0 || !p.scopesAllowed(client, scopes) {
		return nil, ErrInvalidScope
	}
	effective, _, err := p.resourcePolicy(ctx, resource, client.ClientID, scopes)
	return effective, err
}

// extensionCode is the wire code of an extension grant's error, or "".
func (p *Plugin) extensionCode(err error) string {
	code := auth.ErrorOf(err).Code
	for _, g := range p.extensions {
		if g.ErrorNamespace != "" && strings.HasPrefix(code, g.ErrorNamespace+".") {
			return strings.TrimPrefix(code, g.ErrorNamespace+".")
		}
	}
	return ""
}
