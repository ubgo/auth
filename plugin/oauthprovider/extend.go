package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// Extension is one module's additions to the provider: extension grants,
// discovery fields, claims, client authentication methods and client discovery.
// Extend installs a list of them. Everything an extension adds is additive: it
// never replaces what the provider or the app set, and between two extensions
// the first wins.
type Extension struct {
	// ID names the extension in errors and logs; unique and not empty.
	ID string
	// Grants are extension grants, as WithGrant registers them.
	Grants []ExtensionGrant
	// Metadata adds members to the discovery document; a member the
	// provider sets (or an earlier extension added) is kept.
	Metadata map[string]any
	// Claims adds claims to the tokens and userinfo.
	Claims ExtensionClaims
	// ClientAuthentication adds token endpoint authentication methods.
	ClientAuthentication []ClientAuthMethod
	// ClientDiscovery resolves client_ids the provider has not stored.
	ClientDiscovery []ClientDiscoverer
}

// ExtensionClaims are an extension's claims. Each is additive: a claim the
// provider, the app's own options, or an earlier extension set is kept,
// and the reserved claims (iss, sub, aud, exp, cnf and the rest) are never
// taken from it.
type ExtensionClaims struct {
	// AccessToken adds claims to JWT access tokens; the per-issuance
	// GrantDecision.AccessTokenClaims, AccessTokenClaims and a resource's
	// CustomClaims override them, in that order.
	AccessToken func(ctx context.Context, info AccessTokenClaimsInfo) map[string]any
	// IDToken adds claims to ID tokens; a claim a granted scope releases
	// (email, name) is never taken from it.
	IDToken func(ctx context.Context, info ClaimsInfo) map[string]any
	// UserInfo adds claims to the userinfo response, the same way.
	UserInfo func(ctx context.Context, info ClaimsInfo) map[string]any
}

// ClaimsInfo is what an extension's ID token and userinfo claims are
// decided from.
type ClaimsInfo struct {
	User     auth.User
	ClientID string
	Scopes   []string
}

// ClientAuthMethod is a token endpoint authentication method an extension
// serves: mutual TLS (RFC 8705), an attestation, a client assertion of another
// type.
type ClientAuthMethod struct {
	// Method is the token_endpoint_auth_method name clients register; it
	// may not be a built-in one.
	Method string
	// AssertionTypes are the client_assertion_type URIs (absolute) whose
	// assertion this method consumes; RFC 7523's jwt-bearer stays the
	// provider's. None means the method takes the client_id alone, plus
	// what Authenticate reads from the credentials (a TLS certificate).
	AssertionTypes []string
	// Authenticate decides whether the credentials prove the client. A
	// Confirmation binds the tokens issued to it (cnf); nil binds nothing.
	// Any error is invalid_client.
	Authenticate func(ctx context.Context, client Client, cred ClientCredentials) (*Confirmation, error)
}

// ClientDiscoverer resolves a client_id that is not registered (CIMD is
// one): the client is stored the first time, with its discovery kind, and
// resolved again after Refresh.
type ClientDiscoverer struct {
	// ID is the discovery kind stored on the client; unique, not "cimd".
	ID string
	// Matches reports whether a client_id is this discovery's.
	Matches func(clientID string) bool
	// Resolve answers the client's metadata, checked as a registration is.
	// An error leaves the client unknown (and is logged).
	Resolve func(ctx context.Context, clientID string) (ClientMetadata, error)
	// Refresh is how long a resolved client is used before it is resolved
	// again; 0 resolves it once.
	Refresh time.Duration
}

// ErrBadExtension is an Extension Validate refuses.
var ErrBadExtension = errors.New("oauthprovider: invalid extension")

// Extend installs extensions.
func Extend(exts ...Extension) Option {
	return func(p *Plugin) {
		for _, e := range exts {
			p.exts = append(p.exts, e)
			p.extensions = append(p.extensions, e.Grants...)
			for range e.Grants {
				p.extensionFrom = append(p.extensionFrom, "oauthprovider.Extend")
			}
		}
	}
}

// validateExt checks the extensions for Validate.
func (p *Plugin) validateExt() error {
	ids, methods, types, kinds := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{discoveryCIMD: true}
	for _, e := range p.exts {
		if e.ID == "" || ids[e.ID] {
			return fmt.Errorf("%w: oauthprovider.Extend: id %q is empty or repeated", ErrBadExtension, e.ID)
		}
		ids[e.ID] = true
		for _, m := range e.ClientAuthentication {
			if m.Method == "" || slices.Contains(AuthMethodValues, m.Method) || methods[m.Method] || m.Authenticate == nil {
				return fmt.Errorf("%w: oauthprovider.Extend: %s: client authentication method %q is empty, built in, repeated, or has no Authenticate", ErrBadExtension, e.ID, m.Method)
			}
			methods[m.Method] = true
			for _, t := range m.AssertionTypes {
				u, err := url.Parse(t)
				if err != nil || u.Scheme == "" || t == ClientAssertionType || types[t] {
					return fmt.Errorf("%w: oauthprovider.Extend: %s: assertion type %q is not an absolute URI, is jwt-bearer, or is repeated", ErrBadExtension, e.ID, t)
				}
				types[t] = true
			}
		}
		for _, d := range e.ClientDiscovery {
			if d.ID == "" || kinds[d.ID] || d.Matches == nil || d.Resolve == nil || d.Refresh < 0 {
				return fmt.Errorf("%w: oauthprovider.Extend: %s: client discovery %q is empty, repeated, or incomplete", ErrBadExtension, e.ID, d.ID)
			}
			kinds[d.ID] = true
		}
	}
	return nil
}

// authMethod is the extension method of a name.
func (p *Plugin) authMethod(name string) (ClientAuthMethod, bool) {
	for _, e := range p.exts {
		for _, m := range e.ClientAuthentication {
			if m.Method == name {
				return m, true
			}
		}
	}
	return ClientAuthMethod{}, false
}

// isExtensionMethod reports whether a method name is an extension's.
func (p *Plugin) isExtensionMethod(name string) bool {
	_, ok := p.authMethod(name)
	return ok
}

// authMethodForAssertion is the extension method consuming an assertion
// type.
func (p *Plugin) authMethodForAssertion(assertionType string) (ClientAuthMethod, bool) {
	for _, e := range p.exts {
		for _, m := range e.ClientAuthentication {
			if slices.Contains(m.AssertionTypes, assertionType) {
				return m, true
			}
		}
	}
	return ClientAuthMethod{}, false
}

// authMethods is every token endpoint authentication method: the built-in
// ones, then the extensions'.
func (p *Plugin) authMethods() []string {
	out := slices.Clone(AuthMethodValues)
	for _, e := range p.exts {
		for _, m := range e.ClientAuthentication {
			out = append(out, m.Method)
		}
	}
	return out
}

// authenticateExtension runs an extension method for a client registered
// with it. The secret and the method of the request must fit: no secret,
// and the method's own name (an assertion of its type) or, for a method
// without assertion types, the client_id alone.
func (p *Plugin) authenticateExtension(ctx context.Context, m ClientAuthMethod, r clientRow, cred ClientCredentials) (clientRow, error) {
	fits := cred.Method == m.Method || (len(m.AssertionTypes) == 0 && cred.Method == AuthMethodNone && cred.Assertion == "")
	if cred.Secret != "" || !fits {
		return clientRow{}, ErrInvalidClient
	}
	conf, err := m.Authenticate(ctx, r.client(), cred)
	if err != nil {
		return clientRow{}, ErrInvalidClient
	}
	if conf != nil && conf.JKT != "" {
		// DPoP binds through its own proof, never through a client method.
		return clientRow{}, ErrInvalidClient
	}
	r.confirmation = conf
	return r, nil
}

// CertificateThumbprint is RFC 8705's x5t#S256 of a certificate:
// base64url(SHA-256(DER)), unpadded. A mutual-TLS ClientAuthMethod returns
// it in its Confirmation.
func CertificateThumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// certificateMatches compares a presented certificate with a bound
// thumbprint in constant time.
func certificateMatches(cert *x509.Certificate, x5t string) bool {
	return cert != nil && subtle.ConstantTimeCompare([]byte(CertificateThumbprint(cert)), []byte(x5t)) == 1
}

// extensionMetadata merges the extensions' discovery members: additive,
// the first extension wins, the provider's members are kept.
func (p *Plugin) extensionMetadata() map[string]any {
	out := map[string]any{}
	for _, e := range p.exts {
		for k, v := range e.Metadata {
			if _, taken := out[k]; taken {
				p.warnCollision(e.ID, "metadata", k)
				continue
			}
			out[k] = v
		}
	}
	return out
}

// MarshalJSON writes the document and, beside it, Extra's members that do
// not collide with one of its own.
func (m Metadata) MarshalJSON() ([]byte, error) {
	type plain Metadata
	b, err := json.Marshal(plain(m))
	if err != nil || len(m.Extra) == 0 {
		return b, err
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	for k, v := range m.Extra {
		if _, taken := doc[k]; !taken && !slices.Contains(metadataFields, k) {
			doc[k] = v
		}
	}
	return json.Marshal(doc)
}

// metadataFields are the discovery members the provider owns, read from
// Metadata's json tags, even when it leaves one out (omitempty), so an
// extension never supplies one.
var metadataFields = func() []string {
	var out []string
	t := reflect.TypeFor[Metadata]()
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}()

// accessReserved are the claims of a JWT access token no extension, option
// or resource sets: RFC 9068's and the provider's own.
var accessReserved = []string{claimIssuer, claimSubject, claimAudience, claimExpires, "nbf", claimIssuedAt, "jti", claimClientID, claimScope, claimAuthTime, "acr", "amr", claimConfirm, claimTokenRow, claimNonce, claimAZP, claimAtHash, "sid", "act"}

// idReserved are the claims of an ID token an extension never sets
// (OpenID Connect Core's and the hash claims).
var idReserved = []string{claimIssuer, claimSubject, claimAudience, claimExpires, "nbf", claimIssuedAt, "jti", claimAuthTime, claimNonce, "acr", "amr", claimAZP, "sid", claimAtHash, "c_hash", "s_hash", "act", claimConfirm}

// addClaims adds src to dst without replacing anything or setting a
// blocked name; a collision with an earlier extension is logged.
func (p *Plugin) addClaims(dst, src map[string]any, extID string, blocked func(string) bool) {
	for k, v := range src {
		if blocked(k) {
			continue
		}
		if _, taken := dst[k]; taken {
			p.warnCollision(extID, "claim", k)
			continue
		}
		dst[k] = v
	}
}

// warnCollision logs an extension member that lost to an earlier one.
func (p *Plugin) warnCollision(extID, kind, name string) {
	if p.core != nil {
		p.core.Logger().Warn("oauthprovider: extension member already set, kept the first", "extension", extID, "kind", kind, "name", name)
	}
}

// identityBlocked blocks the reserved ID token claims and every claim a
// scope releases, so an extension cannot pose as the user's email.
func identityBlocked(k string) bool {
	_, scoped := standardClaims[k]
	return scoped || slices.Contains(idReserved, k)
}

// extensionIDClaims adds the extensions' ID token claims and the
// per-issuance ones.
func (p *Plugin) extensionIDClaims(ctx context.Context, claims map[string]any, info ClaimsInfo, perIssuance map[string]any) {
	for _, e := range p.exts {
		if e.Claims.IDToken != nil {
			p.addClaims(claims, e.Claims.IDToken(ctx, cloneInfo(info)), e.ID, identityBlocked)
		}
	}
	p.addClaims(claims, perIssuance, "grant", identityBlocked)
}

// extensionUserInfo adds the extensions' userinfo claims.
func (p *Plugin) extensionUserInfo(ctx context.Context, claims map[string]any, info ClaimsInfo) {
	for _, e := range p.exts {
		if e.Claims.UserInfo != nil {
			p.addClaims(claims, e.Claims.UserInfo(ctx, cloneInfo(info)), e.ID, identityBlocked)
		}
	}
}

func cloneInfo(info ClaimsInfo) ClaimsInfo {
	info.Scopes = slices.Clone(info.Scopes)
	return info
}

// accessClaimsFor builds a JWT access token's own claims, lowest first:
// the extensions' (additive), the grant's per-issuance claims, the
// AccessTokenClaims option, then the resource's CustomClaims; a reserved
// claim is never taken from any of them.
func (p *Plugin) accessClaimsFor(ctx context.Context, is issuance) (map[string]any, error) {
	claims := map[string]any{}
	reserved := func(k string) bool { return slices.Contains(accessReserved, k) }
	info := AccessTokenClaimsInfo{ClientID: is.client.c.ClientID, Scopes: slices.Clone(is.scopes), Resource: is.resource, ReferenceID: is.referenceID}
	if is.userID != "" {
		u, err := p.core.User(ctx, is.userID)
		if err != nil {
			return nil, err
		}
		info.User = &u
	}
	for _, e := range p.exts {
		if e.Claims.AccessToken != nil {
			p.addClaims(claims, e.Claims.AccessToken(ctx, info), e.ID, reserved)
		}
	}
	override := func(src map[string]any) {
		for k, v := range src {
			if !reserved(k) {
				claims[k] = v
			}
		}
	}
	override(is.accessClaims)
	if p.accessClaims != nil {
		override(p.accessClaims(ctx, info))
	}
	override(maps.Clone(is.policy.CustomClaims))
	return claims, nil
}

// discoverer is the first extension discoverer matching a client_id.
func (p *Plugin) discoverer(id string) (ClientDiscoverer, bool) {
	if id == "" {
		return ClientDiscoverer{}, false
	}
	for _, e := range p.exts {
		for _, d := range e.ClientDiscovery {
			if d.Matches(id) {
				return d, true
			}
		}
	}
	return ClientDiscoverer{}, false
}

// discoveredClient resolves a client through a discoverer: a registered
// client of another kind is kept as it is, a stored one of this kind is
// used until Refresh, and an unknown one is resolved, checked as a
// registration is, and stored. A failed resolution is an unknown client.
func (p *Plugin) discoveredClient(ctx context.Context, d ClientDiscoverer, id string, r clientRow, loadErr error) (clientRow, error) {
	now := p.core.Now()
	switch {
	case loadErr != nil && !errors.Is(loadErr, ErrClientNotFound):
		return r, loadErr
	case loadErr == nil && deref(r.discovery) != d.ID:
		return r, nil
	case loadErr == nil && (d.Refresh == 0 || r.fetchedAt == nil || now.Before(r.fetchedAt.Add(d.Refresh))):
		return r, nil
	}
	m, err := d.Resolve(ctx, id)
	if err != nil {
		p.core.Logger().Warn("oauthprovider: client discovery", "discovery", d.ID, "client_id", id, "error", err)
		return clientRow{}, ErrClientNotFound
	}
	if loadErr == nil {
		if err := p.refreshDiscovered(ctx, id, d.ID, m, now); err != nil {
			return clientRow{}, err
		}
	} else if _, err := p.insertClient(ctx, ClientSpec{ClientMetadata: m, id: id, discovery: d.ID, fetchedAt: &now}); err != nil && !auth.IsUniqueViolation(err) {
		// A unique violation is a concurrent resolution that stored it
		// first. Metadata the provider refuses (a client error) makes the
		// client unknown; a failed write is the database's error, not a
		// verdict on the client.
		if auth.ErrorOf(err).Status >= http.StatusInternalServerError {
			return clientRow{}, err
		}
		p.core.Logger().Warn("oauthprovider: client discovery refused", "discovery", d.ID, "client_id", id, "error", err)
		return clientRow{}, ErrClientNotFound
	}
	return p.loadClient(ctx, id)
}
