package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
)

// Scope is what a credential may do.
type Scope string

// Scopes. A GET or HEAD needs the resource's read scope, anything else its
// write scope; /Groups paths need the groups scopes, every other path the
// users scopes.
const (
	ScopeUsersRead   Scope = "scim.users.read"
	ScopeUsersWrite  Scope = "scim.users.write"
	ScopeGroupsRead  Scope = "scim.groups.read"
	ScopeGroupsWrite Scope = "scim.groups.write"
)

// ScopeValues is every scope, the default of a credential that names none.
var ScopeValues = []Scope{ScopeUsersRead, ScopeUsersWrite, ScopeGroupsRead, ScopeGroupsWrite}

// Connection is one identity provider tenant: its
// id scopes every resource it creates, and any of its credentials
// authenticates it, so a token can be rotated by adding the new credential
// before removing the old.
//
//ds:def id=scim-connection-4t8qm2wv owner=@khanakia stability=stable
type Connection struct {
	ID          string
	Credentials []Credential
	// ProvisioningDomainID groups connections of one tenant; it defaults to
	// ID and cannot change once the connection has been used.
	ProvisioningDomainID string
}

// Credential is one static bearer token of a connection. Scopes default to
// ScopeValues; an expired credential answers 401.
type Credential struct {
	ID        string
	Token     string
	Scopes    []Scope
	ExpiresAt *time.Time
}

// BearerRequest is what VerifyBearerToken is asked to authenticate.
type BearerRequest struct {
	Token  string
	Method string
	Path   string
	Header http.Header
}

// Principal is an authenticated caller: the connection, the credential and
// its scopes (ScopeValues when empty), and an optional expiry.
type Principal struct {
	ConnectionID string
	CredentialID string
	Scopes       []Scope
	ExpiresAt    *time.Time
	// ProvisioningDomainID defaults to ConnectionID.
	ProvisioningDomainID string
	// managed marks a managed credential, whose connection must exist.
	managed bool
}

// ErrUnauthorized is VerifyBearerToken's answer for a token it does not know.
var ErrUnauthorized = errors.New("scim: invalid bearer token")

// validID is a connection or credential id: trimmed, 1 to 255 characters.
func validID(id string) bool {
	return id != "" && len(id) <= maxIDLength && strings.TrimSpace(id) == id
}

// validToken is a non-empty token without whitespace.
func validToken(t string) bool {
	return t != "" && strings.IndexFunc(t, unicode.IsSpace) < 0
}

// validScopes accepts only known scopes.
func validScopes(ss []Scope) bool {
	for _, s := range ss {
		if !slices.Contains(ScopeValues, s) {
			return false
		}
	}
	return true
}

// authenticate finds the caller of r. Every static credential is compared,
// in constant time over the token's SHA-256, so neither the position of the
// match nor the length of a token is observable; only then is
// VerifyBearerToken asked.
func (p *Plugin) authenticate(r *http.Request) (Principal, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	raw = strings.TrimSpace(raw)
	if !ok || raw == "" {
		return Principal{}, errMissingToken
	}
	sum := sha256.Sum256([]byte(raw))
	var found Principal
	match := 0
	for _, cn := range p.connections {
		for _, cr := range cn.Credentials {
			want := sha256.Sum256([]byte(cr.Token))
			if subtle.ConstantTimeCompare(sum[:], want[:]) == 1 {
				found, match = Principal{ConnectionID: cn.ID, CredentialID: cr.ID, Scopes: cr.Scopes, ExpiresAt: cr.ExpiresAt, ProvisioningDomainID: cn.ProvisioningDomainID}, 1
			}
		}
	}
	switch {
	case match == 1:
	case p.managed != nil && strings.HasPrefix(raw, ManagedTokenPrefix):
		// A managed token never falls through to the verifier.
		pr, err := p.managedAuth(r.Context(), raw)
		if err != nil {
			return Principal{}, err
		}
		found = pr
	default:
		if p.verifier == nil {
			return Principal{}, errInvalidToken
		}
		pr, err := p.verifier(r.Context(), BearerRequest{Token: raw, Method: r.Method, Path: r.URL.Path, Header: r.Header})
		if errors.Is(err, ErrUnauthorized) {
			return Principal{}, errInvalidToken
		}
		if err != nil {
			return Principal{}, err
		}
		if !validID(pr.ConnectionID) || !validScopes(pr.Scopes) || strings.HasPrefix(pr.ConnectionID, managedConnPrefix+"_") || p.configured(pr.ConnectionID) {
			return Principal{}, errInvalidToken
		}
		found = pr
	}
	if found.ExpiresAt != nil && !p.core.Now().Before(*found.ExpiresAt) {
		return Principal{}, errExpiredToken
	}
	if len(found.Scopes) == 0 {
		found.Scopes = ScopeValues
	}
	return found, nil
}

// configured reports whether id names a connection given to Connections. A
// dynamic principal may not take such an id, so a dynamic connection id
// never collides with a configured one: the verifier
// would otherwise hand a token the configured connection's users without
// its credentials.
func (p *Plugin) configured(id string) bool {
	for _, cn := range p.connections {
		if cn.ID == id {
			return true
		}
	}
	return false
}

// requiredScope is the scope a request needs.
func requiredScope(method, path string) Scope {
	read := method == http.MethodGet || method == http.MethodHead
	groups := strings.Contains(path, "/Groups")
	switch {
	case groups && read:
		return ScopeGroupsRead
	case groups:
		return ScopeGroupsWrite
	case read:
		return ScopeUsersRead
	}
	return ScopeUsersWrite
}

// principalKey carries the authenticated caller on the request context.
type principalKey struct{}

// PrincipalFrom returns the caller of a SCIM request, for a ResolveUser or
// GroupMapper that needs more than the connection id.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	pr, ok := ctx.Value(principalKey{}).(Principal)
	return pr, ok
}
