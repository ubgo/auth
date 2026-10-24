package oauthprovider

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Client actions ClientPrivileges is asked about.
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionList   = "list"
	ActionRotate = "rotate"
	// ActionConfigureCCScopes sets a client's client_credentials ceiling
	// through the owner operations. Without a ClientPrivileges function it
	// is always refused: the ceiling grants machine access, so the app must
	// say who may give it.
	ActionConfigureCCScopes = "configure-client-credentials-scopes"
)

// ErrForbidden is an owner operation ClientPrivileges refused.
var ErrForbidden = auth.NewError("oauthprovider.forbidden", http.StatusForbidden, "You may not do this with this client.")

// ClientPrivilegesFunc decides whether the signed-in user may perform an
// action on a client (nil for create and list); false is ErrForbidden.
type ClientPrivilegesFunc func(ctx context.Context, action string, c *auth.Call, client *Client) bool

// ClientPrivileges installs a ClientPrivilegesFunc over the owner
// operations (create, get, list, update, rotate, delete).
func ClientPrivileges(fn ClientPrivilegesFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.ClientPrivileges", fn) {
			return
		}
		p.privileges = fn
	}
}

// ClientReference makes clients belong to a reference (an organization, a
// team) instead of the user: fn returns the signed-in user's current reference
// (such as the active organization), a created client takes it as ReferenceID
// with no owning user, and the owner operations see the clients of that
// reference. "" falls back to the user.
func ClientReference(fn func(ctx context.Context, c *auth.Call) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.ClientReference", fn) {
			return
		}
		p.clientReference = fn
	}
}

// allowed asks ClientPrivileges, allowing everything without one.
func (p *Plugin) allowed(ctx context.Context, action string, c *auth.Call, client *Client) error {
	if p.privileges == nil || p.privileges(ctx, action, c, client) {
		return nil
	}
	return ErrForbidden
}

// allowCCScopes is the ActionConfigureCCScopes check: refused without a
// ClientPrivileges function.
func (p *Plugin) allowCCScopes(ctx context.Context, c *auth.Call, client *Client) error {
	if p.privileges == nil {
		return ErrForbidden
	}
	return p.allowed(ctx, ActionConfigureCCScopes, c, client)
}

// reference is the caller's client reference, or "".
func (p *Plugin) reference(ctx context.Context, c *auth.Call) string {
	if p.clientReference == nil {
		return ""
	}
	return p.clientReference(ctx, c)
}

// ownerPredicate selects the caller's clients: by reference when one
// applies, by user otherwise.
func (p *Plugin) ownerPredicate(ctx context.Context, c *auth.Call) sqlb.Predicate {
	if ref := p.reference(ctx, c); ref != "" {
		return sqlb.Eq(ClientRefID, &ref)
	}
	return sqlb.Eq(ClientOwner, &c.User.ID)
}

// owns reports whether a client is the caller's, compared in constant time.
func (p *Plugin) owns(ctx context.Context, c *auth.Call, r clientRow) bool {
	if ref := p.reference(ctx, c); ref != "" {
		return r.refID != nil && subtle.ConstantTimeCompare([]byte(*r.refID), []byte(ref)) == 1
	}
	return r.owner != nil && subtle.ConstantTimeCompare([]byte(*r.owner), []byte(c.User.ID)) == 1
}
