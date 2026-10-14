package organization

import (
	"context"
	"errors"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
)

// Every permission decision of the plugin goes through one Authorizer: each
// operation's role check, has-permission, Can, RequirePermission, the grant
// check of a dynamic role and plugin/apikey's organization-key question. The
// default (RoleAuthorizer) is better-auth's: one of the member's static or
// dynamic roles must grant the whole request. WithAuthorizer replaces it with
// any model (ABAC, a relationship store such as OpenFGA or SpiceDB, Casbin,
// OPA, Cedar); membership itself is still the plugin's, so a non-member is
// refused before the authorizer is asked.

// AccessRequest is one permission decision. It is a struct so it can carry
// more context later without breaking an Authorizer.
type AccessRequest struct {
	// OrgID is the organization the decision is about.
	OrgID string
	// UserID is the member whose permission is decided: the caller, or the
	// user Can names.
	UserID string
	// Role is UserID's role in OrgID (Role.Parts for several). A model that
	// does not use roles ignores it.
	Role Role
	// Request is what is asked for, per resource.
	Request access.Request
	// Connector joins the resources; access.And when empty.
	Connector access.Connector
	// Operation is the operation asking, or "" outside one (Can,
	// RequirePermission, APIKeyPermission).
	Operation auth.EndpointID
	// Call is the operation's call (client, session, decoded input) for an
	// attribute-based rule, or nil outside an operation. Read it; never
	// change it.
	Call *auth.Call
}

// Authorizer decides whether an AccessRequest is allowed. Any error refuses:
// the plugin never reads the boolean of a call that returned an error, so a
// policy engine that is down fails closed. It must be safe for concurrent
// use.
//
//ds:def id=authorizer-nqtw4zda owner=@khanakia stability=api
type Authorizer interface {
	Authorize(ctx context.Context, req AccessRequest) (bool, error)
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(ctx context.Context, req AccessRequest) (bool, error)

// Authorize calls f.
func (f AuthorizerFunc) Authorize(ctx context.Context, req AccessRequest) (bool, error) {
	return f(ctx, req)
}

// WithAuthorizer replaces the role check as the decider of every
// organization permission. nil is refused by auth.New. An authorizer that
// only adds a rule wraps p.RoleAuthorizer(). The creator role's
// all-permissions rule for API keys belongs to the role model, so with a
// custom authorizer it decides organization keys too. Roles stay the
// plugin's for everything that is not a permission: which roles a member may
// be given, and the owner protections.
func WithAuthorizer(a Authorizer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("organization.WithAuthorizer", a) {
			return
		}
		p.authorizer, p.customAuthorizer = a, true
	}
}

// ErrNoAuthorizer was WithAuthorizer(nil).
//
// Deprecated: no longer returned. WithAuthorizer(nil) fails auth.New with
// auth.ErrNilOption naming the option, as every option given nil does.
var ErrNoAuthorizer = errors.New("organization: WithAuthorizer needs an authorizer")

// RoleAuthorizer is the default Authorizer: allowed when one of the
// request's roles, static or dynamic in the request's organization, grants
// the whole request. A role that no longer exists grants nothing.
func (p *Plugin) RoleAuthorizer() Authorizer { return AuthorizerFunc(p.rolesAllow) }

func (p *Plugin) rolesAllow(ctx context.Context, req AccessRequest) (bool, error) {
	for _, part := range req.Role.Parts() {
		role, ok := p.roles[part]
		if !ok {
			var err error
			if role, ok, err = p.dynamicRole(ctx, req.OrgID, part); err != nil {
				return false, err
			}
		}
		if ok && role.Authorize(req.Request, req.Connector) == nil {
			return true, nil
		}
	}
	return false, nil
}

// decide asks the authorizer; an error is returned as is and never allows.
func (p *Plugin) decide(ctx context.Context, req AccessRequest) (bool, error) {
	ok, err := p.authorizer.Authorize(ctx, req)
	if err != nil {
		return false, err
	}
	return ok, nil
}
