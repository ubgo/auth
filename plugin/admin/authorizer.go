package admin

import (
	"context"
	"errors"
	"slices"
	"sort"

	"github.com/ubgo/auth"
)

// Every permission decision of the plugin goes through one Authorizer: the
// first check of every operation, the impersonate-admins check, has-permission
// and CheckRolePermission. The plugin never decides a permission itself, so an
// app can answer with RBAC, ABAC, a relationship store, a policy
// engine or its own rules. The default is a fixed pair of roles
// (DefaultRoles); fine-grained roles built from a statement vocabulary plug in
// through plugin/access's accessadmin adapter, a separate module, so the core
// module carries no permission engine.

// Permissions are actions per resource: what a role grants, or what a check
// asks for ({"user": ["ban"]}). JSON-encoded it is the permission object,
// the body of has-permission. Every listed action of a resource is
// required.
type Permissions map[string][]string

// Clone returns a deep copy.
func (p Permissions) Clone() Permissions {
	out := make(Permissions, len(p))
	for res, acts := range p {
		out[res] = slices.Clone(acts)
	}
	return out
}

// Connector says how the resources of a check combine.
type Connector string

// Connectors, spelled as clients send them.
const (
	// And requires every resource; the default when empty.
	And Connector = "AND"
	// Or requires one resource.
	Or Connector = "OR"
)

// AccessRequest is one permission decision. It is a struct rather than bare
// strings so it can carry more context later without breaking an Authorizer:
// a field added here is a zero value to an implementation that ignores it.
type AccessRequest struct {
	// UserID is the user whose permission is decided: the caller, or
	// has-permission's userId. Empty for CheckRolePermission, which decides
	// for a role and nobody in particular.
	UserID string
	// Roles are UserID's admin roles as the plugin resolved them: the stored
	// admin_role, the first of AdminRoles for a user the staff flag or
	// AdminIDs makes an admin, or DefaultRole when that leaves none. A model
	// that does not use roles ignores them.
	Roles []string
	// Permissions are what is asked for; every action of a resource is
	// required.
	Permissions Permissions
	// Connector joins the resources; And when empty.
	Connector Connector
	// TargetUserID is the user the operation acts on (ban, set-role,
	// impersonate, …) as the request names it, or "" when there is none
	// (list, create-user, a check of oneself). It is the input's value: the
	// decision comes before the target is looked up, so a refusal never
	// reveals whether the user exists.
	TargetUserID string
	// Operation is the operation asking, or "" outside one
	// (CheckRolePermission, RolesOf callers).
	Operation auth.EndpointID
	// Call is the operation's call (client IP, session, decoded input) for
	// an attribute-based rule, or nil outside an operation. Read it; never
	// change it.
	Call *auth.Call
}

// Authorizer decides whether an AccessRequest is allowed. Any error refuses:
// the plugin never reads the boolean of a call that returned an error, so a
// policy engine that is down fails closed. It must be safe for concurrent
// use.
//
//ds:def id=authorizer-yr8g745x owner=@khanakia stability=api
type Authorizer interface {
	Authorize(ctx context.Context, req AccessRequest) (bool, error)
}

// AuthorizerFunc adapts a function to Authorizer.
type AuthorizerFunc func(ctx context.Context, req AccessRequest) (bool, error)

// Authorize calls f.
func (f AuthorizerFunc) Authorize(ctx context.Context, req AccessRequest) (bool, error) {
	return f(ctx, req)
}

// RoleCatalog is an optional upgrade of Authorizer: the role names it
// defines, which set-role accepts and AdminRoles and DefaultRole may name. An
// Authorizer without it accepts the built-in names (RoleAdmin, RoleUser)
// only, so set-role never stores a role nothing could decide on.
type RoleCatalog interface {
	DefinesRole(name string) bool
}

// WithAuthorizer replaces the built-in roles as the decider of every admin
// permission. nil is refused by auth.New. Implement RoleCatalog as well when
// set-role should accept roles other than admin and user.
func WithAuthorizer(a Authorizer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("admin.WithAuthorizer", a) {
			return
		}
		p.authorizer = a
	}
}

// ErrNoAuthorizer was WithAuthorizer(nil).
//
// Deprecated: no longer returned. WithAuthorizer(nil) fails auth.New with
// auth.ErrNilOption naming the option, as every option given nil does.
var ErrNoAuthorizer = errors.New("admin: WithAuthorizer needs an authorizer")

// DefaultRoles returns the built-in roles, the default Authorizer's: RoleAdmin
// may do everything in DefaultStatements except impersonate-admins, which
// stays opt-in; RoleUser grants nothing. A new map each call.
func DefaultRoles() map[string]Permissions {
	all := DefaultStatements.Clone()
	all[ResourceUser] = slices.DeleteFunc(all[ResourceUser], func(a string) bool { return a == ActionImpersonateAdmins })
	return map[string]Permissions{RoleAdmin: all, RoleUser: {}}
}

// defaultAuthorizer is the built-in roles: allowed when one of the request's
// roles grants the whole request.
type defaultAuthorizer struct{ roles map[string]Permissions }

func newDefaultAuthorizer() defaultAuthorizer { return defaultAuthorizer{roles: DefaultRoles()} }

// Authorize never fails.
func (d defaultAuthorizer) Authorize(_ context.Context, req AccessRequest) (bool, error) {
	for _, name := range req.Roles {
		if granted, ok := d.roles[name]; ok && Grants(granted, req.Permissions, req.Connector) {
			return true, nil
		}
	}
	return false, nil
}

// DefinesRole is RoleAdmin and RoleUser.
func (d defaultAuthorizer) DefinesRole(name string) bool { _, ok := d.roles[name]; return ok }

// Grants reports whether granted covers want under connector, for a
// request requiring every listed action: a resource
// granted nothing fails at once whatever the connector, every listed action
// of a resource must be granted (and at least one listed), And needs every
// resource and Or one, and an empty request is denied because asking for
// nothing proves nothing. Resources are visited in sorted order, so the
// answer never depends on map iteration. It is exported for an Authorizer
// that keeps a role table of its own.
func Grants(granted, want Permissions, connector Connector) bool {
	if connector == "" {
		connector = And
	}
	resources := make([]string, 0, len(want))
	for res := range want {
		resources = append(resources, res)
	}
	sort.Strings(resources)
	ok := false
	for _, res := range resources {
		allowed, has := granted[res]
		if !has {
			return false
		}
		acts := want[res]
		ok = len(acts) > 0 && !slices.ContainsFunc(acts, func(a string) bool { return !slices.Contains(allowed, a) })
		if ok && connector == Or {
			return true
		}
		if !ok && connector == And {
			return false
		}
	}
	return ok
}

// decide asks the authorizer; an error is returned as is and never allows.
func (p *Plugin) decide(ctx context.Context, req AccessRequest) (bool, error) {
	ok, err := p.authorizer.Authorize(ctx, req)
	if err != nil {
		return false, err
	}
	return ok, nil
}

// definesRole reports whether set-role may store name.
func (p *Plugin) definesRole(name string) bool {
	if rc, ok := p.authorizer.(RoleCatalog); ok {
		return rc.DefinesRole(name)
	}
	return name == RoleAdmin || name == RoleUser
}

// targetOf is the user the call's input names, through the TargetUserID
// method every admin request with a target has (the audit log's hook).
func targetOf(c *auth.Call) string {
	if t, ok := c.Input.(interface{ TargetUserID() string }); ok {
		return t.TargetUserID()
	}
	return ""
}
