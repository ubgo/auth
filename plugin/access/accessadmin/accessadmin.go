// Package accessadmin decides plugin/admin's permissions with plugin/access
// roles: better-auth's admin `ac` and `roles` options. It is the adapter that
// lets the admin plugin, which lives in the core module and imports no
// permission engine, use fine-grained roles from the access module:
//
//	authz := accessadmin.MustNew(accessadmin.DefaultAccessControl, map[string]access.Role{"support": support})
//	auth.New(db, auth.WithPlugins(admin.New(admin.WithAuthorizer(authz), …)))
//
// Without it the admin plugin keeps its two built-in roles (admin, user).
package accessadmin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/admin"
)

// DefaultAccessControl is the access control of admin.DefaultStatements, the
// vocabulary every admin operation asks from. An app adding resources of its
// own builds one from a copy of admin.DefaultStatements.
var DefaultAccessControl = access.MustNew(access.Statements(admin.DefaultStatements.Clone()))

// DefaultRoles returns admin.DefaultRoles as access roles of
// DefaultAccessControl; a new map each call.
func DefaultRoles() map[string]access.Role {
	out := map[string]access.Role{}
	for name, perms := range admin.DefaultRoles() {
		out[name] = DefaultAccessControl.MustRole(access.Permissions(perms))
	}
	return out
}

// roleSeparator is how admin_role joins several roles, so no role name may
// contain it.
const roleSeparator = ","

// ErrNoAccessControl is New with a nil access control.
var ErrNoAccessControl = errors.New("accessadmin: needs an access control")

// Authorizer is an admin.Authorizer and admin.RoleCatalog over access roles.
// Build it with New; it is immutable afterwards and safe for concurrent use.
type Authorizer struct {
	roles map[string]access.Role
}

// New builds the authorizer from ac and roles, which are added to
// DefaultRoles or replace one of them under its name. Every role must name
// only statements ac declares, and every name must be one name without
// commas, as admin_role stores several comma-joined.
func New(ac *access.AccessControl, roles map[string]access.Role) (*Authorizer, error) {
	if ac == nil {
		return nil, ErrNoAccessControl
	}
	all := DefaultRoles()
	for name, r := range roles {
		all[name] = r
	}
	for name, r := range all {
		if name == "" || strings.TrimSpace(name) != name || strings.Contains(name, roleSeparator) {
			return nil, fmt.Errorf("accessadmin: role name %q must be one name without commas", name)
		}
		if err := ac.Check(r.Permissions()); err != nil {
			return nil, fmt.Errorf("accessadmin: role %q: %w", name, err)
		}
	}
	return &Authorizer{roles: all}, nil
}

// MustNew is New for roles known at compile time; it panics on an error,
// which then shows at start-up.
func MustNew(ac *access.AccessControl, roles map[string]access.Role) *Authorizer {
	a, err := New(ac, roles)
	if err != nil {
		panic(err)
	}
	return a
}

// Authorize allows req when one of its roles passes the whole request under
// its connector, as better-auth checks a user with several roles. It never
// fails.
func (a *Authorizer) Authorize(_ context.Context, req admin.AccessRequest) (bool, error) {
	want := access.Permissions(req.Permissions).Request()
	for _, name := range req.Roles {
		if r, ok := a.roles[name]; ok && r.Authorize(want, access.Connector(req.Connector)) == nil {
			return true, nil
		}
	}
	return false, nil
}

// DefinesRole reports whether name is one of the authorizer's roles, which
// set-role then accepts.
func (a *Authorizer) DefinesRole(name string) bool {
	_, ok := a.roles[name]
	return ok
}

// The adapter must stay an admin.Authorizer and admin.RoleCatalog.
var (
	_ admin.Authorizer  = (*Authorizer)(nil)
	_ admin.RoleCatalog = (*Authorizer)(nil)
)
