package organization

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/sqlb"
)

// Resources of DefaultStatements, the ones the plugin's own operations check.
const (
	ResourceOrganization = "organization"
	ResourceMember       = "member"
	ResourceInvitation   = "invitation"
	ResourceTeam         = "team"
	// ResourceAC is access control itself: the dynamic roles.
	ResourceAC = "ac"
)

// Actions of DefaultStatements.
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionCancel = "cancel"
)

// DefaultStatements is the organization vocabulary: what each
// operation of the plugin checks. An app adding resources of its own builds
// its access control from a copy of it (WithAccessControl).
var DefaultStatements = access.Statements{
	ResourceOrganization: {ActionUpdate, ActionDelete},
	ResourceMember:       {ActionCreate, ActionUpdate, ActionDelete},
	ResourceInvitation:   {ActionCreate, ActionCancel},
	ResourceTeam:         {ActionCreate, ActionUpdate, ActionDelete},
	ResourceAC:           {ActionCreate, ActionRead, ActionUpdate, ActionDelete},
}

// DefaultAccessControl is the access control of DefaultStatements.
var DefaultAccessControl = access.MustNew(DefaultStatements)

// DefaultRoles returns the three built-in roles: the owner may do
// everything; the admin everything but delete the organization; the member
// only read the roles. A new map each call, so an app can change it.
func DefaultRoles() map[Role]access.Role {
	ac := DefaultAccessControl
	return map[Role]access.Role{
		RoleOwner: ac.MustRole(access.Permissions(DefaultStatements)),
		RoleAdmin: ac.MustRole(access.Permissions{
			ResourceOrganization: {ActionUpdate},
			ResourceMember:       {ActionCreate, ActionUpdate, ActionDelete},
			ResourceInvitation:   {ActionCreate, ActionCancel},
			ResourceTeam:         {ActionCreate, ActionUpdate, ActionDelete},
			ResourceAC:           {ActionCreate, ActionRead, ActionUpdate, ActionDelete},
		}),
		RoleMember: ac.MustRole(access.Permissions{
			ResourceOrganization: {}, ResourceMember: {}, ResourceInvitation: {}, ResourceTeam: {},
			ResourceAC: {ActionRead},
		}),
	}
}

// checkRole accepts a role whose every part is a static role, or a dynamic
// role of orgID; anything else, or no role at all, is ErrBadRole.
func (p *Plugin) checkRole(ctx context.Context, orgID string, r Role) error {
	parts := r.Parts()
	if len(parts) == 0 {
		return ErrBadRole
	}
	for _, part := range parts {
		if _, ok := p.roles[part]; ok {
			continue
		}
		if _, found, err := p.dynamicRole(ctx, orgID, part); err != nil {
			return err
		} else if !found {
			return ErrBadRole
		}
	}
	return nil
}

// authorize passes when the authorizer allows the caller, whose role in
// orgID is r, req; ErrForbidden otherwise.
func (p *Plugin) authorize(ctx context.Context, c *auth.Call, orgID string, r Role, req access.Request) error {
	ok, err := p.allows(ctx, c, orgID, c.User.ID, r, req, access.And)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

// allows asks the authorizer whether userID, whose role in orgID is r, may
// do req under connector; c is nil outside an operation.
func (p *Plugin) allows(ctx context.Context, c *auth.Call, orgID, userID string, r Role, req access.Request, connector access.Connector) (bool, error) {
	ar := AccessRequest{OrgID: orgID, UserID: userID, Role: r, Request: req, Connector: connector, Call: c}
	if c != nil {
		ar.Operation = c.Op.ID
	}
	return p.decide(ctx, ar)
}

// guardCreator keeps the creator role (owner by default) in its holders'
// hands: a caller who does not hold it may not grant it, nor touch a member
// who holds it.
func (p *Plugin) guardCreator(mine Role, touched ...Role) error {
	if mine.Has(p.creatorRole) {
		return nil
	}
	for _, r := range touched {
		if r.Has(p.creatorRole) {
			return ErrForbidden
		}
	}
	return nil
}

// PermissionRequest is the input of has-permission: the permissions asked
// for, in an organization (the active one when OrgID is empty). Connector
// joins the resources, AND by default.
type PermissionRequest struct {
	OrgID       string             `json:"orgId,omitempty"`
	Permissions access.Permissions `json:"permissions"`
	Connector   access.Connector   `json:"connector,omitempty"`
}

// PermissionResult is the output of has-permission.
type PermissionResult struct {
	Success bool `json:"success"`
}

// HasPermission reports whether the signed-in member holds the permissions
// (has-permission). A non-member is ErrNotMember.
func (p *Plugin) HasPermission(ctx context.Context, in PermissionRequest) (bool, error) {
	r, err := p.hasPermission.Call(ctx, in)
	return r.Success, err
}

func (p *Plugin) doHasPermission(ctx context.Context, c *auth.Call, in PermissionRequest) (PermissionResult, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return PermissionResult{}, err
	}
	r, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return PermissionResult{}, err
	}
	ok, err := p.allows(ctx, c, orgID, c.User.ID, r, in.Permissions.Request(), in.Connector)
	return PermissionResult{Success: ok}, err
}

// Can reports whether userID's roles in orgID pass req under connector (AND
// when empty), from Go: the server-side check behind an app's own routes. A
// non-member is ErrNotMember.
func (p *Plugin) Can(ctx context.Context, orgID, userID string, req access.Request, connector access.Connector) (bool, error) {
	r, err := p.RoleOf(ctx, orgID, userID)
	if err != nil {
		return false, err
	}
	return p.allows(ctx, nil, orgID, userID, r, req, connector)
}

// RequirePermission is middleware that refuses a request unless the
// signed-in user's roles in the organization orgID names grant req. It must
// be inside authhttp.Middleware. A non-member gets ErrNotMember and a member
// without the permission ErrForbidden, as RequireRole answers.
func (p *Plugin) RequirePermission(orgID func(r *http.Request) string, req access.Request) func(http.Handler) http.Handler {
	return authhttp.RequireFunc(func(r *http.Request) error {
		u, ok := auth.CurrentUser(r.Context())
		if !ok {
			return auth.ErrSignedOut
		}
		allowed, err := p.Can(r.Context(), orgID(r), u.ID, req, access.And)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrForbidden
		}
		return nil
	})
}

// errIsNoRows maps sqlb.ErrNoRows to notFound and passes any other error.
func errIsNoRows(err, notFound error) error {
	if errors.Is(err, sqlb.ErrNoRows) {
		return notFound
	}
	return err
}

// resourceAPIKey is plugin/apikey's resource name (apikey.ResourceAPIKey),
// spelled here because this module may not import plugin/apikey; the
// apikey tests pin that the two agree.
const resourceAPIKey = "apiKey"

// APIKeyPermission answers plugin/apikey's question about an organization
// key, so *Plugin satisfies
// apikey.Organizations without either module importing the other: member
// is false for someone outside orgID; a holder of the creator role may do
// every action (allowCreatorAllPermissions) under the default
// RoleAuthorizer; anyone else, and everyone under WithAuthorizer, needs the
// authorizer to allow action on the "apiKey" resource. Only ErrNotMember is
// "not a member"; any other failure is returned.
func (p *Plugin) APIKeyPermission(ctx context.Context, orgID, userID, action string) (member, allowed bool, err error) {
	r, err := p.RoleOf(ctx, orgID, userID)
	switch {
	case errors.Is(err, ErrNotMember):
		return false, false, nil
	case err != nil:
		return false, false, err
	case !p.customAuthorizer && r.Has(p.creatorRole):
		return true, true, nil
	}
	ok, err := p.allows(ctx, nil, orgID, userID, r, access.Request{resourceAPIKey: access.All(action)}, access.And)
	if err != nil {
		return true, false, err
	}
	return true, ok, nil
}

// PermissionsOf returns the permissions role grants in orgID: the union of
// every part of a (possibly comma-joined) role, from the static roles
// (DefaultRoles merged with WithRoles) and, with DynamicRoles, orgID's
// dynamic roles. A part that names no known role grants nothing. Actions are
// deduplicated and sorted, so a token claim built from it is deterministic,
// and the map is a fresh copy the caller may change. It reads roles only;
// what a custom Authorizer would decide is not reflected here.
func (p *Plugin) PermissionsOf(ctx context.Context, orgID string, role Role) (access.Permissions, error) {
	out := access.Permissions{}
	for _, part := range role.Parts() {
		r, ok := p.roles[part]
		if !ok {
			var err error
			if r, ok, err = p.dynamicRole(ctx, orgID, part); err != nil {
				return nil, err
			}
		}
		if !ok {
			continue
		}
		for res, actions := range r.Permissions() {
			out[res] = append(out[res], actions...)
		}
	}
	for res, actions := range out {
		slices.Sort(actions)
		out[res] = slices.Compact(actions)
	}
	return out, nil
}
