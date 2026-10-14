package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Roles and permissions (better-auth's admin access control). Every admin
// operation asks the Authorizer (authorizer.go) for a permission from
// DefaultStatements, passing the caller's roles. A user's roles are stored in auth_user.admin_role (comma-joined, as
// better-auth's user.role); the staff flag of before, admin_granted_at and
// AdminIDs, still makes a user an admin: it counts as holding the first of
// AdminRoles. With no role and no flag, a user holds DefaultRole, which
// grants nothing by default, so an app that never names a role behaves
// exactly as the flag did.

// Resources of DefaultStatements.
const (
	ResourceUser    = "user"
	ResourceSession = "session"
	// ResourceTwoFactor is another user's second factor: read it, pause it,
	// switch it back on, or reset it so the user enrols again. Its own
	// resource rather than more user actions, so a support role can be
	// granted it without ban or set-password.
	ResourceTwoFactor = "two-factor"
)

// Actions of DefaultStatements, better-auth's names.
const (
	ActionCreate            = "create"
	ActionList              = "list"
	ActionSetRole           = "set-role"
	ActionBan               = "ban"
	ActionImpersonate       = "impersonate"
	ActionImpersonateAdmins = "impersonate-admins"
	ActionDelete            = "delete"
	ActionSetPassword       = "set-password"
	ActionSetEmail          = "set-email"
	ActionGet               = "get"
	ActionUpdate            = "update"
	ActionRevoke            = "revoke"
	// ActionEnable, ActionDisable and ActionReset are the two-factor
	// actions beside ActionGet: switch a paused factor back on, pause it,
	// and remove it with its recovery codes.
	ActionEnable  = "enable"
	ActionDisable = "disable"
	ActionReset   = "reset"
)

// DefaultStatements is better-auth's admin vocabulary, plus the two-factor
// resource: every permission the plugin asks for. An access control built for accessadmin starts from it.
var DefaultStatements = Permissions{
	ResourceUser: {ActionCreate, ActionList, ActionSetRole, ActionBan, ActionImpersonate, ActionImpersonateAdmins,
		ActionDelete, ActionSetPassword, ActionSetEmail, ActionGet, ActionUpdate},
	ResourceSession:   {ActionList, ActionRevoke, ActionDelete},
	ResourceTwoFactor: {ActionGet, ActionDisable, ActionEnable, ActionReset},
}

// Built-in role names.
const (
	// RoleAdmin may do every admin operation except impersonate another
	// admin, which stays opt-in (AllowImpersonatingAdmins, or a role with
	// impersonate-admins).
	RoleAdmin = "admin"
	// RoleUser grants nothing: the role of everyone else.
	RoleUser = "user"
)

// ColRole is the column holding a user's admin roles.
const ColRole = "admin_role"

// UserRole is the typed admin_role column.
var UserRole = sqlb.Col[string](auth.TableUser, ColRole)

// roleSeparator joins several roles in admin_role.
const roleSeparator = ","

// AdminRoles names the roles that make a user an admin (better-auth's
// adminRoles): protected from bans, impersonation and removal, counted for
// the last-admin rule, and in sync with the staff flag. ["admin"] by
// default; the first one is the role the flag stands for.
func AdminRoles(names ...string) Option { return func(p *Plugin) { p.adminRoles = names } }

// DefaultRole is the role of a user with none stored and no flag
// (better-auth's defaultRole); RoleUser by default.
func DefaultRole(name string) Option { return func(p *Plugin) { p.defaultRole = name } }

// validateRoles refuses a configuration whose roles could not be checked.
func (p *Plugin) validateRoles() error {
	if len(p.adminRoles) == 0 {
		return errors.New("admin: AdminRoles needs at least one role")
	}
	// Each name is checked under the option that set it, so the error names
	// the setting to fix rather than a role the reader has to trace back.
	if err := p.checkRoleName("admin.DefaultRole", p.defaultRole); err != nil {
		return err
	}
	for _, name := range p.adminRoles {
		if err := p.checkRoleName("admin.AdminRoles", name); err != nil {
			return err
		}
	}
	return nil
}

// checkRoleName refuses a role name option set that is not one stored name
// or that no role defines.
func (p *Plugin) checkRoleName(option, name string) error {
	if !validRoleName(name) {
		return fmt.Errorf("admin: %s: role name %q must be one name without commas", option, name)
	}
	if !p.definesRole(name) {
		return fmt.Errorf("admin: %s: role %q is not defined", option, name)
	}
	return nil
}

func validRoleName(name string) bool {
	return name != "" && strings.TrimSpace(name) == name && !strings.Contains(name, roleSeparator)
}

// splitRoles is the roles a stored value holds, trimmed, empties dropped.
func splitRoles(v string) []string {
	var out []string
	for _, part := range strings.Split(v, roleSeparator) {
		if part = strings.TrimSpace(part); part != "" && !slices.Contains(out, part) {
			out = append(out, part)
		}
	}
	return out
}

// rolesOf is the roles userID holds: the stored ones, the flag's admin role
// when the flag or AdminIDs makes them an admin without one, or DefaultRole
// when that leaves none.
func (p *Plugin) rolesOf(userID string, c AdminColumns) []string {
	roles := splitRoles(c.Role)
	if (c.AdminGrantedAt != nil || p.adminIDs[userID]) && !slices.ContainsFunc(roles, p.isAdminRole) {
		roles = append(roles, p.adminRoles[0])
	}
	if len(roles) == 0 {
		roles = []string{p.defaultRole}
	}
	return roles
}

func (p *Plugin) isAdminRole(name string) bool { return slices.Contains(p.adminRoles, name) }

// may asks the authorizer whether userID may do action on resource in the
// call c (nil outside an operation).
func (p *Plugin) may(ctx context.Context, c *auth.Call, userID, resource, action string) (bool, error) {
	cols, err := p.columnsOf(ctx, userID)
	if err != nil {
		return false, err
	}
	req := AccessRequest{UserID: userID, Roles: p.rolesOf(userID, cols),
		Permissions: Permissions{resource: {action}}, Connector: And, Call: c}
	if c != nil {
		req.TargetUserID, req.Operation = targetOf(c), c.Op.ID
	}
	return p.decide(ctx, req)
}

// require refuses a caller the authorizer does not allow action on resource. It
// is every admin operation's first step, before the target is looked up, so
// a refusal never reveals whether a user exists. An impersonation session
// is refused after that check (a caller without the permission still reads
// ErrForbidden): acting as an admin must not hand the acting admin a second
// admin identity.
func (p *Plugin) require(ctx context.Context, c *auth.Call, resource, action string) error {
	ok, err := p.may(ctx, c, c.User.ID, resource, action)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	if c.Session.ImpersonatedBy != nil {
		return auth.ErrImpersonationRefused
	}
	return nil
}

// callerMay reports whether the authorizer allows the caller action on
// resource, for a second permission inside an operation
// (impersonate-admins).
func (p *Plugin) callerMay(ctx context.Context, c *auth.Call, resource, action string) (bool, error) {
	return p.may(ctx, c, c.User.ID, resource, action)
}

// Roles is a list of role names that decodes from a JSON string ("a,b") or
// array, as better-auth's set-role sends either.
type Roles []string

// UnmarshalJSON accepts a string or an array of strings.
func (r *Roles) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*r = splitRoles(one)
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return ErrBadRole
	}
	*r = splitRoles(strings.Join(many, roleSeparator))
	return nil
}

// Operation ids of the role operations.
const (
	EndpointSetRole       auth.EndpointID = "admin.set-role"
	EndpointHasPermission auth.EndpointID = "admin.has-permission"
)

// Errors of the role operations.
var (
	// ErrBadRole is a role the plugin does not define, or no role at all.
	ErrBadRole = auth.NewError("admin.bad_role", http.StatusBadRequest, "This role does not exist.")
)

// SetRoleRequest is the input of set-role.
type SetRoleRequest struct {
	UserID string `json:"userId"`
	Role   Roles  `json:"role"`
}

// TargetUserID names the user for the audit log.
func (r SetRoleRequest) TargetUserID() string { return r.UserID }

// PermissionRequest is the input of has-permission: the permissions asked
// for, of the caller, or of UserID, which needs user:get.
type PermissionRequest struct {
	UserID      string      `json:"userId,omitempty"`
	Permissions Permissions `json:"permissions"`
	Connector   Connector   `json:"connector,omitempty"`
}

// PermissionResult is the output of has-permission.
type PermissionResult struct {
	Success bool `json:"success"`
}

// SetRole replaces a user's roles, as a caller with user:set-role.
func (p *Plugin) SetRole(ctx context.Context, in SetRoleRequest) error {
	_, err := p.setRole.Call(ctx, in)
	return err
}

// HasPermission reports whether the caller, or in.UserID, holds the
// permissions (better-auth's admin hasPermission).
func (p *Plugin) HasPermission(ctx context.Context, in PermissionRequest) (bool, error) {
	r, err := p.hasPermission.Call(ctx, in)
	return r.Success, err
}

// CheckRolePermission reports whether the authorizer allows role (one name
// or several, comma-joined) every action of perms, with no database:
// better-auth's checkRolePermission, for a UI that shows or hides a button by
// role. The request has no UserID; an unknown role grants nothing and an
// authorizer error is false.
func (p *Plugin) CheckRolePermission(ctx context.Context, role string, perms Permissions) bool {
	ok, err := p.decide(ctx, AccessRequest{Roles: splitRoles(role), Permissions: perms, Connector: And})
	return err == nil && ok
}

// RolesOf returns userID's roles, from Go.
func (p *Plugin) RolesOf(ctx context.Context, userID string) ([]string, error) {
	cols, err := p.columnsOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	return p.rolesOf(userID, cols), nil
}

// SetRoleFor replaces userID's roles from Go, with no caller to check: a seed
// or an import. The last-admin rule still applies.
func (p *Plugin) SetRoleFor(ctx context.Context, userID string, roles ...string) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error { return p.writeRoles(ctx, userID, roles) })
}

func (p *Plugin) doSetRole(ctx context.Context, c *auth.Call, in SetRoleRequest) (auth.Done, error) {
	if err := p.require(ctx, c, ResourceUser, ActionSetRole); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.writeRoles(ctx, in.UserID, in.Role)
}

// writeRoles stores roles and keeps the staff flag in step: set when the
// roles hold an admin role, cleared when they do not, so the flag, the user
// list's admin filter and the last-admin count keep meaning "admin". Taking
// the last admin's admin role is ErrLastAdmin.
func (p *Plugin) writeRoles(ctx context.Context, userID string, roles []string) error {
	roles = splitRoles(strings.Join(roles, roleSeparator))
	if len(roles) == 0 {
		return ErrBadRole
	}
	for _, r := range roles {
		if !p.definesRole(r) {
			return ErrBadRole
		}
	}
	r, err := p.load(ctx, userID)
	if err != nil {
		return err
	}
	admin := slices.ContainsFunc(roles, p.isAdminRole)
	if !admin && r.cols.AdminGrantedAt != nil {
		n, err := p.admins(ctx)
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastAdmin
		}
	}
	stored := strings.Join(roles, roleSeparator)
	if err := auth.SetUserColumn(ctx, p.core, PluginName, userID, UserRole, stored); err != nil {
		return err
	}
	switch {
	case admin && r.cols.AdminGrantedAt == nil:
		now := p.core.Now()
		return auth.SetUserColumn(ctx, p.core, PluginName, userID, GrantedAt, &now)
	case !admin && r.cols.AdminGrantedAt != nil:
		return auth.SetUserColumn(ctx, p.core, PluginName, userID, GrantedAt, (*time.Time)(nil))
	}
	return nil
}

func (p *Plugin) doHasPermission(ctx context.Context, c *auth.Call, in PermissionRequest) (PermissionResult, error) {
	who := c.User.ID
	if in.UserID != "" && in.UserID != who {
		if err := p.require(ctx, c, ResourceUser, ActionGet); err != nil {
			return PermissionResult{}, err
		}
		if _, err := p.load(ctx, in.UserID); err != nil {
			return PermissionResult{}, err
		}
		who = in.UserID
	}
	cols, err := p.columnsOf(ctx, who)
	if err != nil {
		return PermissionResult{}, err
	}
	ok, err := p.decide(ctx, AccessRequest{UserID: who, Roles: p.rolesOf(who, cols), Permissions: in.Permissions,
		Connector: in.Connector, Operation: c.Op.ID, Call: c})
	return PermissionResult{Success: ok}, err
}
