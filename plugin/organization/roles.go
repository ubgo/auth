package organization

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/sqlb"
)

// DynamicRolesConfig configures roles created at run time (DynamicRoles),
// better-auth's dynamicAccessControl.
type DynamicRolesConfig struct {
	// MaxRoles caps the dynamic roles of one organization
	// (maximumRolesPerOrganization); zero is no cap.
	MaxRoles int
}

// OrgRole is a role an organization created at run time: a name and the
// permissions it grants, from the access control's statements.
type OrgRole struct {
	ID         string             `json:"id"`
	OrgID      string             `json:"orgId"`
	Role       Role               `json:"role"`
	Permission access.Permissions `json:"permission"`
	CreatedAt  time.Time          `json:"createdAt"`
	UpdatedAt  time.Time          `json:"updatedAt"`
	// Fields are the extra columns WithFields declares
	// (organizationRole.additionalFields).
	Fields auth.Fields `json:"fields,omitempty"`
}

// PermissionDoc is access.Permissions as a column: JSON text on every
// engine.
type PermissionDoc access.Permissions

// Value stores the permissions as JSON text.
func (d PermissionDoc) Value() (driver.Value, error) {
	b, err := json.Marshal(access.Permissions(d))
	return string(b), err
}

// Scan reads the JSON text the three drivers return as a string or bytes.
func (d *PermissionDoc) Scan(src any) error {
	var b []byte
	switch v := src.(type) {
	case string:
		b = []byte(v)
	case []byte:
		b = v
	default:
		return fmt.Errorf("organization: scan permissions from %T", src)
	}
	var p access.Permissions
	if err := json.Unmarshal(b, &p); err != nil {
		return fmt.Errorf("organization: decode permissions: %w", err)
	}
	*d = PermissionDoc(p)
	return nil
}

// CreateRoleRequest is the input of create-role; an empty OrgID means the
// active organization.
type CreateRoleRequest struct {
	OrgID      string             `json:"orgId,omitempty"`
	Role       Role               `json:"role"`
	Permission access.Permissions `json:"permission"`
	Fields     auth.Fields        `json:"fields,omitempty"`
	// top holds top-level body keys for fieldSet.merge; never set from Go.
	top auth.Fields
}

// RoleRequest names a dynamic role by id, or by name when RoleID is empty,
// as the input of delete-role and get-role.
type RoleRequest struct {
	OrgID    string `json:"orgId,omitempty"`
	RoleID   string `json:"roleId,omitempty"`
	RoleName Role   `json:"roleName,omitempty"`
}

// UpdateRoleRequest is the input of update-role.
type UpdateRoleRequest struct {
	OrgID    string     `json:"orgId,omitempty"`
	RoleID   string     `json:"roleId,omitempty"`
	RoleName Role       `json:"roleName,omitempty"`
	Data     RoleUpdate `json:"data"`
}

// RoleUpdate is what update-role changes; nil stays.
type RoleUpdate struct {
	RoleName   *Role              `json:"roleName,omitempty"`
	Permission access.Permissions `json:"permission,omitempty"`
	Fields     auth.Fields        `json:"fields,omitempty"`
	// top holds top-level body keys for fieldSet.merge; never set from Go.
	top auth.Fields
}

// RolesResult is the output of list-roles.
type RolesResult struct {
	Roles []OrgRole `json:"roles"`
}

// CreateRole creates a dynamic role, as a member with ac:create who holds
// every permission the role grants.
func (p *Plugin) CreateRole(ctx context.Context, in CreateRoleRequest) (OrgRole, error) {
	return p.createRole.Call(ctx, in)
}

// UpdateRole renames a dynamic role or replaces its permissions, as a member
// with ac:update.
func (p *Plugin) UpdateRole(ctx context.Context, in UpdateRoleRequest) (OrgRole, error) {
	return p.updateRole.Call(ctx, in)
}

// DeleteRole deletes a dynamic role no member holds, as a member with
// ac:delete.
func (p *Plugin) DeleteRole(ctx context.Context, in RoleRequest) error {
	_, err := p.deleteRole.Call(ctx, in)
	return err
}

// GetRole returns a dynamic role, as a member with ac:read.
func (p *Plugin) GetRole(ctx context.Context, in RoleRequest) (OrgRole, error) {
	return p.getRole.Call(ctx, in)
}

// ListRoles lists an organization's dynamic roles, as a member with ac:read.
func (p *Plugin) ListRoles(ctx context.Context, orgID string) ([]OrgRole, error) {
	r, err := p.listRoles.Call(ctx, OrgRequest{OrgID: orgID})
	return r.Roles, err
}

// roleBindings binds every auth_org_role column to r.
func roleBindings(r *OrgRole, perm *PermissionDoc) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(RoleID, &r.ID), sqlb.Bind(RoleOrgID, &r.OrgID), sqlb.Bind(RoleName, &r.Role),
		sqlb.Bind(RolePermission, perm), sqlb.Bind(RoleCreatedAt, &r.CreatedAt), sqlb.Bind(RoleUpdatedAt, &r.UpdatedAt),
	}
}

// rolesOf lists orgID's dynamic roles matching where, by name.
func (p *Plugin) rolesOf(ctx context.Context, orgID string, where ...sqlb.Predicate) ([]OrgRole, error) {
	var r OrgRole
	var perm PermissionDoc
	out := []OrgRole{}
	extra, read := p.roleFields().read()
	q := p.core.Select().Columns(append(roleBindings(&r, &perm), extra...)...).From(TableRole).
		Where(append([]sqlb.Predicate{sqlb.Eq(RoleOrgID, orgID)}, where...)...).Order(sqlb.OrderBy(RoleName, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error {
		r.Permission = access.Permissions(perm)
		r.Fields = read()
		out = append(out, r)
		return nil
	})
	return out, err
}

// dynamicRole is orgID's dynamic role named name, as an access role; found
// is false without DynamicRoles, or when there is none. A stored permission
// the access control no longer declares grants nothing rather than failing
// every check of the organization.
func (p *Plugin) dynamicRole(ctx context.Context, orgID string, name Role) (access.Role, bool, error) {
	if p.dynamic == nil || orgID == "" {
		return access.Role{}, false, nil
	}
	list, err := p.rolesOf(ctx, orgID, sqlb.Eq(RoleName, name))
	if err != nil || len(list) == 0 {
		return access.Role{}, false, err
	}
	r, err := p.ac.NewRole(list[0].Permission)
	if err != nil {
		return access.Role{}, true, nil
	}
	return r, true, nil
}

// acMember resolves the organization and requires an ac permission of the
// caller.
func (p *Plugin) acMember(ctx context.Context, c *auth.Call, orgID, action string) (string, Role, error) {
	orgID, err := p.resolveOrg(ctx, c, orgID)
	if err != nil {
		return "", "", err
	}
	mine, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return "", "", err
	}
	return orgID, mine, p.authorize(ctx, c, orgID, mine, access.Request{ResourceAC: access.All(action)})
}

// checkGrant refuses permissions outside the statements, and permissions
// the caller does not hold: a member cannot mint a role more powerful than
// their own.
func (p *Plugin) checkGrant(ctx context.Context, c *auth.Call, orgID string, mine Role, perm access.Permissions) error {
	if err := p.ac.Check(perm); err != nil {
		return ErrBadPermission
	}
	for res, acts := range perm {
		if len(acts) == 0 {
			continue
		}
		ok, err := p.allows(ctx, c, orgID, c.User.ID, mine, access.Request{res: access.All(acts...)}, access.And)
		if err != nil {
			return err
		}
		if !ok {
			return ErrBadPermission
		}
	}
	return nil
}

// checkRoleName accepts one trimmed name, no comma, not a static role's.
func (p *Plugin) checkRoleName(name Role) error {
	if name == "" || strings.TrimSpace(string(name)) != string(name) || strings.Contains(string(name), roleSeparator) {
		return ErrBadRole
	}
	if _, ok := p.roles[name]; ok {
		return ErrRoleTaken
	}
	return nil
}

func (p *Plugin) doCreateRole(ctx context.Context, c *auth.Call, in CreateRoleRequest) (OrgRole, error) {
	orgID, mine, err := p.acMember(ctx, c, in.OrgID, ActionCreate)
	if err != nil {
		return OrgRole{}, err
	}
	if err := p.checkRoleName(in.Role); err != nil {
		return OrgRole{}, err
	}
	if err := p.checkGrant(ctx, c, orgID, mine, in.Permission); err != nil {
		return OrgRole{}, err
	}
	fs := p.roleFields()
	if in.Fields, err = fs.merge(in.Fields, in.top); err != nil {
		return OrgRole{}, err
	}
	extra, err := fs.set(in.Fields, fromClient(c), true)
	if err != nil {
		return OrgRole{}, err
	}
	existing, err := p.rolesOf(ctx, orgID)
	if err != nil {
		return OrgRole{}, err
	}
	for _, r := range existing {
		if r.Role == in.Role {
			return OrgRole{}, ErrRoleTaken
		}
	}
	if max := p.dynamic.MaxRoles; max > 0 && len(existing) >= max {
		return OrgRole{}, ErrRolesLimit
	}
	id, err := p.core.NewID(idPrefixRole)
	if err != nil {
		return OrgRole{}, err
	}
	now := p.core.Now()
	r := OrgRole{ID: id, OrgID: orgID, Role: in.Role, Permission: in.Permission.Clone(), CreatedAt: now, UpdatedAt: now}
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableRole).Row(append([]sqlb.Assignment{sqlb.Set(RoleID, r.ID), sqlb.Set(RoleOrgID, r.OrgID), sqlb.Set(RoleName, r.Role),
		sqlb.Set(RolePermission, PermissionDoc(r.Permission)), sqlb.Set(RoleCreatedAt, r.CreatedAt), sqlb.Set(RoleUpdatedAt, r.UpdatedAt)}, extra...)...)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return OrgRole{}, err
	}
	if len(fs.fields) > 0 {
		return p.findRole(ctx, orgID, r.ID, "")
	}
	return r, nil
}

// predefined reports whether a role request names, by name, a role fixed
// in configuration rather than a dynamic one.
func (p *Plugin) predefined(id string, name Role) bool {
	_, ok := p.roles[name]
	return id == "" && ok
}

// findRole reads the dynamic role in names, by id or name; ErrRoleNotFound
// when there is none.
func (p *Plugin) findRole(ctx context.Context, orgID, id string, name Role) (OrgRole, error) {
	where := sqlb.Eq(RoleName, name)
	if id != "" {
		where = sqlb.Eq(RoleID, id)
	}
	list, err := p.rolesOf(ctx, orgID, where)
	if err != nil {
		return OrgRole{}, err
	}
	if len(list) == 0 {
		return OrgRole{}, ErrRoleNotFound
	}
	return list[0], nil
}

// roleInUse reports whether a member of orgID holds name, splitting the
// stored roles in Go so the match is exact.
func (p *Plugin) roleInUse(ctx context.Context, orgID string, name Role) (bool, error) {
	var r Role
	used := false
	q := p.core.Select().Columns(sqlb.Bind(MemberRole, &r)).From(TableMember).Where(sqlb.Eq(MemberOrgID, orgID))
	err := p.core.Each(ctx, q, func() error {
		used = used || r.Has(name)
		return nil
	})
	return used, err
}

// doUpdateRole may rename a role only while no member holds it, since the
// members' stored role would otherwise name nothing.
func (p *Plugin) doUpdateRole(ctx context.Context, c *auth.Call, in UpdateRoleRequest) (OrgRole, error) {
	orgID, mine, err := p.acMember(ctx, c, in.OrgID, ActionUpdate)
	if err != nil {
		return OrgRole{}, err
	}
	if p.predefined(in.RoleID, in.RoleName) {
		return OrgRole{}, ErrPredefinedRole
	}
	r, err := p.findRole(ctx, orgID, in.RoleID, in.RoleName)
	if err != nil {
		return OrgRole{}, err
	}
	if in.Data.RoleName != nil && *in.Data.RoleName != r.Role {
		if err := p.checkRoleName(*in.Data.RoleName); err != nil {
			return OrgRole{}, err
		}
		if _, err := p.findRole(ctx, orgID, "", *in.Data.RoleName); err == nil {
			return OrgRole{}, ErrRoleTaken
		} else if !errors.Is(err, ErrRoleNotFound) {
			return OrgRole{}, err
		}
		used, err := p.roleInUse(ctx, orgID, r.Role)
		if err != nil {
			return OrgRole{}, err
		}
		if used {
			return OrgRole{}, ErrRoleInUse
		}
		r.Role = *in.Data.RoleName
	}
	if in.Data.Permission != nil {
		if err := p.checkGrant(ctx, c, orgID, mine, in.Data.Permission); err != nil {
			return OrgRole{}, err
		}
		r.Permission = in.Data.Permission.Clone()
	}
	fs := p.roleFields()
	if in.Data.Fields, err = fs.merge(in.Data.Fields, in.Data.top); err != nil {
		return OrgRole{}, err
	}
	extra, err := fs.set(in.Data.Fields, fromClient(c), false)
	if err != nil {
		return OrgRole{}, err
	}
	r.UpdatedAt = p.core.Now()
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableRole).Set(append([]sqlb.Assignment{sqlb.Set(RoleName, r.Role), sqlb.Set(RolePermission, PermissionDoc(r.Permission)),
		sqlb.Set(RoleUpdatedAt, r.UpdatedAt)}, extra...)...).Where(sqlb.Eq(RoleID, r.ID))
	if _, err := p.core.Exec(ctx, upd); err != nil {
		return OrgRole{}, err
	}
	if len(fs.fields) > 0 {
		return p.findRole(ctx, orgID, r.ID, "")
	}
	return r, nil
}

func (p *Plugin) doDeleteRole(ctx context.Context, c *auth.Call, in RoleRequest) (auth.Done, error) {
	orgID, _, err := p.acMember(ctx, c, in.OrgID, ActionDelete)
	if err != nil {
		return auth.Done{}, err
	}
	if p.predefined(in.RoleID, in.RoleName) {
		return auth.Done{}, ErrPredefinedRole
	}
	r, err := p.findRole(ctx, orgID, in.RoleID, in.RoleName)
	if err != nil {
		return auth.Done{}, err
	}
	used, err := p.roleInUse(ctx, orgID, r.Role)
	if err != nil {
		return auth.Done{}, err
	}
	if used {
		return auth.Done{}, ErrRoleInUse
	}
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableRole).Where(sqlb.Eq(RoleID, r.ID))); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) doGetRole(ctx context.Context, c *auth.Call, in RoleRequest) (OrgRole, error) {
	orgID, _, err := p.acMember(ctx, c, in.OrgID, ActionRead)
	if err != nil {
		return OrgRole{}, err
	}
	return p.findRole(ctx, orgID, in.RoleID, in.RoleName)
}

func (p *Plugin) doListRoles(ctx context.Context, c *auth.Call, in OrgRequest) (RolesResult, error) {
	orgID, _, err := p.acMember(ctx, c, in.OrgID, ActionRead)
	if err != nil {
		return RolesResult{}, err
	}
	list, err := p.rolesOf(ctx, orgID)
	return RolesResult{Roles: list}, err
}
