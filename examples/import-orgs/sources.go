package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/organization"
)

// auth0Org is one organization from GET /api/v2/organizations, with the
// members of GET /api/v2/organizations/{id}/members?fields=user_id,roles
// saved under "members".
type auth0Org struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Members     []struct {
		UserID string      `json:"user_id"`
		Roles  []auth0Role `json:"roles"`
	} `json:"members"`
}

// auth0Role is a role as Auth0 lists it.
type auth0Role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// auth0OrgRoles maps Auth0 organization role names, compared ignoring case,
// onto the organization plugin's roles. Auth0 has no built-in organization
// roles: these are the names most tenants create; a name not listed maps to
// member, with a note.
//
//ds:def id=auth0orgroles-8r4mv2xs
var auth0OrgRoles = map[string]organization.Role{
	"owner":  organization.RoleOwner,
	"admin":  organization.RoleAdmin,
	"member": organization.RoleMember,
}

// readAuth0 reads a JSON array of auth0Org. An organization's name is its
// slug (Auth0 restricts it to lowercase letters, digits and dashes) and its
// display name its name; a member with several roles gets the highest.
func readAuth0(r io.Reader) ([]org, error) {
	var in []auth0Org
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("auth0: want an array of organizations: %w", err)
	}
	out := make([]org, 0, len(in))
	for _, o := range in {
		g := org{SourceID: o.ID, Name: o.DisplayName, Slug: o.Name}
		if g.Name == "" {
			g.Name = o.Name
		}
		for _, m := range o.Members {
			mm := member{UserID: m.UserID, Role: organization.RoleMember}
			var unknown []string
			for _, role := range m.Roles {
				mapped, ok := auth0OrgRoles[strings.ToLower(role.Name)]
				if !ok {
					unknown = append(unknown, role.Name)
					continue
				}
				if mapped.Rank() > mm.Role.Rank() {
					mm.Role = mapped
				}
			}
			if len(unknown) > 0 {
				mm.Note = fmt.Sprintf("role %s has no equivalent; imported as %s", strings.Join(unknown, ", "), mm.Role)
			}
			g.Members = append(g.Members, mm)
		}
		out = append(out, g)
	}
	return out, nil
}

// auth0TenantRole is one tenant role from GET /api/v2/roles, with the users
// of GET /api/v2/roles/{id}/users saved under "users".
type auth0TenantRole struct {
	Name  string `json:"name"`
	Users []struct {
		UserID string `json:"user_id"`
	} `json:"users"`
}

// readAuth0Roles reads a JSON array of auth0TenantRole and returns, per
// user, the admin plugin roles to set: admin.RoleAdmin for a user holding a
// role named in adminRoles (ignoring case). Every other Auth0 role is the
// app's own permission model and is not imported.
//
//ds:def id=readauth0roles-5n7qc3wk
func readAuth0Roles(r io.Reader, adminRoles []string) (map[string][]string, error) {
	var in []auth0TenantRole
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("auth0 roles: want an array of roles: %w", err)
	}
	out := map[string][]string{}
	for _, role := range in {
		if !slices.ContainsFunc(adminRoles, func(n string) bool { return strings.EqualFold(n, role.Name) }) {
			continue
		}
		for _, u := range role.Users {
			out[u.UserID] = []string{admin.RoleAdmin}
		}
	}
	return out, nil
}

// clerkOrg is one organization from GET /v1/organizations, with the
// memberships of GET /v1/organizations/{id}/memberships saved under
// "memberships".
type clerkOrg struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	CreatedBy   string `json:"created_by"`
	Memberships []struct {
		Role           string `json:"role"`
		PublicUserData struct {
			UserID string `json:"user_id"`
		} `json:"public_user_data"`
	} `json:"memberships"`
}

// clerkOrgRoles maps Clerk's two built-in organization roles; a custom
// "org:…" role maps to member, with a note.
//
//ds:def id=clerkorgroles-2w9dx6pb
var clerkOrgRoles = map[string]organization.Role{
	"org:admin":  organization.RoleAdmin,
	"org:member": organization.RoleMember,
}

// readClerk reads a JSON array of clerkOrg. Clerk has no owner role: the
// creator (created_by) becomes the owner.
func readClerk(r io.Reader) ([]org, error) {
	var in []clerkOrg
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("clerk: want an array of organizations: %w", err)
	}
	out := make([]org, 0, len(in))
	for _, o := range in {
		g := org{SourceID: o.ID, Name: o.Name, Slug: o.Slug, CreatorID: o.CreatedBy}
		for _, m := range o.Memberships {
			mm := member{UserID: m.PublicUserData.UserID, Role: organization.RoleMember}
			if mapped, ok := clerkOrgRoles[m.Role]; ok {
				mm.Role = mapped
			} else {
				mm.Note = fmt.Sprintf("role %s has no equivalent; imported as %s", m.Role, mm.Role)
			}
			g.Members = append(g.Members, mm)
		}
		out = append(out, g)
	}
	return out, nil
}
