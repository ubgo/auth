package scim

import (
	"context"
	"slices"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Role projection, better-auth's projection.roles and projection.reconcileUser:
// the app maps each group to roles, the plugin keeps one grant row per
// member and role (scimProjectionGrant), and tells the app each affected
// user's full grant list after every change, inside the request's
// transaction. It sits beside GroupMapper: the mapper sees groups, the
// projection sees users and roles.
const (
	TableNameGrant  = "auth_scim_grant"
	TableAliasGrant = "scx"
	ColRole         = "role"
)

// TableGrant and its typed columns.
var (
	TableGrant      = sqlb.Table{Name: TableNameGrant, Alias: TableAliasGrant}
	GrantConnection = sqlb.Col[string](TableGrant, ColConnectionID)
	GrantGroupID    = sqlb.Col[string](TableGrant, ColGroupID)
	GrantSCIMUserID = sqlb.Col[string](TableGrant, ColSCIMUserID)
	GrantUserID     = sqlb.Col[string](TableGrant, ColUserID)
	GrantRole       = sqlb.Col[string](TableGrant, ColRole)
	GrantCreatedAt  = sqlb.Col[time.Time](TableGrant, ColCreatedAt)
)

// RoleSource is the group a role is mapped from.
type RoleSource struct {
	ConnectionID string
	GroupID      string
	ExternalID   string
	DisplayName  string
}

// RoleGrant is one role a user holds through one group.
type RoleGrant struct {
	ConnectionID string
	GroupID      string
	Role         string
}

// ProjectedUser is a user's projected state: Active while any linked SCIM
// user is active, and every role it holds through any group.
type ProjectedUser struct {
	UserID string
	Active bool
	Grants []RoleGrant
}

// RoleProjection configures ProjectRoles.
//
//ds:def id=scim-roleprojection-6m3wq8kv owner=@khanakia stability=stable
type RoleProjection struct {
	// Map returns the roles a group grants its members (projection.roles.map).
	Map func(ctx context.Context, g RoleSource) ([]string, error)
	// Exists, when set, keeps only roles the app knows
	// (projection.roles.exists); a refused role grants nothing.
	Exists func(ctx context.Context, connectionID, role string) (bool, error)
	// Reconcile receives each affected user's full state, idempotent, in the
	// request's transaction (projection.reconcileUser); an error rolls back.
	Reconcile func(ctx context.Context, u ProjectedUser) error
}

// ProjectRoles turns role projection on.
func ProjectRoles(rp RoleProjection) Option { return func(p *Plugin) { p.roles = &rp } }

// grantMigration creates the grant table.
func (p *Plugin) grantMigration(t auth.SQLTypes) string {
	return "CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableGrant) + " (" +
		ColConnectionID + " " + t.Key + " NOT NULL, " +
		ColGroupID + " " + t.ID + " NOT NULL, " +
		ColSCIMUserID + " " + t.ID + " NOT NULL, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColRole + " " + t.Key + " NOT NULL, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		"PRIMARY KEY (" + ColGroupID + ", " + ColSCIMUserID + ", " + ColRole + "))" + t.TableSuffix
}

// projectGroup recomputes a group's grants from its members and roles and
// reconciles every user who held or now holds one. A nil members list
// (the group is gone) removes its grants.
func (p *Plugin) projectGroup(ctx context.Context, src RoleSource, members []memberRef) error {
	if p.roles == nil {
		return nil
	}
	var uid string
	affected := map[string]bool{}
	if err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(GrantUserID, &uid)).From(TableGrant).Where(sqlb.Eq(GrantGroupID, src.GroupID)),
		func() error { affected[uid] = true; return nil }); err != nil {
		return err
	}
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableGrant).Where(sqlb.Eq(GrantGroupID, src.GroupID))); err != nil {
		return err
	}
	var roles []string
	if len(members) > 0 {
		mapped, err := p.roles.Map(ctx, src)
		if err != nil {
			return err
		}
		for _, r := range mapped {
			if r == "" || slices.Contains(roles, r) {
				continue
			}
			if p.roles.Exists != nil {
				ok, err := p.roles.Exists(ctx, src.ConnectionID, r)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
			}
			roles = append(roles, r)
		}
	}
	now := p.now()
	for _, m := range members {
		affected[m.userID] = true
		for _, r := range roles {
			if _, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TableGrant).Row(
				sqlb.Set(GrantConnection, src.ConnectionID), sqlb.Set(GrantGroupID, src.GroupID), sqlb.Set(GrantSCIMUserID, m.scimID),
				sqlb.Set(GrantUserID, m.userID), sqlb.Set(GrantRole, r), sqlb.Set(GrantCreatedAt, now),
			)); err != nil {
				return err
			}
		}
	}
	users := make([]string, 0, len(affected))
	for u := range affected {
		users = append(users, u)
	}
	slices.Sort(users)
	for _, u := range users {
		if err := p.reconcileRoles(ctx, u); err != nil {
			return err
		}
	}
	return nil
}

// reconcileRoles hands Reconcile one user's full projected state.
func (p *Plugin) reconcileRoles(ctx context.Context, userID string) error {
	if p.roles == nil || p.roles.Reconcile == nil {
		return nil
	}
	var active int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &active)).From(TableUser).
		Where(sqlb.Eq(UserUserID, userID), sqlb.Eq(UserActive, true))); err != nil {
		return err
	}
	out := ProjectedUser{UserID: userID, Active: active > 0, Grants: []RoleGrant{}}
	var g RoleGrant
	err := p.core.Each(ctx, p.core.Select().Columns(sqlb.Bind(GrantConnection, &g.ConnectionID), sqlb.Bind(GrantGroupID, &g.GroupID), sqlb.Bind(GrantRole, &g.Role)).
		From(TableGrant).Where(sqlb.Eq(GrantUserID, userID)).
		Order(sqlb.OrderBy(GrantGroupID, sqlb.SortAsc), sqlb.OrderBy(GrantRole, sqlb.SortAsc)),
		func() error {
			if !slices.Contains(out.Grants, g) {
				out.Grants = append(out.Grants, g)
			}
			return nil
		})
	if err != nil {
		return err
	}
	return p.roles.Reconcile(ctx, out)
}
