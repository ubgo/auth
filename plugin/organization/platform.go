package organization

import (
	"context"
	"database/sql"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// The platform API: what an operator of the whole app (a support desk, an
// admin dashboard) does to any organization, from Go only. Every function
// here trusts its caller: there is no session, no membership and no
// permission check, so it belongs behind the app's own admin gate (for
// example a handler wrapped in the admin plugin's RequireAdmin). The rules
// that keep an organization sound still hold: the slug rules, the last-owner
// rule and every hook. Each runs in one transaction, joining the caller's if
// any, like CreateFor. Together with CreateFor and AddMember this is
// a dashboard organization overview, as a library.

// AllOrgsRequest is the input of ListAll. Search keeps organizations whose
// slug contains it; a slug is lowercase, so the search is lowercased first
// and matches the same on every engine.
type AllOrgsRequest struct {
	Page   int
	Limit  int
	Search string
}

// OrgSummary is an organization with how many members it has.
type OrgSummary struct {
	Org
	MemberCount int64 `json:"memberCount"`
}

// AllOrgsResult is one page of ListAll, newest first.
type AllOrgsResult struct {
	Orgs  []OrgSummary `json:"orgs"`
	Total int64        `json:"total"`
	Page  int          `json:"page"`
	Limit int          `json:"limit"`
}

// ListAll pages through every organization of the app, newest first, with
// member counts. Limit defaults to DefaultMembersPage and is clamped to
// MaxMembersPage, as the members list is.
func (p *Plugin) ListAll(ctx context.Context, in AllOrgsRequest) (AllOrgsResult, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = DefaultMembersPage
	}
	limit = min(limit, MaxMembersPage)
	page := max(in.Page, 1)
	var where []sqlb.Predicate
	if in.Search != "" {
		where = append(where, sqlb.Contains(OrgSlug, strings.ToLower(strings.TrimSpace(in.Search))))
	}
	out := AllOrgsResult{Orgs: []OrgSummary{}, Page: page, Limit: limit}
	var row OrgSummary
	var count *int64 // a scalar subquery is nullable to the type system
	cols, done := p.orgCols(&row.Org)
	members := p.core.Select().Exprs(sqlb.Count()).From(TableMember).Where(sqlb.EqExpr(MemberOrgID, OrgID))
	q := p.core.Select().Columns(append(cols, sqlb.Bind(sqlb.Subquery[int64](members), &count))...).From(TableOrg).Where(where...).
		Order(sqlb.OrderBy(OrgCreatedAt, sqlb.SortDesc), sqlb.OrderBy(OrgID, sqlb.SortAsc)).Limit(limit).Offset((page - 1) * limit)
	err := p.core.Each(ctx, q, func() error {
		done()
		row.MemberCount = 0
		if count != nil {
			row.MemberCount = *count
		}
		out.Orgs = append(out.Orgs, row)
		return nil
	})
	if err != nil {
		return AllOrgsResult{}, err
	}
	cq := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &out.Total)).From(TableOrg).Where(where...)
	return out, p.core.One(ctx, cq)
}

// GetFor reads any organization by id; ErrNotMember when there is none, the
// code every other read gives for an unknown organization.
func (p *Plugin) GetFor(ctx context.Context, orgID string) (Org, error) {
	return p.orgByIDOrSlug(ctx, orgID, "")
}

// UpdateFor changes any organization. ServerOnly fields are allowed, since
// the caller is trusted code.
func (p *Plugin) UpdateFor(ctx context.Context, orgID string, data OrgUpdate) (o Org, err error) {
	err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		old, err := p.GetFor(ctx, orgID)
		if err != nil {
			return err
		}
		o, err = p.applyUpdate(ctx, old, data, false)
		return err
	})
	return o, err
}

// DeleteFor deletes any organization and every row of it, between the
// delete hooks.
func (p *Plugin) DeleteFor(ctx context.Context, orgID string) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		o, err := p.GetFor(ctx, orgID)
		if err != nil {
			return err
		}
		return p.removeOrg(ctx, o)
	})
}

// MembersFor pages through any organization's members with in's paging,
// sort and filter (in.OrgID names the organization; it is required here,
// since there is no session to supply an active one).
func (p *Plugin) MembersFor(ctx context.Context, in OrgRequest) (MembersResult, error) {
	if _, err := p.GetFor(ctx, in.OrgID); err != nil {
		return MembersResult{}, err
	}
	return p.membersPage(ctx, in.OrgID, in)
}

// SetRoleFor gives a member of any organization role. The caller acts with
// the creator role, so it may grant or take it, but the last holder still
// cannot be demoted (ErrLastOwner) and the role hooks run.
func (p *Plugin) SetRoleFor(ctx context.Context, orgID, userID string, role Role) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		if err := p.checkRole(ctx, orgID, role); err != nil {
			return err
		}
		return p.applyRole(ctx, orgID, userID, role, p.creatorRole)
	})
}

// RemoveMemberFor removes a member from any organization, between the member
// hooks; the last holder of the creator role cannot be removed
// (ErrLastOwner), so no organization is left without one.
func (p *Plugin) RemoveMemberFor(ctx context.Context, orgID, userID string) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		theirs, err := p.RoleOf(ctx, orgID, userID)
		if err != nil {
			return err
		}
		return p.applyRemove(ctx, orgID, userID, theirs)
	})
}

// InvitationsFor lists every invitation of any organization, newest first,
// with its status, as list-invitations does for a member.
func (p *Plugin) InvitationsFor(ctx context.Context, orgID string) ([]Invitation, error) {
	if _, err := p.GetFor(ctx, orgID); err != nil {
		return nil, err
	}
	return p.invitations(ctx, orgID)
}

// CancelFor withdraws a pending invitation of any organization. by is
// recorded as who canceled it and handed to the cancel hooks; an invitation
// that is unknown or no longer pending is ErrInviteInvalid.
func (p *Plugin) CancelFor(ctx context.Context, inviteID string, by auth.User) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		row, err := p.invitationRow(ctx, inviteID)
		if err != nil {
			return err
		}
		if row.Status != StatusPending {
			return ErrInviteInvalid
		}
		_, err = p.closeInvitation(ctx, row, by, StatusCanceled, p.hooks.BeforeCancelInvitation, p.hooks.AfterCancelInvitation)
		return err
	})
}
