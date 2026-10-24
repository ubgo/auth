package organization

import (
	"context"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/sqlb"
)

// InvitationsResult is the output of list-invitations.
type InvitationsResult struct {
	Invitations []Invitation `json:"invitations"`
}

// Reject declines one of the signed-in user's pending invitations.
func (p *Plugin) Reject(ctx context.Context, inviteID string) error {
	_, err := p.reject.Call(ctx, AcceptRequest{InviteID: inviteID})
	return err
}

// Cancel withdraws a pending invitation, as a member of its organization
// with invitation:cancel.
func (p *Plugin) Cancel(ctx context.Context, inviteID string) error {
	_, err := p.cancel.Call(ctx, AcceptRequest{InviteID: inviteID})
	return err
}

// ListInvitations returns every invitation of an organization the signed-in
// user belongs to, newest first, whatever its state.
func (p *Plugin) ListInvitations(ctx context.Context, orgID string) ([]Invitation, error) {
	r, err := p.listInvitations.Call(ctx, OrgRequest{OrgID: orgID})
	return r.Invitations, err
}

// doReject finds the invitation through the same verified-address match as
// accept, so only its addressee can decline it.
func (p *Plugin) doReject(ctx context.Context, c *auth.Call, in AcceptRequest) (auth.Done, error) {
	inv, err := p.pendingByID(ctx, c.User.ID, in.InviteID)
	if err != nil {
		return auth.Done{}, err
	}
	row, err := p.invitationRow(ctx, inv.ID)
	if err != nil {
		return auth.Done{}, err
	}
	c.Annotate(auth.AnnotationOrganization, row.OrgID)
	return p.closeInvitation(ctx, row, *c.User, StatusRejected, p.hooks.BeforeRejectInvitation, p.hooks.AfterRejectInvitation)
}

// doCancel needs invitation:cancel in the invitation's organization. A
// stranger, and an invitation that is not pending, get ErrInviteInvalid, so
// a guessed id reveals nothing.
func (p *Plugin) doCancel(ctx context.Context, c *auth.Call, in AcceptRequest) (auth.Done, error) {
	row, err := p.invitationRow(ctx, in.InviteID)
	if err != nil {
		return auth.Done{}, err
	}
	mine, err := p.RoleOf(ctx, row.OrgID, c.User.ID)
	if err != nil {
		return auth.Done{}, ErrInviteInvalid
	}
	// Only once the caller is a member: a stranger's refused guess must not
	// tie the invitation's organization to them in the log.
	c.Annotate(auth.AnnotationOrganization, row.OrgID)
	if err := p.authorize(ctx, c, row.OrgID, mine, access.Request{ResourceInvitation: access.All(ActionCancel)}); err != nil {
		return auth.Done{}, err
	}
	if row.Status != StatusPending {
		return auth.Done{}, ErrInviteInvalid
	}
	return p.closeInvitation(ctx, row, *c.User, StatusCanceled, p.hooks.BeforeCancelInvitation, p.hooks.AfterCancelInvitation)
}

// closeInvitation moves a pending invitation to status between the hooks.
// The status is in the WHERE, so a concurrent accept or cancel wins once.
func (p *Plugin) closeInvitation(ctx context.Context, row Invitation, by auth.User, status InviteStatus, before, after func(context.Context, Invitation, auth.User) error) (auth.Done, error) {
	if before != nil {
		if err := before(ctx, row, by); err != nil {
			return auth.Done{}, err
		}
	}
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableInvite).Set(sqlb.Set(InviteStatusCol, status)).
		Where(sqlb.Eq(InviteID, row.ID), sqlb.Eq(InviteStatusCol, StatusPending))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return auth.Done{}, err
	}
	if n != 1 {
		return auth.Done{}, ErrInviteInvalid
	}
	row.Status = status
	if after != nil {
		if err := after(ctx, row, by); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) doListInvitations(ctx context.Context, c *auth.Call, in OrgRequest) (InvitationsResult, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return InvitationsResult{}, err
	}
	if _, err := p.RoleOf(ctx, orgID, c.User.ID); err != nil {
		return InvitationsResult{}, err
	}
	list, err := p.invitations(ctx, orgID)
	return InvitationsResult{Invitations: list}, err
}

// invitations lists orgID's invitations matching where, newest first.
func (p *Plugin) invitations(ctx context.Context, orgID string, where ...sqlb.Predicate) ([]Invitation, error) {
	var row Invitation
	out := []Invitation{}
	cols, done := p.invitationCols(&row)
	q := p.core.Select().Columns(cols...).From(TableInvite).
		Where(append([]sqlb.Predicate{sqlb.Eq(InviteOrgID, orgID)}, where...)...).
		Order(sqlb.OrderBy(InviteCreatedAt, sqlb.SortDesc), sqlb.OrderBy(InviteID, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error { done(); out = append(out, row); return nil })
	return out, err
}

// invitationRow reads one invitation by id; ErrInviteInvalid when there is
// none.
func (p *Plugin) invitationRow(ctx context.Context, id string) (Invitation, error) {
	var row Invitation
	cols, done := p.invitationCols(&row)
	q := p.core.Select().Columns(cols...).From(TableInvite).Where(sqlb.Eq(InviteID, id)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		return Invitation{}, errIsNoRows(err, ErrInviteInvalid)
	}
	done()
	return row, nil
}
