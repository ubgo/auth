package organization

import (
	"context"
	"strings"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/sqlb"
)

// GetRequest names an organization by id or slug, the active one when both
// are empty, as the input of get-organization and get-full-organization.
// MembersLimit bounds the members of the full read (DefaultMembersPage, at
// most MaxMembersPage).
type GetRequest struct {
	OrgID        string `json:"orgId,omitempty"`
	OrgSlug      string `json:"orgSlug,omitempty"`
	MembersLimit int    `json:"membersLimit,omitempty,string"`
}

// FullOrg is an organization with its members, its pending invitations and,
// with Teams, its teams: one read for a settings page.
type FullOrg struct {
	Org
	Members     []MemberView `json:"members"`
	Invitations []Invitation `json:"invitations"`
	Teams       []Team       `json:"teams,omitempty"`
}

// OrgUpdate is what update changes; a nil field stays as it is. An empty
// Logo clears the logo; Metadata replaces the whole document.
type OrgUpdate struct {
	Name     *string      `json:"name,omitempty"`
	Slug     *string      `json:"slug,omitempty"`
	Logo     *string      `json:"logo,omitempty"`
	Metadata auth.AppData `json:"metadata,omitempty"`
	// Fields change the extra columns named; the others stay.
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds top-level body keys for fieldSet.merge; never set from Go.
	top auth.Fields
}

// UpdateRequest is the input of update: the organization (the active one
// when OrgID is empty) and the changes.
type UpdateRequest struct {
	OrgID string    `json:"orgId,omitempty"`
	Data  OrgUpdate `json:"data"`
}

// Get returns an organization the signed-in user belongs to.
func (p *Plugin) Get(ctx context.Context, in GetRequest) (Org, error) {
	return p.get.Call(ctx, in)
}

// GetFull returns an organization with its members, pending invitations and
// teams.
func (p *Plugin) GetFull(ctx context.Context, in GetRequest) (FullOrg, error) {
	return p.getFull.Call(ctx, in)
}

// Update changes an organization, as a member with organization:update.
func (p *Plugin) Update(ctx context.Context, in UpdateRequest) (Org, error) {
	return p.update.Call(ctx, in)
}

// Delete deletes an organization and everything in it, as a member with
// organization:delete.
func (p *Plugin) Delete(ctx context.Context, orgID string) error {
	_, err := p.deleteOrg.Call(ctx, OrgRequest{OrgID: orgID})
	return err
}

// memberOrg resolves the organization in (by id, slug or the active one)
// and requires the caller to be a member, returning the caller's role.
func (p *Plugin) memberOrg(ctx context.Context, c *auth.Call, id, slug string) (Org, Role, error) {
	if id == "" && slug == "" {
		var err error
		if id, err = p.resolveOrg(ctx, c, ""); err != nil {
			return Org{}, "", err
		}
	}
	o, err := p.orgByIDOrSlug(ctx, id, slug)
	if err != nil {
		return Org{}, "", err
	}
	c.Annotate(auth.AnnotationOrganization, o.ID)
	r, err := p.RoleOf(ctx, o.ID, c.User.ID)
	return o, r, err
}

func (p *Plugin) doGet(ctx context.Context, c *auth.Call, in GetRequest) (Org, error) {
	o, _, err := p.memberOrg(ctx, c, in.OrgID, in.OrgSlug)
	return o, err
}

func (p *Plugin) doGetFull(ctx context.Context, c *auth.Call, in GetRequest) (FullOrg, error) {
	o, _, err := p.memberOrg(ctx, c, in.OrgID, in.OrgSlug)
	if err != nil {
		return FullOrg{}, err
	}
	limit := in.MembersLimit
	if limit <= 0 {
		limit = DefaultMembersPage
	}
	out := FullOrg{Org: o, Members: []MemberView{}, Invitations: []Invitation{}}
	order := []sqlb.OrderTerm{sqlb.OrderBy(MemberJoinedAt, sqlb.SortAsc), sqlb.OrderBy(MemberUserID, sqlb.SortAsc)}
	err = p.eachMember(ctx, []sqlb.Predicate{sqlb.Eq(MemberOrgID, o.ID)}, order, min(limit, MaxMembersPage), 0, func(v MemberView) {
		out.Members = append(out.Members, v)
	})
	if err != nil {
		return FullOrg{}, err
	}
	if out.Invitations, err = p.invitations(ctx, o.ID, sqlb.Eq(InviteStatusCol, StatusPending), sqlb.Greater(InviteExpiresAt, p.core.Now())); err != nil {
		return FullOrg{}, err
	}
	if p.teams != nil {
		if out.Teams, err = p.teamsOf(ctx, sqlb.Eq(TeamOrgID, o.ID)); err != nil {
			return FullOrg{}, err
		}
	}
	return out, nil
}

// doUpdate needs organization:update. The slug follows the create rules, and
// the hooks see the organization before and after.
func (p *Plugin) doUpdate(ctx context.Context, c *auth.Call, in UpdateRequest) (Org, error) {
	old, mine, err := p.memberOrg(ctx, c, in.OrgID, "")
	if err != nil {
		return Org{}, err
	}
	if err := p.authorize(ctx, c, old.ID, mine, access.Request{ResourceOrganization: access.All(ActionUpdate)}); err != nil {
		return Org{}, err
	}
	return p.applyUpdate(ctx, old, in.Data, fromClient(c))
}

// applyUpdate changes old by data between the update hooks. client refuses
// ServerOnly fields, as for a request.
func (p *Plugin) applyUpdate(ctx context.Context, old Org, data OrgUpdate, client bool) (Org, error) {
	in := UpdateRequest{OrgID: old.ID, Data: data}
	var err error
	o := old
	if in.Data.Name != nil {
		o.Name = strings.TrimSpace(*in.Data.Name)
	}
	if in.Data.Slug != nil {
		o.Slug = *in.Data.Slug
	}
	if in.Data.Logo != nil {
		o.Logo = in.Data.Logo
		if *in.Data.Logo == "" {
			o.Logo = nil
		}
	}
	if in.Data.Metadata != nil {
		o.Metadata = in.Data.Metadata
	}
	fs := p.orgFields()
	if in.Data.Fields, err = fs.merge(in.Data.Fields, in.Data.top); err != nil {
		return Org{}, err
	}
	if _, err := fs.set(in.Data.Fields, client, false); err != nil {
		return Org{}, err
	}
	o.Fields = mergeFields(old.Fields, in.Data.Fields)
	if h := p.hooks.BeforeUpdateOrg; h != nil {
		if err := h(ctx, old, &o); err != nil {
			return Org{}, err
		}
		o.ID, o.CreatedAt = old.ID, old.CreatedAt
	}
	if o.Slug = normalizeSlug(o.Slug); o.Slug == "" {
		return Org{}, ErrBadSlug
	}
	if err := checkMetadata(o.Metadata); err != nil {
		return Org{}, err
	}
	if o.Slug != old.Slug {
		// Checked first: a unique violation would abort a Postgres
		// transaction, and it needs to answer slug_taken.
		r, err := p.doCheckSlug(ctx, nil, SlugRequest{Slug: o.Slug})
		if err != nil {
			return Org{}, err
		}
		if !r.Available {
			return Org{}, ErrSlugTaken
		}
	}
	extra, err := fs.set(o.Fields, false, false)
	if err != nil {
		return Org{}, err
	}
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableOrg).Set(append([]sqlb.Assignment{
		sqlb.Set(OrgName, o.Name), sqlb.Set(OrgSlug, o.Slug), sqlb.Set(OrgLogo, o.Logo), sqlb.Set(OrgMetadata, o.Metadata),
	}, extra...)...).Where(sqlb.Eq(OrgID, o.ID))
	if _, err := p.core.Exec(ctx, upd); err != nil {
		return Org{}, err
	}
	if len(fs.fields) > 0 {
		if o, err = p.org(ctx, o.ID); err != nil {
			return Org{}, err
		}
	}
	if h := p.hooks.AfterUpdateOrg; h != nil {
		if err := h(ctx, o); err != nil {
			return Org{}, err
		}
	}
	return o, nil
}

// doDelete needs organization:delete and removes every row of the
// organization in the call's transaction: no foreign key cascades
// (ADR-0002), so this is the cascade.
func (p *Plugin) doDelete(ctx context.Context, c *auth.Call, in OrgRequest) (auth.Done, error) {
	o, mine, err := p.memberOrg(ctx, c, in.OrgID, "")
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.authorize(ctx, c, o.ID, mine, access.Request{ResourceOrganization: access.All(ActionDelete)}); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.removeOrg(ctx, o)
}

// removeOrg removes o and every row of it between the delete hooks.
func (p *Plugin) removeOrg(ctx context.Context, o Org) error {
	if h := p.hooks.BeforeDeleteOrg; h != nil {
		if err := h(ctx, o); err != nil {
			return err
		}
	}
	d := p.core.Dialect()
	dels := []auth.Statement{
		sqlb.NewDelete(d).From(TableMember).Where(sqlb.Eq(MemberOrgID, o.ID)),
		sqlb.NewDelete(d).From(TableInvite).Where(sqlb.Eq(InviteOrgID, o.ID)),
		sqlb.NewDelete(d).From(TableActive).Where(sqlb.Eq(activeOrgKey, o.ID)),
	}
	if p.teams != nil {
		teams := p.core.Select().Exprs(TeamID).From(TableTeam).Where(sqlb.Eq(TeamOrgID, o.ID))
		dels = append(dels,
			sqlb.NewDelete(d).From(TableTeamMember).Where(sqlb.InSubquery(TeamMemberTeamID, teams)),
			sqlb.NewDelete(d).From(TableTeam).Where(sqlb.Eq(TeamOrgID, o.ID)))
	}
	if p.dynamic != nil {
		dels = append(dels, sqlb.NewDelete(d).From(TableRole).Where(sqlb.Eq(RoleOrgID, o.ID)))
	}
	if p.domains != nil {
		dels = append(dels,
			sqlb.NewDelete(d).From(TableDomainRequest).Where(sqlb.Eq(RequestOrgID, o.ID)),
			sqlb.NewDelete(d).From(TableDomain).Where(sqlb.Eq(DomainOrgID, o.ID)))
	}
	dels = append(dels, sqlb.NewDelete(d).From(TableOrg).Where(sqlb.Eq(OrgID, o.ID)))
	for _, del := range dels {
		if _, err := p.core.Exec(ctx, del); err != nil {
			return err
		}
	}
	if h := p.hooks.AfterDeleteOrg; h != nil {
		return h(ctx, o)
	}
	return nil
}
