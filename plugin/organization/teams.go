package organization

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/sqlb"
)

// TeamsConfig configures teams (Teams), better-auth's teams option.
type TeamsConfig struct {
	// MaxTeams caps the teams of one organization; zero is no cap.
	MaxTeams int
	// MaxMembersPerTeam caps the members of one team; zero is no cap.
	MaxMembersPerTeam int
	// AllowRemovingAllTeams lets an organization's last team be removed;
	// by default it cannot be, so a team-scoped app always has one.
	AllowRemovingAllTeams bool
	// NoDefaultTeam stops create from making a team, with the creator in
	// it, named after the organization (better-auth's defaultTeam.enabled
	// false).
	NoDefaultTeam bool
	// DefaultTeamName names the default team (customCreateDefaultTeam);
	// the organization's name when nil.
	DefaultTeamName func(ctx context.Context, org Org, creator auth.User) (string, error)
}

// Team is a sub-group of an organization. MemberCount is counted when the
// team is read, not stored, so it cannot drift from the rows.
type Team struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"orgId"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	MemberCount int64     `json:"memberCount"`
	// Fields are the extra columns WithFields declares.
	Fields auth.Fields `json:"fields,omitempty"`
}

// TeamMember is one member of a team, with the user fields safe to show.
type TeamMember struct {
	TeamID    string        `json:"teamId"`
	User      auth.UserView `json:"user"`
	CreatedAt time.Time     `json:"createdAt"`
}

// CreateTeamRequest is the input of create-team; an empty OrgID means the
// active organization.
type CreateTeamRequest struct {
	OrgID  string      `json:"orgId,omitempty"`
	Name   string      `json:"name"`
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds top-level body keys for fieldSet.merge; never set from Go.
	top auth.Fields
}

// TeamRequest names a team, as the input of remove-team, set-active-team
// and list-team-members. An empty TeamID clears the active team in
// set-active-team, and means the active team in list-team-members.
type TeamRequest struct {
	TeamID string `json:"teamId"`
}

// UpdateTeamRequest is the input of update-team.
type UpdateTeamRequest struct {
	TeamID string     `json:"teamId"`
	Data   TeamUpdate `json:"data"`
}

// TeamUpdate is what update-team changes; nil stays.
type TeamUpdate struct {
	Name   *string     `json:"name,omitempty"`
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds top-level body keys for fieldSet.merge; never set from Go.
	top auth.Fields
}

// TeamMemberRequest names a member of a team, as the input of
// add-team-member and remove-team-member.
type TeamMemberRequest struct {
	TeamID string `json:"teamId"`
	UserID string `json:"userId"`
}

// TeamsResult is the output of list-teams and list-user-teams.
type TeamsResult struct {
	Teams []Team `json:"teams"`
}

// TeamMembersResult is the output of list-team-members.
type TeamMembersResult struct {
	Members []TeamMember `json:"members"`
}

// CreateTeam creates a team, as a member with team:create.
func (p *Plugin) CreateTeam(ctx context.Context, in CreateTeamRequest) (Team, error) {
	return p.createTeam.Call(ctx, in)
}

// ListTeams lists an organization's teams, as a member.
func (p *Plugin) ListTeams(ctx context.Context, orgID string) ([]Team, error) {
	r, err := p.listTeams.Call(ctx, OrgRequest{OrgID: orgID})
	return r.Teams, err
}

// UpdateTeam renames a team, as a member with team:update.
func (p *Plugin) UpdateTeam(ctx context.Context, in UpdateTeamRequest) (Team, error) {
	return p.updateTeam.Call(ctx, in)
}

// RemoveTeam deletes a team and its memberships, as a member with
// team:delete.
func (p *Plugin) RemoveTeam(ctx context.Context, teamID string) error {
	_, err := p.removeTeam.Call(ctx, TeamRequest{TeamID: teamID})
	return err
}

// SetActiveTeam makes a team the session's active one (and its organization
// the active organization), or clears it with an empty id.
func (p *Plugin) SetActiveTeam(ctx context.Context, teamID string) (ActiveResult, error) {
	return p.setActiveTeam.Call(ctx, TeamRequest{TeamID: teamID})
}

// ListUserTeams lists the teams the signed-in user is in, in every
// organization.
func (p *Plugin) ListUserTeams(ctx context.Context) ([]Team, error) {
	r, err := p.listUserTeams.Call(ctx, struct{}{})
	return r.Teams, err
}

// ListTeamMembers lists a team's members, as a member of its organization.
func (p *Plugin) ListTeamMembers(ctx context.Context, teamID string) ([]TeamMember, error) {
	r, err := p.listTeamMembers.Call(ctx, TeamRequest{TeamID: teamID})
	return r.Members, err
}

// AddTeamMember adds a member of the organization to a team, as a member
// with team:update.
func (p *Plugin) AddTeamMember(ctx context.Context, in TeamMemberRequest) error {
	_, err := p.addTeamMember.Call(ctx, in)
	return err
}

// RemoveTeamMember removes someone from a team: themself, or anyone as a
// member with team:update.
func (p *Plugin) RemoveTeamMember(ctx context.Context, in TeamMemberRequest) error {
	_, err := p.removeTeamMember.Call(ctx, in)
	return err
}

// teamsOf lists the teams matching where, by name, each with its member
// count from a correlated subquery, so one statement reads them all.
func (p *Plugin) teamsOf(ctx context.Context, where ...sqlb.Predicate) ([]Team, error) {
	var t Team
	var count *int64 // a scalar subquery is nullable to the type system
	sub := p.core.Select().Exprs(sqlb.Count()).From(TableTeamMember).Where(sqlb.EqExpr(TeamMemberTeamID, TeamID))
	out := []Team{}
	extra, read := p.teamFields().read()
	q := p.core.Select().Columns(append([]sqlb.Binding{
		sqlb.Bind(TeamID, &t.ID), sqlb.Bind(TeamOrgID, &t.OrgID), sqlb.Bind(TeamName, &t.Name),
		sqlb.Bind(TeamCreatedAt, &t.CreatedAt), sqlb.Bind(TeamUpdatedAt, &t.UpdatedAt),
		sqlb.Bind(sqlb.Subquery[int64](sub), &count),
	}, extra...)...).From(TableTeam).Where(where...).
		Order(sqlb.OrderBy(TeamName, sqlb.SortAsc), sqlb.OrderBy(TeamID, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error {
		t.MemberCount = 0
		if count != nil {
			t.MemberCount = *count
		}
		t.Fields = read()
		out = append(out, t)
		return nil
	})
	return out, err
}

// teamByID reads a team; ErrTeamNotFound when there is none.
func (p *Plugin) teamByID(ctx context.Context, teamID string) (Team, error) {
	list, err := p.teamsOf(ctx, sqlb.Eq(TeamID, teamID))
	if err != nil {
		return Team{}, err
	}
	if len(list) == 0 {
		return Team{}, ErrTeamNotFound
	}
	return list[0], nil
}

// teamIn reads a team of orgID; a team of another organization is
// ErrTeamNotFound, as an unknown one is.
func (p *Plugin) teamIn(ctx context.Context, orgID, teamID string) (Team, error) {
	t, err := p.teamByID(ctx, teamID)
	if err == nil && t.OrgID != orgID {
		return Team{}, ErrTeamNotFound
	}
	return t, err
}

// memberTeam reads a team whose organization the caller belongs to, with
// the caller's role there; a stranger gets ErrTeamNotFound.
func (p *Plugin) memberTeam(ctx context.Context, c *auth.Call, teamID string) (Team, Role, error) {
	t, err := p.teamByID(ctx, teamID)
	if err != nil {
		return Team{}, "", err
	}
	c.Annotate(auth.AnnotationOrganization, t.OrgID)
	r, err := p.RoleOf(ctx, t.OrgID, c.User.ID)
	if errors.Is(err, ErrNotMember) {
		return Team{}, "", ErrTeamNotFound
	}
	return t, r, err
}

// createDefaultTeam makes the organization's first team with the creator
// in it.
func (p *Plugin) createDefaultTeam(ctx context.Context, o Org, creator auth.User) error {
	name := o.Name
	if fn := p.teams.DefaultTeamName; fn != nil {
		var err error
		if name, err = fn(ctx, o, creator); err != nil {
			return err
		}
	}
	t, err := p.insertTeam(ctx, o.ID, name, nil, false, false)
	if err != nil {
		return err
	}
	return p.joinTeam(ctx, o.ID, t.ID, creator.ID)
}

// insertTeam creates a team between the team hooks. client refuses
// ServerOnly fields; required enforces Required ones (off for the default
// team, which no request names fields for).
func (p *Plugin) insertTeam(ctx context.Context, orgID, name string, fields auth.Fields, client, required bool) (Team, error) {
	fs := p.teamFields()
	if _, err := fs.set(fields, client, required); err != nil {
		return Team{}, err
	}
	id, err := p.core.NewID(idPrefixTeam)
	if err != nil {
		return Team{}, err
	}
	now := p.core.Now()
	t := Team{ID: id, OrgID: orgID, Name: strings.TrimSpace(name), CreatedAt: now, UpdatedAt: now, Fields: fields}
	if h := p.hooks.BeforeCreateTeam; h != nil {
		if err := h(ctx, &t); err != nil {
			return Team{}, err
		}
		t.ID, t.OrgID, t.MemberCount = id, orgID, 0
	}
	extra, err := fs.set(t.Fields, false, required)
	if err != nil {
		return Team{}, err
	}
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableTeam).Row(append([]sqlb.Assignment{sqlb.Set(TeamID, t.ID), sqlb.Set(TeamOrgID, t.OrgID),
		sqlb.Set(TeamName, t.Name), sqlb.Set(TeamCreatedAt, t.CreatedAt), sqlb.Set(TeamUpdatedAt, t.UpdatedAt)}, extra...)...)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return Team{}, err
	}
	if len(fs.fields) > 0 {
		if t, err = p.teamByID(ctx, t.ID); err != nil {
			return Team{}, err
		}
	}
	if h := p.hooks.AfterCreateTeam; h != nil {
		if err := h(ctx, t); err != nil {
			return Team{}, err
		}
	}
	return t, nil
}

// joinTeam adds userID to a team of orgID unless they are in it, applying
// MaxMembersPerTeam and the team member hooks.
func (p *Plugin) joinTeam(ctx context.Context, orgID, teamID, userID string) error {
	t, err := p.teamIn(ctx, orgID, teamID)
	if err != nil {
		return err
	}
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableTeamMember).
		Where(sqlb.Eq(TeamMemberTeamID, teamID), sqlb.Eq(TeamMemberUserID, userID))
	if err := p.core.One(ctx, q); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if max := p.teams.MaxMembersPerTeam; max > 0 && t.MemberCount >= int64(max) {
		return ErrTeamMembersLimit
	}
	m := TeamMemberChange{OrgID: orgID, TeamID: teamID, UserID: userID}
	if h := p.hooks.BeforeAddTeamMember; h != nil {
		if err := h(ctx, m); err != nil {
			return err
		}
	}
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableTeamMember).Row(sqlb.Set(TeamMemberTeamID, teamID),
		sqlb.Set(TeamMemberUserID, userID), sqlb.Set(TeamMemberCreatedAt, p.core.Now()))
	if _, err := p.core.Exec(ctx, ins); err != nil {
		return err
	}
	if h := p.hooks.AfterAddTeamMember; h != nil {
		return h(ctx, m)
	}
	return nil
}

func (p *Plugin) doCreateTeam(ctx context.Context, c *auth.Call, in CreateTeamRequest) (Team, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return Team{}, err
	}
	mine, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return Team{}, err
	}
	if err := p.authorize(ctx, c, orgID, mine, access.Request{ResourceTeam: access.All(ActionCreate)}); err != nil {
		return Team{}, err
	}
	if max := p.teams.MaxTeams; max > 0 {
		n, err := p.teamCount(ctx, orgID)
		if err != nil {
			return Team{}, err
		}
		if n >= int64(max) {
			return Team{}, ErrTeamsLimit
		}
	}
	fields, err := p.teamFields().merge(in.Fields, in.top)
	if err != nil {
		return Team{}, err
	}
	return p.insertTeam(ctx, orgID, in.Name, fields, fromClient(c), true)
}

// teamCount counts an organization's teams.
func (p *Plugin) teamCount(ctx context.Context, orgID string) (int64, error) {
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableTeam).Where(sqlb.Eq(TeamOrgID, orgID))
	return n, p.core.One(ctx, q)
}

func (p *Plugin) doListTeams(ctx context.Context, c *auth.Call, in OrgRequest) (TeamsResult, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return TeamsResult{}, err
	}
	if _, err := p.RoleOf(ctx, orgID, c.User.ID); err != nil {
		return TeamsResult{}, err
	}
	list, err := p.teamsOf(ctx, sqlb.Eq(TeamOrgID, orgID))
	return TeamsResult{Teams: list}, err
}

func (p *Plugin) doUpdateTeam(ctx context.Context, c *auth.Call, in UpdateTeamRequest) (Team, error) {
	old, mine, err := p.memberTeam(ctx, c, in.TeamID)
	if err != nil {
		return Team{}, err
	}
	if err := p.authorize(ctx, c, old.OrgID, mine, access.Request{ResourceTeam: access.All(ActionUpdate)}); err != nil {
		return Team{}, err
	}
	t := old
	if in.Data.Name != nil {
		t.Name = strings.TrimSpace(*in.Data.Name)
	}
	fs := p.teamFields()
	if in.Data.Fields, err = fs.merge(in.Data.Fields, in.Data.top); err != nil {
		return Team{}, err
	}
	if _, err := fs.set(in.Data.Fields, fromClient(c), false); err != nil {
		return Team{}, err
	}
	t.Fields = mergeFields(old.Fields, in.Data.Fields)
	t.UpdatedAt = p.core.Now()
	if h := p.hooks.BeforeUpdateTeam; h != nil {
		if err := h(ctx, old, &t); err != nil {
			return Team{}, err
		}
		t.ID, t.OrgID, t.CreatedAt, t.MemberCount = old.ID, old.OrgID, old.CreatedAt, old.MemberCount
	}
	extra, err := fs.set(t.Fields, false, false)
	if err != nil {
		return Team{}, err
	}
	upd := sqlb.NewUpdate(p.core.Dialect()).Table(TableTeam).Set(append([]sqlb.Assignment{sqlb.Set(TeamName, t.Name), sqlb.Set(TeamUpdatedAt, t.UpdatedAt)}, extra...)...).
		Where(sqlb.Eq(TeamID, t.ID))
	if _, err := p.core.Exec(ctx, upd); err != nil {
		return Team{}, err
	}
	if len(fs.fields) > 0 {
		if t, err = p.teamByID(ctx, t.ID); err != nil {
			return Team{}, err
		}
	}
	if h := p.hooks.AfterUpdateTeam; h != nil {
		if err := h(ctx, t); err != nil {
			return Team{}, err
		}
	}
	return t, nil
}

func (p *Plugin) doRemoveTeam(ctx context.Context, c *auth.Call, in TeamRequest) (auth.Done, error) {
	t, mine, err := p.memberTeam(ctx, c, in.TeamID)
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.authorize(ctx, c, t.OrgID, mine, access.Request{ResourceTeam: access.All(ActionDelete)}); err != nil {
		return auth.Done{}, err
	}
	if !p.teams.AllowRemovingAllTeams {
		n, err := p.teamCount(ctx, t.OrgID)
		if err != nil {
			return auth.Done{}, err
		}
		if n <= 1 {
			return auth.Done{}, ErrLastTeam
		}
	}
	if h := p.hooks.BeforeDeleteTeam; h != nil {
		if err := h(ctx, t); err != nil {
			return auth.Done{}, err
		}
	}
	d := p.core.Dialect()
	for _, del := range []auth.Statement{
		sqlb.NewDelete(d).From(TableTeamMember).Where(sqlb.Eq(TeamMemberTeamID, t.ID)),
		sqlb.NewDelete(d).From(TableTeam).Where(sqlb.Eq(TeamID, t.ID)),
	} {
		if _, err := p.core.Exec(ctx, del); err != nil {
			return auth.Done{}, err
		}
	}
	// Sessions that had it active keep their organization.
	clear := sqlb.NewUpdate(d).Table(TableActive).Set(sqlb.Set(ActiveTeamID, (*string)(nil))).Where(sqlb.Eq(activeTeamKey, t.ID))
	if _, err := p.core.Exec(ctx, clear); err != nil {
		return auth.Done{}, err
	}
	if h := p.hooks.AfterDeleteTeam; h != nil {
		if err := h(ctx, t); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, nil
}

// doSetActiveTeam needs the caller to be in the team; its organization
// becomes the active one too.
func (p *Plugin) doSetActiveTeam(ctx context.Context, c *auth.Call, in TeamRequest) (ActiveResult, error) {
	s, err := session(c)
	if err != nil {
		return ActiveResult{}, err
	}
	if in.TeamID == "" {
		org, _, err := p.readActive(ctx, s)
		if err != nil {
			return ActiveResult{}, err
		}
		return ActiveResult{OrgID: org}, p.writeActive(ctx, s, org, nil)
	}
	t, _, err := p.memberTeam(ctx, c, in.TeamID)
	if err != nil {
		return ActiveResult{}, err
	}
	in2, err := p.inTeam(ctx, t.ID, c.User.ID)
	if err != nil {
		return ActiveResult{}, err
	}
	if !in2 {
		return ActiveResult{}, ErrTeamNotFound
	}
	if err := p.writeActive(ctx, s, &t.OrgID, &t.ID); err != nil {
		return ActiveResult{}, err
	}
	return ActiveResult{OrgID: &t.OrgID, TeamID: &t.ID}, nil
}

// activeTeam is the session's active team; ErrNoActiveTeam when there is
// none, or no session to hold one (an API key).
func (p *Plugin) activeTeam(ctx context.Context, c *auth.Call) (string, error) {
	s, err := session(c)
	if err != nil {
		return "", ErrNoActiveTeam
	}
	_, team, err := p.readActive(ctx, s)
	if err != nil {
		return "", err
	}
	if team == nil {
		return "", ErrNoActiveTeam
	}
	return *team, nil
}

// inTeam reports whether userID is in teamID.
func (p *Plugin) inTeam(ctx context.Context, teamID, userID string) (bool, error) {
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableTeamMember).
		Where(sqlb.Eq(TeamMemberTeamID, teamID), sqlb.Eq(TeamMemberUserID, userID))
	return n > 0, p.core.One(ctx, q)
}

func (p *Plugin) doListUserTeams(ctx context.Context, c *auth.Call, _ struct{}) (TeamsResult, error) {
	mine := p.core.Select().Exprs(TeamMemberTeamID).From(TableTeamMember).Where(sqlb.Eq(TeamMemberUserID, c.User.ID))
	list, err := p.teamsOf(ctx, sqlb.InSubquery(TeamID, mine))
	return TeamsResult{Teams: list}, err
}

// doListTeamMembers lists a team the caller's organization has; with no
// teamId it is the session's active team, as better-auth defaults it.
func (p *Plugin) doListTeamMembers(ctx context.Context, c *auth.Call, in TeamRequest) (TeamMembersResult, error) {
	if in.TeamID == "" {
		team, err := p.activeTeam(ctx, c)
		if err != nil {
			return TeamMembersResult{}, err
		}
		in.TeamID = team
	}
	t, _, err := p.memberTeam(ctx, c, in.TeamID)
	if err != nil {
		return TeamMembersResult{}, err
	}
	var u auth.User
	var row TeamMember
	q := p.core.Select().Columns(append(auth.UserBindings(&u), sqlb.Bind(TeamMemberCreatedAt, &row.CreatedAt))...).
		From(TableTeamMember).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: auth.TableUser, On: []sqlb.Predicate{sqlb.EqExpr(auth.UserID, TeamMemberUserID)}}).
		Where(sqlb.Eq(TeamMemberTeamID, t.ID)).
		Order(sqlb.OrderBy(TeamMemberCreatedAt, sqlb.SortAsc), sqlb.OrderBy(TeamMemberUserID, sqlb.SortAsc))
	out := TeamMembersResult{Members: []TeamMember{}}
	err = p.core.Each(ctx, q, func() error {
		out.Members = append(out.Members, TeamMember{TeamID: t.ID, User: auth.ViewOf(u), CreatedAt: row.CreatedAt})
		return nil
	})
	return out, err
}

// doAddTeamMember needs team:update, and the user must be a member of the
// team's organization.
func (p *Plugin) doAddTeamMember(ctx context.Context, c *auth.Call, in TeamMemberRequest) (auth.Done, error) {
	t, mine, err := p.memberTeam(ctx, c, in.TeamID)
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.authorize(ctx, c, t.OrgID, mine, access.Request{ResourceTeam: access.All(ActionUpdate)}); err != nil {
		return auth.Done{}, err
	}
	if _, err := p.RoleOf(ctx, t.OrgID, in.UserID); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.joinTeam(ctx, t.OrgID, t.ID, in.UserID)
}

// doRemoveTeamMember lets a member leave a team, and one with team:update
// remove anyone from it. A session that had the team active keeps its
// organization.
func (p *Plugin) doRemoveTeamMember(ctx context.Context, c *auth.Call, in TeamMemberRequest) (auth.Done, error) {
	t, mine, err := p.memberTeam(ctx, c, in.TeamID)
	if err != nil {
		return auth.Done{}, err
	}
	if in.UserID != c.User.ID {
		if err := p.authorize(ctx, c, t.OrgID, mine, access.Request{ResourceTeam: access.All(ActionUpdate)}); err != nil {
			return auth.Done{}, err
		}
	}
	member, err := p.inTeam(ctx, t.ID, in.UserID)
	if err != nil {
		return auth.Done{}, err
	}
	if !member {
		return auth.Done{}, ErrNotMember
	}
	m := TeamMemberChange{OrgID: t.OrgID, TeamID: t.ID, UserID: in.UserID}
	if h := p.hooks.BeforeRemoveTeamMember; h != nil {
		if err := h(ctx, m); err != nil {
			return auth.Done{}, err
		}
	}
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableTeamMember).Where(sqlb.Eq(TeamMemberTeamID, t.ID), sqlb.Eq(TeamMemberUserID, in.UserID))); err != nil {
		return auth.Done{}, err
	}
	clear := sqlb.NewUpdate(d).Table(TableActive).Set(sqlb.Set(ActiveTeamID, (*string)(nil))).
		Where(sqlb.Eq(ActiveUserID, in.UserID), sqlb.Eq(activeTeamKey, t.ID))
	if _, err := p.core.Exec(ctx, clear); err != nil {
		return auth.Done{}, err
	}
	if h := p.hooks.AfterRemoveTeamMember; h != nil {
		if err := h(ctx, m); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, nil
}
