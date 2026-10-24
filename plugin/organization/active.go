package organization

import (
	"context"
	"errors"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Active organization and team (activeOrganizationId and activeTeamId).
// They are kept in auth_org_active, one row per session,
// rather than as columns of auth_session, because sessions are pluggable
// (SQL, Redis, memory, stateless) and a plugin's table works beside every
// store, as plugin/sessiondata does. Reading the selection is one query by
// primary key, and only the operations that need it run it.

// activeOrgKey and activeTeamKey compare the nullable columns with a plain
// string: a predicate needs no pointer.
var (
	activeOrgKey  = sqlb.Col[string](TableActive, ColActiveOrgID)
	activeTeamKey = sqlb.Col[string](TableActive, ColActiveTeamID)
)

// SetActiveRequest is the input of set-active: the organization to make
// active, by id or by slug. Both empty clears the selection, as
// organizationId: null does.
type SetActiveRequest struct {
	OrgID   string `json:"orgId,omitempty"`
	OrgSlug string `json:"orgSlug,omitempty"`
}

// ActiveResult is the session's selection: the active organization and team
// ids, nil for none, and the organization itself when one is active.
type ActiveResult struct {
	OrgID  *string `json:"activeOrganizationId"`
	TeamID *string `json:"activeTeamId"`
	Org    *Org    `json:"organization,omitempty"`
}

// SetActive makes an organization the signed-in session's active one, or
// clears the selection.
func (p *Plugin) SetActive(ctx context.Context, in SetActiveRequest) (ActiveResult, error) {
	return p.setActive.Call(ctx, in)
}

// Active returns the signed-in session's selection.
func (p *Plugin) Active(ctx context.Context) (ActiveResult, error) {
	return p.active.Call(ctx, struct{}{})
}

// ActiveOrgID returns the active organization of the request's session in
// ctx, from Go, for an app route that scopes to it. ok is false for none, a
// signed-out request and an API-key request. It resolves the session first,
// so it works outside an operation and outside authhttp.Middleware.
func (p *Plugin) ActiveOrgID(ctx context.Context) (id string, ok bool, err error) {
	if err := p.core.Resolve(ctx); err != nil {
		return "", false, err
	}
	s, signedIn := auth.CurrentSession(ctx)
	if !signedIn || s.APIKeyID != "" {
		return "", false, nil
	}
	org, _, err := p.readActive(ctx, s)
	if err != nil || org == nil {
		return "", false, err
	}
	return *org, true, nil
}

// session returns the call's session, or ErrSessionDataUnavailable for a
// request with no session row to hold a selection (an API key).
func session(c *auth.Call) (auth.Session, error) {
	if c.Session == nil || c.Session.APIKeyID != "" {
		return auth.Session{}, auth.ErrSessionDataUnavailable
	}
	return *c.Session, nil
}

func (p *Plugin) doSetActive(ctx context.Context, c *auth.Call, in SetActiveRequest) (ActiveResult, error) {
	s, err := session(c)
	if err != nil {
		return ActiveResult{}, err
	}
	if in.OrgID == "" && in.OrgSlug == "" {
		return ActiveResult{}, p.writeActive(ctx, s, nil, nil)
	}
	o, err := p.orgByIDOrSlug(ctx, in.OrgID, in.OrgSlug)
	if err != nil {
		return ActiveResult{}, err
	}
	c.Annotate(auth.AnnotationOrganization, o.ID)
	if _, err := p.RoleOf(ctx, o.ID, c.User.ID); err != nil {
		return ActiveResult{}, err
	}
	if err := p.writeActive(ctx, s, &o.ID, nil); err != nil {
		return ActiveResult{}, err
	}
	return ActiveResult{OrgID: &o.ID, Org: &o}, nil
}

func (p *Plugin) doActive(ctx context.Context, c *auth.Call, _ struct{}) (ActiveResult, error) {
	s, err := session(c)
	if err != nil {
		return ActiveResult{}, err
	}
	org, team, err := p.readActive(ctx, s)
	if err != nil || org == nil {
		return ActiveResult{TeamID: team}, err
	}
	o, err := p.org(ctx, *org)
	if err != nil {
		return ActiveResult{}, errIsNoRows(err, ErrNoActiveOrg)
	}
	return ActiveResult{OrgID: org, TeamID: team, Org: &o}, nil
}

// orgByIDOrSlug finds an organization by id, or by slug when id is empty;
// ErrNotMember when there is none, the answer a stranger gets for an
// organization they may not see.
func (p *Plugin) orgByIDOrSlug(ctx context.Context, id, slug string) (Org, error) {
	var o Org
	where := sqlb.Eq(OrgID, id)
	if id == "" {
		where = sqlb.Eq(OrgSlug, normalizeSlug(slug))
	}
	cols, done := p.orgCols(&o)
	q := p.core.Select().Columns(cols...).From(TableOrg).Where(where).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		return Org{}, errIsNoRows(err, ErrNotMember)
	}
	done()
	return o, nil
}

// resolveOrg is the organization an operation acts on: the one named, or
// the session's active one when none is; ErrNoActiveOrg when neither exists.
func (p *Plugin) resolveOrg(ctx context.Context, c *auth.Call, id string) (string, error) {
	if id != "" {
		c.Annotate(auth.AnnotationOrganization, id)
		return id, nil
	}
	s, err := session(c)
	if err != nil {
		return "", ErrNoActiveOrg
	}
	org, _, err := p.readActive(ctx, s)
	if err != nil {
		return "", err
	}
	if org == nil {
		return "", ErrNoActiveOrg
	}
	c.Annotate(auth.AnnotationOrganization, *org)
	return *org, nil
}

// readActive returns the session's selection; nil ids for none. The user id
// is in the WHERE, so another user's session id matches nothing.
func (p *Plugin) readActive(ctx context.Context, s auth.Session) (org, team *string, err error) {
	q := p.core.Select().Columns(sqlb.Bind(ActiveOrgID, &org), sqlb.Bind(ActiveTeamID, &team)).From(TableActive).
		Where(sqlb.Eq(ActiveSessionID, s.ID), sqlb.Eq(ActiveUserID, s.UserID)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return org, team, nil
}

// writeActive replaces the session's selection; both nil removes it. A
// delete and an insert rather than an upsert, which has three spellings
// across the engines; both run in the call's transaction.
func (p *Plugin) writeActive(ctx context.Context, s auth.Session, org, team *string) error {
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableActive).Where(sqlb.Eq(ActiveSessionID, s.ID))); err != nil {
		return err
	}
	if org == nil && team == nil {
		return nil
	}
	_, err := p.core.Exec(ctx, sqlb.NewInsert(d).Into(TableActive).Row(
		sqlb.Set(ActiveSessionID, s.ID), sqlb.Set(ActiveUserID, s.UserID), sqlb.Set(ActiveOrgID, org),
		sqlb.Set(ActiveTeamID, team), sqlb.Set(ActiveExpiresAt, hardStop(s))))
	return err
}

// hardStop is the latest moment the session can live, so auth sweep can
// drop a selection whose session is gone.
func hardStop(s auth.Session) time.Time {
	if s.MaxExpiresAt != nil {
		return *s.MaxExpiresAt
	}
	return s.ExpiresAt
}

// SessionEnded drops the ended session's selection.
func (p *Plugin) SessionEnded(ctx context.Context, userID, id string) error {
	_, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableActive).
		Where(sqlb.Eq(ActiveSessionID, id), sqlb.Eq(ActiveUserID, userID)))
	return err
}

// UserSessionsEnded drops the selections of every session of userID but
// exceptID's.
func (p *Plugin) UserSessionsEnded(ctx context.Context, userID, exceptID string) error {
	where := []sqlb.Predicate{sqlb.Eq(ActiveUserID, userID)}
	if exceptID != "" {
		where = append(where, sqlb.NotEq(ActiveSessionID, exceptID))
	}
	_, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableActive).Where(where...))
	return err
}

// SessionReplaced moves a pending second-factor session's selection to the
// full session, so an organization chosen before the second factor is still
// active after it.
func (p *Plugin) SessionReplaced(ctx context.Context, old, new auth.Session) error {
	org, team, err := p.readActive(ctx, old)
	if err != nil || (org == nil && team == nil) {
		return err
	}
	if err := p.writeActive(ctx, old, nil, nil); err != nil {
		return err
	}
	return p.writeActive(ctx, new, org, team)
}
