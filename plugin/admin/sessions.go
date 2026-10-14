package admin

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// EndpointAllSessions lists every live session of every user, for an
// operator's session monitor (better-auth's dashboard view of all sessions).
// One session is ended with revoke-session and all of a user's with
// revoke-sessions, as before.
const EndpointAllSessions auth.EndpointID = "admin.all-sessions"

// ErrSessionsNotListable refuses all-sessions when sessions do not live in
// the database: a memory, Redis or custom store (auth.WithSessionStore), a
// mirror of two stores, or stateless sessions keep no table to page through,
// and an empty page would read as "nobody is signed in".
var ErrSessionsNotListable = auth.NewError("admin.sessions_not_listable", http.StatusConflict, "Sessions are not kept in the database, so they cannot be listed together.")

// AllSessionsRequest pages through every live session, most recently used
// first. UserID, when set, narrows the list to one user's sessions. Strings
// in JSON, because a Query operation's input arrives as URL query values.
type AllSessionsRequest struct {
	UserID string `json:"userId,omitempty"`
	Page   int    `json:"page,omitempty,string"`
	Limit  int    `json:"limit,omitempty,string"`
	Offset int    `json:"offset,omitempty,string"`
}

// FleetSession is one row of all-sessions: the user it belongs to and what
// the user's own session list shows of it, plus its expiry.
type FleetSession struct {
	ID           string    `json:"id"`
	UserID       string    `json:"userId"`
	Impersonated bool      `json:"impersonated"`
	IP           string    `json:"ip"`
	UserAgent    string    `json:"userAgent"`
	CreatedAt    time.Time `json:"createdAt"`
	LastSeenAt   time.Time `json:"lastSeenAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// AllSessionsResult is one page; Total counts every match, for a pager.
type AllSessionsResult struct {
	Sessions []FleetSession `json:"sessions"`
	Total    int64          `json:"total"`
	Page     int            `json:"page"`
	Limit    int            `json:"limit"`
	Offset   int            `json:"offset"`
}

// AllSessions pages through every live session, as the signed-in admin.
func (p *Plugin) AllSessions(ctx context.Context, in AllSessionsRequest) (AllSessionsResult, error) {
	return p.allSessions.Call(ctx, in)
}

// sessionsInSQL reports whether sessions are rows of auth_session. Only the
// SQL store implements auth.SessionUserFinder (its single-query lookup joins
// auth_session to auth_user), so that is the test; a mirror whose primary is
// the SQL store is refused too, which is safe: the caller is told, never
// shown an incomplete page.
func (p *Plugin) sessionsInSQL() bool {
	_, ok := p.core.SessionStore().(auth.SessionUserFinder)
	return ok
}

// livePredicates is what every live session satisfies, the condition the SQL
// store's own List uses: not expired at now, not a pending second-factor
// session, not revoked under WithSessionArchive.
func livePredicates(now time.Time) []sqlb.Predicate {
	return []sqlb.Predicate{sqlb.Greater(auth.SessionExpiresAt, now), sqlb.Eq(auth.SessionFactorPending, false), sqlb.IsNull(auth.SessionRevokedAt)}
}

// doAllSessions checks the caller first, like every admin operation, then the
// store; the token hash is never read.
func (p *Plugin) doAllSessions(ctx context.Context, c *auth.Call, in AllSessionsRequest) (AllSessionsResult, error) {
	if err := p.require(ctx, c, ResourceSession, ActionList); err != nil {
		return AllSessionsResult{}, err
	}
	if !p.sessionsInSQL() {
		return AllSessionsResult{}, ErrSessionsNotListable
	}
	limit, page, offset := paging(c.Auth.Config(), in.Page, in.Limit, in.Offset)
	where := livePredicates(c.Auth.Now())
	if in.UserID != "" {
		where = append(where, sqlb.Eq(auth.SessionUserID, in.UserID))
	}
	out := AllSessionsResult{Sessions: []FleetSession{}, Page: page, Limit: limit, Offset: offset}
	var s auth.Session
	q := c.Auth.Select().Columns(auth.SessionBindings(&s)...).From(auth.TableSession).Where(where...).
		Order(sqlb.OrderBy(auth.SessionLastSeenAt, sqlb.SortDesc), sqlb.OrderBy(auth.SessionID, sqlb.SortDesc)).Limit(limit).Offset(offset)
	if err := c.Auth.Each(ctx, q, func() error {
		out.Sessions = append(out.Sessions, FleetSession{ID: s.ID, UserID: s.UserID, Impersonated: s.ImpersonatedBy != nil, IP: s.IP, UserAgent: s.UserAgent,
			CreatedAt: s.CreatedAt, LastSeenAt: s.LastSeenAt, ExpiresAt: s.ExpiresAt})
		return nil
	}); err != nil {
		return AllSessionsResult{}, err
	}
	return out, c.Auth.One(ctx, c.Auth.Select().Columns(sqlb.Bind(sqlb.Count(), &out.Total)).From(auth.TableSession).Where(where...))
}

// paging resolves a page request the way the users list does: the limit by
// the core's one rule (cfg.PageSize: the request, else
// auth.WithDefaultPageSize, else DefaultPageSize, never more than
// MaxPageSize), page from 1, and an offset that, when set, replaces the page.
func paging(cfg auth.Config, page, limit, offset int) (int, int, int) {
	limit = cfg.PageSize(limit, DefaultPageSize, MaxPageSize)
	page = max(page, 1)
	if offset > 0 {
		return limit, offset/limit + 1, offset
	}
	return limit, page, (page - 1) * limit
}

// lastActive is the most recent activity of each of ids: the latest
// last_seen_at among the user's sessions (better-auth's lastActiveAt). With
// sessions in SQL it is one statement over every row the table still holds,
// expired and revoked ones included, so it reaches back as far as auth sweep
// (and WithSessionArchive's retention) allows; with any other store it is
// each user's live sessions. A user with none is absent from the map. In
// stateless mode only the caller's own session is known.
func (p *Plugin) lastActive(ctx context.Context, ids []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if len(ids) == 0 {
		return out, nil
	}
	note := func(userID string, at time.Time) {
		if prev, ok := out[userID]; !ok || at.After(prev) {
			out[userID] = at
		}
	}
	if p.sessionsInSQL() {
		var userID string
		var seen time.Time
		q := p.core.Select().Columns(sqlb.Bind(auth.SessionUserID, &userID), sqlb.Bind(auth.SessionLastSeenAt, &seen)).
			From(auth.TableSession).Where(sqlb.In(auth.SessionUserID, ids...))
		return out, p.core.Each(ctx, q, func() error { note(userID, seen); return nil })
	}
	for _, id := range ids {
		list, err := p.core.Sessions(ctx, id)
		switch {
		case errors.Is(err, auth.ErrSessionsUnavailable):
			// Stateless: only the request's own session is known, so the
			// caller's row answers and everyone else's stays nil.
			continue
		case err != nil:
			return nil, err
		}
		for _, s := range list {
			note(id, s.LastSeenAt)
		}
	}
	return out, nil
}

// withLastActive fills LastActiveAt of every summary in users, in one
// lastActive call.
func (p *Plugin) withLastActive(ctx context.Context, users []UserSummary) error {
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	seen, err := p.lastActive(ctx, ids)
	if err != nil {
		return err
	}
	for i := range users {
		if at, ok := seen[users[i].ID]; ok {
			users[i].LastActiveAt = &at
		}
	}
	return nil
}
