package oauthprovider

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// OpenID Connect Back-Channel Logout 1.0, as better-auth sends it.
const (
	// backchannelEvent is the logout token's events member.
	backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"
	// LogoutTokenType is the logout token's typ header.
	LogoutTokenType = "logout+jwt"
	// logoutTokenTTL is at most two minutes, as the specification
	// recommends against replay.
	logoutTokenTTL = 2 * time.Minute
	// backchannelTimeout bounds one delivery; a slow client cannot extend a
	// logout, and nothing is retried (section 2.5: SHOULD NOT retransmit).
	backchannelTimeout = 5 * time.Second
	claimEvents        = "events"
	paramLogoutToken   = "logout_token"
)

// BackchannelHTTPClient replaces the client that delivers logout tokens,
// for tests or an egress proxy; it must not follow redirects. The default
// follows none and times out after 5 seconds.
func BackchannelHTTPClient(c *http.Client) Option { return func(p *Plugin) { p.backchannelClient = c } }

var _ auth.SessionLifecycle = (*Plugin)(nil)

// SessionEnded ends what this provider issued on a session: its access
// tokens stop, its refresh tokens too unless offline_access was granted
// (Back-Channel Logout section 2.7), and every client with a
// backchannel_logout_uri is sent a logout token after the commit.
func (p *Plugin) SessionEnded(ctx context.Context, userID, id string) error {
	return p.endSessions(ctx, userID, sqlb.Eq(TokenSession, &id))
}

// UserSessionsEnded is SessionEnded for every session of a user but one.
func (p *Plugin) UserSessionsEnded(ctx context.Context, userID, exceptID string) error {
	where := sqlb.IsNotNull(TokenSession)
	if exceptID != "" {
		where = sqlb.And(where, sqlb.NotEq(TokenSession, &exceptID))
	}
	return p.endSessions(ctx, userID, where)
}

// SessionReplaced moves tokens issued on a pending session to the session
// that replaced it, so a later logout of the new one reaches them.
func (p *Plugin) SessionReplaced(ctx context.Context, old, new auth.Session) error {
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(sqlb.Set(TokenSession, &new.ID)).Where(sqlb.Eq(TokenSession, &old.ID)))
	return err
}

// logoutTarget is one client to notify for one session.
type logoutTarget struct {
	client    clientRow
	sessionID string
	userID    string
}

// endSessions revokes the user's tokens on the matching sessions and
// schedules the logout tokens.
func (p *Plugin) endSessions(ctx context.Context, userID string, sessions sqlb.Predicate) error {
	var r tokenRow
	var rows []tokenRow
	q := p.core.Select().Columns(r.bindings()...).From(TableToken).Where(sqlb.Eq(TokenUser, &userID), sessions, sqlb.IsNull(TokenRevoked))
	if err := p.core.Each(ctx, q, func() error { rows = append(rows, r); return nil }); err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	now := p.core.Now()
	var targets []logoutTarget
	seen := map[string]bool{}
	for _, t := range rows {
		set := []sqlb.Assignment{sqlb.Set(TokenAccessExpires, now)}
		if !slices.Contains(strings.Fields(t.scopes), ScopeOfflineAccess) {
			// The refresh token ends with the session; with offline_access it
			// outlives it, which is what that scope asks for.
			set = append(set, sqlb.Set(TokenRevoked, &now))
		}
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(set...).Where(sqlb.Eq(TokenID, t.id))); err != nil {
			return err
		}
		key := t.client + "\x00" + deref(t.session)
		if seen[key] {
			continue
		}
		seen[key] = true
		c, err := p.loadClient(ctx, t.client)
		if errors.Is(err, ErrClientNotFound) {
			// A deleted client has nobody to notify.
			continue
		}
		if err != nil {
			// A failed read would otherwise drop the client's logout token
			// silently while the logout itself reported success.
			return err
		}
		if c.disabledAt != nil || deref(c.backchannel) == "" {
			continue
		}
		targets = append(targets, logoutTarget{client: c, sessionID: deref(t.session), userID: userID})
	}
	if len(targets) > 0 {
		p.core.AfterCommit(ctx, func(ctx context.Context) {
			p.core.RunInBackground(ctx, func(ctx context.Context) { p.deliverLogoutTokens(ctx, targets) })
		})
	}
	return nil
}

// deliverLogoutTokens posts one logout token per target; every failure is
// logged and none is retried.
func (p *Plugin) deliverLogoutTokens(ctx context.Context, targets []logoutTarget) {
	client := p.backchannelClient
	if client == nil {
		client = &http.Client{Timeout: backchannelTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	for _, t := range targets {
		tok, err := p.signer.Sign(ctx, jwt.SignRequest{
			Subject: p.subjectFor(t.client, t.userID), Audience: []string{t.client.c.ClientID}, TTL: logoutTokenTTL,
			Type: LogoutTokenType, SessionID: t.sessionID, Claims: map[string]any{claimEvents: map[string]any{backchannelEvent: map[string]any{}}},
		})
		if err != nil {
			p.core.Logger().Warn("oauthprovider: back-channel logout token", "client", t.client.c.ClientID, "error", err)
			continue
		}
		sendCtx, cancel := context.WithTimeout(ctx, backchannelTimeout)
		req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, deref(t.client.backchannel), strings.NewReader(url.Values{paramLogoutToken: {tok.Token}}.Encode()))
		if err == nil {
			req.Header.Set(headerContentType, contentTypeForm)
			req.Header.Set(headerAccept, contentTypeJSON)
			var res *http.Response
			if res, err = client.Do(req); err == nil {
				res.Body.Close()
				// Section 2.8: 200 is required; many frameworks answer 204.
				if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
					p.core.Logger().Warn("oauthprovider: back-channel logout answered", "client", t.client.c.ClientID, "status", res.StatusCode)
				}
			}
		}
		cancel()
		if err != nil {
			p.core.Logger().Warn("oauthprovider: back-channel logout failed", "client", t.client.c.ClientID, "error", err)
		}
	}
}
