package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// OpenID Connect Back-Channel Logout 1.0.
const (
	// backchannelEvent is the logout token's events member.
	backchannelEvent = "http://schemas.openid.net/event/backchannel-logout"
	// LogoutTokenType is the logout token's typ header.
	LogoutTokenType = "logout+jwt"
	// DefaultBackchannelLogoutTokenTTL is a logout token's lifetime: two
	// minutes, short, as the specification recommends against replay.
	//
	//ds:def id=oauthprovider-defaultbackchannellogouttokenttl-wyrq8uee owner=@khanakia stability=stable
	DefaultBackchannelLogoutTokenTTL = 2 * time.Minute
	// DefaultBackchannelTimeout bounds one delivery, so a slow client
	// cannot hold a logout's background work.
	//
	//ds:def id=oauthprovider-defaultbackchanneltimeout-na9cwfke owner=@khanakia stability=stable
	DefaultBackchannelTimeout = 5 * time.Second
	claimEvents               = "events"
	paramLogoutToken          = "logout_token"
)

// BackchannelHTTPClient replaces the client that delivers logout tokens,
// for tests or an egress proxy; it must not follow redirects. The default
// follows none and times out after BackchannelTimeout.
func BackchannelHTTPClient(c *http.Client) Option { return func(p *Plugin) { p.backchannelClient = c } }

// BackchannelLogoutTokenTTL overrides DefaultBackchannelLogoutTokenTTL. It
// is at least a second (ErrBadTTL otherwise): a logout token must carry an
// exp, and a long one only widens the window for a replayed token.
func BackchannelLogoutTokenTTL(d time.Duration) Option {
	return func(p *Plugin) { p.logoutTokenTTL = d }
}

// BackchannelTimeout overrides DefaultBackchannelTimeout, the bound on one
// delivery (with BackchannelHTTPClient too). 0 sets no bound of the
// plugin's own: a delivery then waits as long as the HTTP client does, and
// the default client has no timeout, so only the core's bound on background
// work (auth.DeliveryTimeout, shared by every delivery of one logout) stops
// it. A negative d is ErrBadTTL.
func BackchannelTimeout(d time.Duration) Option { return func(p *Plugin) { p.backchannelTimeout = d } }

// BackchannelLogout is one signed logout token on its way to one client.
type BackchannelLogout struct {
	// ClientID is the client notified; URI its backchannel_logout_uri.
	ClientID string
	URI      string
	// LogoutToken is the signed logout token, the form's logout_token.
	LogoutToken string
	// SessionID is the token's sid ("" when it names the user alone), and
	// UserID the user, unlike the token's sub, which may be pairwise.
	SessionID string
	UserID    string
}

// BackchannelDeliverFunc delivers one logout token. Its error is logged and
// nothing else: a logout has already happened by the time it runs. It runs
// after the commit, in the background (auth.WithBackground), once per client
// and session, with a context bounded by the core (auth.DeliveryTimeout).
type BackchannelDeliverFunc func(ctx context.Context, l BackchannelLogout) error

// BackchannelDelivery replaces how logout tokens are delivered: to queue
// them in the app's outbox, retry them, count them, or send them through an
// egress service. The default (PostBackchannelLogout) posts each once and
// retries nothing; a delivery that wants retries calls PostBackchannelLogout
// itself, again on failure. The token is already signed, with its exp
// (BackchannelLogoutTokenTTL): a retry later than that is refused by the
// client.
//
//ds:def id=oauthprovider-backchanneldelivery-cxz4bac5 owner=@khanakia stability=stable
func BackchannelDelivery(fn BackchannelDeliverFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.BackchannelDelivery", fn) {
			return
		}
		p.backchannelDeliver = fn
	}
}

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
		offline := slices.Contains(strings.Fields(t.scopes), ScopeOfflineAccess)
		if !offline {
			// The refresh token ends with the session; with offline_access it
			// outlives it, which is what that scope asks for.
			set = append(set, sqlb.Set(TokenRevoked, &now))
		}
		if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableToken).Set(set...).Where(sqlb.Eq(TokenID, t.id))); err != nil {
			return err
		}
		// Reported when something ended: the row, or a live access token
		// whose refresh token outlives the session.
		if accessLive := now.Before(t.accessExpires) && t.accessRevoked == nil; !offline || accessLive {
			p.emitToken(ctx, TokenEvent{Kind: TokenEventRevoked, Reason: RevokeReasonSessionEnded, ClientID: t.client, UserID: userID, SessionID: deref(t.session), Family: t.family, TokenID: t.id, AccessOnly: offline})
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

// deliverLogoutTokens signs one logout token per target and hands each to
// BackchannelDelivery (PostBackchannelLogout by default); every failure is
// logged.
func (p *Plugin) deliverLogoutTokens(ctx context.Context, targets []logoutTarget) {
	deliver := p.backchannelDeliver
	if deliver == nil {
		deliver = p.PostBackchannelLogout
	}
	for _, t := range targets {
		tok, err := p.signer.Sign(ctx, jwt.SignRequest{
			Subject: p.subjectFor(t.client, t.userID), Audience: []string{t.client.c.ClientID}, TTL: p.logoutTokenTTL,
			Type: LogoutTokenType, SessionID: t.sessionID, Claims: map[string]any{claimEvents: map[string]any{backchannelEvent: map[string]any{}}},
		})
		if err != nil {
			p.core.Logger().Warn("oauthprovider: back-channel logout token", "client", t.client.c.ClientID, "error", err)
			continue
		}
		l := BackchannelLogout{ClientID: t.client.c.ClientID, URI: deref(t.client.backchannel), LogoutToken: tok.Token, SessionID: t.sessionID, UserID: t.userID}
		err = deliver(ctx, l)
		var se *BackchannelStatusError
		switch {
		case errors.As(err, &se):
			p.core.Logger().Warn("oauthprovider: back-channel logout answered", "client", l.ClientID, "status", se.Status)
		case err != nil:
			p.core.Logger().Warn("oauthprovider: back-channel logout failed", "client", l.ClientID, "error", err)
		}
	}
}

// ErrBackchannelStatus is a back-channel logout the client answered with a
// status other than 200 or 204; PostBackchannelLogout returns it as a
// *BackchannelStatusError carrying the status.
var ErrBackchannelStatus = errors.New("oauthprovider: back-channel logout answered")

// BackchannelStatusError is the status a client answered a logout token
// with; errors.Is sees ErrBackchannelStatus.
type BackchannelStatusError struct{ Status int }

func (e *BackchannelStatusError) Error() string {
	return fmt.Sprintf("%v: status %d", ErrBackchannelStatus, e.Status)
}

// Is makes errors.Is(err, ErrBackchannelStatus) true.
func (e *BackchannelStatusError) Is(target error) bool { return target == ErrBackchannelStatus }

// PostBackchannelLogout is the default BackchannelDelivery: one POST of the
// logout token to l.URI, as a form, through BackchannelHTTPClient (or a
// client that follows no redirect), bounded by BackchannelTimeout. A 200 or
// 204 answer is success (section 2.8 asks for 200; many frameworks answer
// 204); any other status is ErrBackchannelStatus.
func (p *Plugin) PostBackchannelLogout(ctx context.Context, l BackchannelLogout) error {
	client := p.backchannelClient
	if client == nil {
		client = &http.Client{Timeout: p.backchannelTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if p.backchannelTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.backchannelTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.URI, strings.NewReader(url.Values{paramLogoutToken: {l.LogoutToken}}.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set(headerContentType, contentTypeForm)
	req.Header.Set(headerAccept, contentTypeJSON)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNoContent {
		return &BackchannelStatusError{Status: res.StatusCode}
	}
	return nil
}
