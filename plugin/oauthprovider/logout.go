package oauthprovider

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"slices"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
)

// RP-initiated logout constants.
const (
	// logoutConfirmCookie holds the signed confirmation state between the
	// end-session request and its confirmation.
	logoutConfirmCookie = "oauth_logout_confirmation"
	// actionConfirm is the confirmation form's only accepted action.
	actionConfirm = "confirm"
	// PageConfirm and PageSuccess are the pages EndSessionResult asks the
	// transport to render.
	PageConfirm = "confirm"
	PageSuccess = "success"
	// noticeUnregistered is the success page's note when the client named a
	// post-logout URI it never registered.
	noticeUnregistered = "The requested post-logout redirect was not registered."
	claimSessionID     = "sid"
)

// DefaultEndSessionConfirmTTL is how long a logout confirmation stays
// valid: the browser must confirm within it.
//
//ds:def id=oauthprovider-defaultendsessionconfirmttl-337cbwz6 owner=@khanakia stability=stable
const DefaultEndSessionConfirmTTL = 5 * time.Minute

// EndSessionConfirmTTL overrides DefaultEndSessionConfirmTTL: how long the
// signed confirmation cookie, and so the confirmation page, stays valid. It
// is at least a second (ErrBadTTL otherwise): the cookie's expiry is whole
// seconds, and a confirmation that never expires is not offered, because it
// would let a page posted long ago end a later session.
func EndSessionConfirmTTL(d time.Duration) Option { return func(p *Plugin) { p.logoutConfirmTTL = d } }

// EndSessionHintGrace accepts an id_token_hint at end-session up to d past
// its exp (and ClockSkew), as OpenID Connect RP-Initiated Logout section 2
// recommends for an RP whose user had a recent session: the signature, the
// issuer and the audience are still checked, only the expiry is relaxed. 0,
// the default, accepts no expired hint: a browser is asked to confirm
// instead, and a caller that is not a browser is refused. A negative d is
// ErrBadTTL. The hint at the authorize endpoint is read whatever its expiry
// (OpenID Connect Core section 3.1.2.1) and is not affected.
//
//ds:def id=oauthprovider-endsessionhintgrace-9ut43fa7 owner=@khanakia stability=stable
func EndSessionHintGrace(d time.Duration) Option { return func(p *Plugin) { p.hintGrace = d } }

// ValidatePostLogoutRedirectURI installs a RedirectValidator for
// post_logout_redirect_uri at end-session: it gets the requested URI, the
// client's registered post-logout URIs and the built-in exact-match result,
// and its answer replaces that result. A URI it accepts must still be a valid
// redirect URI (absolute, no fragment, no credentials). Without it the match
// is exact, and an unregistered URI is never redirected to (the success page
// says so): accept only hosts you control.
func ValidatePostLogoutRedirectURI(fn RedirectValidator) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.ValidatePostLogoutRedirectURI", fn) {
			return
		}
		p.postLogoutValidator = fn
	}
}

// postLogoutAccepted is the post-logout redirect decision: an exact match
// with a registered URI, or the ValidatePostLogoutRedirectURI answer.
func (p *Plugin) postLogoutAccepted(uri string, registered []string) bool {
	exact := slices.Contains(registered, uri)
	if p.postLogoutValidator == nil {
		return exact
	}
	return p.postLogoutValidator(uri, slices.Clone(registered), exact) && validRedirectURI(uri)
}

// hintLeeway is the jwt leeway an end-session hint is verified with:
// ClockSkew plus EndSessionHintGrace, saturating rather than overflowing.
func (p *Plugin) hintLeeway() time.Duration {
	if p.hintGrace > math.MaxInt64-p.clockSkew {
		return math.MaxInt64
	}
	return verifierLeeway(p.clockSkew + p.hintGrace)
}

// EndSessionRequest is an OpenID Connect RP-Initiated Logout request.
type EndSessionRequest struct {
	// IDTokenHint is an ID token this provider issued. With a valid one
	// naming the browser's user, the session ends at once; without one,
	// or with one for someone else, a browser is asked to confirm first.
	IDTokenHint string `json:"id_token_hint"`
	// ClientID names the client when there is no hint; with one, it must be
	// an audience of the hint.
	ClientID string `json:"client_id"`
	// PostLogoutRedirectURI is used only when the client registered it
	// exactly; otherwise the success page says it was not registered.
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
	State                 string `json:"state"`
	// Browser is true for a top-level browser navigation that accepts HTML,
	// which Handler decides from the request; only such a request may be
	// shown the confirmation page.
	Browser bool `json:"-"`
}

// EndSessionResult is where to send the browser, or which page to show.
type EndSessionResult struct {
	RedirectTo string `json:"redirect_to,omitempty"`
	// Page is PageConfirm, PageSuccess, or "" for a non-browser caller that
	// needs no page.
	Page string `json:"page,omitempty"`
	// Notice is shown on the success page.
	Notice string `json:"notice,omitempty"`
}

// EndSessionConfirmRequest is the confirmation form's post.
type EndSessionConfirmRequest struct {
	Action  string `json:"action"`
	Browser bool   `json:"-"`
}

// logoutState is the signed confirmation state.
type logoutState struct {
	SessionID       string `json:"sessionId,omitempty"`
	ClientID        string `json:"clientId,omitempty"`
	PostLogout      string `json:"postLogoutRedirectUri,omitempty"`
	State           string `json:"state,omitempty"`
	RedirectInvalid bool   `json:"redirectInvalid,omitempty"`
	ExpiresAt       int64  `json:"expiresAt"`
}

// EndSession runs an RP-initiated logout from Go.
func (p *Plugin) EndSession(ctx context.Context, in EndSessionRequest) (EndSessionResult, error) {
	return p.endSession.Call(ctx, in)
}

// ConfirmEndSession completes a confirmed logout from Go.
func (p *Plugin) ConfirmEndSession(ctx context.Context, in EndSessionConfirmRequest) (EndSessionResult, error) {
	return p.endSessionConfirm.Call(ctx, in)
}

// logoutClient loads the client of a logout: unknown or disabled is
// invalid_client, as is one that may not end sessions. A failed read is
// its own error, not a verdict on the client.
func (p *Plugin) logoutClient(ctx context.Context, id string) (clientRow, error) {
	r, err := p.loadClient(ctx, id)
	if err != nil && !errors.Is(err, ErrClientNotFound) {
		return clientRow{}, err
	}
	if err != nil || r.disabledAt != nil || !r.c.EndSession {
		return clientRow{}, ErrInvalidClient
	}
	return r, nil
}

// confirmationContext records the client, its post-logout URI when
// accepted (or that it was not), and the state.
func (p *Plugin) confirmationContext(r clientRow, in EndSessionRequest) logoutState {
	s := logoutState{ClientID: r.c.ClientID, State: in.State}
	if in.PostLogoutRedirectURI != "" {
		if p.postLogoutAccepted(in.PostLogoutRedirectURI, r.client().PostLogoutRedirectURIs) {
			s.PostLogout = in.PostLogoutRedirectURI
		} else {
			s.RedirectInvalid = true
		}
	}
	return s
}

// doEndSession is RP-initiated logout: a valid hint for the browser's own user
// ends the session at once; anything else is a browser confirmation (or
// invalid_request for a caller that is not a browser).
func (p *Plugin) doEndSession(ctx context.Context, c *auth.Call, in EndSessionRequest) (EndSessionResult, error) {
	signedIn := c.User != nil && c.Session != nil
	if in.IDTokenHint == "" {
		var conf logoutState
		if in.ClientID != "" {
			r, err := p.logoutClient(ctx, in.ClientID)
			if err != nil {
				return EndSessionResult{}, err
			}
			conf = p.confirmationContext(r, in)
		}
		return p.confirmationRequired(c, in.Browser, conf)
	}
	clientID := in.ClientID
	claims, _ := payload(in.IDTokenHint)
	if clientID == "" {
		clientID, _ = claims[claimAZP].(string)
	}
	r, err := p.loadClient(ctx, clientID)
	if err != nil && !errors.Is(err, ErrClientNotFound) {
		return EndSessionResult{}, err
	}
	if err != nil {
		if signedIn && in.Browser {
			return p.confirmationRequired(c, true, logoutState{})
		}
		return EndSessionResult{}, ErrInvalidClient
	}
	if r.disabledAt != nil || !r.c.EndSession {
		return EndSessionResult{}, ErrInvalidClient
	}
	v := jwt.Verifier{Keys: jwt.KeysFromJWKS(p.signer.PublicKeys()), Issuer: p.issuer, Audience: clientID, Now: p.core.Now, Leeway: p.hintLeeway()}
	hint, err := v.Verify(in.IDTokenHint)
	if err != nil {
		if signedIn && in.Browser {
			conf := logoutState{}
			if in.ClientID != "" {
				conf = p.confirmationContext(r, in)
			}
			return p.confirmationRequired(c, true, conf)
		}
		return EndSessionResult{}, ErrInvalidToken
	}
	// The hint names the browser's session by its sid when it has one, and
	// by its user otherwise.
	matches := signedIn && subtle.ConstantTimeCompare([]byte(p.subjectFor(r, c.User.ID)), []byte(hint.Subject)) == 1
	if sid, ok := claims[claimSessionID].(string); ok && sid != "" {
		matches = signedIn && subtle.ConstantTimeCompare([]byte(c.Session.ID), []byte(sid)) == 1
	}
	if signedIn && !matches {
		return p.confirmationRequired(c, in.Browser, p.confirmationContext(r, in))
	}
	if matches {
		if err := p.core.EndSession(ctx, c.User.ID, c.Session.ID, auth.SessionEndSignOut); err != nil {
			return EndSessionResult{}, err
		}
		c.Effects.ClearSession()
	} else if sid, _ := claims[claimSessionID].(string); sid != "" {
		// No browser session: end the hinted one. Its user comes from this
		// client's tokens for that session, since a pairwise sub does not name
		// the user.
		if err := p.endHintedSession(ctx, r.c.ClientID, sid); err != nil {
			return EndSessionResult{}, err
		}
	}
	clearLogoutState(c)
	return p.loggedOut(p.confirmationContext(r, in), in.Browser), nil
}

// endHintedSession deletes the session a valid hint names when the browser
// has none, finding its user through the client's tokens for it; a session
// the client holds no token for is left alone.
func (p *Plugin) endHintedSession(ctx context.Context, clientID, sid string) error {
	if clientID == "" || sid == "" {
		return nil
	}
	toks, err := p.store.Tokens(ctx, TokenFilter{ClientID: clientID, SessionID: sid})
	if err != nil {
		return err
	}
	var user *string
	for _, t := range toks {
		if t.UserID != nil {
			user = t.UserID
			break
		}
	}
	if user == nil {
		return nil
	}
	err = p.core.EndSession(ctx, *user, sid, auth.SessionEndProviderLogout)
	// Gone already, or a stateless session the server cannot end by id.
	if errors.Is(err, auth.ErrSessionNotFound) || errors.Is(err, auth.ErrSessionsUnavailable) {
		return nil
	}
	return err
}

// confirmationRequired stores the signed confirmation state and asks a
// browser to confirm; a caller that is not a browser cannot confirm, so it
// is refused. Without auth.WithSecret there is no key to sign the state
// with, and no client can have EnableEndSession (ErrNoSecret), so the
// endpoint is not advertised and this answers invalid_request, carrying the
// signing error, rather than the 500 that error alone would.
func (p *Plugin) confirmationRequired(c *auth.Call, browser bool, conf logoutState) (EndSessionResult, error) {
	if !browser {
		return EndSessionResult{}, ErrInvalidRequest
	}
	if c.User != nil && c.Session != nil {
		conf.SessionID = c.Session.ID
	}
	exp := p.core.Now().Add(p.logoutConfirmTTL)
	conf.ExpiresAt = exp.Unix()
	b, _ := json.Marshal(conf) // a struct of strings and numbers always encodes
	if err := c.SetSignedCookie(logoutConfirmCookie, string(b), exp); err != nil {
		// The name is a constant that passes CheckCookieName, so the only
		// failure is auth.ErrNoSecret.
		return EndSessionResult{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return EndSessionResult{Page: PageConfirm}, nil
}

// clearLogoutState deletes the confirmation cookie.
func clearLogoutState(c *auth.Call) {
	_ = c.Effects.SetCookie(logoutConfirmCookie, "", time.Time{}) // the name is a constant that passes CheckCookieName
}

// loggedOut is the answer after a logout: the registered post-logout URI
// with state, or, for a browser, the success page (noting an unregistered
// URI).
func (p *Plugin) loggedOut(s logoutState, browser bool) EndSessionResult {
	if s.PostLogout != "" {
		u, _ := url.Parse(s.PostLogout) // accepted, so it parsed (exact match of a registered URI, or validRedirectURI)
		if s.State != "" {
			q := u.Query()
			q.Set(paramState, s.State)
			u.RawQuery = q.Encode()
		}
		return EndSessionResult{RedirectTo: u.String()}
	}
	if !browser {
		return EndSessionResult{}
	}
	res := EndSessionResult{Page: PageSuccess}
	if s.RedirectInvalid {
		res.Notice = noticeUnregistered
	}
	return res
}

// doEndSessionConfirm completes a confirmed logout: the signed,
// unexpired state is the only context it accepts, and it ends the session
// only when that state was made for it.
func (p *Plugin) doEndSessionConfirm(ctx context.Context, c *auth.Call, in EndSessionConfirmRequest) (EndSessionResult, error) {
	if in.Action != actionConfirm {
		return EndSessionResult{}, ErrInvalidRequest
	}
	raw, ok := c.SignedCookie(logoutConfirmCookie)
	var s logoutState
	if !ok || json.Unmarshal([]byte(raw), &s) != nil || s.ExpiresAt <= p.core.Now().Unix() || (s.PostLogout != "" && s.ClientID == "") {
		return EndSessionResult{}, ErrInvalidRequest
	}
	// The client may have changed since the request: recheck it and its URI.
	if s.ClientID != "" {
		r, err := p.logoutClient(ctx, s.ClientID)
		switch {
		case errors.Is(err, ErrInvalidClient):
			s.PostLogout = ""
		case err != nil:
			return EndSessionResult{}, err
		case s.PostLogout != "" && !p.postLogoutAccepted(s.PostLogout, r.client().PostLogoutRedirectURIs):
			s.PostLogout, s.RedirectInvalid = "", true
		}
	}
	signedIn := c.User != nil && c.Session != nil
	if !signedIn {
		clearLogoutState(c)
		res := p.loggedOut(s, in.Browser)
		if res.RedirectTo == "" && res.Page == "" {
			return EndSessionResult{}, ErrInvalidRequest
		}
		return res, nil
	}
	if s.SessionID != "" && subtle.ConstantTimeCompare([]byte(s.SessionID), []byte(c.Session.ID)) != 1 {
		return EndSessionResult{}, ErrInvalidRequest
	}
	if err := p.core.EndSession(ctx, c.User.ID, c.Session.ID, auth.SessionEndSignOut); err != nil {
		return EndSessionResult{}, err
	}
	c.Effects.ClearSession()
	clearLogoutState(c)
	return p.loggedOut(s, in.Browser), nil
}
