package oidcclient

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// Authorization request parameters (RFC 6749 section 4.1.1, RFC 7636,
// OpenID Connect Core section 3.1.2.1) and callback parameters (RFC 9207).
const (
	paramResponseType        = "response_type"
	paramScope               = "scope"
	paramState               = "state"
	paramNonce               = "nonce"
	paramCodeChallenge       = "code_challenge"
	paramCodeChallengeMethod = "code_challenge_method"
	paramError               = "error"
	paramIss                 = "iss"
	paramIDTokenHint         = "id_token_hint"
	paramPostLogoutRedirect  = "post_logout_redirect_uri"
	responseTypeCode         = "code"
	scopeSeparator           = " "
)

// allowMethod answers 405 with an Allow header unless r uses one of
// methods.
func allowMethod(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	if slices.Contains(methods, r.Method) {
		return true
	}
	w.Header().Set(headerAllow, strings.Join(methods, ", "))
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	return false
}

// redirectURI is where the login server sends the browser back.
func (c *Client) redirectURI() string { return c.appOrigin + c.set.paths.Callback }

// landing applies the ReturnPolicy to requested and holds its answer to
// the floor: a same-site path that is not one of the auth routes (landing
// on the login route would start another sign-in, on the logout route sign
// the person out). Anything else is "/".
func (c *Client) landing(r *http.Request, requested string) string {
	p := c.set.returns(ReturnRequest{Requested: requested, Request: r})
	if !isSameSitePath(p) {
		return siteRoot
	}
	path, _, _ := strings.Cut(p, "?")
	path, _, _ = strings.Cut(path, "#")
	if slices.Contains(c.set.paths.list(), path) {
		return siteRoot
	}
	return p
}

// providerRefusal is the Refusal for a failure to use the login server at
// sign-in or sign-out: unavailable when it could not be asked, a failure
// when its configuration or answer breaks a floor.
func providerRefusal(err error) Refusal {
	if errors.Is(err, ErrProviderUnavailable) {
		return Refusal{Kind: RefusalUnavailable, Reason: ReasonServerDown, Err: err}
	}
	return Refusal{Kind: RefusalFailed, Reason: ReasonProviderInvalid, Err: err}
}

// hookRefusal is the Refusal for a UserMapper or Authorizer error:
// ErrAccessDenied is no access, anything else a failure.
func hookRefusal(err error) Refusal {
	if errors.Is(err, ErrAccessDenied) {
		return Refusal{Kind: RefusalNoAccess, Reason: ReasonNotAuthorized, Err: err}
	}
	return Refusal{Kind: RefusalFailed, Reason: ReasonHookFailed, Err: err}
}

// serveLogin implements LoginHandler.
func (c *Client) serveLogin(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	ctx := r.Context()
	meta, err := c.provider.Metadata(ctx)
	if err != nil {
		c.refuse(w, r, providerRefusal(err), nil)
		return
	}
	f := pendingFlow{
		State: randomToken(), Nonce: randomToken(), Verifier: randomToken(),
		ReturnTo: c.landing(r, r.URL.Query().Get(ParamReturnTo)), CreatedAt: c.set.now(),
	}
	fc := c.readFlows(ctx, r)
	fc.addFlow(f)
	if err := c.writeFlows(ctx, w, r, fc); err != nil {
		c.refuse(w, r, Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: fmt.Errorf("oidcclient: seal flow cookie: %w", err)}, nil)
		return
	}
	u, err := url.Parse(meta.AuthorizationEndpoint)
	if err != nil {
		c.refuse(w, r, providerRefusal(fmt.Errorf("%w: authorization_endpoint: %w", ErrInvalidConfig, err)), nil)
		return
	}
	q := u.Query()
	for k, v := range c.set.authParams {
		q.Set(k, v)
	}
	// The protocol parameters are set last, so nothing above can replace
	// one (WithAuthParams refuses them at New as well).
	for k, v := range map[string]string{
		paramResponseType: responseTypeCode, paramClientID: c.cfg.ClientID, paramRedirectURI: c.redirectURI(),
		paramScope: strings.Join(c.set.scopes, scopeSeparator), paramState: f.State, paramNonce: f.Nonce,
		paramCodeChallenge: codeChallenge(f.Verifier), paramCodeChallengeMethod: pkceS256,
	} {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	noStore(w)
	w.Header().Set(headerLocation, u.String())
	w.WriteHeader(http.StatusFound)
}

// serveCallback implements CallbackHandler.
func (c *Client) serveCallback(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodGet) {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	fc := c.readFlows(ctx, r)
	f, ok := fc.takeFlow(q.Get(paramState))
	if !ok {
		c.refuse(w, r, Refusal{Kind: RefusalFailed, Reason: ReasonBadCallback, Err: errors.New("oidcclient: state matches no sign-in this browser started")}, nil)
		return
	}
	// The flow is spent whatever happens next: one state, one try.
	if err := c.writeFlows(ctx, w, r, fc); err != nil {
		c.refuse(w, r, Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: fmt.Errorf("oidcclient: seal flow cookie: %w", err)}, nil)
		return
	}
	meta, err := c.provider.Metadata(ctx)
	if err != nil {
		c.refuse(w, r, providerRefusal(err), nil)
		return
	}
	// RFC 9207: an iss sent must be the issuer, and a server that says it
	// sends one must have sent it. Not a secret: a plain comparison.
	if iss, sent := q[paramIss]; (sent || meta.IssParameterSupported) && (len(iss) != 1 || iss[0] != meta.Issuer) {
		c.refuse(w, r, Refusal{Kind: RefusalFailed, Reason: ReasonBadCallback, Err: fmt.Errorf("oidcclient: callback iss %q is not the issuer", iss)}, nil)
		return
	}
	if e := q.Get(paramError); e != "" {
		ref := Refusal{Kind: RefusalFailed, Reason: ReasonBadCallback, Err: fmt.Errorf("oidcclient: the login server answered %q", e)}
		if e == oauthAccessDenied {
			ref.Kind, ref.Reason = RefusalNoAccess, ReasonProviderDenied
		}
		c.refuse(w, r, ref, nil)
		return
	}
	code := q.Get(paramCode)
	if code == "" {
		c.refuse(w, r, Refusal{Kind: RefusalFailed, Reason: ReasonBadCallback, Err: errors.New("oidcclient: callback without a code")}, nil)
		return
	}
	tok, id, err := c.provider.exchange(ctx, code, f.Verifier, f.Nonce)
	if err != nil {
		ref := Refusal{Kind: RefusalFailed, Reason: ReasonBadCallback, Err: err}
		switch {
		case errors.Is(err, ErrProviderUnavailable):
			ref.Kind, ref.Reason = RefusalUnavailable, ReasonServerDown
		case oauthErrorOf(err) == oauthAccessDenied:
			ref.Kind, ref.Reason = RefusalNoAccess, ReasonProviderDenied
		}
		c.refuse(w, r, ref, nil)
		return
	}
	user, err := c.mapUser(ctx, MapUserRequest{Reason: MapSignIn, Identity: id, AccessToken: tok.AccessToken, Provider: c.provider})
	if err != nil {
		c.refuse(w, r, hookRefusal(err), nil)
		return
	}
	now := c.set.now()
	s := Session{ID: randomToken(), User: user, ProviderSessionID: id.ProviderSessionID, Tokens: tok, CreatedAt: now, LastSeenAt: now, CheckedAt: now}
	// A session this browser held before ends here, so a stale or planted
	// one does not linger in a server-side store after a new sign-in.
	if old, _, err := c.openSession(ctx, r); err == nil {
		if err := c.set.store.Delete(ctx, old); err != nil {
			c.set.logger.WarnContext(ctx, "oidcclient: delete the previous session", "error", err)
		}
	}
	if err := c.saveSession(ctx, w, r, &s); err != nil {
		c.refuse(w, r, Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: err}, &s)
		return
	}
	c.observe(ctx, Event{Kind: EventLogin, SessionID: s.ID, Subject: s.User.Subject})
	c.land(w, r, f.ReturnTo)
}

// landingPage is the page the callback answers with under SameSite=Strict:
// a same-site navigation to the return path, because the redirect chain
// that brought the browser here started at the login server, and the
// browser holds back Strict cookies on every request of that chain.
const landingPage = `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url='%[1]s'"><title>Signing in</title><p><a href="%[1]s">Continue</a></p>`

// metaRefreshEscaper keeps a quote from ending the meta refresh URL early;
// html.EscapeString then makes the value safe in an attribute.
var metaRefreshEscaper = strings.NewReplacer(`'`, "%27", `"`, "%22")

// land sends the browser to path after a sign-in: a redirect, or under
// SameSite=Strict a page that navigates there.
func (c *Client) land(w http.ResponseWriter, r *http.Request, path string) {
	if !isSameSitePath(path) {
		path = siteRoot
	}
	noStore(w)
	if c.set.cookie.SameSite == http.SameSiteStrictMode {
		w.Header().Set(headerContentType, mediaTypeHTMLUTF8)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, landingPage, html.EscapeString(metaRefreshEscaper.Replace(path))) // a browser that hung up cannot be told
		return
	}
	w.Header().Set(headerLocation, path)
	w.WriteHeader(http.StatusFound)
}

// mapUser runs the UserMapper (DefaultUser without one) and refuses a User
// whose Issuer or Subject differ from the Identity's: they key back-channel
// logout and the refresh check.
func (c *Client) mapUser(ctx context.Context, in MapUserRequest) (User, error) {
	if c.set.mapper == nil {
		return DefaultUser(in.Identity), nil
	}
	u, err := c.set.mapper(ctx, in)
	if err != nil {
		return User{}, err
	}
	if u.Issuer != in.Identity.Issuer || u.Subject != in.Identity.Subject {
		return User{}, errors.New("oidcclient: the UserMapper changed the User's Issuer or Subject")
	}
	return u, nil
}

// sameOrigin reports whether r was sent by a page of this app: its Origin
// is the app's origin, or, without an Origin, the browser says
// Sec-Fetch-Site: same-origin. A request with neither is refused, so
// another site cannot sign people out with a form.
func (c *Client) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get(headerOrigin); o != "" {
		return strings.EqualFold(o, c.appOrigin)
	}
	return r.Header.Get(headerSecFetchSite) == fetchSameOrigin
}

// serveLogout implements LogoutHandler.
func (c *Client) serveLogout(w http.ResponseWriter, r *http.Request) {
	if !allowMethod(w, r, http.MethodPost) {
		return
	}
	if !c.sameOrigin(r) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	ctx := r.Context()
	noStore(w)
	s, had, err := c.openSession(ctx, r)
	if had {
		cookieWriter{opts: c.set.cookie}.clearChunked(w, r)
	}
	if err == nil {
		if err := c.set.store.Delete(ctx, s); err != nil {
			// The cookie is gone from this browser, but a copy would still
			// open a session the store kept: say so rather than pretend.
			c.refuse(w, r, Refusal{Kind: RefusalFailed, Reason: ReasonStoreFailed, Err: fmt.Errorf("oidcclient: delete session at logout: %w", err)}, &s)
			return
		}
		// Under the stateless CookieStore, deleting the session forgets
		// nothing: a cookie copy saved earlier still carries the refresh
		// token, and a server keeps an offline_access refresh token after
		// its own session ends. Revoking it makes the copy's next re-check
		// a "no". Best effort: a failure is logged and observed, and the
		// person is still signed out here and sent on.
		if !s.Tokens.RefreshToken.IsZero() {
			if rerr := c.provider.revokeRefreshToken(ctx, s.Tokens.RefreshToken); rerr != nil {
				if !errors.Is(rerr, errNoRevocation) {
					c.set.logger.WarnContext(ctx, "oidcclient: logout could not revoke the refresh token", "session", s.ID, "error", rerr)
				}
				c.observe(ctx, Event{Kind: EventRevokeFailed, SessionID: s.ID, Subject: s.User.Subject, Err: fmt.Errorf("oidcclient: revoke the refresh token at logout: %w", rerr)})
			}
		}
		c.observe(ctx, Event{Kind: EventLogout, SessionID: s.ID, Subject: s.User.Subject})
	}
	target := c.set.postLogout
	meta, merr := c.provider.Metadata(ctx)
	switch {
	case merr != nil:
		c.set.logger.WarnContext(ctx, "oidcclient: logout ended the app session only; the login server could not be asked", "error", merr)
	case meta.EndSessionEndpoint != "":
		if u, perr := url.Parse(meta.EndSessionEndpoint); perr == nil {
			q := u.Query()
			if err == nil && !s.Tokens.IDToken.IsZero() {
				q.Set(paramIDTokenHint, s.Tokens.IDToken.Reveal())
			}
			q.Set(paramPostLogoutRedirect, c.appOrigin+c.set.postLogout)
			q.Set(paramClientID, c.cfg.ClientID)
			u.RawQuery = q.Encode()
			target = u.String()
		}
	}
	w.Header().Set(headerLocation, target)
	w.WriteHeader(http.StatusSeeOther)
}
