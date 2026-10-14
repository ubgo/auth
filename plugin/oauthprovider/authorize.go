package oauthprovider

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Authorization request values.
const (
	responseTypeAuthorization = "code"
	responseModeQry           = "query"
	// methodS256 is the only PKCE method accepted: "plain" sends the
	// verifier through the browser, which is what PKCE exists to avoid.
	methodS256 = "S256"
	// Prompt values (OpenID Connect Core section 3.1.2.1).
	promptNone          = "none"
	promptConsent       = "consent"
	promptLogin         = "login"
	promptSelectAccount = "select_account"
	promptCreate        = "create"
	// minVerifier and maxVerifier bound a PKCE verifier and an S256
	// challenge (RFC 7636 section 4.1: 43 to 128 unreserved characters).
	minVerifier = 43
	maxVerifier = 128
	// maxNonce bounds a nonce, which is stored and signed into the ID token.
	maxNonce = 512
	// maxState bounds a state, which is echoed into a URL.
	maxState = 1024
	// codeIDPrefix starts every auth_oauth_code id, which is also the token
	// family of the tokens the code is exchanged for.
	codeIDPrefix = "oaco"
	// consentIDPrefix starts every auth_oauth_consent id.
	consentIDPrefix = "oacn"
	// unreserved is RFC 3986's unreserved set, the PKCE alphabet.
	unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

// Query parameter names of the authorization response.
const (
	paramCode             = "code"
	paramState            = "state"
	paramIss              = "iss"
	paramError            = "error"
	paramErrorDescription = "error_description"
	paramPrompt           = "prompt"
)

// AuthorizeRequest is an authorization request, RFC 6749 section 4.1.1 with
// PKCE (RFC 7636) and the OpenID Connect parameters. Handler fills it from
// the query string; the json tags are the parameter names.
type AuthorizeRequest struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Nonce               string `json:"nonce"`
	Prompt              string `json:"prompt"`
	ResponseMode        string `json:"response_mode"`
	// Resource is the RFC 8707 resource indicator: a ProtectedResource the
	// tokens are for. Tokens for a resource are JWTs whose aud is it.
	// Several resources (the parameter repeated over HTTP) are written
	// space-separated; their policies combine (resourcePolicy).
	Resource string `json:"resource"`
	// MaxAge is the OpenID Connect max_age in seconds: a session older than
	// this signs in again.
	MaxAge string `json:"max_age"`
	// LoginHint is passed to the login page untouched.
	LoginHint string `json:"login_hint"`
	// Display and UILocales (OpenID Connect Core section 3.1.2.1) are
	// passed to the login, consent and other pages untouched, for them to
	// choose a layout and a language.
	Display   string `json:"display"`
	UILocales string `json:"ui_locales"`
	// IDTokenHint is an ID token this provider issued to the client earlier
	// (expired is fine). When the signed-in user is not its subject, the
	// browser goes to the login page, or prompt=none fails with
	// login_required; one this provider did not sign for this client is
	// invalid_request.
	IDTokenHint string `json:"id_token_hint"`
	// Request and RequestURI are refused (request_not_supported,
	// request_uri_not_supported): this provider takes plain parameters.
	Request    string `json:"request"`
	RequestURI string `json:"request_uri"`
	// Claims is the OpenID Connect claims request (a JSON object); it needs
	// openid. Its userinfo names are released at userinfo whatever the
	// scopes, once consented.
	Claims string `json:"claims"`
	// DPoPJKT binds the code to a DPoP key thumbprint (RFC 9449 section
	// 10): the token request must carry a proof by that key.
	DPoPJKT string `json:"dpop_jkt"`
}

// AuthorizeResult is where to send the browser: the client's redirect URI
// with a code, the login page, or the consent page.
type AuthorizeResult struct {
	RedirectTo string `json:"redirect_to"`
}

// RedirectError is an authorization error that is answered by redirecting
// to the client's redirect URI with error and state (RFC 6749 section
// 4.1.2.1). Err is the reason; errors.Is sees through it.
type RedirectError struct {
	Err        error
	RedirectTo string
}

// Error is the reason's message; the redirect itself is RedirectTo.
func (e *RedirectError) Error() string { return e.Err.Error() }

// Unwrap returns the reason, so errors.Is matches the error being redirected.
func (e *RedirectError) Unwrap() error { return e.Err }

// ConsentRequest is the consent page's answer. Query is the authorize
// request's query string, which the page received; it is validated again in
// full, so nothing the page sends is trusted.
type ConsentRequest struct {
	Query  string `json:"oauth_query"`
	Accept bool   `json:"accept"`
	// Scope, when set, grants only these of the requested scopes.
	Scope string `json:"scope,omitempty"`
	// Claims, when set, is an OpenID Connect claims request object
	// ({"userinfo": {...}}) granting only these of the requested userinfo
	// claims, better-auth's consent claims; a claim the request did not ask
	// for is invalid_request.
	Claims json.RawMessage `json:"claims,omitempty"`
}

// authzContext is a validated authorization request.
type authzContext struct {
	in       AuthorizeRequest
	client   clientRow
	redirect string
	scopes   []string
	prompts  []string
	maxAge   int64
	// userInfoClaims are the claims request's supported userinfo names.
	userInfoClaims []string
	// hintSubject is the id_token_hint's sub, or "".
	hintSubject string
}

// fail answers err at the client's redirect URI.
func (p *Plugin) fail(z authzContext, err error) error {
	return &RedirectError{Err: err, RedirectTo: p.redirectWith(z.redirect, z.in.State, url.Values{paramError: {rfcCode(err)}, paramErrorDescription: {auth.ErrorOf(err).Message}})}
}

// redirectWith adds params, state and iss (RFC 9207) to a redirect URI,
// keeping its own query.
func (p *Plugin) redirectWith(redirect, state string, params url.Values) string {
	u, _ := url.Parse(redirect) // registered, so it parsed at registration
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	if state != "" {
		q.Set(paramState, state)
	}
	q.Set(paramIss, p.issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// validate checks an authorization request in the order RFC 6749 section
// 4.1.2.1 requires: the client and redirect URI first, answered directly
// (ErrBadRedirectTarget), then everything else, answered at the redirect URI.
func (p *Plugin) validate(ctx context.Context, in AuthorizeRequest) (authzContext, error) {
	z := authzContext{in: in}
	r, err := p.resolveClient(ctx, in.ClientID)
	if errors.Is(err, ErrClientNotFound) {
		return z, badTarget(ErrInvalidClient)
	}
	if err == nil && r.disabledAt != nil {
		return z, badTarget(ErrClientDisabled)
	}
	if err != nil {
		return z, err
	}
	z.client = r
	registered := splitList(r.redirects, redirectSeparator)
	switch {
	case in.RedirectURI == "" && len(registered) == 1:
		z.redirect = registered[0]
	case in.RedirectURI != "" && p.redirectAccepted(in.RedirectURI, registered):
		z.redirect = in.RedirectURI
	default:
		return z, ErrBadRedirectTarget
	}
	if len(in.State) > maxState {
		return z, ErrBadRedirectTarget
	}
	if in.ResponseType != responseTypeAuthorization {
		return z, p.fail(z, ErrUnsupportedResponseType)
	}
	if in.ResponseMode != "" && in.ResponseMode != responseModeQry {
		return z, p.fail(z, ErrInvalidRequest)
	}
	if in.Request != "" {
		return z, p.fail(z, ErrRequestNotSupported)
	}
	if in.MaxAge != "" {
		n, err := strconv.ParseInt(in.MaxAge, 10, 64)
		if err != nil || n < 0 {
			return z, p.fail(z, ErrInvalidRequest)
		}
		z.maxAge = n
	} else {
		z.maxAge = -1
	}
	cl := r.client()
	if !slices.Contains(cl.GrantTypes, GrantAuthorizationCode) {
		return z, p.fail(z, ErrUnauthorizedClient)
	}
	z.scopes = strings.Fields(in.Scope)
	if len(z.scopes) == 0 {
		z.scopes = strings.Fields(cl.Scope)
	}
	if len(z.scopes) == 0 || !p.scopesAllowed(cl, z.scopes) {
		return z, p.fail(z, ErrInvalidScope)
	}
	z.scopes = dedupe(z.scopes)
	scopes, _, err := p.resourcePolicy(ctx, in.Resource, r.c.ClientID, z.scopes)
	if err != nil {
		return z, p.fail(z, err)
	}
	z.scopes = scopes
	openid := slices.Contains(z.scopes, ScopeOpenID)
	if in.Claims != "" {
		if !openid {
			return z, p.fail(z, ErrInvalidRequest)
		}
		cr, ok := parseClaimsRequest(in.Claims)
		if !ok {
			return z, p.fail(z, ErrInvalidRequest)
		}
		if !cr.acrSatisfiable() {
			return z, p.fail(z, ErrAccessDenied)
		}
		z.userInfoClaims = cr.requestedUserInfo(p.supportedClaims())
	}
	switch {
	case in.CodeChallenge == "" && cl.RequirePKCE:
		return z, p.fail(z, ErrInvalidRequest)
	case in.CodeChallenge == "" && slices.Contains(z.scopes, ScopeOfflineAccess) && (cl.Public || !openid || in.Nonce == ""):
		// better-auth's rule: a refresh token needs PKCE even for a client
		// that may omit it, unless a confidential client makes an OpenID
		// request with a nonce, which binds the code to the ID token.
		return z, p.fail(z, ErrInvalidRequest)
	case in.CodeChallenge != "" && (in.CodeChallengeMethod != methodS256 || !validVerifier(in.CodeChallenge)):
		return z, p.fail(z, ErrInvalidRequest)
	case in.CodeChallenge == "" && in.CodeChallengeMethod != "":
		return z, p.fail(z, ErrInvalidRequest)
	}
	if in.DPoPJKT != "" && !validJKT(in.DPoPJKT) {
		return z, p.fail(z, ErrInvalidRequest)
	}
	if len(in.Nonce) > maxNonce {
		return z, p.fail(z, ErrInvalidRequest)
	}
	z.prompts = strings.Fields(in.Prompt)
	if slices.Contains(z.prompts, promptNone) && len(z.prompts) > 1 {
		return z, p.fail(z, ErrInvalidRequest)
	}
	if in.IDTokenHint != "" {
		sub, ok := p.idTokenHintSubject(in.IDTokenHint, r.c.ClientID)
		if !ok {
			return z, p.fail(z, ErrInvalidRequest)
		}
		z.hintSubject = sub
	}
	return z, nil
}

// redirectAccepted is the redirect URI decision: an exact string match
// (no prefix, no wildcard, no normalisation, so a registered https://app/cb
// never admits https://app/cb/../evil), or the RedirectValidator's answer
// when one is installed. A URI the validator accepts must still be a valid
// redirect URI (absolute, no fragment, no credentials).
func (p *Plugin) redirectAccepted(uri string, registered []string) bool {
	exact := slices.Contains(registered, uri) || loopbackPortMatch(uri, registered)
	if p.redirectValidator == nil {
		return exact
	}
	return p.redirectValidator(uri, slices.Clone(registered), exact) && validRedirectURI(uri)
}

// loopbackPortMatch is RFC 8252 section 7.3: a native app's loopback
// redirect (http, an IP literal loopback host) may use any port, because
// the operating system assigns it; everything else must match exactly.
func loopbackPortMatch(uri string, registered []string) bool {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != schemeHTTP || u.Port() == "" || !loopbackIP(u.Hostname()) || u.User != nil || u.Fragment != "" {
		return false
	}
	for _, r := range registered {
		v, err := url.Parse(r)
		if err == nil && v.Scheme == u.Scheme && v.Hostname() == u.Hostname() && v.Path == u.Path && v.RawQuery == u.RawQuery && v.User == nil {
			return true
		}
	}
	return false
}

// loopbackIP reports an IP literal loopback host (127.0.0.0/8, ::1); the
// name localhost is not one, since it can resolve elsewhere.
func loopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// scopesAllowed reports whether every scope is supported by the provider and
// allowed for the client (its registered scope, or every scope when it
// registered none).
func (p *Plugin) scopesAllowed(cl Client, scopes []string) bool {
	allowed := strings.Fields(cl.Scope)
	for _, s := range scopes {
		if !slices.Contains(p.scopes, s) || (len(allowed) > 0 && !slices.Contains(allowed, s)) {
			return false
		}
	}
	return true
}

func dedupe(s []string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// validVerifier checks the length and alphabet of a PKCE verifier or S256
// challenge.
func validVerifier(v string) bool {
	if len(v) < minVerifier || len(v) > maxVerifier {
		return false
	}
	for _, r := range v {
		if !strings.ContainsRune(unreserved, r) {
			return false
		}
	}
	return true
}

// s256 is the PKCE S256 transform: base64url(SHA-256(verifier)), unpadded.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pageURL appends the authorize request's parameters to a page's URL, with
// prompt values that would loop removed: a login page that sent the browser
// back with prompt=login would be sent to itself again.
func (p *Plugin) pageURL(page string, in AuthorizeRequest, dropPrompt bool, extra url.Values) string {
	u, _ := url.Parse(page) // checked by Init
	q := u.Query()
	for k, v := range authorizeValues(in) {
		if dropPrompt && k == paramPrompt {
			continue
		}
		q[k] = v
	}
	for k, v := range extra {
		q[k] = v
	}
	u.RawQuery = p.signQuery(q).Encode()
	return u.String()
}

// authorizeValues encodes a request back into query parameters.
func authorizeValues(in AuthorizeRequest) url.Values {
	v := url.Values{}
	for k, s := range map[string]string{
		"response_type": in.ResponseType, "client_id": in.ClientID, "redirect_uri": in.RedirectURI, "scope": in.Scope,
		"state": in.State, "code_challenge": in.CodeChallenge, "code_challenge_method": in.CodeChallengeMethod,
		"nonce": in.Nonce, paramPrompt: in.Prompt, "response_mode": in.ResponseMode, "resource": in.Resource,
		"max_age": in.MaxAge, "login_hint": in.LoginHint, "display": in.Display, "ui_locales": in.UILocales, "id_token_hint": in.IDTokenHint, "request": in.Request, "request_uri": in.RequestURI, "claims": in.Claims, "dpop_jkt": in.DPoPJKT,
	} {
		if s != "" {
			v.Set(k, s)
		}
	}
	if rs := splitResources(in.Resource); len(rs) > 1 {
		v[paramResource] = rs
	}
	return v
}

// decodeAuthorize is the inverse of authorizeValues; a repeated parameter
// is refused, as RFC 6749 section 3.1 requires.
func decodeAuthorize(q url.Values) (AuthorizeRequest, error) {
	// A signed query's own parameters are not part of the request (and
	// ba_param repeats by design).
	q = stripSigned(q)
	for k, v := range q {
		if len(v) > 1 && k != paramResource {
			return AuthorizeRequest{}, ErrInvalidRequest
		}
	}
	resource, err := joinResources(q[paramResource])
	if err != nil {
		return AuthorizeRequest{}, err
	}
	return AuthorizeRequest{
		ResponseType: q.Get("response_type"), ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"),
		Scope: q.Get("scope"), State: q.Get("state"), CodeChallenge: q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"), Nonce: q.Get("nonce"), Prompt: q.Get(paramPrompt),
		ResponseMode: q.Get("response_mode"), Resource: resource, MaxAge: q.Get("max_age"),
		LoginHint: q.Get("login_hint"), Display: q.Get("display"), UILocales: q.Get("ui_locales"), IDTokenHint: q.Get("id_token_hint"), Request: q.Get("request"), RequestURI: q.Get("request_uri"), Claims: q.Get("claims"), DPoPJKT: q.Get("dpop_jkt"),
	}, nil
}

// ResumeURL is the authorize endpoint with query, for the login page to
// send the browser back to once the user has signed in. query is the
// parameters the login page received.
func (p *Plugin) ResumeURL(query url.Values) string {
	return p.endpoint(pathAuthorize) + "?" + query.Encode()
}

// Authorize runs an authorization request from Go: the redirect to answer,
// or an error. A *RedirectError carries the redirect that reports it to the
// client; any other error must be shown to the user, never redirected.
func (p *Plugin) Authorize(ctx context.Context, in AuthorizeRequest) (AuthorizeResult, error) {
	return p.authorize.Call(ctx, in)
}

func (p *Plugin) doAuthorize(ctx context.Context, c *auth.Call, in AuthorizeRequest) (AuthorizeResult, error) {
	return p.authorizeFlow(ctx, c, in, passed{})
}

// authorizeFlow runs an authorization with the gates done already passed
// (by Continue): sign-in, the gates, consent, then the code.
func (p *Plugin) authorizeFlow(ctx context.Context, c *auth.Call, in AuthorizeRequest, done passed) (AuthorizeResult, error) {
	in, err := p.resolvePushed(ctx, in)
	if err != nil {
		return AuthorizeResult{}, err
	}
	z, err := p.validate(ctx, in)
	if err != nil {
		return AuthorizeResult{}, err
	}
	none := slices.Contains(z.prompts, promptNone)
	stale := c.Session != nil && z.maxAge >= 0 && p.core.Now().Sub(c.Session.CreatedAt) > time.Duration(z.maxAge)*time.Second
	if slices.Contains(z.prompts, promptCreate) {
		// prompt=create: the sign-up page, or the login page without one.
		page := p.signupPage
		if page == "" {
			page = p.loginPage
		}
		return AuthorizeResult{RedirectTo: p.pageURL(page, in, true, nil)}, nil
	}
	// prompt=select_account goes to the picker when there is one and the
	// user is signed in, otherwise to the login page.
	reselect := slices.Contains(z.prompts, promptSelectAccount) && p.selectAccount == nil
	if reselect && !p.selectViaLogin {
		return AuthorizeResult{}, ErrUnsupportedPromptSelectAccount
	}
	// An id_token_hint naming another user than the signed-in one asks for
	// that user: sign in again (OpenID Connect Core section 3.1.2.1).
	otherUser := c.User != nil && z.hintSubject != "" && z.hintSubject != p.subjectFor(z.client, c.User.ID)
	if c.User == nil || stale || slices.Contains(z.prompts, promptLogin) || reselect || otherUser {
		if none {
			return AuthorizeResult{}, p.fail(z, ErrLoginRequired)
		}
		return AuthorizeResult{RedirectTo: p.pageURL(p.loginPage, in, true, nil)}, nil
	}
	page, err := p.gate(ctx, c, z, done)
	if err != nil {
		return AuthorizeResult{}, err
	}
	if page != "" {
		if none {
			if p.selectAccount != nil && page == p.selectAccount.Page {
				return AuthorizeResult{}, p.fail(z, ErrAccountSelectionRequired)
			}
			return AuthorizeResult{}, p.fail(z, ErrInteractionRequired)
		}
		return AuthorizeResult{RedirectTo: p.pageURL(page, in, true, nil)}, nil
	}
	ref := p.referenceFor(ctx, c, z)
	if !z.client.c.SkipConsent {
		granted, err := p.consented(ctx, c.User.ID, z.client.c.ClientID, z.scopes, z.userInfoClaims, splitResources(z.in.Resource), ref)
		if err != nil {
			return AuthorizeResult{}, err
		}
		if !granted || slices.Contains(z.prompts, promptConsent) {
			if none || p.consentPage == "" {
				return AuthorizeResult{}, p.fail(z, ErrConsentRequired)
			}
			var marker url.Values
			if done.postLogin {
				// The consent page carries the passed post-login gate,
				// bound to this session, inside the signed query.
				marker = url.Values{paramPostLogin: {postLoginMarker(p.queryKeys()[0], c.Session.ID)}}
			}
			return AuthorizeResult{RedirectTo: p.pageURL(p.consentPage, in, true, marker)}, nil
		}
	}
	return p.issueCode(ctx, c, z, z.scopes, ref)
}

// resolvePushed replaces a request_uri with its stored parameters through
// RequestURIResolver, keeping the URL's client_id (RFC 9126 section 4).
// request with request_uri is invalid_request, and an unresolvable
// request_uri invalid_request_uri; neither is redirected, because the
// client's redirect URI is not known yet.
func (p *Plugin) resolvePushed(ctx context.Context, in AuthorizeRequest) (AuthorizeRequest, error) {
	if in.RequestURI == "" {
		return in, nil
	}
	if in.Request != "" {
		return in, ErrInvalidRequest
	}
	if p.requestURIResolver == nil {
		return in, ErrRequestURINotSupported
	}
	values, err := p.requestURIResolver(ctx, in.RequestURI, in.ClientID)
	if err != nil {
		return in, err
	}
	if values == nil {
		return in, ErrInvalidRequestURI
	}
	resolved, err := decodeAuthorize(values)
	if err != nil {
		return in, err
	}
	if resolved.RequestURI != "" || resolved.Request != "" {
		return in, ErrInvalidRequestURI
	}
	if in.ClientID != "" {
		resolved.ClientID = in.ClientID
	}
	return resolved, nil
}

// Consent records the signed-in user's answer from Go; see ConsentRequest.
func (p *Plugin) Consent(ctx context.Context, in ConsentRequest) (AuthorizeResult, error) {
	return p.consent.Call(ctx, in)
}

func (p *Plugin) doConsent(ctx context.Context, c *auth.Call, in ConsentRequest) (AuthorizeResult, error) {
	// better-auth's oauth_query before-hook: the page posts back the signed
	// query it was given, unchanged and unexpired.
	if err := p.VerifyOAuthQuery(in.Query); err != nil {
		return AuthorizeResult{}, err
	}
	q, err := url.ParseQuery(in.Query)
	if err != nil {
		return AuthorizeResult{}, ErrInvalidRequest
	}
	req, err := decodeAuthorize(q)
	if err != nil {
		return AuthorizeResult{}, err
	}
	z, err := p.validate(ctx, req)
	if err != nil {
		return AuthorizeResult{}, err
	}
	// A query from before the post-login gate (the login page's) cannot
	// skip it: the consent page's carries the session's marker.
	if p.postLoginRequired(ctx, c, z) && !p.markerValid(q, c.Session.ID) {
		return AuthorizeResult{}, ErrInvalidSignature
	}
	if !in.Accept {
		// A denial is a normal answer, not a failure: the client learns it
		// at its redirect URI.
		var re *RedirectError
		errors.As(p.fail(z, ErrAccessDenied), &re)
		return AuthorizeResult{RedirectTo: re.RedirectTo}, nil
	}
	granted := z.scopes
	if in.Scope != "" {
		granted = dedupe(strings.Fields(in.Scope))
		for _, s := range granted {
			if !slices.Contains(z.scopes, s) {
				return AuthorizeResult{}, ErrInvalidScope
			}
		}
	}
	if len(in.Claims) > 0 {
		cr, ok := parseClaimsRequest(string(in.Claims))
		if !ok {
			return AuthorizeResult{}, ErrInvalidRequest
		}
		accepted := cr.requestedUserInfo(p.supportedClaims())
		for _, name := range accepted {
			if !slices.Contains(z.userInfoClaims, name) {
				return AuthorizeResult{}, ErrInvalidRequest
			}
		}
		z.userInfoClaims = accepted
	}
	ref := p.referenceFor(ctx, c, z)
	if err := p.recordConsent(ctx, c.User.ID, z.client.c.ClientID, granted, z.userInfoClaims, splitResources(z.in.Resource), ref); err != nil {
		return AuthorizeResult{}, err
	}
	return p.issueCode(ctx, c, z, granted, ref)
}

// consented reports whether the user's stored consent for the client covers
// every scope.
func (p *Plugin) consented(ctx context.Context, userID, clientID string, scopes, claims, resources []string, ref string) (bool, error) {
	var stored string
	var storedClaims, storedRef, storedRes *string
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(ConsentScopes, &stored), sqlb.Bind(ConsentClaims, &storedClaims), sqlb.Bind(ConsentRef, &storedRef), sqlb.Bind(ConsentResources, &storedRes)).From(TableConsent).
		Where(sqlb.Eq(ConsentUser, userID), sqlb.Eq(ConsentClient, clientID)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if deref(storedRef) != ref {
		// A consent given for another post-login reference (organization)
		// does not cover this one.
		return false, nil
	}
	have, haveClaims := strings.Fields(stored), splitClaims(storedClaims)
	for _, r := range resources {
		if !slices.Contains(splitResources(deref(storedRes)), r) {
			return false, nil
		}
	}
	for _, s := range scopes {
		if !slices.Contains(have, s) {
			return false, nil
		}
	}
	for _, c := range claims {
		if !slices.Contains(haveClaims, c) {
			return false, nil
		}
	}
	return true, nil
}

// recordConsent adds scopes to the user's consent for the client, creating
// it the first time.
func (p *Plugin) recordConsent(ctx context.Context, userID, clientID string, scopes, claims, resources []string, ref string) error {
	now := p.core.Now()
	var id, stored string
	var storedClaims, storedRef, storedRes *string
	err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(ConsentID, &id), sqlb.Bind(ConsentScopes, &stored), sqlb.Bind(ConsentClaims, &storedClaims), sqlb.Bind(ConsentRef, &storedRef), sqlb.Bind(ConsentResources, &storedRes)).From(TableConsent).
		Where(sqlb.Eq(ConsentUser, userID), sqlb.Eq(ConsentClient, clientID)))
	if errors.Is(err, sqlb.ErrNoRows) {
		id, err = p.core.NewID(consentIDPrefix)
		if err != nil {
			return err
		}
		_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableConsent).Row(
			sqlb.Set(ConsentID, id), sqlb.Set(ConsentUser, userID), sqlb.Set(ConsentClient, clientID),
			sqlb.Set(ConsentScopes, strings.Join(scopes, listSeparator)), sqlb.Set(ConsentCreated, now), sqlb.Set(ConsentUpdated, now),
			sqlb.Set(ConsentClaims, joinClaims(claims)), sqlb.Set(ConsentRef, optional(ref)), sqlb.Set(ConsentResources, optional(strings.Join(resources, listSeparator)))))
		return err
	}
	if err != nil {
		return err
	}
	merged := dedupe(append(strings.Fields(stored), scopes...))
	mergedClaims := dedupe(append(splitClaims(storedClaims), claims...))
	mergedRes := dedupe(append(splitResources(deref(storedRes)), resources...))
	if deref(storedRef) != ref {
		// A consent for another reference is replaced, not widened.
		merged, mergedClaims, mergedRes = scopes, claims, resources
	}
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableConsent).
		Set(sqlb.Set(ConsentScopes, strings.Join(merged, listSeparator)), sqlb.Set(ConsentClaims, joinClaims(mergedClaims)), sqlb.Set(ConsentRef, optional(ref)), sqlb.Set(ConsentResources, optional(strings.Join(mergedRes, listSeparator))), sqlb.Set(ConsentUpdated, now)).Where(sqlb.Eq(ConsentID, id)))
	return err
}

// issueCode stores a new code for the signed-in user and answers the
// client's redirect URI with it.
func (p *Plugin) issueCode(ctx context.Context, c *auth.Call, z authzContext, scopes []string, ref string) (AuthorizeResult, error) {
	code := PrefixCode + auth.NewToken().Reveal()
	id, err := p.core.NewID(codeIDPrefix)
	if err != nil {
		return AuthorizeResult{}, err
	}
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableCode).Row(
		sqlb.Set(CodeID, id), sqlb.Set(CodeHash, p.hashSecret(SecretCode, code)), sqlb.Set(CodeClient, z.client.c.ClientID),
		sqlb.Set(CodeUser, c.User.ID), sqlb.Set(CodeSession, c.Session.ID), sqlb.Set(CodeRedirect, z.in.RedirectURI),
		sqlb.Set(CodeScopes, strings.Join(scopes, listSeparator)), sqlb.Set(CodeChallenge, optional(z.in.CodeChallenge)),
		sqlb.Set(CodeMethod, optional(z.in.CodeChallengeMethod)), sqlb.Set(CodeNonce, optional(z.in.Nonce)),
		sqlb.Set(CodeAuthTime, c.Session.CreatedAt), sqlb.Set(CodeExpires, now.Add(p.codeTTL)), sqlb.Set(CodeCreated, now),
		sqlb.Set(CodeResource, optional(z.in.Resource)), sqlb.Set(CodeClaims, joinClaims(z.userInfoClaims)), sqlb.Set(CodeJKT, optional(z.in.DPoPJKT)),
		sqlb.Set(CodeRef, optional(ref)),
	)); err != nil {
		return AuthorizeResult{}, err
	}
	return AuthorizeResult{RedirectTo: p.redirectWith(z.redirect, z.in.State, url.Values{paramCode: {code}})}, nil
}

// codeRow is a stored code.
type codeRow struct {
	id, client, user, session, redirect, scopes string
	challenge, method, nonce, resource, claims  *string
	dpopJKT, refID                              *string
	authTime, expires                           time.Time
	consumed                                    *time.Time
}

func (r *codeRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(CodeID, &r.id), sqlb.Bind(CodeClient, &r.client), sqlb.Bind(CodeUser, &r.user), sqlb.Bind(CodeSession, &r.session),
		sqlb.Bind(CodeRedirect, &r.redirect), sqlb.Bind(CodeScopes, &r.scopes), sqlb.Bind(CodeChallenge, &r.challenge),
		sqlb.Bind(CodeMethod, &r.method), sqlb.Bind(CodeNonce, &r.nonce), sqlb.Bind(CodeAuthTime, &r.authTime),
		sqlb.Bind(CodeExpires, &r.expires), sqlb.Bind(CodeConsumed, &r.consumed), sqlb.Bind(CodeResource, &r.resource), sqlb.Bind(CodeClaims, &r.claims), sqlb.Bind(CodeJKT, &r.dpopJKT), sqlb.Bind(CodeRef, &r.refID),
	}
}

// redeemCode spends a code once. A second use of a spent code is a replay:
// it revokes every token issued from the code (RFC 6749 section 4.1.2) on a
// write that the refused request's rollback does not undo.
func (p *Plugin) redeemCode(ctx context.Context, code string) (codeRow, error) {
	hash := p.hashSecret(SecretCode, code)
	now := p.core.Now()
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableCode).Set(sqlb.Set(CodeConsumed, &now)).
		Where(sqlb.Eq(CodeHash, hash), sqlb.IsNull(CodeConsumed)))
	if err != nil {
		return codeRow{}, err
	}
	var r codeRow
	err = p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableCode).Where(sqlb.Eq(CodeHash, hash)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return codeRow{}, ErrInvalidGrant
	}
	if err != nil {
		return codeRow{}, err
	}
	if n == 0 {
		family := r.id
		p.core.AfterTx(ctx, func(ctx context.Context) { p.revokeFamily(ctx, family) })
		return codeRow{}, ErrInvalidGrant
	}
	if !now.Before(r.expires) {
		return codeRow{}, ErrInvalidGrant
	}
	return r, nil
}

// checkPKCE compares the verifier with the stored challenge in constant
// time. A code issued without a challenge refuses a verifier, so a stripped
// challenge cannot be "upgraded" past (OAuth 2.1 section 4.1.3).
func checkPKCE(r codeRow, verifier string) error {
	if r.challenge == nil {
		if verifier != "" {
			return ErrInvalidGrant
		}
		return nil
	}
	if !validVerifier(verifier) || deref(r.method) != methodS256 {
		return ErrInvalidGrant
	}
	if subtle.ConstantTimeCompare([]byte(s256(verifier)), []byte(*r.challenge)) != 1 {
		return ErrInvalidGrant
	}
	return nil
}
