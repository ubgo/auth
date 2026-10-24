package oauthprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/ubgo/auth"
)

// The pages a signed-in user may be sent to before consent: the
// select-account, signup and post-login gates. Each page receives the signed
// authorize query and resumes with Continue (POST
// /oauthprovider/continue), which runs the authorization again with that gate
// passed.

// GateInfo is what a gate decides from: the signed-in call, the client and
// the requested scopes.
type GateInfo struct {
	Call     *auth.Call
	ClientID string
	Scopes   []string
}

// SelectAccountGate is the account picker a signed-in user is sent to for
// prompt=select_account, or whenever ShouldRedirect says so.
type SelectAccountGate struct {
	// Page is the picker, a same-site path or a URL on a trusted origin.
	Page string
	// ShouldRedirect, when set, sends the user to Page without
	// prompt=select_account too.
	ShouldRedirect func(ctx context.Context, info GateInfo) bool
}

// PostLoginGate is a page after sign-in (choosing an organization or team)
// whose choice the consent and the tokens are tied to.
type PostLoginGate struct {
	// Page is the post-login page, a same-site path or a trusted URL.
	Page string
	// ShouldRedirect decides whether the user must pass Page; required.
	ShouldRedirect func(ctx context.Context, info GateInfo) bool
	// ConsentReferenceID, when set, is the reference (an organization id)
	// a consent is given for: a consent for another reference asks again,
	// and the codes and tokens carry it (AccessToken.ReferenceID,
	// AccessTokenClaimsInfo.ReferenceID).
	ConsentReferenceID func(ctx context.Context, info GateInfo) string
}

// SignupRedirectFunc decides the signup gate: true sends a
// signed-in user to more registration steps, at page or, when page is "",
// SignupPage.
type SignupRedirectFunc func(ctx context.Context, info GateInfo) (redirect bool, page string)

// SelectAccount installs the select-account gate.
func SelectAccount(g SelectAccountGate) Option { return func(p *Plugin) { p.selectAccount = &g } }

// PostLogin installs the post-login gate; it needs auth.WithSecret, which
// signs the marker the consent page carries once the gate is passed
// (auth.New refuses it without one, with ErrBadGate and ErrNoSecret).
func PostLogin(g PostLoginGate) Option { return func(p *Plugin) { p.postLogin = &g } }

// SignupRedirect installs the sign-up gate.
func SignupRedirect(fn SignupRedirectFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.SignupRedirect", fn) {
			return
		}
		p.signupRedirect = fn
	}
}

// The OpenID Connect prompt=none errors of a gate: the picker is
// account_selection_required, the sign-up and post-login pages
// interaction_required.
var (
	ErrAccountSelectionRequired = auth.NewError("oauthprovider.account_selection_required", http.StatusForbidden, "The user must choose an account.")
	ErrInteractionRequired      = auth.NewError("oauthprovider.interaction_required", http.StatusForbidden, "The user must complete a step before this authorization.")
)

// ErrBadGate is a gate without its page or decision, or a post-login gate
// without auth.WithSecret.
var ErrBadGate = errors.New("oauthprovider: a gate needs its page (trusted) and its decision, and PostLogin needs auth.WithSecret")

// ContinueRequest resumes an authorization from a gate's page: Query is the
// signed query the page received; Selected, Created and PostLogin say which
// gate was passed.
type ContinueRequest struct {
	Query     string `json:"oauth_query"`
	Selected  bool   `json:"selected,omitempty"`
	Created   bool   `json:"created,omitempty"`
	PostLogin bool   `json:"post_login,omitempty"`
}

// passed records the gates a Continue passed.
type passed struct {
	selected, created, postLogin bool
}

// initGates checks the gates' pages against the trusted origins and that
// the post-login gate has its decision; Validate has already checked that
// it can sign its marker.
func (p *Plugin) initGates(a *auth.Auth) error {
	if g := p.selectAccount; g != nil && (g.Page == "" || !a.TrustsReturnURL(g.Page)) {
		return fmt.Errorf("%w: oauthprovider.SelectAccount: page %q", ErrBadGate, g.Page)
	}
	if g := p.postLogin; g != nil && (g.Page == "" || g.ShouldRedirect == nil || !a.TrustsReturnURL(g.Page)) {
		return fmt.Errorf("%w: oauthprovider.PostLogin: page %q", ErrBadGate, g.Page)
	}
	return nil
}

// postLoginMarker binds a passed post-login gate to the session: an HMAC of the
// session id under the query key.
func postLoginMarker(key []byte, sessionID string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(paramPostLogin + "\x00" + sessionID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// markerValid reports whether a signed query carries the post-login marker
// of this session, under the current or a previous key.
func (p *Plugin) markerValid(q url.Values, sessionID string) bool {
	got := q.Get(paramPostLogin)
	if got == "" {
		return false
	}
	for _, k := range p.queryKeys() {
		if subtle.ConstantTimeCompare([]byte(got), []byte(postLoginMarker(k, sessionID))) == 1 {
			return true
		}
	}
	return false
}

// gateInfo builds a gate's GateInfo.
func gateInfo(c *auth.Call, z authzContext) GateInfo {
	return GateInfo{Call: c, ClientID: z.client.c.ClientID, Scopes: slices.Clone(z.scopes)}
}

// referenceFor is the post-login reference of a request, or "".
func (p *Plugin) referenceFor(ctx context.Context, c *auth.Call, z authzContext) string {
	if p.postLogin == nil || p.postLogin.ConsentReferenceID == nil {
		return ""
	}
	return p.postLogin.ConsentReferenceID(ctx, gateInfo(c, z))
}

// postLoginRequired reports whether the post-login gate applies to a
// request.
func (p *Plugin) postLoginRequired(ctx context.Context, c *auth.Call, z authzContext) bool {
	return p.postLogin != nil && p.postLogin.ShouldRedirect(ctx, gateInfo(c, z))
}

// gate answers the page a signed-in user must pass before consent, or "":
// the picker, the sign-up steps, then the post-login page, skipping the
// ones Continue passed.
func (p *Plugin) gate(ctx context.Context, c *auth.Call, z authzContext, done passed) (string, error) {
	info := gateInfo(c, z)
	if g := p.selectAccount; g != nil && !done.selected {
		if slices.Contains(z.prompts, promptSelectAccount) || (g.ShouldRedirect != nil && g.ShouldRedirect(ctx, info)) {
			return g.Page, nil
		}
	}
	if p.signupRedirect != nil && !done.created {
		if redirect, page := p.signupRedirect(ctx, info); redirect {
			if page == "" {
				page = p.signupPage
			}
			if page == "" || !p.core.TrustsReturnURL(page) {
				return "", ErrBadGate
			}
			return page, nil
		}
	}
	if !done.postLogin && p.postLoginRequired(ctx, c, z) {
		return p.postLogin.Page, nil
	}
	return "", nil
}

// Continue resumes an authorization after a gate's page, from Go.
func (p *Plugin) Continue(ctx context.Context, in ContinueRequest) (AuthorizeResult, error) {
	return p.continueOp.Call(ctx, in)
}

func (p *Plugin) doContinue(ctx context.Context, c *auth.Call, in ContinueRequest) (AuthorizeResult, error) {
	if err := p.VerifyOAuthQuery(in.Query); err != nil {
		return AuthorizeResult{}, err
	}
	if !in.Selected && !in.Created && !in.PostLogin {
		return AuthorizeResult{}, ErrInvalidRequest
	}
	q, err := url.ParseQuery(in.Query)
	if err != nil {
		return AuthorizeResult{}, ErrInvalidRequest
	}
	req, err := decodeAuthorize(q)
	if err != nil {
		return AuthorizeResult{}, err
	}
	// The gate passed no longer prompts: select_account was answered by the
	// picker, create by the sign-up steps.
	drop := func(v string) {
		req.Prompt = strings.Join(slices.DeleteFunc(strings.Fields(req.Prompt), func(s string) bool { return s == v }), " ")
	}
	if in.Selected {
		drop(promptSelectAccount)
	}
	if in.Created {
		drop(promptCreate)
	}
	return p.authorizeFlow(ctx, c, req, passed{selected: in.Selected, created: in.Created, postLogin: in.PostLogin})
}
