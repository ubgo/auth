package samlidp

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/ubgo/auth"
)

// Result is what an endpoint answers: a redirect (to the continue step or
// the login page), or the response form the browser posts to the SP.
// Exactly one is set.
type Result struct {
	RedirectTo string        `json:"redirect_to,omitempty"`
	Form       *ResponseForm `json:"form,omitempty"`
}

// ContinueRequest names a pending request by the handle in the continue URL.
type ContinueRequest struct {
	Request string `json:"request"`
}

// InitiateRequest starts IdP-initiated sign-on to an SP.
type InitiateRequest struct {
	// ServiceProvider is the SP's entity ID.
	ServiceProvider string `json:"sp"`
	// ACSURL picks a registered ACS URL; the first when empty.
	ACSURL     string `json:"acs_url,omitempty"`
	RelayState string `json:"relay_state,omitempty"`
}

// paramRequest is the continue URL's query parameter.
const paramRequest = "request"

// pending is an accepted AuthnRequest waiting for sign-in, stored as the
// Meta of a PurposePending verification row.
type pending struct {
	SP          string    `json:"sp"`
	RequestID   string    `json:"id"`
	ACS         string    `json:"acs"`
	RelayState  string    `json:"relay,omitempty"`
	ForceAuthn  bool      `json:"force,omitempty"`
	IsPassive   bool      `json:"passive,omitempty"`
	RequestedAt time.Time `json:"at"`
	Expires     time.Time `json:"exp"`
}

// SSO accepts an AuthnRequest from Go: the redirect to the continue step,
// or an error to show the user.
func (p *Plugin) SSO(ctx context.Context, in SSORequest) (Result, error) { return p.sso.Call(ctx, in) }

// Continue answers a pending request for the caller's session: the login
// redirect while signed out, the response form once signed in.
func (p *Plugin) Continue(ctx context.Context, in ContinueRequest) (Result, error) {
	return p.cont.Call(ctx, in)
}

// Initiate builds an unsolicited response for the signed-in caller to an SP
// that allows IdP-initiated sign-on.
func (p *Plugin) Initiate(ctx context.Context, in InitiateRequest) (Result, error) {
	return p.initiate.Call(ctx, in)
}

// ContinueURL is the continue step for a pending request's handle.
func (p *Plugin) ContinueURL(handle string) string {
	return p.endpoint(pathContinue) + "?" + url.Values{paramRequest: {handle}}.Encode()
}

func (p *Plugin) doSSO(ctx context.Context, c *auth.Call, in SSORequest) (Result, error) {
	if in.SAMLRequest == "" {
		return Result{}, ErrMissingRequestParam
	}
	if len(in.RelayState) > MaxRelayState {
		return Result{}, ErrRelayStateTooLong
	}
	req, sp, err := p.parseRequest(ctx, in)
	if err != nil {
		return Result{}, err
	}
	now := p.core.Now()
	acs, err := p.checkRequest(req, sp, now)
	if err != nil {
		return Result{}, err
	}
	claim := RequestClaim{SP: sp.EntityID, Request: req.ID, Until: req.IssueInstant.Add(p.requestMaxAge + p.skew)}
	if err := p.guard.Claim(ctx, claim); err != nil {
		if errors.Is(err, ErrRequestReplayed) {
			c.Auth.Logger().Warn("samlidp: AuthnRequest replayed", "sp", sp.EntityID)
			c.Auth.EmitSecurityOf(c, auth.SecurityEvent{
				Kind: auth.SecurityTokenReplay, Severity: auth.SeverityAlert, Outcome: auth.RateOutcomeBlocked,
				Attrs: map[string]string{auth.AttrProvider: sp.EntityID},
			})
		}
		return Result{}, err
	}
	pd := pending{
		SP: sp.EntityID, RequestID: req.ID, ACS: acs, RelayState: in.RelayState,
		ForceAuthn: req.ForceAuthn, IsPassive: req.IsPassive, RequestedAt: now, Expires: now.Add(p.loginTTL),
	}
	handle, err := p.storePending(ctx, pd)
	if err != nil {
		return Result{}, err
	}
	return Result{RedirectTo: p.ContinueURL(handle)}, nil
}

// storePending files pd until its Expires and returns its handle.
func (p *Plugin) storePending(ctx context.Context, pd pending) (string, error) {
	meta, _ := json.Marshal(pd) // strings, bools and times: Marshal cannot fail
	tok, err := p.core.IssueVerification(ctx, PurposePending, pd.SP, pd.Expires.Sub(p.core.Now()), string(meta))
	return string(tok), err
}

func (p *Plugin) doContinue(ctx context.Context, c *auth.Call, in ContinueRequest) (Result, error) {
	if in.Request == "" {
		return Result{}, ErrRequestNotFound
	}
	// Spending the handle first makes it single use: of two tabs that reach
	// here with one handle, one goes on.
	v, err := c.Auth.ConsumeVerification(ctx, PurposePending, auth.Token(in.Request))
	if errors.Is(err, auth.ErrTokenInvalid) {
		return Result{}, ErrRequestNotFound
	}
	if err != nil {
		return Result{}, err
	}
	var pd pending
	if err := json.Unmarshal([]byte(v.Meta), &pd); err != nil {
		return Result{}, ErrRequestNotFound
	}
	sp, err := p.lookupSP(ctx, pd.SP)
	if err != nil {
		return Result{}, err
	}
	// The pipeline already hides a session that waits for a second factor
	// or has a task pending from a Public operation; the check is repeated
	// here because issuing an assertion for such a session would sign the
	// user in somewhere else before they finished signing in here.
	signedIn := c.User != nil && c.Session != nil && !c.Session.SecondFactorPending && len(c.Session.Tasks) == 0
	fresh := signedIn && (!pd.ForceAuthn || !c.Session.CreatedAt.Before(pd.RequestedAt))
	is := issue{sp: sp, acs: pd.ACS, inResponseTo: pd.RequestID, relayState: pd.RelayState}
	if !fresh {
		if pd.IsPassive {
			// The SP asked not to show any page: answer NoPassive at its
			// ACS URL instead of the login page.
			resp, err := p.buildFailure(issue{sp: sp, acs: pd.ACS, inResponseTo: pd.RequestID, status: StatusResponder, subStatus: StatusNoPassive})
			if err != nil {
				return Result{}, err
			}
			return Result{Form: &ResponseForm{ACSURL: pd.ACS, SAMLResponse: resp, RelayState: pd.RelayState}}, nil
		}
		// Still signed out: file the request again under a new handle, so
		// the login page's return link works once and the old one is dead.
		handle, err := p.storePending(ctx, pd)
		if err != nil {
			return Result{}, err
		}
		return Result{RedirectTo: p.loginURL(p.ContinueURL(handle), signedIn)}, nil
	}
	return p.answer(ctx, *c.User, *c.Session, is)
}

func (p *Plugin) doInitiate(ctx context.Context, c *auth.Call, in InitiateRequest) (Result, error) {
	if len(in.RelayState) > MaxRelayState {
		return Result{}, ErrRelayStateTooLong
	}
	sp, err := p.lookupSP(ctx, in.ServiceProvider)
	if err != nil {
		return Result{}, err
	}
	if !sp.AllowIdPInitiated {
		return Result{}, ErrIdPInitiatedOff
	}
	acs, err := resolveACS(authnRequest{ACSURL: in.ACSURL, ACSIndex: -1}, sp)
	if err != nil {
		return Result{}, err
	}
	return p.answer(ctx, *c.User, *c.Session, issue{sp: sp, acs: acs, relayState: in.RelayState})
}

// answer checks access and builds the response form for the user.
func (p *Plugin) answer(ctx context.Context, u auth.User, s auth.Session, is issue) (Result, error) {
	if p.access != nil {
		if err := p.access(ctx, u, is.sp); err != nil {
			var ae *auth.Error
			if errors.As(err, &ae) {
				return Result{}, err
			}
			return Result{}, ErrAccessDenied
		}
	}
	sub, err := p.subjectOf(ctx, u, s)
	if err != nil {
		return Result{}, err
	}
	resp, err := p.buildSuccess(ctx, is, sub)
	if err != nil {
		return Result{}, err
	}
	return Result{Form: &ResponseForm{ACSURL: is.acs, SAMLResponse: resp, RelayState: is.relayState}}, nil
}

// loginURL is LoginPage with the continue URL, and prompt=login when the
// browser has a session that is too old for ForceAuthn.
func (p *Plugin) loginURL(returnTo string, reauth bool) string {
	u, _ := url.Parse(p.loginPage) // checked by Init
	q := u.Query()
	q.Set(p.returnParam, returnTo)
	if reauth {
		q.Set(ParamPrompt, PromptLogin)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
