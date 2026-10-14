package oauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// Re-authentication with a provider: a signed-in user whose way in is a
// provider (no password, no passkey) proves "it is still me" by a round trip
// to a provider account already linked to them, and their current session
// becomes fresh again (auth.Reauthenticate) with no new session, row or
// cookie.
//
// The flow is the sign-in flow with three bindings added. The start is a
// POST from a signed-in page (origin-checked, so no other site can start one)
// that records the session's id in the flow's state, beside the PKCE verifier
// and the flow cookie as at sign-in. The callback refuses unless it arrives on
// that same session, and unless the provider account that came back is one
// LINKED to that session's user: never another person's account, never an
// unlinked one, never a link made on the way. Then the core asks the second
// factor question exactly as the OAuth sign-in callback does (same operation,
// same method), so a policy that asks a code after a provider sign-in asks it
// here too.
//
// What it proves: control of the linked provider account in this browser,
// now. The provider may answer from its own session without asking anything;
// a caller who wants the provider to ask again passes Prompt "login" (OpenID
// Connect), which a ParamsProvider forwards. Under authhttp.SameSiteStrict the
// session cookie does not travel on the provider's redirect, so the callback
// arrives signed out and is refused (auth.ErrSignedOut), as a link flow is.

// EndpointReauthenticate starts a re-authentication with a linked provider:
// POST /reauthenticate, signed in. It answers the provider URL for the page to
// navigate to; it never redirects, because a fetch would follow the redirect.
//
//ds:def id=oauth-endpointreauthenticate-6qv3mx8k owner=@khanakia stability=stable
const EndpointReauthenticate auth.EndpointID = "oauth.reauthenticate"

const pathReauthenticate = "/reauthenticate"

// The landing page's query after a re-authentication callback, beside what
// ReturnTo carried: ParamReauth is ReauthFresh or ReauthSecondFactor, and
// with the latter ParamReauthTicket is the ticket the second factor's
// re-authentication operation takes (twofactor.reauthenticate). The ticket is
// single use, bound to this session and valid for auth.PendingSessionTTL,
// so in the URL it is worth what an authorization code is. A refused
// callback lands on ErrorTo, or on ReturnTo when the start named none, with
// `?error=<code>`.
//
//ds:def id=oauth-paramreauth-2kd8wq5n owner=@khanakia stability=stable
const (
	ParamReauth        = "reauth"
	ParamReauthTicket  = "reauthTicket"
	ReauthFresh        = "fresh"
	ReauthSecondFactor = "second_factor"
)

// Rate limits of the re-authentication start. Each start writes a state row,
// so it shares the sign-in start's per-IP bound; it is also bounded per
// signed-in user, as the password and passkey re-authentications are, since
// a stolen session must not get unlimited tries at the provider round trip.
const (
	//ds:def id=oauth-reauthuserlimit-5wm2kq7x owner=@khanakia stability=stable
	reauthUserLimit  = 10
	reauthUserWindow = 15 * time.Minute
)

// ErrReauthNotLinked refuses a re-authentication with a provider the user has
// no account linked at, or whose callback brought back a provider account
// that is not linked to the signed-in user (another person's, or one never
// linked). One code for every case, so the answer does not tell which
// accounts exist.
var ErrReauthNotLinked = auth.NewError("oauth.reauth_not_linked", http.StatusForbidden, "Continue with the provider account that is linked to this account.")

// ReauthenticateRequest is the input of EndpointReauthenticate.
//
//ds:def id=oauth-reauthenticaterequest-9tn4wk2p owner=@khanakia stability=stable
type ReauthenticateRequest struct {
	// Provider is the provider to confirm with; the user must have an
	// account linked there.
	Provider string `json:"provider"`
	// ReturnTo is where the callback lands, with ParamReauth added: the page
	// that asked, so it can rerun the refused action. Same rules as
	// StartRequest.ReturnTo; empty is the site root.
	ReturnTo string `json:"returnTo,omitempty"`
	// ErrorTo is where a refused callback lands with `?error=<code>`; empty
	// takes ReturnTo, so the user comes back to the page that asked.
	ErrorTo string `json:"errorTo,omitempty"`
	// Prompt is forwarded to a ParamsProvider ("login" asks the provider to
	// sign the person in again rather than answer from its own session).
	Prompt string `json:"prompt,omitempty"`
	// LoginHint pre-fills the account at a ParamsProvider. Empty takes the
	// address of the user's linked account there when there is exactly one.
	LoginHint string `json:"loginHint,omitempty"`
}

// Reauthenticate starts a re-authentication with in.Provider for the
// signed-in user and returns the provider URL the browser must navigate to.
func (p *Plugin) Reauthenticate(ctx context.Context, in ReauthenticateRequest) (StartResult, error) {
	return p.reauth.Call(ctx, in)
}

// reauthRules are the browser re-authentication's rate rules, which
// RateLimits adds. The ID-token re-authentication (reauthIDTokenRules) is
// bounded per IP as the native sign-in is, since each call verifies a
// signature and may fetch a key set, and per user as every
// re-authentication is.
func reauthRules() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointReauthenticate, Key: auth.ByIP, Limit: startIPLimit, Window: startIPWindow},
		{Match: EndpointReauthenticate, Key: auth.ByFunc, Limit: reauthUserLimit, Window: reauthUserWindow, KeyFunc: auth.UserRateKey},
	}
}

// reauthIDTokenRules bound EndpointReauthenticateIDToken, added only where
// the operation exists.
func reauthIDTokenRules() []auth.RateRule {
	return []auth.RateRule{
		{Match: EndpointReauthenticateIDToken, Key: auth.ByIP, Limit: idTokenIPLimit, Window: idTokenIPWindow},
		{Match: EndpointReauthenticateIDToken, Key: auth.ByFunc, Limit: reauthUserLimit, Window: reauthUserWindow, KeyFunc: auth.UserRateKey},
	}
}

// Re-authentication with an ID token: the native counterpart of the round
// trip above, for an app that cannot follow a browser redirect (a mobile,
// desktop or command-line app holding a bearer token). The app signs the
// person in again with the provider's own SDK, which hands it a fresh ID
// token, and posts it here on the session it already holds.
//
// The token is verified exactly as the native sign-in verifies it
// (verifyNative: signature from the provider's key set, issuer, audience,
// lifetime, the nonce rule, an access token only when at_hash binds it), and
// the provider account it names must be one LINKED to the signed-in user, as
// at the callback (reauthProfile). Nothing is ever linked or created here.
//
// Replay: verifyNative claims every token it accepts (replay.go), shared
// with the native sign-in, so a token that signed someone in cannot also
// re-authenticate, and one that re-authenticated cannot do it again
// (ErrIDTokenReplayed). The app asks the SDK for a new token each time.

// EndpointReauthenticateIDToken re-authenticates the signed-in user with a
// provider ID token from a native SDK: POST /reauthenticate-id-token,
// signed in. The answer is auth.Reauthentication, as password.reauthenticate
// answers; when the second factor is due, its Ticket goes to the second
// factor's re-authentication operation with the code.
//
//ds:def id=oauth-endpointreauthidtoken-8kw3nq5v owner=@khanakia stability=stable
const EndpointReauthenticateIDToken auth.EndpointID = "oauth.reauthenticate-id-token"

const pathReauthenticateIDToken = "/reauthenticate-id-token"

// ReauthenticateIDTokenRequest is the input of EndpointReauthenticateIDToken:
// IDTokenRequest's fields, minus SignUp (nothing is created here), plus the
// provider, since the operation is one route for every provider.
//
//ds:def id=oauth-reauthidtokenrequest-3vn8kq2w owner=@khanakia stability=stable
type ReauthenticateIDTokenRequest struct {
	// Provider names the provider that issued IDToken; it must verify ID
	// tokens (an IDTokenVerifier) and the user must have an account linked
	// there.
	Provider string `json:"provider"`
	// IDToken is the provider's ID token, a compact JWS.
	IDToken string `json:"idToken"`
	// Nonce is the value the app sent to the provider, when it sent one,
	// under the same rule as IDTokenRequest.Nonce.
	Nonce string `json:"nonce,omitempty"`
	// AccessToken is the access token the SDK received with the ID token,
	// taken only when the ID token's at_hash binds it, and then stored under
	// StoreTokens, as IDTokenRequest.AccessToken is.
	AccessToken string `json:"accessToken,omitempty"`
}

// ReauthenticateIDToken re-authenticates the signed-in user with a provider
// ID token, for a Go caller holding the request context. Without a provider
// that verifies ID tokens it is ErrIDTokenUnsupported.
func (p *Plugin) ReauthenticateIDToken(ctx context.Context, in ReauthenticateIDTokenRequest) (auth.Reauthentication, error) {
	if p.reauthIDToken == nil {
		return auth.Reauthentication{}, ErrIDTokenUnsupported
	}
	return p.reauthIDToken.Call(ctx, in)
}

// doReauthIDToken refuses a caller who cannot re-authenticate before
// anything else (auth.CanReauthenticate), so a refused caller costs no
// signature check; then a provider that is not configured
// (ErrReauthNotLinked, as the browser start answers) or verifies no ID
// tokens (ErrIDTokenUnsupported). The verified profile goes through the
// callback's decision, and the core refreshes the session or answers the
// second factor's ticket, asked as at sign-in. A refused proof (a token that
// fails verification, an account not linked to this user, a hook's refusal)
// is reported to the security stream; a provider outage is not a proof and
// is not reported.
func (p *Plugin) doReauthIDToken(ctx context.Context, c *auth.Call, in ReauthenticateIDTokenRequest) (auth.Reauthentication, error) {
	if err := c.Auth.CanReauthenticate(c); err != nil {
		return auth.Reauthentication{}, err
	}
	prov := p.provider(in.Provider)
	if prov == nil {
		return auth.Reauthentication{}, ErrReauthNotLinked
	}
	v, ok := prov.(IDTokenVerifier)
	if !ok {
		return auth.Reauthentication{}, ErrIDTokenUnsupported
	}
	prof, err := p.verifyNative(ctx, c, v, in.IDToken, in.Nonce, in.AccessToken)
	if err == nil {
		var server map[string]string
		if server, err = p.runServerContext(ctx, c, v.Name()); err == nil {
			err = p.reauthProfile(ctx, c, v.Name(), prof, "", server)
		}
	}
	if err != nil {
		var refused *auth.Error
		if errors.As(err, &refused) && !errors.Is(err, ErrProviderFailed) && !errors.Is(err, ErrIDTokenUnsupported) {
			c.Auth.ReportReauthFailure(c)
		}
		return auth.Reauthentication{}, err
	}
	c.Annotate(AnnotationAction, string(AccountReauthenticated))
	return c.Auth.Reauthenticate(ctx, c, auth.ReauthAttempt{})
}

// doReauthStart refuses a caller who cannot re-authenticate before anything
// else (auth.CanReauthenticate), then a provider the user has no account at,
// and begins a flow bound to the current session.
func (p *Plugin) doReauthStart(ctx context.Context, c *auth.Call, in ReauthenticateRequest) (StartResult, error) {
	if err := c.Auth.CanReauthenticate(c); err != nil {
		return StartResult{}, err
	}
	prov := p.provider(in.Provider)
	if prov == nil {
		return StartResult{}, ErrReauthNotLinked
	}
	accs, err := p.Accounts(ctx, c.User.ID)
	if err != nil {
		return StartResult{}, err
	}
	var linked []Account
	for _, acc := range accs {
		if acc.Provider == prov.Name() {
			linked = append(linked, acc)
		}
	}
	if len(linked) == 0 {
		return StartResult{}, ErrReauthNotLinked
	}
	start := StartRequest{ReturnTo: in.ReturnTo, ErrorTo: in.ErrorTo, Prompt: in.Prompt, LoginHint: in.LoginHint}
	if _, ok := prov.(ParamsProvider); ok && start.LoginHint == "" && len(linked) == 1 {
		// The provider then offers the linked account first, so the person
		// does not pick another one by habit and get refused.
		start.LoginHint = linked[0].Email
	}
	meta, err := p.startMeta(ctx, c, prov, start)
	if err != nil {
		return StartResult{}, err
	}
	meta.Reauth = c.Session.ID
	u, err := p.beginFlow(ctx, c, prov, start, meta)
	return StartResult{URL: u}, err
}

// reauthSession is the callback's first check of a re-authentication flow,
// made before the code is exchanged: the caller may re-authenticate, and is
// on the session the flow was started on (a sign-out and another sign-in in
// between, or a URL carried to another browser, proves nothing here).
func reauthSession(c *auth.Call, sessionID string) error {
	if err := c.Auth.CanReauthenticate(c); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(sessionID), []byte(c.Session.ID)) != 1 {
		return ErrStateInvalid
	}
	return nil
}

// reauthCallback finishes a re-authentication once the provider answered:
// the sign-in profile rules, then the account must be linked to the
// signed-in user, then the ValidateProfile hooks see a sign-in
// (ProfileEvent.Reauthentication set), the new provider tokens are kept as at
// sign-in, and the core refreshes the session or asks for the second factor.
// A refusal is reported to the security stream and changes nothing.
func (p *Plugin) reauthCallback(ctx context.Context, c *auth.Call, provider string, prof Profile, meta flowMeta) (CallbackResult, error) {
	if err := p.reauthProfile(ctx, c, provider, prof, meta.Data, meta.Server); err != nil {
		var refused *auth.Error
		if errors.As(err, &refused) {
			c.Auth.ReportReauthFailure(c)
		}
		return CallbackResult{}, err
	}
	c.Annotate(AnnotationAction, string(AccountReauthenticated))
	res, err := c.Auth.Reauthenticate(ctx, c, auth.ReauthAttempt{})
	if err != nil {
		return CallbackResult{}, err
	}
	landing := reauthLanding(meta.ReturnTo, res)
	c.Effects.Redirect(landing)
	return CallbackResult{User: auth.ViewOf(*c.User), RedirectTo: landing, Reauthentication: &res, Data: meta.Data, ServerContext: meta.Server}, nil
}

// reauthProfile is the decision both re-authentications share, once the
// provider's answer is trusted (a callback's exchange, a verified ID token):
// the sign-in profile rules, then the provider account must be one LINKED to
// the signed-in user (another user's or an unlinked one is
// ErrReauthNotLinked, and nothing is linked or created), then the
// ValidateProfile hooks see a sign-in with Reauthentication set, and the
// provider tokens that came with the answer are kept as at sign-in.
func (p *Plugin) reauthProfile(ctx context.Context, c *auth.Call, provider string, prof Profile, data string, server map[string]string) error {
	if err := p.signInProfileRule(prof); err != nil {
		return err
	}
	return c.Auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		acc, err := p.accountBySubject(ctx, provider, prof.Subject)
		switch {
		case errors.Is(err, sqlb.ErrNoRows):
			return ErrReauthNotLinked
		case err != nil:
			return err
		case acc.UserID != c.User.ID:
			// Linked, to someone else: proves nothing about this user.
			return ErrReauthNotLinked
		}
		ev := ProfileEvent{Provider: provider, Profile: prof, Action: ActionSignIn, UserID: acc.UserID, Data: data, ServerContext: server, Reauthentication: true}
		if err := p.validateProfile(ctx, c, ev); err != nil {
			return err
		}
		return p.storeTokens(ctx, acc.ID, prof.Tokens)
	})
}

// reauthLanding adds the outcome to page's query, keeping what is there.
// page passed TrustsReturnURL at the start, so it parses; one that does not
// is answered as it is.
func reauthLanding(page string, r auth.Reauthentication) string {
	u, err := url.Parse(page)
	if err != nil {
		return page
	}
	q := u.Query()
	if r.SecondFactorRequired {
		q.Set(ParamReauth, ReauthSecondFactor)
		q.Set(ParamReauthTicket, string(r.Ticket))
	} else {
		q.Set(ParamReauth, ReauthFresh)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
