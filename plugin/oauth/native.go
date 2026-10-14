package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/ubgo/auth"
)

// Logouter is a Provider with an RP-initiated logout endpoint (OpenID
// Connect RP-Initiated Logout 1.0). *OAuth2 (EndSessionURL) and
// *OIDCProvider (the discovery document's end_session_endpoint) implement
// it; the logout operation exists only for providers that do.
//
//ds:def id=logouter-x3nd8bqv owner=@khanakia stability=stable
type Logouter interface {
	Provider
	// EndSession returns the provider's end_session_endpoint, or "" when the
	// provider has none.
	EndSession(ctx context.Context, hc *http.Client) (string, error)
}

// EndSession returns EndSessionURL.
func (o *OAuth2) EndSession(context.Context, *http.Client) (string, error) {
	return o.EndSessionURL, nil
}

// IDTokenRequest is the input of an id-token operation: a token the app
// received from the provider's native SDK.
//
//ds:def id=idtokenrequest-g7mw4ztk owner=@khanakia stability=stable
type IDTokenRequest struct {
	// IDToken is the provider's ID token, a compact JWS.
	IDToken string `json:"idToken"`
	// Nonce is the value the app sent to the provider, when it sent one;
	// the token's nonce claim must be it or its SHA-256 hex.
	Nonce string `json:"nonce,omitempty"`
	// SignUp says the person meant to sign up, which ExplicitSignUp
	// requires before a user is created.
	SignUp bool `json:"signUp,omitempty"`
	// AccessToken is the access token the native SDK received with the ID
	// token, better-auth's idToken.accessToken. It is taken only when the ID
	// token binds it: an at_hash claim (OpenID Connect Core 3.1.3.6) equal
	// to the hash of this value, so a client cannot attach a stolen or
	// unrelated token to a verified identity. A token without at_hash, or
	// with another hash, is ErrIDTokenInvalid. Once taken, it is the
	// account's stored access token under StoreTokens, like a callback's.
	AccessToken string `json:"accessToken,omitempty"`
}

// atHash is the OpenID Connect at_hash of accessToken for an ID token signed
// with alg: the left half of the hash the algorithm uses, base64url without
// padding. EdDSA (Ed25519) hashes with SHA-512, the rest listed here with
// SHA-256; "" for an algorithm this plugin does not accept.
func atHash(alg, accessToken string) string {
	var sum []byte
	switch alg {
	case algRS256, algES256:
		h := sha256.Sum256([]byte(accessToken))
		sum = h[:]
	case algEdDSA:
		h := sha512.Sum512([]byte(accessToken))
		sum = h[:]
	default:
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// bindAccessToken checks that the verified ID token's at_hash binds
// accessToken, and records it on the profile. idToken has been verified, so
// its header (signed with it) names the real algorithm.
func bindAccessToken(idToken, accessToken string, prof *Profile) error {
	head, _, _ := strings.Cut(idToken, ".")
	hb, err := base64.RawURLEncoding.DecodeString(head)
	var h idTokenHeader
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return fmt.Errorf("%w: header", ErrIDTokenInvalid)
	}
	var claim string
	if raw, ok := prof.Claims[claimAtHash]; !ok || json.Unmarshal(raw, &claim) != nil || claim == "" {
		return fmt.Errorf("%w: no at_hash binds the access token", ErrIDTokenInvalid)
	}
	want := atHash(h.Alg, accessToken)
	if want == "" || subtle.ConstantTimeCompare([]byte(claim), []byte(want)) != 1 {
		return fmt.Errorf("%w: at_hash does not match the access token", ErrIDTokenInvalid)
	}
	prof.Tokens.AccessToken = auth.Token(accessToken)
	return nil
}

// claimAtHash is the ID token claim that binds an access token.
const claimAtHash = "at_hash"

// LogoutRequest is the input of a provider logout. Every field is optional:
// an empty request sends the configured PostLogoutURL.
//
//ds:def id=logoutrequest-q7hn2vwc owner=@khanakia stability=stable
type LogoutRequest struct {
	// Provider names the provider to sign out of on the general logout
	// route (POST /logout), which needs it (ErrLogoutProvider). On a
	// provider's own route (/<provider>/logout) it may be left empty; any
	// other value than that provider is ErrLogoutProvider.
	Provider string `json:"provider,omitempty"`
	// ReturnTo is where the provider sends the browser after its logout, as
	// post_logout_redirect_uri, instead of PostLogoutURL. It passes the same
	// TrustsReturnURL check as a sign-in's returnTo, so it is a path on this
	// site, a URL on a trusted origin or a trusted deep-link scheme;
	// anything else is ErrBadReturnTo and the session is not ended. A path
	// is made absolute against the base URL, because the parameter must be
	// an absolute URI. It must still be registered at the provider, which
	// refuses an unregistered one on its own page.
	ReturnTo string `json:"returnTo,omitempty"`
}

// LogoutResult is the provider URL that ends the session there. HTTP
// transports redirect to it; a Go or API caller navigates itself.
type LogoutResult struct {
	URL string `json:"url"`
}

// validate checks an IDTokenConfig: a JWKSURL needs issuers to compare
// against, and ProfileFromToken needs a verifier to run.
func (c IDTokenConfig) validate() error {
	if (c.Enabled() && len(c.Issuers) == 0) || (c.ProfileFromToken && !c.Enabled()) {
		return ErrIDTokenConfig
	}
	return nil
}

// doIDToken signs in with a verified ID token. The resolution is the
// callback's: a linked account signs in, a verified address links, a
// signed-in caller links the provider, otherwise a user is created. No
// provider tokens are stored unless the request carries an access token the
// ID token binds (IDTokenRequest.AccessToken); the app holds the SDK's
// refresh token, never this server. The token is checked by verifyNative.
func (p *Plugin) doIDToken(ctx context.Context, c *auth.Call, prov IDTokenVerifier, in IDTokenRequest) (CallbackResult, error) {
	profile, err := p.verifyNative(ctx, c, prov, in.IDToken, in.Nonce, in.AccessToken)
	if err != nil {
		return CallbackResult{}, err
	}
	meta := flowMeta{SignUp: in.SignUp}
	if c.User != nil {
		meta.LinkUser = c.User.ID
	}
	if meta.Server, err = p.runServerContext(ctx, c, prov.Name()); err != nil {
		return CallbackResult{}, err
	}
	out, err := p.resolveTx(ctx, c, prov.Name(), profile, meta)
	if err != nil {
		return CallbackResult{}, err
	}
	out.ServerContext = meta.Server
	if out.Linked {
		return out, nil
	}
	if held, err := p.hold(ctx, c, &out, ""); held || err != nil {
		return out, err
	}
	sess, tok, err := c.Auth.CreateSession(ctx, out.User.ID, c.Client)
	if err != nil {
		return CallbackResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	out.Token, out.SecondFactorRequired = tok, sess.SecondFactorPending
	return out, nil
}

// verifyNative is the verification every ID-token operation shares, the
// native sign-in and its re-authentication (EndpointReauthenticateIDToken)
// alike, so the two can never drift: the provider's checks (signature from
// the key set, issuer, audience, lifetime, the nonce rule), then the access
// token when one is sent, which only an at_hash binding admits, then the
// replay guard's claim (ErrIDTokenReplayed for a token already accepted). A
// key-set fetch failure is ErrProviderFailed; a token that must not be
// trusted is ErrIDTokenInvalid, one answer for every reason.
func (p *Plugin) verifyNative(ctx context.Context, c *auth.Call, prov IDTokenVerifier, idToken, nonce, accessToken string) (Profile, error) {
	if idToken == "" {
		return Profile{}, ErrIDTokenInvalid
	}
	// Verification may fetch the key set, a network call, so it runs
	// outside the pipeline's transaction... except that an id-token
	// operation is a Mutation, so the pipeline opened one. The fetch is
	// bounded by the HTTP client's timeout, which is the price of a
	// cookie-free POST.
	profile, err := prov.VerifyIDToken(ctx, p.hc, idToken, nonce)
	switch {
	case errors.Is(err, ErrJWKSFailed):
		c.Auth.Logger().Warn("oauth: key set", "provider", prov.Name(), "error", err)
		return Profile{}, ErrProviderFailed
	case errors.Is(err, ErrIDTokenInvalid), errors.Is(err, ErrNonceRequired), errors.Is(err, ErrIDTokenUnsupported):
		c.Auth.Logger().Info("oauth: id token refused", "provider", prov.Name(), "error", err)
		return Profile{}, err
	case err != nil:
		c.Auth.Logger().Warn("oauth: id token", "provider", prov.Name(), "error", err)
		return Profile{}, ErrProviderFailed
	}
	if accessToken != "" {
		if err := bindAccessToken(idToken, accessToken, &profile); err != nil {
			c.Auth.Logger().Info("oauth: access token refused", "provider", prov.Name(), "error", err)
			return Profile{}, ErrIDTokenInvalid
		}
	}
	// Last, once everything about the token is proven and before anything
	// is created, linked or refreshed: a token is accepted once
	// (replay.go), so a refused one above never spends it.
	if err := p.claimIDToken(ctx, c, prov.Name(), idToken, profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

// ErrLogoutProvider is a logout request that names no provider on the
// general route, or another provider than its own route's.
var ErrLogoutProvider = auth.NewError("oauth.logout_provider", http.StatusBadRequest, "Name the provider to sign out of.")

// doLogoutAny is the general logout route: the provider comes from the
// request, and the rest is the per-provider route's code path, returnTo check
// included. A provider that is not configured, was left out, or has no
// logout is ErrLogoutUnsupported, the answer its own route would give if it
// existed. Nothing is guessed from the linked accounts: an empty provider is
// ErrLogoutProvider, because the most recently used account is not
// necessarily the provider the person means to leave.
func (p *Plugin) doLogoutAny(ctx context.Context, c *auth.Call, in LogoutRequest) (LogoutResult, error) {
	if in.Provider == "" {
		return LogoutResult{}, ErrLogoutProvider
	}
	l, ok := p.provider(in.Provider).(Logouter)
	if !ok {
		return LogoutResult{}, ErrLogoutUnsupported
	}
	return p.doLogout(ctx, c, l, in)
}

// doLogout ends the session here, through the core's own sign-out, then
// sends the browser to the provider's end-session endpoint with the stored
// ID token as id_token_hint (when StoreTokens kept one), the client id and
// the post-logout redirect URI. The local sign-out happens first and
// unconditionally: a provider that is down must not keep this app's session
// alive.
func (p *Plugin) doLogout(ctx context.Context, c *auth.Call, prov Logouter, in LogoutRequest) (LogoutResult, error) {
	if in.Provider != "" && in.Provider != prov.Name() {
		return LogoutResult{}, ErrLogoutProvider
	}
	// The return address is checked before anything else, so a refused one
	// leaves the session and the provider untouched.
	landing, err := p.logoutReturn(prov.Name(), in.ReturnTo)
	if err != nil {
		return LogoutResult{}, err
	}
	end, err := prov.EndSession(ctx, p.hc)
	if err != nil {
		c.Auth.Logger().Warn("oauth: end session", "provider", prov.Name(), "error", err)
		return LogoutResult{}, ErrProviderFailed
	}
	if end == "" {
		return LogoutResult{}, ErrLogoutUnsupported
	}
	q := url.Values{}
	_, ts, err := p.loadTokens(ctx, c.User.ID, prov.Name())
	switch {
	case err == nil && ts.IDToken != "":
		q.Set(paramIDTokenHint, ts.IDToken.Reveal())
	case err != nil && !errors.Is(err, ErrNoTokens):
		return LogoutResult{}, err
	}
	if id := clientIDOf(prov); id != "" {
		q.Set(paramClientID, id)
	}
	q.Set(paramPostLogoutRedirect, landing)
	if err := c.Auth.SignOut(ctx); err != nil {
		return LogoutResult{}, err
	}
	sep := "?"
	if strings.Contains(end, "?") {
		sep = "&"
	}
	u := end + sep + q.Encode()
	c.Effects.Redirect(u)
	return LogoutResult{URL: u}, nil
}

// logoutReturn is the post_logout_redirect_uri of one logout: the request's
// ReturnTo when it passes TrustsReturnURL, made absolute against the base
// URL when it is a path (refused when there is no base URL); PostLogoutURL
// when the request names none.
func (p *Plugin) logoutReturn(provider, requested string) (string, error) {
	if requested == "" {
		return p.postLogout(provider), nil
	}
	if !p.core.TrustsReturnURL(requested) {
		return "", ErrBadReturnTo
	}
	if !strings.HasPrefix(requested, "/") {
		return requested, nil
	}
	// Without a base URL (an app that set both CallbackURL and
	// PostLogoutURL) a path cannot become the absolute URI the parameter
	// must be, so it is refused rather than sent relative.
	base := strings.TrimSuffix(p.core.Config().BaseURL, "/")
	if base == "" {
		return "", ErrBadReturnTo
	}
	return base + requested, nil
}

// clientIDOf reads the client id of a built-in provider; a custom Logouter
// that is neither sends none, which the specification allows when an
// id_token_hint is present.
func clientIDOf(prov Provider) string {
	switch o := prov.(type) {
	case *OAuth2:
		return o.ClientID
	case *OIDCProvider:
		return o.ClientID
	}
	return ""
}

// redirectOnError asks the transport to send a failed callback to path with
// the error code in the query (the core appends it as the error parameter):
// the plugin's or the request's path, else the core's auth.WithErrorURL.
func (p *Plugin) redirectOnError(c *auth.Call, path string) {
	// An empty path is passed on too: the core then falls back to
	// auth.WithErrorURL, and keeps JSON when the app set neither.
	c.RedirectOnError(path)
}

// PostedProfile is a Provider whose form-post callback carries a user field
// beside the code (Apple's first-consent name): the plugin hands the field to
// it after the exchange. *OAuth2 implements it through PostedUser.
//
//ds:def id=postedprofile-k4wn7xqt owner=@khanakia stability=stable
type PostedProfile interface {
	Provider
	// ApplyPosted reads raw, the callback's user field, into p; "" is a
	// callback that carried none.
	ApplyPosted(raw string, p *Profile)
}

// FormPoster is a Provider that answers by response_mode=form_post. For each
// one the plugin also serves POST at the callback route: a relay that turns
// the cross-site form into the GET callback the flow cookie travels with.
// *OAuth2 implements it through FormPost.
//
//ds:def id=formposter-n2xk8wqm owner=@khanakia stability=stable
type FormPoster interface {
	Provider
	PostsBack() bool
}
