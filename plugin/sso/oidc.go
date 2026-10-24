package sso

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// reservedAuthParams are the authorization-request parameters the flow sets
// itself (RFC 6749, OpenID Connect, PKCE); SignInRequest.AdditionalParams
// may not name one (ErrBadParams).
var reservedAuthParams = []string{"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge",
	"code_challenge_method", "nonce", "response_mode", "request", "request_uri"}

// oauthProvider builds the plugin/oauth provider a flow runs on: the
// provider's endpoints (discovered first when missing), PKCE, and ID-token
// verification against its JWKS with the client id as audience and the
// issuer as the only accepted iss. The ID token is the profile source;
// userinfo, when published, only adds claims (userInfo).
func (p *Plugin) oauthProvider(ctx context.Context, pr Provider, scopes []string, params map[string]string) (*oauth.OAuth2, error) {
	cfg := *pr.OIDC
	if NeedsRuntimeDiscovery(cfg) {
		if err := p.Discover(ctx, pr.Issuer, &cfg); err != nil {
			return nil, err
		}
	}
	if len(scopes) == 0 {
		scopes = cfg.scopes()
	}
	ta := cfg.TokenEndpointAuthentication
	if ta == "" {
		ta = oauth.ClientSecretBasic
	}
	o := &oauth.OAuth2{
		ID: oauthProviderName, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		AuthURL: cfg.AuthorizationEndpoint, TokenURL: cfg.TokenEndpoint, Scopes: scopes, TokenAuth: ta,
		NoPKCE:  !cfg.pkceOn(),
		IDToken: oauth.IDTokenConfig{JWKSURL: cfg.JWKSEndpoint, Issuers: issuerSpellings(pr.Issuer), ProfileFromToken: true, RequireNonce: true},
	}
	if len(params) > 0 {
		o.AuthParams = url.Values{}
		for k, v := range params {
			o.AuthParams.Set(k, v)
		}
	}
	if ta == oauth.PrivateKeyJWT {
		if p.keys == nil {
			return nil, fmt.Errorf("%w: provider %q uses private_key_jwt without sso.WithPrivateKeyResolver", ErrBadProvider, pr.ProviderID)
		}
		key, kid, err := p.keys(ctx, PrivateKeyRequest{ProviderID: pr.ProviderID, KeyID: cfg.PrivateKeyID, Issuer: pr.Issuer, Algorithm: cfg.PrivateKeyAlgorithm})
		if err != nil || key == nil {
			return nil, fmt.Errorf("%w: %v", ErrNoPrivateKey, err)
		}
		if kid == "" {
			kid = cfg.PrivateKeyID
		}
		if err := keyMatchesAlgorithm(key, cfg.PrivateKeyAlgorithm); err != nil {
			return nil, err
		}
		if o.ClientAssertion, err = oauth.ClientAssertion(cfg.ClientID, kid, key); err != nil {
			return nil, err
		}
		o.ClientSecret = ""
	}
	if err := oauth.ValidateProvider(o); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadProvider, err)
	}
	return o, nil
}

// oauthProviderName names every flow's oauth.OAuth2. It is never a route
// or a stored name here (auth_sso_account keys on the provider id), and a
// provider id may hold characters plugin/oauth's names may not.
const oauthProviderName = PluginName

// keyMatchesAlgorithm checks privateKeyAlgorithm against the resolved key:
// oauth.ClientAssertion signs RS256 with an RSA key and ES256 with a P-256
// key, so any other pairing would send an assertion the IdP refuses. Empty
// is RS256, the default, unless the key is ECDSA.
func keyMatchesAlgorithm(key crypto.Signer, alg string) error {
	_, isEC := key.Public().(*ecdsa.PublicKey)
	_, isRSA := key.Public().(*rsa.PublicKey)
	switch {
	case alg == "":
		return nil
	case alg == privateKeyRS256 && isRSA, alg == privateKeyES256 && isEC:
		return nil
	}
	return fmt.Errorf("%w: privateKeyAlgorithm %q does not match the resolved key", ErrBadProvider, alg)
}

// The private_key_jwt algorithms oauth.ClientAssertion signs.
const (
	privateKeyRS256 = "RS256"
	privateKeyES256 = "ES256"
)

// issuerSpellings is the issuer with and without a trailing slash: the
// discovery check ignores it, and issuers differ on whether iss carries one.
func issuerSpellings(iss string) []string {
	bare := strings.TrimSuffix(iss, "/")
	return []string{bare, bare + "/"}
}

// startOIDC writes the state and returns the authorization URL.
func (p *Plugin) startOIDC(ctx context.Context, c *auth.Call, pr Provider, in SignInRequest, meta flowMeta) (string, error) {
	for k := range in.AdditionalParams {
		if slices.Contains(reservedAuthParams, strings.ToLower(k)) {
			return "", ErrBadParams
		}
	}
	prov, err := p.oauthProvider(ctx, pr, in.Scopes, in.AdditionalParams)
	if err != nil {
		return "", p.providerFailure(c, pr, err)
	}
	meta.Verifier = auth.NewToken().Reveal()
	state, err := c.Auth.IssueVerification(ctx, PurposeState, pr.ProviderID, p.stateTTL, meta.encode())
	if err != nil {
		return "", err
	}
	hint := in.LoginHint
	if hint == "" {
		hint = in.Email
	}
	u := prov.AuthCodeURLWithParams(state.Reveal(), oauth.PKCEChallenge(meta.Verifier), p.callbackURLFor(pr.ProviderID), oauth.RequestParams{LoginHint: hint})
	c.Effects.BindFlow(state, c.Auth.Now().Add(p.stateTTL))
	return u, nil
}

// providerFailure logs an IdP failure and returns what the caller sees: a
// configuration or discovery error as itself, anything else as
// ErrProviderFailed.
func (p *Plugin) providerFailure(c *auth.Call, pr Provider, err error) error {
	c.Auth.Logger().Warn("sso: provider failed", "provider", pr.ProviderID, "error", err)
	var de *DiscoveryError
	switch {
	case errors.As(err, &de) || errors.Is(err, ErrBadProvider) || errors.Is(err, ErrNoIDToken) ||
		errors.Is(err, ErrTokenNotVerified) || errors.Is(err, ErrNoPrivateKey):
		return err
	case errors.Is(err, oauth.ErrIDTokenInvalid):
		return ErrTokenNotVerified
	case errors.Is(err, oauth.ErrExchange):
		return ErrTokenExchange
	}
	return ErrProviderFailed
}

// CallbackRequest is the OIDC callback's query.
type CallbackRequest struct {
	Code             string `json:"code,omitempty"`
	State            string `json:"state,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	// Iss is RFC 9207's issuer parameter.
	Iss string `json:"iss,omitempty"`
	// ProviderID names the provider of an IdP-initiated callback, which has
	// no state: register the redirect URI with ?providerId=<id> at the IdP.
	ProviderID string `json:"providerId,omitempty"`
}

// CallbackResult is a completed sign-in.
type CallbackResult struct {
	User       auth.UserView `json:"user"`
	Token      auth.Token    `json:"-"`
	RedirectTo string        `json:"redirectTo"`
	// Created is true when the sign-in created the user.
	Created              bool `json:"created"`
	SecondFactorRequired bool `json:"secondFactorRequired,omitempty"`
}

func (p *Plugin) doCallback(ctx context.Context, c *auth.Call, in CallbackRequest) (CallbackResult, error) {
	c.Effects.BindFlow("", time.Time{}) // the binding is single use too
	c.RedirectOnError(p.errorURL)
	if in.Error != "" {
		return CallbackResult{}, ErrProviderDenied
	}
	if in.State == "" && in.Code != "" && in.ProviderID != "" {
		return p.restartInitiated(ctx, c, in.ProviderID)
	}
	if in.State == "" || subtle.ConstantTimeCompare([]byte(in.State), []byte(c.Flow.Reveal())) != 1 {
		return CallbackResult{}, ErrStateInvalid
	}
	v, err := c.Auth.ConsumeVerification(ctx, PurposeState, auth.Token(in.State))
	if errors.Is(err, auth.ErrTokenInvalid) {
		return CallbackResult{}, ErrStateInvalid
	}
	if err != nil {
		return CallbackResult{}, err
	}
	var meta flowMeta
	if err := json.Unmarshal([]byte(v.Meta), &meta); err != nil || meta.Provider != v.Identifier {
		return CallbackResult{}, ErrStateInvalid
	}
	// Under PerProviderPaths the URL names the provider too; a callback for
	// one provider at another's URL is refused.
	if in.ProviderID != "" && in.ProviderID != meta.Provider {
		return CallbackResult{}, ErrStateInvalid
	}
	if meta.ErrorTo != "" {
		c.RedirectOnError(meta.ErrorTo)
	}
	pr, err := p.ProviderByID(ctx, meta.Provider)
	if err != nil {
		return CallbackResult{}, ErrStateInvalid
	}
	if pr.OIDC == nil || subtle.ConstantTimeCompare([]byte(pr.Reference()), []byte(meta.Reference)) != 1 {
		return CallbackResult{}, ErrProviderChanged
	}
	// RFC 9207: an iss parameter, when sent, must be this provider's issuer
	// (the mix-up defence); the ID token's iss is checked regardless.
	if in.Iss != "" && strings.TrimSuffix(in.Iss, "/") != strings.TrimSuffix(pr.Issuer, "/") {
		return CallbackResult{}, ErrStateInvalid
	}
	prov, err := p.callbackProvider(ctx, pr, oauth.PKCEChallenge(meta.Verifier))
	if err != nil {
		return CallbackResult{}, p.providerFailure(c, pr, err)
	}
	prof, err := prov.Exchange(ctx, p.hc, in.Code, meta.Verifier, p.callbackURLFor(pr.ProviderID))
	if err != nil {
		return CallbackResult{}, p.providerFailure(c, pr, err)
	}
	info, err := p.oidcUserInfo(ctx, pr, prof)
	if err != nil {
		return CallbackResult{}, p.providerFailure(c, pr, err)
	}
	return p.complete(ctx, c, pr, ProtocolOIDC, pr.Issuer, info, meta)
}

// callbackProvider is oauthProvider for the code exchange, with the ID
// token verified here rather than inside plugin/oauth's exchange, so each
// failure keeps its own answer: a token endpoint that refused is
// ErrTokenExchange, a response without an id_token ErrNoIDToken, a token
// that does not verify (signature, iss, aud, exp, nonce) ErrTokenNotVerified.
// nonce is the flow's PKCE challenge, which the start sent as the nonce.
func (p *Plugin) callbackProvider(ctx context.Context, pr Provider, nonce string) (*oauth.OAuth2, error) {
	prov, err := p.oauthProvider(ctx, pr, nil, nil)
	if err != nil {
		return nil, err
	}
	verifier, err := p.oauthProvider(ctx, pr, nil, nil)
	if err != nil {
		return nil, err
	}
	prov.IDToken.ProfileFromToken = false
	prov.FetchProfileFromTokens = func(ctx context.Context, hc *http.Client, ts oauth.TokenSet) (oauth.Profile, error) {
		if ts.IDToken == "" {
			return oauth.Profile{}, ErrNoIDToken
		}
		prof, err := verifier.VerifyIDToken(ctx, hc, ts.IDToken.Reveal(), nonce)
		if err != nil {
			return oauth.Profile{}, fmt.Errorf("%w: %w", ErrTokenNotVerified, err)
		}
		return prof, nil
	}
	return prov, nil
}

// restartInitiated answers an IdP-initiated callback (a code, no state) for
// a provider with AllowIdPInitiated by starting a fresh flow: the code it
// carried is never redeemed, so nothing an attacker planted can sign anyone
// in; the person lands at the IdP again and comes back with a state bound
// to this browser.
func (p *Plugin) restartInitiated(ctx context.Context, c *auth.Call, providerID string) (CallbackResult, error) {
	pr, err := p.ProviderByID(ctx, providerID)
	if err != nil || pr.OIDC == nil || !pr.OIDC.AllowIdPInitiated {
		return CallbackResult{}, ErrStateInvalid
	}
	meta := flowMeta{Provider: pr.ProviderID, Reference: pr.Reference(), Protocol: ProtocolOIDC, ReturnTo: siteRoot}
	u, err := p.startOIDC(ctx, c, pr, SignInRequest{}, meta)
	if err != nil {
		return CallbackResult{}, err
	}
	c.Effects.Redirect(u)
	return CallbackResult{RedirectTo: u}, nil
}

// oidcUserInfo maps a verified ID token, plus the userinfo answer when the
// provider publishes one, onto UserInfo. The ID token's azp, when present,
// must be the client id; userinfo's sub must equal the token's.
func (p *Plugin) oidcUserInfo(ctx context.Context, pr Provider, prof oauth.Profile) (UserInfo, error) {
	claims := map[string]any{}
	for k, raw := range prof.Claims {
		var v any
		if json.Unmarshal(raw, &v) == nil {
			claims[k] = v
		}
	}
	if azp, ok := claims["azp"].(string); ok && azp != "" && azp != pr.OIDC.ClientID {
		return UserInfo{}, fmt.Errorf("%w: id_token azp %q", oauth.ErrIDTokenInvalid, azp)
	}
	if ep := pr.OIDC.UserInfoEndpoint; ep != "" && prof.Tokens.AccessToken != "" {
		up, err := oauth.UserInfoProfile(ep, "")(ctx, p.hc, prof.Tokens.AccessToken.Reveal())
		if err != nil {
			return UserInfo{}, err
		}
		if up.Subject != prof.Subject {
			return UserInfo{}, fmt.Errorf("%w: userinfo sub %q differs from the id_token's", oauth.ErrIDTokenInvalid, up.Subject)
		}
		for k, raw := range up.Claims {
			var v any
			if _, have := claims[k]; !have && json.Unmarshal(raw, &v) == nil {
				claims[k] = v
			}
		}
	}
	return MapClaims(pr.OIDC.Mapping, claims), nil
}

// MapClaims applies an OIDCMapping to claims. email_verified counts only as
// the boolean true or the string "true".
func MapClaims(m OIDCMapping, claims map[string]any) UserInfo {
	str := func(name, def string) string {
		if name == "" {
			name = def
		}
		s, _ := claims[name].(string)
		return s
	}
	ev := claims[firstOf(m.EmailVerified, "email_verified")]
	info := UserInfo{
		Subject: str(m.ID, "sub"), Email: strings.ToLower(strings.TrimSpace(str(m.Email, "email"))),
		EmailVerified: ev == true || ev == "true", Name: str(m.Name, "name"), Image: str(m.Image, "picture"), Claims: claims,
	}
	if info.Name == "" {
		info.Name = strings.TrimSpace(str("", "given_name") + " " + str("", "family_name"))
	}
	if len(m.ExtraFields) > 0 {
		info.Extra = map[string]any{}
		for k, claim := range m.ExtraFields {
			if v, ok := claims[claim]; ok {
				info.Extra[k] = v
			}
		}
	}
	return info
}

// firstOf returns the first non-empty string.
func firstOf(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
