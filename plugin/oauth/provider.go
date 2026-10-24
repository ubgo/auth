package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth"
)

// Profile is what a provider says about the person who signed in.
type Profile struct {
	// Subject is the provider's stable id for the person. Never the email,
	// which the person can change at the provider.
	Subject string
	Email   string
	// EmailVerified is the provider's claim that the person controls Email.
	// Only a verified claim can link to an existing account.
	EmailVerified bool
	Name          string
	Image         string
	// Tokens are the provider's tokens, kept only with StoreTokens.
	Tokens TokenSet
	// Claims are the raw claims the profile was read from: the userinfo or
	// API answer of a built-in FetchProfile, or the ID token's payload. A
	// ValidateProfile or OnResolved hook reads provider-specific fields here
	// (a Google hd, a GitHub login). Nil for a custom FetchProfile that does
	// not fill it.
	Claims map[string]json.RawMessage
}

// TokenSet is what a provider's token endpoint issued. The tokens are
// auth.Token, so they print as "[redacted]" everywhere.
type TokenSet struct {
	AccessToken  auth.Token
	RefreshToken auth.Token
	// ExpiresAt is when AccessToken expires; zero when the provider did not
	// say.
	ExpiresAt time.Time
	// RefreshParams are parameters every refresh grant of this account
	// must repeat, kept (sealed) with the tokens under StoreTokens: VK ID's
	// device_id, taken from the callback (OAuth2.RefreshCallbackParams).
	// Nil for every other provider.
	RefreshParams url.Values
	// IDToken is the OpenID Connect ID token the token endpoint returned,
	// empty when it returned none. Stored (sealed) only with StoreTokens, for
	// the id_token_hint of a provider logout.
	IDToken auth.Token
	// Scope is the scope the provider says it granted (RFC 6749 section 5.1),
	// "" when it did not say; stored with StoreTokens so an app knows which
	// scopes an incremental authorization added.
	Scope string
	// RefreshExpiresAt is when RefreshToken expires, for the providers that
	// say (refresh_token_expires_in, refresh_expires_in); zero when unknown.
	RefreshExpiresAt time.Time
	// Raw is the token endpoint's whole JSON answer, for a
	// FetchProfileFromTokens that needs a provider-specific field (WeChat's
	// openid, Slack's authed_user). Never stored.
	Raw json.RawMessage
}

// Provider is one identity provider. The library ships Google and GitHub as
// *OAuth2 values; an app adds any other by implementing this interface.
//
//ds:def id=provider-9wm45phy owner=@khanakia stability=stable
type Provider interface {
	// Name is the route segment and the stored provider name, such as
	// "google". It must match auth.KindNamePattern and never change.
	Name() string
	// AuthCodeURL is where the browser goes to sign in. PKCE is not
	// optional: every URL carries the S256 challenge.
	AuthCodeURL(state, codeChallenge, redirectURI string) string
	// Exchange turns the callback's code into the person's profile.
	Exchange(ctx context.Context, hc *http.Client, code, codeVerifier, redirectURI string) (Profile, error)
}

// TokenAuth is how the client proves itself at the token endpoint (RFC 6749
// section 2.3.1). Providers differ: most accept the secret in the form body,
// some (Reddit, PayPal, Zoom, X, Cloudflare) only as HTTP Basic, and a native
// or browser client has no secret at all and relies on PKCE.
type TokenAuth string

const (
	// ClientSecretPost sends client_id and client_secret in the form body.
	// The default, and what the built-in providers use.
	ClientSecretPost TokenAuth = "client_secret_post"
	// ClientSecretBasic sends them in an Authorization: Basic header, each
	// form-encoded first as the RFC requires.
	ClientSecretBasic TokenAuth = "client_secret_basic"
	// PublicClient sends client_id only; the code is protected by PKCE alone.
	// Validate refuses a ClientSecret together with it, since a secret that
	// is never sent is a configuration mistake.
	PublicClient TokenAuth = "none"
	// PrivateKeyJWT sends a signed assertion (RFC 7523 section 2.2) instead
	// of a secret: client_assertion_type and client_assertion from
	// OAuth2.ClientAssertion. For Entra ID workload identity and any issuer
	// that refuses shared secrets. Validate refuses a ClientSecret with it.
	PrivateKeyJWT TokenAuth = "private_key_jwt"
)

// TokenAuthValues is every TokenAuth, for validation and documentation.
var TokenAuthValues = []TokenAuth{ClientSecretPost, ClientSecretBasic, PublicClient, PrivateKeyJWT}

// OAuth2 is a provider that speaks plain OAuth 2.0 with PKCE and reads the
// profile with the access token. The URL fields are exported so a test can
// point them at a local server.
//
//ds:def id=oauth2-vwfanjbg owner=@khanakia stability=stable
type OAuth2 struct {
	ID           string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Scopes       []string
	// FetchProfile reads the profile with the access token.
	FetchProfile func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error)
	// FetchProfileFromTokens reads the profile from the whole token set
	// (TokenSet.Raw included), for a provider whose profile call needs more
	// than the access token. One profile source is required: this,
	// FetchProfile, or IDToken.ProfileFromToken; the first set wins in that
	// order reversed (ProfileFromToken, then this, then FetchProfile).
	FetchProfileFromTokens func(ctx context.Context, hc *http.Client, tokens TokenSet) (Profile, error)
	// TokenAuth is how the token endpoint is authenticated to; zero is ClientSecretPost.
	TokenAuth TokenAuth
	// AuthParams are added to every authorization URL (prompt, access_type,
	// hd, …); the protocol's own keys (reservedAuthParams) are ignored, so a
	// parameter here can never weaken the flow.
	AuthParams url.Values
	// TokenParams are added to every token and refresh request; the grant's
	// own keys (reservedTokenParams) are ignored.
	TokenParams url.Values
	// RefreshParams are added to refresh requests only, on top of
	// TokenParams, for a provider whose refresh grant takes a parameter the
	// code exchange does not; the grant's own keys are ignored here too.
	RefreshParams url.Values
	// AuthorizationIssuer is the iss value the callback must carry (RFC
	// 9207), for a provider that sends one; a callback without it, or with
	// another, is refused as ErrStateInvalid, the mix-up attack defence.
	// Empty means the provider sends none and nothing is checked. An
	// OIDCProvider fills it from the discovery document when the issuer
	// publishes authorization_response_iss_parameter_supported.
	AuthorizationIssuer string
	// RevokeURL is the provider's token revocation endpoint (RFC 7009); when
	// set and StoreTokens kept tokens, unlink revokes them there, best
	// effort. Empty revokes nothing.
	RevokeURL string
	// ClientAssertion signs the RFC 7523 client assertion for TokenAuth
	// PrivateKeyJWT; see the ClientAssertion constructor. Validate requires
	// it with PrivateKeyJWT and refuses it with any other TokenAuth.
	ClientAssertion func(ctx context.Context, tokenURL string) (string, error)
	// OptionalScopes are the scopes a start request may add to Scopes for
	// incremental authorization; any other is refused with ErrBadScope.
	OptionalScopes []string
	// OptionalParams are the authorization parameters a start request may
	// set (StartRequest.Params), such as display, ui_locales or acr_values.
	// Only names listed here are forwarded, any other is refused with
	// ErrBadParam, and the protocol's own (reservedAuthParams) are never
	// forwarded, so a client can never choose a parameter the app did not name.
	OptionalParams []string
	// TokenLifetime is the access token's lifetime when the token response
	// has no expires_in; zero keeps the expiry unknown, which disables refresh.
	TokenLifetime time.Duration
	// IDToken makes the provider accept ID tokens (the id-token operation)
	// and, with ProfileFromToken, read the profile from the token response's
	// id_token instead of FetchProfile. Zero accepts none.
	IDToken IDTokenConfig
	// EndSessionURL is the provider's RP-initiated logout endpoint; empty
	// means none, and the logout operation answers ErrLogoutUnsupported.
	EndSessionURL string
	// ClientSecretFunc computes the client secret per token request, for a
	// secret that is a signed assertion (Apple; see AppleClientSecret).
	ClientSecretFunc func(ctx context.Context) (string, error)
	// Headers are added to every token, refresh and revocation request, for
	// a provider that requires a User-Agent naming the app (Reddit) or an
	// API version header. Authorization and Content-Type (reservedHeaders)
	// are ignored: the credentials and the encoding are the grant's own.
	Headers http.Header
	// FormPost asks the provider to answer with response_mode=form_post
	// (OAuth 2.0 Form Post Response Mode): the callback arrives as a
	// cross-site POST, which the plugin relays into the GET callback. Apple
	// requires it whenever a scope is requested; see AppleWithEmail.
	FormPost bool
	// PostedUser reads the user field a form-post callback may carry into
	// the profile after the exchange: Apple sends the person's name there,
	// once, on first consent, and nowhere else. Nil ignores the field.
	PostedUser func(raw string, p *Profile)
	// GetToken, when set, replaces the built-in code exchange: it receives
	// the callback's code, the flow's PKCE verifier ("" on a
	// provider-initiated sign-in, which has none) and the redirect URI, and
	// returns the provider's tokens. For a provider whose token endpoint is
	// not RFC 6749 (a GET, a JSON body, another parameter name). Everything
	// else stays the plugin's: the state, PKCE, the profile read from the
	// returned tokens (FetchProfile, FetchProfileFromTokens or the ID token),
	// linking and the session. An error it returns comes out of Exchange
	// unchanged; the callback logs it and answers ErrProviderFailed, as for
	// every failed exchange. A set without an AccessToken is a failed
	// exchange, and TokenLifetime fills a zero ExpiresAt. With it, TokenURL
	// is needed only for Refresh.
	GetToken func(ctx context.Context, code, verifier, redirectURI string) (TokenSet, error)
	// DisplayName is the provider's name for people ("Google", "Okta at
	// Acme"), listed by the providers route for a sign-in page's buttons.
	// The presets set it; empty falls back to ID.
	DisplayName string
	// NoPKCE leaves PKCE out of this provider's flow: no code_challenge on
	// the authorization URL and no code_verifier at the exchange, for a
	// provider whose web flow has no PKCE and might refuse
	// or misread the parameters (Notion, TikTok's web Login Kit, WeChat). The
	// state is still single use and bound to the browser by the flow cookie,
	// and the client secret still guards the exchange; what is lost is RFC
	// 7636's defence against an authorization code stolen in transit and
	// injected into another browser's callback, the accepted risk of setting
	// it. Validate refuses it with PublicClient, where PKCE is the only thing
	// that ties the code to this client. The verifier is still generated, so
	// an IDToken.ProfileFromToken nonce keeps its binding to the flow.
	NoPKCE bool
	// ClientIDParam is the name the client id travels under on the
	// authorization URL and in the token, refresh and revocation forms;
	// empty is client_id (RFC 6749). TikTok calls it client_key, WeChat appid.
	ClientIDParam string
	// ClientSecretParam is the name of the client secret in the token,
	// refresh and revocation forms under ClientSecretPost; empty is
	// client_secret. WeChat calls it secret.
	ClientSecretParam string
	// ScopeSeparator joins the scopes in the scope parameter; empty is a
	// space (RFC 6749 section 3.3). TikTok and WeChat take a comma.
	ScopeSeparator string
	// AuthURLFragment is appended to the authorization URL as #fragment, for
	// a provider that requires one (WeChat's #wechat_redirect). Empty adds
	// none.
	AuthURLFragment string

	// CallbackParams are callback query parameters the token request
	// carries as well, for a provider whose exchange needs a value its
	// redirect returned: VK ID requires the device_id and the state it sent
	// back. Each must be one of CallbackParamValues; Validate refuses any
	// other. Empty forwards none, the RFC 6749 exchange.
	CallbackParams []CallbackParam
	// RefreshCallbackParams are callback values the refresh grant needs
	// again, long after the callback: VK ID's device_id. The exchange puts
	// them in TokenSet.RefreshParams, StoreTokens keeps them sealed with the
	// tokens, and RefreshWithParams sends them. Each must be one of
	// CallbackParamValues.
	RefreshCallbackParams []CallbackParam

	// exchange and renew replace the code and refresh grants for a preset
	// whose token endpoint is not RFC 6749 (WeChat's GET with appid and
	// secret, Notion's JSON body). Unexported, with the plugin's HTTP
	// client: an app's own replacement is GetToken.
	exchange func(ctx context.Context, hc *http.Client, code, redirectURI string) (TokenSet, error)
	renew    func(ctx context.Context, hc *http.Client, refreshToken auth.Token) (TokenSet, error)

	// The ID-token verifier is built once (one key cache); now is the test clock.
	idOnce     sync.Once
	idVerifier *idTokenVerifier
	now        func() time.Time
}

// RequestParams are what one start request adds to the authorization URL,
// on top of the provider's static configuration.
type RequestParams struct {
	// Prompt is the OpenID Connect prompt value: none, login, consent,
	// select_account.
	Prompt string
	// LoginHint pre-fills the account at the provider.
	LoginHint string
	// Scopes are extra scopes, already checked against OptionalScopes.
	Scopes []string
	// Extra are further authorization parameters, already checked against
	// the provider's OptionalParams; the protocol's own keys are never in
	// it.
	Extra url.Values
}

// ParamsAllowLister is a ParamsProvider that names the extra parameters a
// start request may set (OptionalParams). *OAuth2 and *OIDCProvider
// implement it; a start with StartRequest.Params at a provider that does not
// is refused with ErrRequestParams.
//
//ds:def id=paramsallowlister-5nw8qk3x owner=@khanakia stability=stable
type ParamsAllowLister interface {
	ParamsProvider
	// OptionalParamList is the parameter names a request may set.
	OptionalParamList() []string
}

// ParamsProvider is a Provider whose authorization URL takes per-request
// parameters. *OAuth2 and *OIDCProvider implement it; a Provider that does
// not is refused a start that carries any (ErrRequestParams), rather than
// silently dropping what the caller asked for.
type ParamsProvider interface {
	Provider
	// AuthCodeURLWithParams is AuthCodeURL plus the request's parameters.
	AuthCodeURLWithParams(state, codeChallenge, redirectURI string, rp RequestParams) string
	// OptionalScopeList is the scopes a request may add.
	OptionalScopeList() []string
}

// reservedAuthParams are the authorization parameters the plugin sets; an
// AuthParams entry with one of these names is ignored.
var reservedAuthParams = []string{paramResponseType, paramClientID, paramRedirectURI, paramScope, paramState, paramChallenge, paramChallengeAlg, paramNonce, paramResponseMode}

// reservedHeaders are the headers a grant request sets itself; a Headers
// entry with one of these names is ignored, so a header can never replace
// the client credentials or mislabel the body.
var reservedHeaders = []string{headerAuthorization, headerContentType}

// reservedTokenParams are the token-request parameters a grant sets; a
// TokenParams or RefreshParams entry with one of these names is ignored.
var reservedTokenParams = []string{paramGrantType, paramCode, paramRedirectURI, paramVerifier, paramRefreshToken, paramClientID, paramClientSecret, paramAssertionType, paramAssertion}

// Name returns ID, the route segment and stored provider name.
func (o *OAuth2) Name() string { return o.ID }

// Label returns DisplayName, or ID when it is empty.
func (o *OAuth2) Label() string { return firstOf(o.DisplayName, o.ID) }

// OAuth 2.0 parameter names (RFC 6749, RFC 7636) the plugin sends.
const (
	paramResponseType = "response_type"
	paramClientID     = "client_id"
	paramClientSecret = "client_secret"
	paramRedirectURI  = "redirect_uri"
	paramScope        = "scope"
	paramState        = "state"
	paramCode         = "code"
	paramChallenge    = "code_challenge"
	paramChallengeAlg = "code_challenge_method"
	paramVerifier     = "code_verifier"
	paramGrantType    = "grant_type"
	paramRefreshToken = "refresh_token"
	paramPrompt       = "prompt"
	paramLoginHint    = "login_hint"
	// paramResponseMode and responseModeFormPost ask for the OAuth 2.0 Form
	// Post Response Mode: the authorization response as a POST form instead
	// of a GET query.
	paramResponseMode    = "response_mode"
	responseModeFormPost = "form_post"
	// paramAssertionType and paramAssertion carry an RFC 7523 client
	// assertion; assertionTypeJWT is the one type the RFC defines.
	paramAssertionType = "client_assertion_type"
	paramAssertion     = "client_assertion"
	assertionTypeJWT   = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// paramToken and paramTokenTypeHint are the RFC 7009 revocation request;
	// the hint values name which token is sent.
	paramToken          = "token"
	paramTokenTypeHint  = "token_type_hint"
	tokenTypeRefresh    = "refresh_token"
	tokenTypeAccess     = "access_token"
	responseTypeCode    = "code"
	challengeMethodS256 = "S256"
	// grantAuthorizationCode trades the callback's code for tokens.
	grantAuthorizationCode = "authorization_code"
	// grantRefreshToken trades a refresh token for new tokens.
	grantRefreshToken = "refresh_token"
	// scopeSeparator joins scopes in the scope parameter (RFC 6749 3.3).
	scopeSeparator = " "
)

// HTTP header names and values of provider calls.
const (
	headerAccept        = "Accept"
	headerAuthorization = "Authorization"
	headerContentType   = "Content-Type"
	contentTypeJSON     = "application/json"
	contentTypeForm     = "application/x-www-form-urlencoded"
	bearerPrefix        = "Bearer "
)

// PostsBack reports FormPost: the authorization response arrives as a POST.
func (o *OAuth2) PostsBack() bool { return o.FormPost }

// ApplyPosted runs PostedUser on p when the provider has one and the callback
// carried a user field.
func (o *OAuth2) ApplyPosted(raw string, p *Profile) {
	if o.PostedUser != nil && raw != "" {
		o.PostedUser(raw, p)
	}
}

// AuthCodeURL builds the authorization URL. An AuthURL that already carries a
// query, as some tenants' endpoints do, keeps it.
func (o *OAuth2) AuthCodeURL(state, challenge, redirectURI string) string {
	return o.AuthCodeURLWithParams(state, challenge, redirectURI, RequestParams{})
}

// OptionalScopeList returns OptionalScopes.
func (o *OAuth2) OptionalScopeList() []string { return o.OptionalScopes }

// OptionalParamList returns OptionalParams.
func (o *OAuth2) OptionalParamList() []string { return o.OptionalParams }

// AuthCodeURLWithParams builds the authorization URL with the provider's
// AuthParams and the request's parameters. Protocol parameters win over
// both, so neither can replace the state or the challenge.
func (o *OAuth2) AuthCodeURLWithParams(state, challenge, redirectURI string, rp RequestParams) string {
	q := url.Values{}
	for _, extra := range []url.Values{o.AuthParams, rp.Extra} {
		for k, vs := range extra {
			if !slices.Contains(reservedAuthParams, k) {
				q[k] = vs
			}
		}
	}
	if rp.Prompt != "" {
		q.Set(paramPrompt, rp.Prompt)
	}
	if rp.LoginHint != "" {
		q.Set(paramLoginHint, rp.LoginHint)
	}
	scopes := slices.Clone(o.Scopes)
	for _, sc := range rp.Scopes {
		if !slices.Contains(scopes, sc) {
			scopes = append(scopes, sc)
		}
	}
	q.Set(paramResponseType, responseTypeCode)
	q.Set(o.clientIDParam(), o.ClientID)
	q.Set(paramRedirectURI, redirectURI)
	q.Set(paramScope, strings.Join(scopes, firstOf(o.ScopeSeparator, scopeSeparator)))
	q.Set(paramState, state)
	if !o.NoPKCE {
		q.Set(paramChallenge, challenge)
		q.Set(paramChallengeAlg, challengeMethodS256)
	}
	if o.FormPost {
		q.Set(paramResponseMode, responseModeFormPost)
	}
	if o.IDToken.ProfileFromToken {
		// The PKCE challenge doubles as the OpenID Connect nonce: it is
		// random per flow, already public in this URL, and Exchange can
		// recompute it from the verifier without carrying a second value.
		q.Set(paramNonce, challenge)
	}
	sep := "?"
	if strings.Contains(o.AuthURL, "?") {
		sep = "&"
	}
	u := o.AuthURL + sep + q.Encode()
	if o.AuthURLFragment != "" {
		u += "#" + o.AuthURLFragment
	}
	return u
}

// clientIDParam is ClientIDParam, or client_id when it is empty.
func (o *OAuth2) clientIDParam() string { return firstOf(o.ClientIDParam, paramClientID) }

// clientSecretParam is ClientSecretParam, or client_secret when it is empty.
func (o *OAuth2) clientSecretParam() string {
	return firstOf(o.ClientSecretParam, paramClientSecret)
}

// ErrExchange is a failed code exchange or profile read. Its text is for the
// log; the client sees ErrProviderFailed.
var ErrExchange = errors.New("oauth: provider exchange failed")

// maxProviderBody bounds what is read from a provider response.
//
//ds:def id=maxproviderbody-dpaxetw2 owner=@khanakia stability=stable
const maxProviderBody = 1 << 20

// Exchange trades the code for an access token and reads the profile.
func (o *OAuth2) Exchange(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (Profile, error) {
	ts, err := o.exchangeCode(ctx, hc, code, verifier, redirectURI)
	if err != nil {
		return Profile{}, err
	}
	var p Profile
	switch {
	case o.IDToken.ProfileFromToken:
		// The nonce AuthCodeURLWithParams sent was the PKCE challenge, which
		// only the holder of the verifier can recompute.
		claims, err := o.idTokens().verify(ctx, hc, ts.IDToken.Reveal(), PKCEChallenge(verifier))
		if err != nil {
			return Profile{}, fmt.Errorf("%w: id_token: %v", ErrExchange, err)
		}
		p = profileFromClaims(claims)
	default:
		if p, err = o.profileFromTokens(ctx, hc, ts); err != nil {
			return Profile{}, err
		}
	}
	return withTokens(p, ts)
}

// exchangeCode runs the authorization_code grant, through GetToken when it
// is set. An empty verifier sends no code_verifier: a provider-initiated
// sign-in has none, and an empty parameter is refused by some servers. A
// GetToken error is returned unchanged.
func (o *OAuth2) exchangeCode(ctx context.Context, hc *http.Client, code, verifier, redirectURI string) (TokenSet, error) {
	if o.GetToken != nil || o.exchange != nil {
		var ts TokenSet
		var err error
		if o.GetToken != nil {
			ts, err = o.GetToken(ctx, code, verifier, redirectURI)
		} else {
			ts, err = o.exchange(ctx, hc, code, redirectURI)
		}
		if err != nil {
			return TokenSet{}, err
		}
		if ts.AccessToken == "" {
			return TokenSet{}, fmt.Errorf("%w: GetToken returned no access token", ErrExchange)
		}
		if ts.ExpiresAt.IsZero() && o.TokenLifetime > 0 {
			ts.ExpiresAt = time.Now().Add(o.TokenLifetime).UTC()
		}
		return ts, nil
	}
	form := url.Values{
		paramGrantType:   {grantAuthorizationCode},
		paramCode:        {code},
		paramRedirectURI: {redirectURI},
	}
	if verifier != "" && !o.NoPKCE {
		form.Set(paramVerifier, verifier)
	}
	cv := CallbackValuesOf(ctx)
	for _, name := range o.CallbackParams {
		if v := cv.value(name); v != "" {
			form.Set(string(name), v)
		}
	}
	tok, err := o.postToken(ctx, hc, form)
	if err != nil {
		return TokenSet{}, err
	}
	if tok.AccessToken == "" {
		return TokenSet{}, fmt.Errorf("%w: token endpoint: %s", ErrExchange, tok.Error)
	}
	ts := tok.tokenSet(o.TokenLifetime)
	for _, name := range o.RefreshCallbackParams {
		if v := cv.value(name); v != "" {
			if ts.RefreshParams == nil {
				ts.RefreshParams = url.Values{}
			}
			ts.RefreshParams.Set(string(name), v)
		}
	}
	return ts, nil
}

// profileFromTokens reads the profile from the provider's profile source,
// naming the provider when it has none.
func (o *OAuth2) profileFromTokens(ctx context.Context, hc *http.Client, ts TokenSet) (Profile, error) {
	p, err := o.FetchProfileWith(ctx, hc, ts)
	if errors.Is(err, ErrProfileUnsupported) {
		return Profile{}, fmt.Errorf("%w: provider %q has no profile source", ErrExchange, o.ID)
	}
	return p, err
}

// withTokens attaches the token set to a profile read at an exchange and
// refuses a profile without a subject, which no account could be keyed by.
func withTokens(p Profile, ts TokenSet) (Profile, error) {
	p.Tokens = ts
	if p.Subject == "" {
		return Profile{}, fmt.Errorf("%w: profile has no subject", ErrExchange)
	}
	return p, nil
}

// ProfileFetcher is a Provider that can read a profile from a token set it
// did not just issue: the stored tokens of a linked account. *OAuth2 and
// *OIDCProvider implement it; Plugin.Profile needs it.
//
//ds:def id=profilefetcher-m2kq8rtv owner=@khanakia stability=stable
type ProfileFetcher interface {
	Provider
	// FetchProfileWith reads the profile with tokens. A provider whose
	// profile exists only in the ID token of the exchange (ProfileFromToken
	// with no other source) answers ErrProfileUnsupported.
	FetchProfileWith(ctx context.Context, hc *http.Client, tokens TokenSet) (Profile, error)
}

// ErrProfileUnsupported is a profile read on a provider that has no profile
// call: its profile comes only from the ID token of the exchange.
var ErrProfileUnsupported = auth.NewError("oauth.profile_unsupported", http.StatusNotFound, "This provider does not offer a profile to read.")

// FetchProfileWith runs FetchProfileFromTokens, else FetchProfile with the
// access token.
func (o *OAuth2) FetchProfileWith(ctx context.Context, hc *http.Client, ts TokenSet) (Profile, error) {
	switch {
	case o.FetchProfileFromTokens != nil:
		return o.FetchProfileFromTokens(ctx, hc, ts)
	case o.FetchProfile != nil:
		return o.FetchProfile(ctx, hc, ts.AccessToken.Reveal())
	}
	return Profile{}, ErrProfileUnsupported
}

// Refresher is a provider that can trade a refresh token for new tokens.
//
//ds:def id=refresher-vxfv33e5 owner=@khanakia stability=stable
type Refresher interface {
	Refresh(ctx context.Context, hc *http.Client, refreshToken auth.Token) (TokenSet, error)
}

// Refresh runs the refresh_token grant. A provider that does not rotate
// refresh tokens answers without one; the caller keeps the old one then.
func (o *OAuth2) Refresh(ctx context.Context, hc *http.Client, refreshToken auth.Token) (TokenSet, error) {
	return o.RefreshWithParams(ctx, hc, refreshToken, nil)
}

// ParamRefresher is a Refresher whose refresh grant takes the account's own
// stored parameters (TokenSet.RefreshParams). *OAuth2 implements it; the
// plugin calls it instead of Refresh when an account has stored parameters.
//
//ds:def id=paramrefresher-6qk3wn8x owner=@khanakia stability=stable
type ParamRefresher interface {
	Refresher
	RefreshWithParams(ctx context.Context, hc *http.Client, refreshToken auth.Token, params url.Values) (TokenSet, error)
}

// RefreshWithParams is Refresh that also sends params, the account's stored
// TokenSet.RefreshParams (VK ID's device_id); the protocol's own keys in it
// are ignored. The parameters stay with the new token set.
func (o *OAuth2) RefreshWithParams(ctx context.Context, hc *http.Client, refreshToken auth.Token, params url.Values) (TokenSet, error) {
	if o.renew != nil {
		return o.renew(ctx, hc, refreshToken)
	}
	form := url.Values{
		paramGrantType:    {grantRefreshToken},
		paramRefreshToken: {refreshToken.Reveal()},
	}
	for _, extra := range []url.Values{o.RefreshParams, params} {
		for k, vs := range extra {
			if !slices.Contains(reservedTokenParams, k) {
				form[k] = vs
			}
		}
	}
	tok, err := o.postToken(ctx, hc, form)
	if err != nil {
		return TokenSet{}, err
	}
	if tok.AccessToken == "" {
		return TokenSet{}, fmt.Errorf("%w: refresh: %s", ErrExchange, tok.Error)
	}
	return tok.tokenSet(o.TokenLifetime), nil
}

// postToken sends a grant to the token endpoint with the client credentials
// (per TokenAuth) and the provider's TokenParams, and decodes the answer. The
// secret goes in the form body or a header, never in a URL, where proxies
// log it.
func (o *OAuth2) postToken(ctx context.Context, hc *http.Client, form url.Values) (tokenResponse, error) {
	for k, vs := range o.TokenParams {
		if !slices.Contains(reservedTokenParams, k) {
			form[k] = vs
		}
	}
	secret, err := o.clientSecret(ctx)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("%w: client secret: %v", ErrExchange, err)
	}
	form.Set(o.clientIDParam(), o.ClientID)
	switch o.TokenAuth {
	case ClientSecretPost, "":
		form.Set(o.clientSecretParam(), secret)
	case PrivateKeyJWT:
		assertion, err := o.ClientAssertion(ctx, o.TokenURL)
		if err != nil {
			return tokenResponse{}, fmt.Errorf("%w: client assertion: %v", ErrExchange, err)
		}
		form.Set(paramAssertionType, assertionTypeJWT)
		form.Set(paramAssertion, assertion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("%w: token request: %v", ErrExchange, err)
	}
	if o.TokenAuth == ClientSecretBasic {
		// RFC 6749 section 2.3.1: both halves are form-encoded before the
		// Basic encoding, so a secret with ':' or '%' survives.
		req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(secret))
	}
	req.Header.Set(headerContentType, contentTypeForm)
	req.Header.Set(headerAccept, contentTypeJSON)
	o.addHeaders(req)
	body, err := fetchJSON(hc, req)
	if err != nil {
		return tokenResponse{}, err
	}
	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return tokenResponse{}, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	tok.raw = body
	return tok, nil
}

// Revoker is a Provider that can revoke tokens it issued (RFC 7009). *OAuth2
// with a RevokeURL implements it; unlink calls it for the stored tokens.
//
//ds:def id=revoker-t7xn3pqw owner=@khanakia stability=stable
type Revoker interface {
	Provider
	// Revoke invalidates the tokens at the provider: the refresh token when
	// there is one (which revokes the access tokens it issued), else the
	// access token. A provider with no revocation endpoint returns nil and
	// revokes nothing.
	Revoke(ctx context.Context, hc *http.Client, tokens TokenSet) error
}

// Revoke posts the token to RevokeURL with the client credentials, per RFC
// 7009 section 2.1. The RFC makes an unknown token a success (200), so only a
// transport failure or another status is an error.
func (o *OAuth2) Revoke(ctx context.Context, hc *http.Client, ts TokenSet) error {
	if o.RevokeURL == "" {
		return nil
	}
	form := url.Values{}
	switch {
	case ts.RefreshToken != "":
		form.Set(paramToken, ts.RefreshToken.Reveal())
		form.Set(paramTokenTypeHint, tokenTypeRefresh)
	case ts.AccessToken != "":
		form.Set(paramToken, ts.AccessToken.Reveal())
		form.Set(paramTokenTypeHint, tokenTypeAccess)
	default:
		return nil
	}
	secret, err := o.clientSecret(ctx)
	if err != nil {
		return fmt.Errorf("%w: client secret: %v", ErrExchange, err)
	}
	form.Set(o.clientIDParam(), o.ClientID)
	if o.TokenAuth == ClientSecretPost || o.TokenAuth == "" {
		form.Set(o.clientSecretParam(), secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: revoke request: %v", ErrExchange, err)
	}
	if o.TokenAuth == ClientSecretBasic {
		req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(secret))
	}
	req.Header.Set(headerContentType, contentTypeForm)
	o.addHeaders(req)
	res, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrExchange, err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxProviderBody))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%w: %s answered %d", ErrExchange, req.URL.Host, res.StatusCode)
	}
	return nil
}

// addHeaders adds Headers to a grant or revocation request, skipping the
// reserved ones. Set after the request's own headers, so a provider header
// (Accept, User-Agent) may replace the default but the credentials stay.
func (o *OAuth2) addHeaders(req *http.Request) {
	for k, vs := range o.Headers {
		if !slices.ContainsFunc(reservedHeaders, func(r string) bool { return strings.EqualFold(r, k) }) {
			req.Header[http.CanonicalHeaderKey(k)] = vs
		}
	}
}

// clientSecret is ClientSecret, or what ClientSecretFunc computes when set.
func (o *OAuth2) clientSecret(ctx context.Context) (string, error) {
	if o.ClientSecretFunc == nil {
		return o.ClientSecret, nil
	}
	return o.ClientSecretFunc(ctx)
}

// tokenSet converts a token response. The expiry is computed from the wall
// clock at arrival, which is what expires_in is relative to; a response
// without expires_in takes fallback, when the provider configured one.
func (t tokenResponse) tokenSet(fallback time.Duration) TokenSet {
	ts := TokenSet{AccessToken: auth.Token(t.AccessToken), RefreshToken: auth.Token(t.RefreshToken), IDToken: auth.Token(t.IDToken), Scope: t.Scope, Raw: t.raw}
	now := time.Now()
	switch {
	case t.ExpiresIn > 0:
		ts.ExpiresAt = now.Add(time.Duration(t.ExpiresIn) * time.Second).UTC()
	case fallback > 0:
		ts.ExpiresAt = now.Add(fallback).UTC()
	}
	// Two spellings: refresh_token_expires_in (Microsoft, GitHub apps,
	// Twitch) and refresh_expires_in (Keycloak).
	if n := max(t.RefreshExpiresIn, t.RefreshExpiresInAlt); n > 0 && t.RefreshToken != "" {
		ts.RefreshExpiresAt = now.Add(time.Duration(n) * time.Second).UTC()
	}
	return ts
}

// tokenResponse is the part of a token endpoint's answer the plugin reads;
// raw is the whole answer, handed on as TokenSet.Raw.
type tokenResponse struct {
	AccessToken         string `json:"access_token"`
	RefreshToken        string `json:"refresh_token"`
	IDToken             string `json:"id_token"`
	ExpiresIn           int64  `json:"expires_in"`
	RefreshExpiresIn    int64  `json:"refresh_token_expires_in"`
	RefreshExpiresInAlt int64  `json:"refresh_expires_in"`
	Scope               string `json:"scope"`
	Error               string `json:"error"`

	raw json.RawMessage
}

// fetchJSON sends req and returns the body, at most maxProviderBody bytes. A
// token endpoint answers a refused code with 400 and a JSON error, so 400 is
// returned too and the caller reads the error field.
func fetchJSON(hc *http.Client, req *http.Request) (json.RawMessage, error) {
	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrExchange, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxProviderBody))
	// Drain what the limit left, so the connection can be reused.
	_, _ = io.Copy(io.Discard, res.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	if res.StatusCode/100 != 2 && res.StatusCode != http.StatusBadRequest {
		return nil, fmt.Errorf("%w: %s answered %d", ErrExchange, req.URL.Host, res.StatusCode)
	}
	return body, nil
}

// claimsOf decodes a JSON object into raw claims for Profile.Claims; a body
// that is not an object yields nil, which the profile parser has already
// refused or will.
func claimsOf(body json.RawMessage) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return nil
	}
	return m
}

// getJSON reads a JSON resource, with a bearer access token when accessToken
// is not empty (a discovery document is public and takes none).
func getJSON[T any](ctx context.Context, hc *http.Client, u, accessToken string) (T, error) {
	var out T
	body, err := getJSONRaw(ctx, hc, u, accessToken)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("%w: %v", ErrExchange, err)
	}
	return out, nil
}

// getJSONRaw is getJSON returning the body, for a profile parser that also
// keeps the raw claims.
func getJSONRaw(ctx context.Context, hc *http.Client, u, accessToken string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: request %v", ErrExchange, err)
	}
	req.Header.Set(headerAccept, contentTypeJSON)
	if accessToken != "" {
		req.Header.Set(headerAuthorization, bearerPrefix+accessToken)
	}
	return fetchJSON(hc, req)
}

// openIDScopes are the OpenID Connect scopes that make a userinfo endpoint
// answer with the subject, the address and whether it is verified, and the
// name. A function, not a variable, so no provider can change another's list.
func openIDScopes() []string { return []string{"openid", "email", "profile"} }

// Google endpoints.
const (
	//ds:def id=googleauthurl-ekqypyzt owner=@khanakia stability=stable
	GoogleAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	//ds:def id=googletokenurl-ktw4f4uv owner=@khanakia stability=stable
	GoogleTokenURL = "https://oauth2.googleapis.com/token"
	//ds:def id=googleuserinfourl-5nkm522q owner=@khanakia stability=stable
	GoogleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
	// GoogleJWKSURL publishes the keys Google signs ID tokens with.
	//ds:def id=googlejwksurl-h4tm9wqz owner=@khanakia stability=stable
	GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
)

// googleIssuers are the two spellings of iss Google puts in ID tokens. A
// function, so no caller can change another's list.
func googleIssuers() []string { return []string{"https://accounts.google.com", "accounts.google.com"} }

// GoogleIDTokens makes oauth.Google accept ID tokens on its id-token route:
// Google One Tap in the browser, and the Android and iOS sign-in libraries.
// audiences are the app's other client ids (the iOS and Android ones); the
// web ClientID is always accepted. Set it on the provider:
//
//	g := oauth.Google(id, secret)
//	g.IDToken = oauth.GoogleIDTokens("ios-client-id")
//
// hostedDomain, when given through GoogleIDTokensFor, refuses tokens whose
// hd claim is another Workspace domain, the native counterpart of
// GoogleProfileFor.
//
//ds:def id=googleidtokens-r8xq2mvd owner=@khanakia stability=stable
func GoogleIDTokens(audiences ...string) IDTokenConfig {
	return GoogleIDTokensFor("", audiences...)
}

// GoogleIDTokensFor is GoogleIDTokens restricted to one Google Workspace
// domain: a token whose hd claim is not hostedDomain is ErrIDTokenInvalid.
// An empty hostedDomain accepts every account.
//
//ds:def id=googleidtokensfor-k3wd7nqe owner=@khanakia stability=stable
func GoogleIDTokensFor(hostedDomain string, audiences ...string) IDTokenConfig {
	return IDTokenConfig{JWKSURL: GoogleJWKSURL, Issuers: googleIssuers(), Audiences: audiences, HostedDomain: hostedDomain}
}

// Google is Google sign-in through its OpenID Connect userinfo endpoint.
//
//ds:def id=google-gp5b6e58 owner=@khanakia stability=stable
func Google(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "google", DisplayName: "Google", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: GoogleAuthURL, TokenURL: GoogleTokenURL, Scopes: openIDScopes(),
		FetchProfile: GoogleProfile(GoogleUserInfoURL),
	}
}

// GoogleProfile reads an OpenID Connect userinfo response from u.
func GoogleProfile(u string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return GoogleProfileFor(u, "")
}

// ErrHostedDomain is a Google userinfo whose hd claim is not the Workspace
// domain the app requires. It wraps ErrExchange, so the user sees
// ErrProviderFailed and the log says which domain answered.
var ErrHostedDomain = fmt.Errorf("%w: the account is not in the required Google Workspace domain", ErrExchange)

// GoogleProfileFor is GoogleProfile restricted to one Google Workspace
// domain: a userinfo whose hd claim is not hostedDomain is refused. The hd
// parameter on the authorization URL is only a hint to the account picker;
// this check on the returned claim is the enforcement. An empty hostedDomain
// accepts every account.
func GoogleProfileFor(u, hostedDomain string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return userInfoProfile(u, hostedDomain, "")
}

// UserInfoProfile reads an OpenID Connect userinfo answer from u and takes
// subjectClaim as the subject instead of sub, for an issuer whose stable
// identifier is another claim (Entra ID's oid). An empty subjectClaim is sub.
// The claim must be a string or a number; anything else is a profile with no
// subject, which the exchange refuses.
//
//ds:def id=userinfoprofile-w9xn4bqk owner=@khanakia stability=stable
func UserInfoProfile(u, subjectClaim string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return userInfoProfile(u, "", subjectClaim)
}

// userInfoProfile is the shared body of GoogleProfileFor and UserInfoProfile.
func userInfoProfile(u, hostedDomain, subjectClaim string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
		body, err := getJSONRaw(ctx, hc, u, accessToken)
		if err != nil {
			return Profile{}, err
		}
		var info googleUserInfo
		if err := json.Unmarshal(body, &info); err != nil {
			return Profile{}, fmt.Errorf("%w: %v", ErrExchange, err)
		}
		if hostedDomain != "" && !strings.EqualFold(info.HD, hostedDomain) {
			return Profile{}, fmt.Errorf("%w: hd %q, want %q", ErrHostedDomain, info.HD, hostedDomain)
		}
		claims := claimsOf(body)
		p := Profile{Subject: info.Sub, Email: info.Email, EmailVerified: bool(info.EmailVerified), Name: firstOf(info.Name, info.PreferredUsername), Image: info.Picture, Claims: claims}
		if subjectClaim != "" {
			p.Subject = stringClaim(claims[subjectClaim])
		}
		return p, nil
	}
}

// stringClaim reads a claim that is a JSON string or number as text, the two
// forms providers use for an identifier; anything else is "".
func stringClaim(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

// GitHub endpoints.
const (
	//ds:def id=githubauthurl-etwyp97v owner=@khanakia stability=stable
	GitHubAuthURL = "https://github.com/login/oauth/authorize"
	//ds:def id=githubtokenurl-2ww26mbk owner=@khanakia stability=stable
	GitHubTokenURL = "https://github.com/login/oauth/access_token"
	//ds:def id=githubapiurl-5sv8a6v5 owner=@khanakia stability=stable
	GitHubAPIURL = "https://api.github.com"
)

// GitHub is GitHub sign-in. The address comes from /user/emails, where GitHub
// says which address is primary and verified; the public profile email is
// neither.
//
//ds:def id=github-xhq2md6c owner=@khanakia stability=stable
func GitHub(clientID, clientSecret string) *OAuth2 {
	return &OAuth2{
		ID: "github", DisplayName: "GitHub", ClientID: clientID, ClientSecret: clientSecret,
		AuthURL: GitHubAuthURL, TokenURL: GitHubTokenURL, Scopes: []string{"read:user", "user:email"},
		FetchProfile: GitHubProfile(GitHubAPIURL),
	}
}

// GitHubProfile reads the GitHub user and primary email from the API at base.
func GitHubProfile(base string) func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
	return func(ctx context.Context, hc *http.Client, accessToken string) (Profile, error) {
		body, err := getJSONRaw(ctx, hc, base+"/user", accessToken)
		if err != nil {
			return Profile{}, err
		}
		var user githubUser
		if err := json.Unmarshal(body, &user); err != nil {
			return Profile{}, fmt.Errorf("%w: %v", ErrExchange, err)
		}
		emails, err := getJSON[[]githubEmail](ctx, hc, base+"/user/emails", accessToken)
		if err != nil {
			return Profile{}, err
		}
		p := Profile{Name: user.Name, Image: user.AvatarURL, Claims: claimsOf(body)}
		if user.ID != 0 {
			p.Subject = strconv.FormatInt(user.ID, 10)
		}
		if p.Name == "" {
			p.Name = user.Login
		}
		for _, e := range emails {
			if e.Primary {
				p.Email, p.EmailVerified = e.Email, e.Verified
			}
		}
		return p, nil
	}
}

// googleUserInfo is the OpenID Connect userinfo answer. EmailVerified is a
// boolish because some issuers (Slack, LinkedIn) send it as a string.
type googleUserInfo struct {
	Sub           string  `json:"sub"`
	Email         string  `json:"email"`
	EmailVerified boolish `json:"email_verified"`
	Name          string  `json:"name"`
	Picture       string  `json:"picture"`
	// PreferredUsername stands in for a missing name (Twitch sends no name).
	PreferredUsername string `json:"preferred_username"`
	// HD is the Google Workspace hosted domain, present for Workspace
	// accounts only.
	HD string `json:"hd"`
}

// githubUser is GitHub's /user answer.
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

// githubEmail is one row of GitHub's /user/emails answer.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}
