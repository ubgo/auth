// Package oauth signs users in with identity providers such as Google and
// GitHub. It owns auth_account, one row per linked provider account.
//
// state and PKCE are always on. The state is a single-use core verification
// token that is also bound to the browser through the flow effect, so a
// callback is accepted only in the browser that started it — the defence
// against login CSRF. Linking to an existing account happens automatically
// only when both sides are verified; otherwise the user signs in first and
// links from settings.
package oauth

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity.
const PluginName = "oauth"

// PurposeState is the verification purpose of a flow's state. Its Identifier
// is the provider name; Meta is a JSON-encoded flowMeta.
const PurposeState auth.Purpose = "oauth.state"

// Operation ids. Start and callback ids are per provider:
// "oauth.<provider>-start" and "oauth.<provider>-callback".
const (
	EndpointUnlink auth.EndpointID = "oauth.unlink"
	//ds:def id=endpointaccounts-j8bwb2tj owner=@khanakia stability=stable
	EndpointAccounts auth.EndpointID = "oauth.accounts"
	// EndpointLogout is the general provider logout, POST /logout with the
	// provider named in the body; it exists when any provider is a
	// Logouter, beside each one's own /<provider>/logout.
	//ds:def id=endpointlogout-h3wq8nzk owner=@khanakia stability=stable
	EndpointLogout auth.EndpointID = "oauth.logout"
	// EndpointProviders lists the configured providers' ids and display
	// names, GET /providers, public.
	//ds:def id=endpointproviders-p6xk2wtm owner=@khanakia stability=stable
	EndpointProviders auth.EndpointID = "oauth.providers"
)

// Routes of the plugin-wide operations, relative to the plugin's mount.
const (
	pathUnlink    = "/unlink"
	pathAccounts  = "/accounts"
	pathLogout    = "/logout"
	pathProviders = "/providers"
)

// The steps of a provider flow. Each names both the operation id suffix and
// the route segment, so "oauth.google-start" is served at /google/start.
const (
	stepStart    = "start"
	stepCallback = "callback"
	// stepIDToken is the native sign-in: a provider ID token posted by the
	// app instead of the redirect dance.
	stepIDToken = "id-token"
	// stepLogout is the RP-initiated provider logout.
	stepLogout = "logout"
	// stepFormPost names the form-post relay operation; it is served at the
	// callback route (POST), so it has an id suffix but no route segment of
	// its own.
	stepFormPost = "form-post"
)

// StartEndpoint names a provider's start operation: "oauth.<provider>-start".
func StartEndpoint(provider string) auth.EndpointID { return stepEndpoint(provider, stepStart) }

// CallbackEndpoint names a provider's callback operation:
// "oauth.<provider>-callback".
func CallbackEndpoint(provider string) auth.EndpointID {
	return stepEndpoint(provider, stepCallback)
}

// IDTokenEndpoint names a provider's id-token operation:
// "oauth.<provider>-id-token". It exists only for an IDTokenVerifier.
func IDTokenEndpoint(provider string) auth.EndpointID { return stepEndpoint(provider, stepIDToken) }

// LogoutEndpoint names a provider's logout operation:
// "oauth.<provider>-logout". It exists only for a Logouter.
func LogoutEndpoint(provider string) auth.EndpointID { return stepEndpoint(provider, stepLogout) }

// FormPostEndpoint names a provider's form-post relay operation:
// "oauth.<provider>-form-post", served as POST at the callback route. It
// exists only for a FormPoster.
func FormPostEndpoint(provider string) auth.EndpointID { return stepEndpoint(provider, stepFormPost) }

func stepEndpoint(provider, step string) auth.EndpointID {
	return auth.EndpointID(PluginName + "." + provider + "-" + step)
}

// stepPath is the route of a provider's step, relative to the plugin's mount.
func stepPath(provider, step string) string { return "/" + provider + "/" + step }

// The plugin's table.
const (
	//ds:def id=tablenameaccount-wkmv8x3c owner=@khanakia stability=stable
	TableNameAccount  = "auth_account"
	TableAliasAccount = "acc"
	//ds:def id=colaccountid-7gm3bq4c owner=@khanakia stability=stable
	ColAccountID = "id"
	//ds:def id=colaccountuserid-hn74aaqn owner=@khanakia stability=stable
	ColAccountUserID = "user_id"
	//ds:def id=colaccountprovider-bdjpuq2m owner=@khanakia stability=stable
	ColAccountProvider = "provider"
	//ds:def id=colaccountsubject-e25223he owner=@khanakia stability=stable
	ColAccountSubject = "subject"
	//ds:def id=colaccountemail-un48a32q owner=@khanakia stability=stable
	ColAccountEmail = "email"
	//ds:def id=colaccountcreated-r3epfyb7 owner=@khanakia stability=stable
	ColAccountCreated = "created_at"
	// The token columns are empty unless StoreTokens is set.
	//ds:def id=colaccountaccess-dxys2my7 owner=@khanakia stability=stable
	ColAccountAccess = "access_token_sealed"
	//ds:def id=colaccountrefresh-mjswm325 owner=@khanakia stability=stable
	ColAccountRefresh = "refresh_token_sealed"
	//ds:def id=colaccountexpires-wg2zr8ha owner=@khanakia stability=stable
	ColAccountExpires = "token_expires_at"
	// ColAccountIDToken is the sealed ID token, NULL unless StoreTokens is
	// set and the provider returned one; added by migration 0002.
	//ds:def id=colaccountidtoken-5w2kjn8p owner=@khanakia stability=stable
	ColAccountIDToken = "id_token_sealed"
	// ColAccountScope is the scope the provider said it granted at the last
	// exchange or refresh, '' when it did not say; migration 0003.
	//ds:def id=colaccountscope-q7mt3xkd owner=@khanakia stability=stable
	ColAccountScope = "token_scope"
	// ColAccountRefreshExpires is when the refresh token expires, NULL when
	// the provider did not say; migration 0003.
	//ds:def id=colaccountrefreshexpires-b4nw8ztp owner=@khanakia stability=stable
	ColAccountRefreshExpires = "refresh_token_expires_at"
	// ColAccountRefreshParams holds the sealed TokenSet.RefreshParams (VK
	// ID's device_id), NULL for every other provider; migration 0004.
	//ds:def id=colaccountrefreshparams-3nq8wk5x owner=@khanakia stability=stable
	ColAccountRefreshParams = "refresh_params_sealed"
)

// Names of the plugin's migrations. They are ledger keys, so they never
// change.
const (
	migrationAccount = "0001_account"
	// migrationAccountIDToken adds id_token_sealed (round 2, 2026-10-02). A
	// second migration rather than a wider CREATE TABLE: the first one's
	// checksum is in every deployed ledger.
	migrationAccountIDToken = "0002_account_id_token"
	// migrationAccountScope adds token_scope and refresh_token_expires_at
	// (round 3, 2026-10-03), for the same reason a third migration.
	migrationAccountScope = "0003_account_token_scope"
	// migrationAccountRefreshParams adds refresh_params_sealed
	// (2026-10-08), for the refresh parameters a provider needs again.
	migrationAccountRefreshParams = "0004_account_refresh_params"
)

// TableAccount and its typed columns.
var (
	TableAccount          = sqlb.Table{Name: TableNameAccount, Alias: TableAliasAccount}
	AccountID             = sqlb.Col[string](TableAccount, ColAccountID)
	AccountUserID         = sqlb.Col[string](TableAccount, ColAccountUserID)
	AccountProvider       = sqlb.Col[string](TableAccount, ColAccountProvider)
	AccountSubject        = sqlb.Col[string](TableAccount, ColAccountSubject)
	AccountEmail          = sqlb.Col[string](TableAccount, ColAccountEmail)
	AccountCreated        = sqlb.Col[time.Time](TableAccount, ColAccountCreated)
	AccountAccess         = sqlb.Col[string](TableAccount, ColAccountAccess)
	AccountRefresh        = sqlb.Col[string](TableAccount, ColAccountRefresh)
	AccountExpires        = sqlb.Col[*time.Time](TableAccount, ColAccountExpires)
	AccountIDToken        = sqlb.Col[*string](TableAccount, ColAccountIDToken)
	AccountScope          = sqlb.Col[string](TableAccount, ColAccountScope)
	AccountRefreshExpires = sqlb.Col[*time.Time](TableAccount, ColAccountRefreshExpires)
	AccountRefreshParams  = sqlb.Col[*string](TableAccount, ColAccountRefreshParams)
)

// Account is one linked provider account. UserID and Subject are hidden
// from JSON: a client never needs the provider's id for the person.
type Account struct {
	ID        string    `json:"id"`
	UserID    string    `json:"-"`
	Provider  string    `json:"provider"`
	Subject   string    `json:"-"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"createdAt"`
	// Scopes are the scopes the provider said it granted at the last
	// exchange or refresh (better-auth's listAccounts scopes), so a page can
	// tell whether to ask for more; empty when tokens are not stored
	// (StoreTokens) or the provider did not say. Scope names are not
	// secrets; the tokens themselves never appear here.
	Scopes []string `json:"scopes"`
	// scope is the stored token_scope column Scopes is split from.
	scope string
}

// Defaults.
const (
	// DefaultStateTTL bounds how long a user may spend at the provider. Ten
	// minutes covers a password manager and a second factor there; a longer
	// window only lengthens the life of a leaked state.
	//ds:def id=defaultstatettl-zsf722py owner=@khanakia stability=stable
	DefaultStateTTL = 10 * time.Minute
	// DefaultHTTPTimeout bounds each call to a provider, so a hung provider
	// fails the callback instead of holding the request open.
	DefaultHTTPTimeout = 10 * time.Second
	// DefaultMountPrefix is where the default callback URL assumes the auth
	// handler is mounted.
	//ds:def id=defaultmountprefix-4xrrxrkb owner=@khanakia stability=stable
	DefaultMountPrefix = "/auth"
	// idPrefixAccount starts every auth_account id.
	idPrefixAccount = "acc"
	// startIPLimit starts per startIPWindow per IP: each start writes a state
	// row, so an unbounded start is a way to fill the verification table.
	// Thirty a minute is far above a person retrying a slow provider.
	//ds:def id=startiplimit-rfjh9rkw owner=@khanakia stability=stable
	startIPLimit = 30
	//ds:def id=startipwindow-bzebr7hm owner=@khanakia stability=stable
	startIPWindow = time.Minute
	// accountUserIndexSuffix, after the account table's real name, names the
	// index that serves the per-user account list and the last-way-in count.
	accountUserIndexSuffix = "_user_idx"
	// idTokenIPLimit id-token sign-ins per idTokenIPWindow per IP: each one
	// verifies a signature and may fetch a key set, so an unbounded rate is
	// a way to spend this server's CPU and the provider's goodwill.
	//ds:def id=idtokeniplimit-r8vq2mzc owner=@khanakia stability=stable
	idTokenIPLimit = 30
	//ds:def id=idtokenipwindow-h4nk7tpw owner=@khanakia stability=stable
	idTokenIPWindow = time.Minute
	// initiatedIPLimit callbacks per initiatedIPWindow per IP for a provider
	// open to provider-initiated sign-in: a callback with no state there
	// costs a token exchange and a signature check (AllowProviderInitiated)
	// or a state row (RestartProviderInitiated), so an unbounded rate spends
	// this server and the provider. A dashboard tile is clicked once.
	//ds:def id=initiatediplimit-m3xq8wkt owner=@khanakia stability=stable
	initiatedIPLimit = 30
	//ds:def id=initiatedipwindow-z2kn7wqx owner=@khanakia stability=stable
	initiatedIPWindow = time.Minute
	// maxPostedUserLength bounds the user field a form-post relay forwards
	// in the redirect URL: Apple's is a name and an address, well under
	// this; anything longer is dropped, and the code and state still flow,
	// since the name is optional and a URL has a length budget.
	//ds:def id=maxposteduserlength-f4kq8wtn owner=@khanakia stability=stable
	maxPostedUserLength = 1024
	// maxFlowDataLength bounds StartRequest.Data: it is stored with the state
	// row, whose meta column holds 4096 characters, and the plugin's own
	// fields need room in the same JSON.
	//ds:def id=maxflowdatalength-q9tz3nwm owner=@khanakia stability=stable
	maxFlowDataLength = 1024
	// paramIDTokenHint, paramPostLogoutRedirect: the RP-initiated logout
	// request parameters (OpenID Connect RP-Initiated Logout 1.0 section 2).
	paramIDTokenHint        = "id_token_hint"
	paramPostLogoutRedirect = "post_logout_redirect_uri"
	// paramError and paramUser are the callback fields a form-post relay
	// forwards beside code and state: the provider's error, and Apple's user.
	paramError = "error"
	paramUser  = "user"
)

// Errors.
var (
	ErrStateInvalid           = auth.NewError("oauth.state_invalid", http.StatusBadRequest, "This sign-in link has expired. Start again.")
	ErrProviderDenied         = auth.NewError("oauth.denied", http.StatusBadRequest, "Sign-in was cancelled at the provider.")
	ErrProviderFailed         = auth.NewError("oauth.provider_failed", http.StatusBadGateway, "The provider could not be reached. Try again.")
	ErrAccountExists          = auth.NewError("oauth.account_exists", http.StatusConflict, "An account with this email already exists. Sign in, then link this provider in settings.")
	ErrAccountLinkedElsewhere = auth.NewError("oauth.linked_elsewhere", http.StatusConflict, "This provider account is linked to another user.")
	ErrNotLinked              = auth.NewError("oauth.not_linked", http.StatusNotFound, "Not found.")
	ErrBadReturnTo            = auth.NewError("oauth.bad_return_to", http.StatusBadRequest, "The return address must be a path on this site or a trusted origin.")
	ErrRefreshFailed          = auth.NewError("oauth.refresh_failed", http.StatusBadGateway, "The provider did not renew access. Link the account again.")
	ErrNoTokens               = auth.NewError("oauth.no_tokens", http.StatusNotFound, "No provider tokens are stored for this account.")
	ErrBadTokenKey            = errors.New("oauth: StoreTokens needs a 32-byte key, or auth.WithSecret to derive one")
	// ErrSignUpDisabled is a callback that would create a user while
	// NoSignUp is set.
	ErrSignUpDisabled = auth.NewError("oauth.sign_up_disabled", http.StatusForbidden, "Sign-up with this provider is not open. Sign in to an existing account first.")
	// ErrEmailUnverified is a provider profile whose email is not verified
	// while RequireVerifiedEmail is set.
	ErrEmailUnverified = auth.NewError("oauth.email_unverified", http.StatusForbidden, "The provider has not verified your email address.")
	// ErrEmailNotFound is a provider profile with no email at all while
	// RequireEmail or VerifyEmailBeforeSignIn is set: better-auth's
	// email_not_found. RequireVerifiedEmail answers it ErrEmailUnverified.
	ErrEmailNotFound = auth.NewError("oauth.email_not_found", http.StatusForbidden, "The provider did not share an email address. Allow access to your email and try again.")
	// ErrEmailNotVerified is the code a sign-in held by
	// VerifyEmailBeforeSignIn lands with (`?error=oauth.email_not_verified`):
	// the user exists, and no session was issued until the address is
	// verified. better-auth's email_not_verified. It is a code in a redirect
	// and a flag in the result, never a failed call, because the user the
	// callback created must not be rolled back.
	ErrEmailNotVerified = auth.NewError("oauth.email_not_verified", http.StatusForbidden, "Verify your email address, then sign in again.")
	// ErrBadParam is a StartRequest.Params that does not parse, is too long,
	// or names a parameter the provider does not list in OptionalParams.
	ErrBadParam = auth.NewError("oauth.bad_param", http.StatusBadRequest, "A requested sign-in parameter is not available for this provider.")
	// ErrBadScope is a StartRequest.Scopes entry the provider does not list
	// in OptionalScopes.
	ErrBadScope = auth.NewError("oauth.bad_scope", http.StatusBadRequest, "A requested scope is not available for this provider.")
	// ErrRequestParams is a start with prompt, loginHint or scopes for a
	// Provider that is not a ParamsProvider, so the parameters would be
	// dropped silently.
	ErrRequestParams = auth.NewError("oauth.params_unsupported", http.StatusBadRequest, "This provider does not take sign-in options.")
	// ErrEmailMismatch is a link flow, under RequireSameEmailOnLink, whose
	// provider address belongs to nobody or to another user.
	ErrEmailMismatch = auth.NewError("oauth.email_mismatch", http.StatusConflict, "The provider account uses an address that is not on this account.")
	// ErrProviderIncomplete is a configuration error: an *OAuth2 without an
	// AuthURL, a TokenURL (unless GetToken replaces the exchange), a
	// ClientID or FetchProfile (unless the profile comes from the ID token),
	// or an unknown TokenAuth, or a PublicClient with a secret or a
	// ClientSecretFunc.
	ErrProviderIncomplete = errors.New("oauth: a provider needs AuthURL, TokenURL (or GetToken), ClientID, FetchProfile (or IDToken.ProfileFromToken) and a known TokenAuth (no secret for a PublicClient)")
	// ErrIDTokenConfig is a configuration error: an IDTokenConfig with a
	// JWKSURL but no Issuers, or ProfileFromToken without a JWKSURL.
	ErrIDTokenConfig = errors.New("oauth: IDToken needs JWKSURL and Issuers (ProfileFromToken needs both)")
	// ErrLogoutUnsupported is a logout for a provider with no end-session
	// endpoint: an *OAuth2 without EndSessionURL, or an issuer whose
	// discovery document publishes none.
	ErrLogoutUnsupported = auth.NewError("oauth.logout_unsupported", http.StatusNotFound, "This provider has no sign-out endpoint.")
	// ErrDataTooLong is a StartRequest.Data longer than maxFlowDataLength.
	ErrDataTooLong = auth.NewError("oauth.data_too_long", http.StatusBadRequest, "The data to carry through sign-in is too long.")
	// ErrSignUpNotRequested is a callback that would create a user under
	// ExplicitSignUp while the request did not ask for a sign-up.
	ErrSignUpNotRequested = auth.NewError("oauth.sign_up_not_requested", http.StatusForbidden, "No account is linked to this provider account. Use sign-up to create one.")
	// ErrProfileRefused is a ValidateProfile hook that refused the profile
	// with an error that is not an *auth.Error; the hook's reason is logged.
	ErrProfileRefused = auth.NewError("oauth.profile_refused", http.StatusForbidden, "This account cannot sign in here.")
	// ErrCannotRefresh is Refresh for an account with no refresh token, or
	// at a provider that is not a Refresher.
	ErrCannotRefresh = auth.NewError("oauth.cannot_refresh", http.StatusNotFound, "This account's tokens cannot be refreshed.")

	// ErrProviderUnknown is an ImportAccount for a provider the plugin was
	// not built with, where nothing could ever sign in with the row, or a
	// Start or Callback for a provider that is not in use.
	ErrProviderUnknown = errors.New("oauth: provider is not configured")
	// ErrImportSubject is an ImportAccount with an empty user id or provider
	// account id.
	ErrImportSubject = errors.New("oauth: ImportAccount needs a user id and a provider account id")

	ErrNoProviders   = errors.New("oauth: no providers")
	ErrNoCallbackURL = errors.New("oauth: callback URLs need auth.WithBaseURL or oauth.CallbackURL")
)

// flowMeta is stored with the state and read back once at the callback.
type flowMeta struct {
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
	// LinkUser is set when a signed-in user started the flow to link a
	// provider, and must still be the signed-in user at the callback.
	LinkUser string `json:"l,omitempty"`
	// Data is StartRequest.Data, handed back untouched in
	// CallbackResult.Data.
	Data string `json:"d,omitempty"`
	// ErrorTo is StartRequest.ErrorTo, the page a failed callback redirects
	// to; empty takes the plugin's ErrorURL.
	ErrorTo string `json:"e,omitempty"`
	// NewUserTo is StartRequest.NewUserTo, where a callback that created the
	// user lands instead of ReturnTo.
	NewUserTo string `json:"n,omitempty"`
	// SignUp is StartRequest.SignUp: the request asked for a user to be
	// created, which ExplicitSignUp requires.
	SignUp bool `json:"s,omitempty"`
	// Server is what the WithServerContext functions returned at the
	// start: server-set values the client cannot populate, handed back in
	// CallbackResult.ServerContext and ProfileEvent.ServerContext.
	Server map[string]string `json:"x,omitempty"`
	// Reauth is the id of the session a re-authentication flow was started
	// on (EndpointReauthenticate); the callback then re-authenticates that
	// session instead of signing in, and refuses on any other.
	Reauth string `json:"a,omitempty"`
	// initiated marks a provider-initiated sign-in, which never links by
	// email. Never stored: such a flow has no state row.
	initiated bool
}

// Plugin is the OAuth sign-in method: a start and a callback operation per
// provider, plus accounts and unlink. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs    auth.OptionErrors
	providers  []Provider
	hc         *http.Client
	stateTTL   time.Duration
	callback   func(provider string) string
	tokenKey   []byte
	keepTokens bool
	// tokenSealer is StoreTokensWith's Sealer, nil without it.
	tokenSealer auth.Sealer
	// ring seals and opens stored provider tokens: the StoreTokens key,
	// StoreTokensWith's Sealer, auth.WithSealer's, or a ring of the keys
	// derived from every app secret (auth.WithSecret), current first; nil
	// when tokens are not stored.
	ring         auth.Sealer
	noSignUp     bool
	noSignUpFor  []string
	requireEmail bool
	// requireAnyEmail is RequireEmail; holdUnverified is
	// VerifyEmailBeforeSignIn.
	requireAnyEmail bool
	holdUnverified  bool
	refreshProfile  bool
	noImplicitLink  bool
	trusted         []string
	sameEmailLink   bool
	errorURL        string
	postLogout      func(provider string) string
	explicitSignUp  bool
	explicitFor     []string
	validate        []ProfileHook
	resolved        []ResolvedHook
	core            *auth.Auth
	// skipBroken is SkipBrokenProviders; skipped holds the providers it
	// left out, with the reason, filled by Validate and Init.
	skipBroken bool
	skipped    map[string]error
	// initiated names the providers AllowProviderInitiated opened to
	// provider-initiated sign-in; restart those RestartProviderInitiated
	// answers with a fresh flow.
	initiated []string
	restart   []string
	// serverContext are the WithServerContext functions, run at each start.
	serverContext []ServerContextFunc
	// exposeTokens is ExposeAccessTokens.
	exposeTokens bool
	// skipStateCookie is SkipStateCookieCheck.
	skipStateCookie bool
	// unlinkAll is AllowUnlinkingAll.
	unlinkAll bool
	// linkUnverifiedLocal is LinkUnverifiedLocalEmail.
	linkUnverifiedLocal bool
	// stateInCookie is StateInCookie; stateRing seals the state with the
	// key derived for it, nil in the default database mode.
	stateInCookie bool
	stateRing     *auth.KeyRing
	// replayGuard claims every accepted ID token (WithIDTokenReplayGuard,
	// else the store guard set at Init); allowReplay is AllowIDTokenReplay,
	// the only way the check is skipped.
	replayGuard IDTokenReplayGuard
	allowReplay bool

	starts    []providerOp
	callbacks []providerOp
	formPosts []providerOp
	idTokens  []providerOp
	logouts   []providerOp
	unlink    *auth.Op[UnlinkRequest, auth.Done]
	accounts  *auth.Op[struct{}, AccountsResult]
	// logout is the general logout route; nil when no provider is a
	// Logouter.
	logout       *auth.Op[LogoutRequest, LogoutResult]
	providerList *auth.Op[struct{}, ProvidersResult]
	// accessToken is the ExposeAccessTokens route; nil without the option.
	accessToken *auth.Op[AccessTokenRequest, AccessTokenResult]
	// reauth is EndpointReauthenticate.
	reauth *auth.Op[ReauthenticateRequest, StartResult]
	// reauthIDToken is EndpointReauthenticateIDToken; nil when no provider
	// verifies ID tokens, so the route exists only where it can succeed.
	reauthIDToken *auth.Op[ReauthenticateIDTokenRequest, auth.Reauthentication]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// providerOp is one provider's operation, kept with the provider's name so
// a provider SkipBrokenProviders leaves out takes its routes with it.
type providerOp struct {
	provider string
	op       auth.Operation
}

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// WithProviders adds providers. The constructors Google and GitHub are the
// usual values.
func WithProviders(ps ...Provider) Option {
	return func(p *Plugin) {
		if auth.RefuseNilEach(&p.optErrs, "oauth.WithProviders", ps) {
			return
		}
		p.providers = append(p.providers, ps...)
	}
}

// WithHTTPClient replaces the client used for provider calls, which by
// default times out after DefaultHTTPTimeout. A client whose CheckRedirect is
// nil is used as a copy that refuses redirects (ErrRedirectRefused), like the
// default one; an app that means its provider calls to follow redirects sets
// a CheckRedirect of its own.
//
//ds:def id=withhttpclient-yfjw32mp owner=@khanakia stability=stable
func WithHTTPClient(hc *http.Client) Option { return func(p *Plugin) { p.hc = refuseRedirects(hc) } }

// ErrRedirectRefused is the error a provider call fails with when the
// provider answered with an HTTP redirect: the token, profile, discovery,
// key-set, refresh and revocation endpoints are called from the server, and
// following a redirect there would let whoever controls one of those URLs
// (a misconfigured issuer, a compromised discovery document) bounce the
// server to an internal address (SSRF). better-auth refuses them the same
// way. The flow fails with ErrProviderFailed and this error is logged;
// configure the final endpoint URL.
var ErrRedirectRefused = errors.New("oauth: provider answered with a redirect; server-side provider calls do not follow redirects")

// refuseRedirects returns hc, or a copy of it that refuses redirects when it
// has no redirect policy of its own. A copy, so the app's client is never
// changed under it.
func refuseRedirects(hc *http.Client) *http.Client {
	if hc == nil || hc.CheckRedirect != nil {
		return hc
	}
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirectRefused }
	return &c
}

// WarnLinkUnverifiedLocal is logged by Init under LinkUnverifiedLocalEmail.
//
//ds:def id=warnlinkunverifiedlocal-7qk3wn5x owner=@khanakia stability=stable
const WarnLinkUnverifiedLocal = "oauth: LinkUnverifiedLocalEmail is on: a provider account links to a local account whose address was never verified (account pre-hijacking)"

// LinkUnverifiedLocalEmail is better-auth's
// accountLinking.requireLocalEmailVerified: false. The implicit link by email
// then also links a provider account with a verified address to a local
// account holding that address unverified, instead of refusing with
// ErrAccountExists. The provider side must still be verified (or trusted).
// Off by default; Init logs WarnLinkUnverifiedLocal at every start while it
// is on.
//
// The attack it opens is account pre-hijacking: anyone can register the
// victim's address with a password of their own and leave it unverified;
// when the victim later signs in with their provider, the provider account
// is linked to that local account, and the attacker's password still signs
// in to it, now holding the victim's data. Use it only where nobody can
// create an account with an address they do not control (no self sign-up,
// or every sign-up verified before any credential is set).
//
//ds:def id=linkunverifiedlocalemail-5wn2kq8x owner=@khanakia stability=stable
func LinkUnverifiedLocalEmail() Option { return func(p *Plugin) { p.linkUnverifiedLocal = true } }

// WarnStateCookieCheckOff is logged by Init under SkipStateCookieCheck.
//
//ds:def id=oauth-warnstatecookiecheckoff-6kq9wd3n owner=@khanakia stability=stable
const WarnStateCookieCheckOff = "oauth: SkipStateCookieCheck is on: a callback is accepted without the flow cookie that ties it to the browser that started it (login CSRF)"

// SkipStateCookieCheck accepts a callback whose state does not match the
// flow cookie, or that arrives with no flow cookie at all: better-auth's
// account.skipStateCookieCheck. The state is still required, still single
// use and still checked against its stored row, provider and expiry. Off by
// default; Init logs WarnStateCookieCheckOff at every start while it is on.
//
// The attack it opens is login CSRF. The flow cookie is the only thing that
// ties a callback to the browser that started the flow; without it an
// attacker starts a flow, signs in at the provider as themself, stops before
// the callback and sends the victim that callback URL, whose state is valid
// in the database. The victim is then signed in to the attacker's account,
// and whatever they save there (a card, a document, a linked provider) the
// attacker reads. Its one honest use is a callback that lands where the flow
// cookie cannot reach (another domain, an embedded browser that drops
// cookies); prefer authhttp's CookieDomain or the desktop hand-off there,
// which keep the binding.
//
//ds:def id=oauth-skipstatecookiecheck-3wn8kq5d owner=@khanakia stability=stable
func SkipStateCookieCheck() Option { return func(p *Plugin) { p.skipStateCookie = true } }

// WithStateTTL overrides DefaultStateTTL, the time a user may spend at the
// provider before the callback is refused as expired.
//
//ds:def id=withstatettl-chn8ez43 owner=@khanakia stability=stable
func WithStateTTL(d time.Duration) Option { return func(p *Plugin) { p.stateTTL = d } }

// StoreTokens keeps each provider's access and refresh token sealed
// (AES-256-GCM), for apps that call the provider's API later; read them back
// with Tokens. Without it, provider tokens are never stored. With a key (32
// bytes) that key seals; with none, the keys derived from auth.WithSecret
// under auth.KeyLabelOAuthTokens do, current secret first, so a rotated
// secret still opens tokens sealed under the previous one. One of the two is
// required (ErrBadTokenKey otherwise), and an explicit key wins.
//
//ds:def id=storetokens-3srdantg owner=@khanakia stability=stable
func StoreTokens(key ...[]byte) Option {
	return func(p *Plugin) {
		p.keepTokens = true
		if len(key) > 0 {
			p.tokenKey = key[0]
		}
	}
}

// StoreTokensWith is StoreTokens with the tokens sealed by s instead of a
// key held in memory: a KMS or HSM behind the auth.Sealer interface (Vault
// transit, AWS KMS). It wins over auth.WithSealer and loses to a StoreTokens
// key. Each token is sealed with the account id as additional data, so s
// must refuse a value opened under another id. A seal error fails the
// sign-in that would have stored the tokens; an open error is reported by
// Tokens, never an empty token.
//
//ds:def id=storetokenswith-8vk2nq5d owner=@khanakia stability=stable
func StoreTokensWith(s auth.Sealer) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.StoreTokensWith", s) {
			return
		}
		p.keepTokens = true
		p.tokenSealer = s
	}
}

// buildRing settles what seals StoreTokens' tokens, first match wins: the
// explicit key, StoreTokensWith's Sealer, auth.WithSealer's, or one key per
// app secret. Validate calls it, so a configuration with nothing to seal
// with fails auth.New.
func (p *Plugin) buildRing(c *auth.Config) error {
	if !p.keepTokens {
		return nil
	}
	if p.tokenKey == nil {
		if s := firstSealer(p.tokenSealer, c.Sealer()); s != nil {
			p.ring = s
			return nil
		}
	}
	keys := [][]byte{p.tokenKey}
	if p.tokenKey == nil {
		derived, err := c.DeriveKeys(auth.KeyLabelOAuthTokens)
		if err != nil {
			return ErrBadTokenKey
		}
		keys = derived
	}
	// NewKeyRing is the one check of the key length (auth.SealKeySize).
	ring, err := auth.NewKeyRing(keys[0], keys[1:]...)
	if err != nil {
		return ErrBadTokenKey
	}
	p.ring = auth.RingSealer(ring)
	return nil
}

// firstSealer returns the first non-nil Sealer, or nil.
func firstSealer(ss ...auth.Sealer) auth.Sealer {
	for _, s := range ss {
		if s != nil {
			return s
		}
	}
	return nil
}

// CallbackURL sets the redirect URI registered at each provider. The default
// is BaseURL + DefaultMountPrefix + "/oauth/<provider>/callback".
//
//ds:def id=callbackurl-drghsqqe owner=@khanakia stability=stable
func CallbackURL(fn func(provider string) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.CallbackURL", fn) {
			return
		}
		p.callback = fn
	}
}

// NoSignUp stops callbacks from creating users: a provider account that is
// already linked signs in, a verified address that matches a verified
// identity links and signs in, a signed-in user may link, and anything else
// is ErrSignUpDisabled. For apps where accounts are invited, not opened.
// With provider names, only those providers are closed to sign-up; with
// none, all are.
func NoSignUp(providers ...string) Option {
	return func(p *Plugin) {
		if len(providers) == 0 {
			p.noSignUp = true
		}
		p.noSignUpFor = append(p.noSignUpFor, providers...)
	}
}

// ExplicitSignUp makes a callback create a user only when the request asked
// for it (StartRequest.SignUp, IDTokenRequest.SignUp); a sign-in for a
// provider account nobody holds is ErrSignUpNotRequested. For apps with
// separate "sign in" and "sign up" buttons, where a person who meant to sign
// in should not end up with a second account. Linked accounts, verified-email
// matches and link flows are unaffected. With provider names, only those
// providers need the flag; with none, all do. NoSignUp wins where both apply.
func ExplicitSignUp(providers ...string) Option {
	return func(p *Plugin) {
		if len(providers) == 0 {
			p.explicitSignUp = true
		}
		p.explicitFor = append(p.explicitFor, providers...)
	}
}

// ProfileAction is what a callback is about to do with a provider profile.
type ProfileAction string

// The three outcomes a profile can have.
const (
	// ActionSignIn: the provider account is linked; its user signs in.
	ActionSignIn ProfileAction = "sign_in"
	// ActionSignUp: nobody holds the provider account; a user is created.
	ActionSignUp ProfileAction = "sign_up"
	// ActionLink: the provider account is linked to an existing user, by a
	// signed-in link flow or by a verified-email match.
	ActionLink ProfileAction = "link"
)

// AnnotationAction is the Call annotation (auth.Call.Annotate) a callback,
// id-token or provider-initiated sign-in records once it resolved its user,
// so an After or Finally hook, plugin/audit's included, can tell what the
// flow did without reading its input or result. The value is an
// AccountAction.
//
//ds:def id=oauth-annotationaction-4wn8qk2x owner=@khanakia stability=stable
const AnnotationAction = "oauth.action"

// AccountAction is the value of AnnotationAction.
type AccountAction string

// What an OAuth flow did. Linking is split by how it happened, because an
// audit log reads them differently: a link the signed-in user asked for, and
// a link the plugin made because the verified addresses matched.
//
//ds:def id=oauth-accountactions-7kq3nw5x owner=@khanakia stability=stable
const (
	// AccountSignIn: a linked provider account signed its user in.
	AccountSignIn AccountAction = "sign_in"
	// AccountSignUp: a user was created for the provider account.
	AccountSignUp AccountAction = "sign_up"
	// AccountLinked: a signed-in user linked the provider account (a link
	// flow, or an id-token call from a session).
	AccountLinked AccountAction = "link"
	// AccountLinkedByEmail: the provider account was linked to an existing
	// user because both sides' verified addresses matched.
	AccountLinkedByEmail AccountAction = "link_email"
	// AccountReauthenticated: a signed-in user confirmed who they are with a
	// linked provider account (EndpointReauthenticate, or
	// EndpointReauthenticateIDToken); nothing was signed in, created or
	// linked.
	AccountReauthenticated AccountAction = "reauthenticate"
)

// AccountActionValues is every AccountAction, for documentation and tests.
var AccountActionValues = []AccountAction{AccountSignIn, AccountSignUp, AccountLinked, AccountLinkedByEmail, AccountReauthenticated}

// annotatedAction maps what resolve did to the AccountAction recorded:
// ActionLink is an explicit link when the flow belonged to a signed-in user
// (linked), else a link by email.
func annotatedAction(action ProfileAction, linked bool) AccountAction {
	switch {
	case action == ActionSignUp:
		return AccountSignUp
	case action == ActionLink && linked:
		return AccountLinked
	case action == ActionLink:
		return AccountLinkedByEmail
	}
	return AccountSignIn
}

// ProfileActionValues is every ProfileAction, for documentation and tests.
var ProfileActionValues = []ProfileAction{ActionSignIn, ActionSignUp, ActionLink}

// ProfileEvent is what a ValidateProfile hook sees: the provider, its
// profile (Claims included), what is about to happen, and whom to.
//
//ds:def id=profileevent-n3kw7xqt owner=@khanakia stability=stable
type ProfileEvent struct {
	Provider string
	Profile  Profile
	Action   ProfileAction
	// UserID is the user the flow resolves to; "" for ActionSignUp, where
	// the user does not exist yet.
	UserID string
	// Data is what the start request carried (StartRequest.Data); "" for an
	// id-token sign-in.
	Data string
	// ProviderInitiated is true for a sign-in the provider started
	// (AllowProviderInitiated), which no request of this app began: a hook
	// may hold such a sign-in to a stricter rule.
	ProviderInitiated bool
	// ServerContext is what the WithServerContext functions returned at
	// the start of this flow, or at the id-token call: trusted, because no
	// client can set it. Nil when none ran or none returned anything.
	ServerContext map[string]string
	// Reauthentication is true when a signed-in user is confirming who they
	// are with a linked account (EndpointReauthenticate, or
	// EndpointReauthenticateIDToken). Action is then
	// ActionSignIn, so a hook that holds sign-ins to a rule holds this to
	// it too; refusing it leaves the session as it was.
	Reauthentication bool
}

// ProfileHook runs before a callback or id-token sign-in writes anything,
// inside its transaction. Returning an error refuses the flow: an *auth.Error
// is answered as it is, any other error is logged and answered as
// ErrProfileRefused. For allow-listing a Workspace domain, refusing a
// provider email, or requiring a claim.
//
//ds:def id=profilehook-y8rm2vkn owner=@khanakia stability=stable
type ProfileHook func(ctx context.Context, c *auth.Call, ev ProfileEvent) error

// ValidateProfile adds a ProfileHook; several run in order and the first
// error wins.
//
//ds:def id=validateprofile-d6tq9pwm owner=@khanakia stability=stable
func ValidateProfile(fn ProfileHook) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.ValidateProfile", fn) {
			return
		}
		p.validate = append(p.validate, fn)
	}
}

// ResolvedEvent is what an OnResolved hook sees: the ProfileEvent with the
// user the flow resolved to, and whether it created or linked.
//
//ds:def id=resolvedevent-g5xp3zqw owner=@khanakia stability=stable
type ResolvedEvent struct {
	ProfileEvent
	Created bool
	Linked  bool
}

// ResolvedHook runs after a callback or id-token sign-in resolved its user,
// inside the same transaction and before any session is issued, with UserID
// set. An error fails the flow and rolls the user back. For writing provider
// claims into the app's own user columns (auth.SetUserColumn) or its own
// tables, which no DataHooks hook can do because none sees the profile.
//
//ds:def id=resolvedhook-c2nv8mkt owner=@khanakia stability=stable
type ResolvedHook func(ctx context.Context, c *auth.Call, ev ResolvedEvent) error

// OnResolved adds a ResolvedHook; several run in order.
//
//ds:def id=onresolved-p7kz4wrq owner=@khanakia stability=stable
func OnResolved(fn ResolvedHook) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.OnResolved", fn) {
			return
		}
		p.resolved = append(p.resolved, fn)
	}
}

// NoImplicitLinking turns off the automatic link by verified email: a
// provider account whose address matches an existing user is refused with
// ErrAccountExists even when both sides are verified, and the person links
// from settings after signing in the usual way. For apps that want every
// link to be a deliberate act.
func NoImplicitLinking() Option { return func(p *Plugin) { p.noImplicitLink = true } }

// TrustedProviders names providers whose addresses are taken as verified
// even when the profile does not say so, so they may link to an existing
// verified identity by email. Use it only for a provider you know verifies
// addresses before returning them: a trusted provider that does not is an
// account takeover for anyone who can register that address there. The
// local identity must still be verified.
func TrustedProviders(providers ...string) Option {
	return func(p *Plugin) { p.trusted = append(p.trusted, providers...) }
}

// RequireSameEmailOnLink refuses a link flow whose provider account carries
// an address that is not one of the signed-in user's identities
// (ErrEmailMismatch), so a settings page cannot attach a stranger's account
// by mistake. Off by default: linking from a signed-in session links
// whatever the provider returns.
func RequireSameEmailOnLink() Option { return func(p *Plugin) { p.sameEmailLink = true } }

// ErrorURL sends the browser to path, a page on this site, when a callback
// fails, with the error code in the query (`?error=oauth.denied`), instead
// of answering the error as JSON. For apps whose sign-in page shows the
// message; a request may name another page with StartRequest.ErrorTo.
// Without it, callbacks answer errors as JSON, as every operation does.
func ErrorURL(path string) Option { return func(p *Plugin) { p.errorURL = path } }

// PostLogoutURL sets the post_logout_redirect_uri sent with a provider
// logout, per provider; it must be registered at the provider. The default
// is the base URL. A logout request's own ReturnTo, once it passes
// TrustsReturnURL, replaces it for that request.
func PostLogoutURL(fn func(provider string) string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauth.PostLogoutURL", fn) {
			return
		}
		p.postLogout = fn
	}
}

// RequireVerifiedEmail refuses a sign-in or sign-up whose provider profile
// has no email or an unverified one (ErrEmailUnverified), so no session is
// ever issued on an address the provider does not vouch for. A link flow by
// a signed-in user is not affected: the user is already proven.
func RequireVerifiedEmail() Option { return func(p *Plugin) { p.requireEmail = true } }

// RequireEmail refuses a sign-in or sign-up whose provider profile carries no
// email at all (ErrEmailNotFound), verified or not, so every user this plugin
// creates can be reached and can recover the account. A link flow by a
// signed-in user is not affected.
//
//ds:def id=requireemail-6wq3nk8v owner=@khanakia stability=stable
func RequireEmail() Option { return func(p *Plugin) { p.requireAnyEmail = true } }

// VerifyEmailBeforeSignIn is better-auth's requireEmailVerification for
// social sign-in: the callback (and an id-token or provider-initiated
// sign-in) creates or resolves the user as usual, but issues no session while
// the user has no verified email address. The browser lands on the error page
// (StartRequest.ErrorTo, ErrorURL or auth.WithErrorURL; the landing page when
// none is set) with `?error=oauth.email_not_verified`, and the result says
// EmailVerificationRequired. The person verifies the address the provider
// gave (plugin/email's resend and verify routes, which need no session) and
// signs in again. A profile with no email is refused with ErrEmailNotFound
// before anything is written, since such a user could never be released.
//
// RequireVerifiedEmail is the stricter alternative: it refuses an unverified
// provider address outright and creates nothing.
//
//ds:def id=verifyemailbeforesignin-3kx8qw2n owner=@khanakia stability=stable
func VerifyEmailBeforeSignIn() Option { return func(p *Plugin) { p.holdUnverified = true } }

// SkipBrokenProviders leaves out, with an Error log, a provider whose
// configuration fails its check or whose discovery document or key set
// cannot be loaded, so the other providers keep working: it disappears from
// the routes, the providers list and every lookup by name, and comes back
// when the app restarts with it fixed. With it, auth.New also loads every
// discovery document and key set at once (in parallel, each bounded by the
// HTTP client's timeout) instead of at the first flow, because that is the
// only moment a provider can be left out; a Fallback in use counts as
// loaded. auth.New still fails when every provider is broken, since there is
// nothing left to keep working. Without it (the default) nothing is
// skipped: a bad configuration fails auth.New, and an unreachable issuer
// fails the flow that needed it with ErrProviderFailed.
//
//ds:def id=skipbrokenproviders-w4nq7xkt owner=@khanakia stability=stable
func SkipBrokenProviders() Option { return func(p *Plugin) { p.skipBroken = true } }

// AllowProviderInitiated lets the named providers start a sign-in
// themselves: a tile on the company's identity dashboard (Okta, Entra ID,
// Google Workspace) that sends the browser to the callback with a code and
// no state. Off by default for every provider, and only for providers that
// verify ID tokens (*OIDCProvider, or *OAuth2 with an IDToken key set;
// auth.New refuses any other with ErrProviderInitiatedConfig).
//
// On that path the code is exchanged without PKCE, and the token response
// must carry an ID token whose signature, issuer, audience and lifetime
// verify; it must carry no nonce (one would mean it was issued for another
// flow), and its subject must be the profile's. The person is signed in
// only as the user already linked to that provider subject, or as a new
// user; an address that matches an existing account is ErrAccountExists,
// never a link, and a signed-in browser is signed out first, never linked.
// It lands on the site root.
//
// The risk, which this switch accepts: without a state bound to the
// browser, anyone who holds a code for their own account at the provider
// can send someone else's browser to the callback with it and sign that
// browser in as themselves (login forgery). The victim then works inside
// the attacker's account. Enable it only for a provider whose dashboard
// people actually use, and keep it off for consumer providers.
// RestartProviderInitiated is the mode without that risk, at the price of a
// second trip to the provider.
//
//ds:def id=allowproviderinitiated-t8kw3nqm owner=@khanakia stability=stable
func AllowProviderInitiated(provider string, more ...string) Option {
	return func(p *Plugin) { p.initiated = append(append(p.initiated, provider), more...) }
}

// RestartProviderInitiated is the other answer to a provider-initiated
// sign-in, better-auth's allowIdpInitiated: a callback with a code and no
// state, for the named providers, discards the code and starts an ordinary
// flow in its place (a fresh state bound to the browser, PKCE, the nonce),
// so the browser goes back to the provider, which signs the person straight
// through when they are signed in there, and the callback that follows is
// checked like any other. The forged code is never exchanged, so this mode
// cannot sign a browser in as someone else: at worst it signs a person in
// as themselves. It works for every provider, and lands on the site root.
// It costs one more round trip than AllowProviderInitiated, and a provider
// that shows a consent or account-picker page shows it again. A provider
// may not be named in both (ErrProviderInitiatedConfig).
//
//ds:def id=restartproviderinitiated-q3wn8xkt owner=@khanakia stability=stable
func RestartProviderInitiated(provider string, more ...string) Option {
	return func(p *Plugin) { p.restart = append(append(p.restart, provider), more...) }
}

// UpdateProfileOnSignIn copies the provider's name and image onto the user
// at every sign-in and link, not only when the user is created, for apps
// whose users expect a new avatar at the provider to show up here.
func UpdateProfileOnSignIn() Option { return func(p *Plugin) { p.refreshProfile = true } }

// AllowUnlinkingAll lets a user unlink the last provider account even when
// nothing else signs them in, better-auth's accountLinking.allowUnlinkingAll.
// Off by default: unlink refuses to remove the last sign-in method, because a
// user who does it cannot sign in again and only an account recovery
// (a password reset to a verified address, an admin) brings them back. For
// apps where signing in again is a fresh sign-up by design.
//
//ds:def id=allowunlinkingall-4wn8qk2x owner=@khanakia stability=stable
func AllowUnlinkingAll() Option { return func(p *Plugin) { p.unlinkAll = true } }

var (
	_ auth.SignInMethod      = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.CredentialCounter = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
)

// New builds the plugin and defines each provider's operations. Providers
// must be passed here: operations are defined once, at construction.
func New(opts ...Option) *Plugin {
	p := &Plugin{hc: refuseRedirects(&http.Client{Timeout: DefaultHTTPTimeout}), stateTTL: DefaultStateTTL, skipped: map[string]error{}}
	for _, o := range opts {
		o(p)
	}
	for _, prov := range p.providers {
		name := prov.Name()
		if v, ok := prov.(IDTokenVerifier); ok {
			p.idTokens = append(p.idTokens, providerOp{name, auth.Define(
				auth.OpInfo{ID: IDTokenEndpoint(name), Kind: auth.Mutation, Require: auth.Public, Path: stepPath(name, stepIDToken), SignIn: true},
				func(ctx context.Context, c *auth.Call, in IDTokenRequest) (CallbackResult, error) {
					return p.doIDToken(ctx, c, v, in)
				})})
		}
		if l, ok := prov.(Logouter); ok {
			p.logouts = append(p.logouts, providerOp{name, auth.Define(
				auth.OpInfo{ID: LogoutEndpoint(name), Kind: auth.Mutation, Require: auth.SignedIn, Path: stepPath(name, stepLogout)},
				func(ctx context.Context, c *auth.Call, in LogoutRequest) (LogoutResult, error) {
					return p.doLogout(ctx, c, l, in)
				})})
		}
		p.starts = append(p.starts, providerOp{name, auth.Define(
			auth.OpInfo{ID: StartEndpoint(name), Kind: auth.Query, Require: auth.Public, Path: stepPath(name, stepStart)},
			func(ctx context.Context, c *auth.Call, in StartRequest) (StartResult, error) {
				return p.doStart(ctx, c, prov, in)
			})})
		p.callbacks = append(p.callbacks, providerOp{name, auth.Define(
			auth.OpInfo{ID: CallbackEndpoint(name), Kind: auth.Query, Require: auth.Public, Path: stepPath(name, stepCallback), SignIn: true},
			func(ctx context.Context, c *auth.Call, in CallbackRequest) (CallbackResult, error) {
				return p.doCallback(ctx, c, prov, in)
			})})
		if fp, ok := prov.(FormPoster); ok && fp.PostsBack() {
			p.formPosts = append(p.formPosts, providerOp{name, auth.Define(
				auth.OpInfo{ID: FormPostEndpoint(name), Kind: auth.Mutation, Require: auth.Public, Path: stepPath(name, stepCallback), CrossSiteForm: true},
				func(ctx context.Context, c *auth.Call, in FormPostRequest) (FormPostResult, error) {
					return p.doFormPost(ctx, c, prov, in)
				})})
		}
	}
	p.unlink = auth.Define(auth.OpInfo{ID: EndpointUnlink, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: pathUnlink}, p.doUnlink)
	p.accounts = auth.Define(auth.OpInfo{ID: EndpointAccounts, Kind: auth.Query, Require: auth.SignedIn, Path: pathAccounts}, p.doAccounts)
	p.providerList = auth.Define(auth.OpInfo{ID: EndpointProviders, Kind: auth.Query, Require: auth.Public, Path: pathProviders}, p.doProviders)
	p.reauth = auth.Define(auth.OpInfo{ID: EndpointReauthenticate, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathReauthenticate}, p.doReauthStart)
	if len(p.idTokens) > 0 {
		p.reauthIDToken = auth.Define(auth.OpInfo{ID: EndpointReauthenticateIDToken, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathReauthenticateIDToken}, p.doReauthIDToken)
	}
	if p.exposeTokens {
		p.accessToken = auth.Define(auth.OpInfo{ID: EndpointAccessToken, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathAccessToken}, p.doAccessToken)
	}
	if len(p.logouts) > 0 {
		p.logout = auth.Define(auth.OpInfo{ID: EndpointLogout, Kind: auth.Mutation, Require: auth.SignedIn, Path: pathLogout}, p.doLogoutAny)
	}
	return p
}

// Name is PluginName; it never changes.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that providers are a way in, so an app with only OAuth
// passes auth.New's "no sign-in method" check.
func (p *Plugin) SignsIn() bool { return len(p.providers) > 0 }

// Tables declares auth_account and its alias, so auth.New can refuse a
// second owner of either.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableAccount} }

// UserTables declares that auth_account rows belong to the user in user_id,
// so DeleteUser removes them (no foreign key does, ADR-0002).
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableAccount, Column: ColAccountUserID}}
}

// Validate checks the providers, the callback URL and the providers named
// by AllowProviderInitiated. Under SkipBrokenProviders a provider that fails
// its own check is recorded as skipped (Init logs it) instead of failing
// auth.New.
func (p *Plugin) Validate(c *auth.Config) error {
	if len(p.providers) == 0 {
		return ErrNoProviders
	}
	for _, prov := range p.providers {
		err := ValidateProvider(prov)
		switch {
		case err == nil:
		case p.skipBroken:
			p.skipped[prov.Name()] = err
		default:
			return err
		}
	}
	if err := p.validateInitiated(); err != nil {
		return err
	}
	if p.exposeTokens && !p.keepTokens {
		return ErrExposeNeedsStoreTokens
	}
	if (p.callback == nil || p.postLogout == nil) && c.BaseURL == "" {
		return ErrNoCallbackURL
	}
	if err := p.buildStateRing(c); err != nil {
		return err
	}
	return p.buildRing(c)
}

// ValidateProvider is the configuration check New's Validate runs on every
// provider: a route-safe name, and for the built-in shapes the fields a
// sign-in cannot work without (endpoints, client id, a profile source, a
// coherent token-endpoint authentication, a usable ID-token configuration).
// Exported so a flow that runs a Provider without this plugin (authgate)
// refuses the same broken configurations at startup. A Provider of another
// type passes on its name alone: its own constructor owns its checks.
//
//ds:def id=oauth-validateprovider-5km2wq7x owner=@khanakia stability=stable
func ValidateProvider(prov Provider) error {
	if !auth.KindNamePattern.MatchString(prov.Name()) {
		return fmt.Errorf("oauth: provider name %q must match %s", prov.Name(), auth.KindNamePattern)
	}
	switch o := prov.(type) {
	case *OAuth2:
		return validateOAuth2(o)
	case *OIDCProvider:
		return validateOIDC(o)
	}
	return nil
}

// validateOAuth2 checks a plain OAuth 2.0 provider.
func validateOAuth2(o *OAuth2) error {
	known := o.TokenAuth == "" || slices.Contains(TokenAuthValues, o.TokenAuth)
	noSecret := o.ClientSecret == "" && o.ClientSecretFunc == nil
	secretOK := (o.TokenAuth != PublicClient && o.TokenAuth != PrivateKeyJWT) || noSecret
	profileOK := o.FetchProfile != nil || o.FetchProfileFromTokens != nil || o.IDToken.ProfileFromToken
	// GetToken replaces the exchange, so the token endpoint is then needed
	// only for Refresh, where its absence fails that call.
	tokenOK := o.TokenURL != "" || o.GetToken != nil || o.exchange != nil
	if o.AuthURL == "" || !tokenOK || o.ClientID == "" || !profileOK || !known || !secretOK {
		return fmt.Errorf("%w: provider %q", ErrProviderIncomplete, o.ID)
	}
	if (o.TokenAuth == PrivateKeyJWT) != (o.ClientAssertion != nil) {
		return fmt.Errorf("%w: provider %q", ErrAssertionConfig, o.ID)
	}
	if o.NoPKCE && o.TokenAuth == PublicClient {
		return fmt.Errorf("%w: provider %q", ErrPublicClientPKCE, o.ID)
	}
	for _, cp := range o.CallbackParams {
		if !slices.Contains(CallbackParamValues, cp) {
			return fmt.Errorf("%w: provider %q: %q", ErrCallbackParam, o.ID, cp)
		}
	}
	if err := o.IDToken.validate(); err != nil {
		return fmt.Errorf("%w: provider %q", err, o.ID)
	}
	return nil
}

// validateOIDC checks a discovered OpenID Connect provider.
func validateOIDC(o *OIDCProvider) error {
	if f := o.Fallback; f.Enabled() && (f.AuthURL == "" || f.TokenURL == "" || f.UserInfoURL == "") {
		return fmt.Errorf("%w: provider %q", ErrFallbackIncomplete, o.ID)
	}
	if o.IDToken.JWKSURL != "" && len(o.IDToken.Issuers) == 0 {
		// Discovery fills Issuers only when both are empty, so a JWKSURL
		// set by hand needs its issuers set by hand too.
		return fmt.Errorf("%w: provider %q", ErrIDTokenConfig, o.ID)
	}
	if (o.TokenAuth == PrivateKeyJWT) != (o.ClientAssertion != nil) || (o.TokenAuth == PrivateKeyJWT && o.ClientSecret != "") {
		return fmt.Errorf("%w: provider %q", ErrAssertionConfig, o.ID)
	}
	return nil
}

// Init captures the core, fills the default callback URL, hands OIDC
// providers the core's logger, and under SkipBrokenProviders loads every
// provider and leaves the broken ones out.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if p.skipStateCookie {
		a.Logger().Warn(WarnStateCookieCheckOff)
	}
	if p.linkUnverifiedLocal {
		a.Logger().Warn(WarnLinkUnverifiedLocal)
	}
	for _, prov := range p.providers {
		if o, ok := prov.(*OIDCProvider); ok && o.Logger == nil {
			o.Logger = a.Logger()
		}
	}
	if p.skipBroken {
		if err := p.skipBrokenProviders(context.Background(), a.Logger()); err != nil {
			return err
		}
	}
	if err := p.initReplayGuard(a); err != nil {
		return err
	}
	base := strings.TrimSuffix(a.Config().BaseURL, "/")
	if p.callback == nil {
		p.callback = func(provider string) string {
			return base + DefaultMountPrefix + "/" + PluginName + stepPath(provider, stepCallback)
		}
	}
	if p.postLogout == nil {
		p.postLogout = func(string) string { return base }
	}
	// ErrorURL is checked here rather than in Validate because the rule it
	// must pass, TrustsReturnURL, lives on the built Auth.
	if p.errorURL != "" {
		if _, err := p.returnTo(p.errorURL); err != nil {
			return fmt.Errorf("oauth: ErrorURL %q: %w", p.errorURL, err)
		}
	}
	return nil
}

// Operations lists every start, callback, form-post, id-token and logout
// operation of the providers in use (SkipBrokenProviders may have left some
// out), then unlink, accounts, the providers list, re-authentication (and its
// ID-token form when a provider verifies ID tokens) and the general logout,
// for the transports to mount.
func (p *Plugin) Operations() []auth.Operation {
	var ops []auth.Operation
	for _, group := range [][]providerOp{p.starts, p.callbacks, p.formPosts, p.idTokens, p.logouts} {
		for _, po := range group {
			if _, gone := p.skipped[po.provider]; !gone {
				ops = append(ops, po.op)
			}
		}
	}
	ops = append(ops, p.unlink, p.accounts, p.providerList, p.reauth)
	if p.reauthIDToken != nil {
		ops = append(ops, p.reauthIDToken)
	}
	if p.logout != nil {
		ops = append(ops, p.logout)
	}
	if p.accessToken != nil {
		ops = append(ops, p.accessToken)
	}
	return ops
}

// RateLimits bounds flow starts, each of which writes a state row (the
// re-authentication start per user too), id-token sign-ins, each of which
// verifies a signature, and the callbacks of providers open to
// provider-initiated sign-in, where a request with no state costs a token
// exchange.
func (p *Plugin) RateLimits() []auth.RateRule {
	rules := reauthRules()
	if p.reauthIDToken != nil {
		rules = append(rules, reauthIDTokenRules()...)
	}
	for _, prov := range p.live() {
		rules = append(rules, auth.RateRule{Match: StartEndpoint(prov.Name()), Key: auth.ByIP, Limit: startIPLimit, Window: startIPWindow})
		if _, ok := prov.(IDTokenVerifier); ok {
			rules = append(rules, auth.RateRule{Match: IDTokenEndpoint(prov.Name()), Key: auth.ByIP, Limit: idTokenIPLimit, Window: idTokenIPWindow})
		}
		if slices.Contains(p.initiated, prov.Name()) || slices.Contains(p.restart, prov.Name()) {
			rules = append(rules, auth.RateRule{Match: CallbackEndpoint(prov.Name()), Key: auth.ByIP, Limit: initiatedIPLimit, Window: initiatedIPWindow})
		}
	}
	if p.accessToken != nil {
		rules = append(rules, auth.RateRule{Match: EndpointAccessToken, Key: auth.ByIP, Limit: accessTokenIPLimit, Window: accessTokenIPWindow})
	}
	return rules
}

// live is the providers in use: all of them, less any SkipBrokenProviders
// left out.
func (p *Plugin) live() []Provider {
	out := make([]Provider, 0, len(p.providers))
	for _, prov := range p.providers {
		if _, gone := p.skipped[prov.Name()]; !gone {
			out = append(out, prov)
		}
	}
	return out
}

// TypedMigrations creates auth_account for engine. (provider, subject) is
// UNIQUE: one provider account belongs to one user.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	table := p.core.TableName(TableAccount)
	userIndex := table + accountUserIndexSuffix
	create := "CREATE TABLE IF NOT EXISTS " + table + " (" +
		ColAccountID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColAccountUserID + " " + t.ID + " NOT NULL, " +
		ColAccountProvider + " " + t.Key + " NOT NULL, " +
		ColAccountSubject + " " + t.Key + " NOT NULL, " +
		ColAccountEmail + " " + t.Value + " NOT NULL DEFAULT '', " +
		ColAccountCreated + " " + t.Timestamp + " NOT NULL, " +
		ColAccountAccess + " " + t.Long + " NOT NULL DEFAULT '', " +
		ColAccountRefresh + " " + t.Long + " NOT NULL DEFAULT '', " +
		ColAccountExpires + " " + t.Timestamp + " NULL, " +
		"UNIQUE (" + ColAccountProvider + ", " + ColAccountSubject + ")"
	st := []string{}
	if engine == auth.EngineMySQL {
		st = append(st, create+", INDEX "+userIndex+" ("+ColAccountUserID+"))"+t.TableSuffix)
	} else {
		st = append(st, create+")"+t.TableSuffix,
			"CREATE INDEX IF NOT EXISTS "+userIndex+" ON "+table+" ("+ColAccountUserID+")")
	}
	return []auth.Migration{
		{Owner: PluginName, Name: migrationAccount, Statements: st},
		{Owner: PluginName, Name: migrationAccountIDToken, Statements: []string{
			"ALTER TABLE " + table + " ADD COLUMN " + ColAccountIDToken + " " + t.Doc + " NULL",
		}},
		{Owner: PluginName, Name: migrationAccountScope, Statements: []string{
			"ALTER TABLE " + table + " ADD COLUMN " + ColAccountScope + " " + t.Long + " NOT NULL DEFAULT ''",
			"ALTER TABLE " + table + " ADD COLUMN " + ColAccountRefreshExpires + " " + t.Timestamp + " NULL",
		}},
		{Owner: PluginName, Name: migrationAccountRefreshParams, Statements: []string{
			"ALTER TABLE " + table + " ADD COLUMN " + ColAccountRefreshParams + " " + t.Doc + " NULL",
		}},
	}, nil
}

// StartRequest is the input of a start operation. It arrives in a URL
// query, since the browser reaches start by a link.
//
//ds:def id=startrequest-q2z8uxqk owner=@khanakia stability=stable
type StartRequest struct {
	// ReturnTo is a path on this site to land on after sign-in.
	ReturnTo string `json:"returnTo,omitempty"`
	// Link, when LinkFlag, links the provider to the signed-in user instead
	// of signing in. A string because it arrives in a URL query.
	Link string `json:"link,omitempty"`
	// Prompt is forwarded to a ParamsProvider as the prompt parameter
	// (select_account, consent, login, none).
	Prompt string `json:"prompt,omitempty"`
	// LoginHint is forwarded as login_hint, to pre-fill the account.
	LoginHint string `json:"loginHint,omitempty"`
	// Scopes are extra scopes, space-separated, each listed in the
	// provider's OptionalScopes; for incremental authorization.
	Scopes string `json:"scopes,omitempty"`
	// Params are extra authorization parameters as a query string
	// ("display=popup&ui_locales=de"), each named in the provider's
	// OptionalParams (ErrBadParam otherwise): better-auth's per-request
	// additionalParams. A string because it arrives in a URL query; at most
	// maxFlowDataLength characters.
	Params string `json:"params,omitempty"`
	// Data is carried through the flow untouched and handed back in
	// CallbackResult.Data: a referral code, an analytics source. At most
	// maxFlowDataLength characters. It comes from the client, so the app
	// treats it as untrusted input.
	Data string `json:"data,omitempty"`
	// ErrorTo is a path on this site a failed callback redirects to, with
	// the error code in the query; empty takes the plugin's ErrorURL. Without
	// either, a failed callback answers JSON.
	ErrorTo string `json:"errorTo,omitempty"`
	// NewUserTo is where a callback that created the user lands (an
	// onboarding page) instead of ReturnTo; same rules as ReturnTo.
	NewUserTo string `json:"newUserTo,omitempty"`
	// SignUp, when SignUpFlag, says the person meant to sign up, which
	// ExplicitSignUp requires before a user is created. A string because it
	// arrives in a URL query.
	SignUp string `json:"signUp,omitempty"`
}

// LinkFlag is the value of StartRequest.Link that starts a link flow.
//
//ds:def id=linkflag-3cm5s49p owner=@khanakia stability=stable
const LinkFlag = "true"

// SignUpFlag is the value of StartRequest.SignUp that asks for a sign-up.
//
//ds:def id=signupflag-v4xk8nqm owner=@khanakia stability=stable
const SignUpFlag = "true"

// StartResult carries the provider URL. HTTP transports redirect to it.
type StartResult struct {
	URL string `json:"url"`
}

// CallbackRequest is what the provider sends back.
type CallbackRequest struct {
	Code  string `json:"code,omitempty"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// Providers add fields such as error_description and scope; they are
	// accepted and ignored.
	ErrorDescription string `json:"error_description,omitempty"`
	Scope            string `json:"scope,omitempty"`
	AuthUser         string `json:"authuser,omitempty"`
	Prompt           string `json:"prompt,omitempty"`
	HD               string `json:"hd,omitempty"`
	// Iss is the RFC 9207 issuer identifier, checked against the provider's
	// AuthorizationIssuer when it has one.
	Iss string `json:"iss,omitempty"`
	// User is the user field of a form-post callback (Apple's first-consent
	// name and email), relayed from the POST and read by the provider's
	// PostedProfile after the exchange; ignored by any other provider.
	User string `json:"user,omitempty"`
	// DeviceID is VK ID's device_id, which its token request requires; a
	// provider forwards it only when its CallbackParams name it.
	DeviceID string `json:"device_id,omitempty"`
}

// CallbackResult is the outcome of a callback.
//
//ds:def id=callbackresult-2a98g7rq owner=@khanakia stability=stable
type CallbackResult struct {
	User auth.UserView `json:"user"`
	// Created is true when the callback created the user.
	Created bool `json:"created"`
	// Linked is true when the callback linked the provider to the signed-in
	// user.
	Linked     bool   `json:"linked"`
	RedirectTo string `json:"redirectTo"`
	// SecondFactorRequired is true when the session is pending a second
	// factor; the app page at RedirectTo asks for it.
	SecondFactorRequired bool `json:"secondFactorRequired"`
	// EmailVerificationRequired is true when VerifyEmailBeforeSignIn held
	// the sign-in: the user exists, no session was issued, and RedirectTo
	// carries `?error=oauth.email_not_verified`.
	EmailVerificationRequired bool       `json:"emailVerificationRequired,omitempty"`
	Token                     auth.Token `json:"-"`
	// Data is what the start request carried in StartRequest.Data; empty
	// for an id-token sign-in.
	Data string `json:"data"`
	// ServerContext is what the WithServerContext functions returned at
	// the start (better-auth's serverContext): server-set values, never
	// sent to the client (json "-"), read by an After hook on the callback.
	ServerContext map[string]string `json:"-"`
	// Reauthentication is the outcome of a re-authentication callback
	// (EndpointReauthenticate), nil for every other flow: the session is
	// fresh, or the second factor is due with a ticket. No session is
	// issued and Token stays empty; RedirectTo carries ParamReauth.
	Reauthentication *auth.Reauthentication `json:"reauthentication,omitempty"`
}

// FormPostRequest is what a response_mode=form_post provider posts to the
// callback route: the same fields as CallbackRequest, as a form.
//
//ds:def id=formpostrequest-t8wn3xkq owner=@khanakia stability=stable
type FormPostRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
	Error string `json:"error"`
	// User is Apple's first-consent user field (name and email as JSON).
	User string `json:"user"`
}

// FormPostResult is the GET callback URL the relay redirects to.
type FormPostResult struct {
	RedirectTo string `json:"redirectTo"`
}

// doFormPost relays a provider's form post into the GET callback. It reads no
// cookie and writes no row: the POST arrives cross-site, so the browser sent
// no SameSite=Lax flow cookie with it, and nothing here could be bound to the
// flow. The redirect is a top-level GET to this site, which the flow cookie
// does travel with, and the GET callback then checks the state as always. The
// fields are forwarded as they came (a user field over maxPostedUserLength
// is dropped); nothing is interpreted.
func (p *Plugin) doFormPost(_ context.Context, c *auth.Call, prov Provider, in FormPostRequest) (FormPostResult, error) {
	q := url.Values{}
	for k, v := range map[string]string{paramCode: in.Code, paramState: in.State, paramError: in.Error} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if in.User != "" && len(in.User) <= maxPostedUserLength {
		q.Set(paramUser, in.User)
	}
	u := p.callback(prov.Name())
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	c.Effects.Redirect(u)
	return FormPostResult{RedirectTo: u}, nil
}

// UnlinkRequest names a provider to unlink from the signed-in user.
type UnlinkRequest struct {
	Provider string `json:"provider"`
	// AccountID picks one of several accounts of Provider (a person may link
	// two GitHub accounts); it must be one of the caller's own, from the
	// accounts operation. Empty unlinks the oldest.
	AccountID string `json:"accountId,omitempty"`
}

// AccountsResult is the output of accounts: the signed-in user's linked
// providers, oldest first.
type AccountsResult struct {
	Accounts []Account `json:"accounts"`
}

// returnTo accepts a place the browser may be sent after a flow: the core's
// TrustsReturnURL rule, which takes a same-site path, an absolute URL on a
// trusted origin, or a deep link in a scheme WithTrustedOrigins listed
// ("myapp://"). Empty means the site root. One rule for returnTo, errorTo
// and ErrorURL, so no destination escapes the check.
func (p *Plugin) returnTo(s string) (string, error) {
	if s == "" {
		return siteRoot, nil
	}
	if !p.core.TrustsReturnURL(s) {
		return "", ErrBadReturnTo
	}
	return s, nil
}

// PKCEChallenge is the RFC 7636 S256 code challenge of verifier: the
// unpadded base64url SHA-256. Exported for a flow that runs a Provider
// without this plugin (authgate): *OAuth2 with IDToken.ProfileFromToken also
// sends this value as the OpenID Connect nonce and recomputes it in Exchange,
// so a caller that builds the authorization URL must derive the challenge by
// exactly this rule or the ID token's nonce check fails.
//
//ds:def id=oauth-pkcechallenge-8rw3nk5t owner=@khanakia stability=stable
func PKCEChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (p *Plugin) doStart(ctx context.Context, c *auth.Call, prov Provider, in StartRequest) (StartResult, error) {
	meta, err := p.startMeta(ctx, c, prov, in)
	if err != nil {
		return StartResult{}, err
	}
	if in.Link == LinkFlag {
		if c.User == nil {
			return StartResult{}, auth.ErrSignedOut
		}
		meta.LinkUser = c.User.ID
	}
	u, err := p.beginFlow(ctx, c, prov, in, meta)
	if err != nil {
		return StartResult{}, err
	}
	c.Effects.Redirect(u)
	return StartResult{URL: u}, nil
}

// startMeta checks a start's return addresses and data, and runs the
// WithServerContext functions: the flow's metadata, short of the verifier
// and of what kind of flow it is.
func (p *Plugin) startMeta(ctx context.Context, c *auth.Call, prov Provider, in StartRequest) (flowMeta, error) {
	returnTo, err := p.returnTo(in.ReturnTo)
	if err != nil {
		return flowMeta{}, err
	}
	if len(in.Data) > maxFlowDataLength {
		return flowMeta{}, ErrDataTooLong
	}
	errorTo := ""
	if in.ErrorTo != "" {
		if errorTo, err = p.returnTo(in.ErrorTo); err != nil {
			return flowMeta{}, err
		}
	}
	newUserTo := ""
	if in.NewUserTo != "" {
		if newUserTo, err = p.returnTo(in.NewUserTo); err != nil {
			return flowMeta{}, err
		}
	}
	meta := flowMeta{ReturnTo: returnTo, Data: in.Data, ErrorTo: errorTo, NewUserTo: newUserTo, SignUp: in.SignUp == SignUpFlag}
	if meta.Server, err = p.runServerContext(ctx, c, prov.Name()); err != nil {
		return flowMeta{}, err
	}
	return meta, nil
}

// beginFlow checks the request's provider parameters, issues the flow's
// state with meta and a new PKCE verifier, binds it to the browser, and
// returns the provider's authorization URL. The caller decides whether the
// response redirects (a start link) or answers the URL (a POST from a page).
func (p *Plugin) beginFlow(ctx context.Context, c *auth.Call, prov Provider, in StartRequest, meta flowMeta) (string, error) {
	rp, err := requestParams(prov, in)
	if err != nil {
		return "", err
	}
	authURL := urlBuilder(prov, rp)
	if ra, ok := prov.(RequestAuthURLer); ok {
		// The request's own context, for a provider whose URL depends on it
		// (a header a proxy reads); the parameters were checked above.
		if rp == nil {
			rp = &RequestParams{}
		}
		authURL = func(state, challenge, redirectURI string) string {
			return ra.AuthCodeURLForRequest(ctx, state, challenge, redirectURI, *rp)
		}
	}
	if d, ok := prov.(Discoverer); ok {
		if err := d.Discover(ctx, p.hc); err != nil {
			c.Auth.Logger().Warn("oauth: discovery failed", "provider", prov.Name(), "error", err)
			return "", ErrProviderFailed
		}
	}
	meta.Verifier = auth.NewToken().Reveal()
	raw, err := json.Marshal(meta)
	if err != nil {
		return "", err
	}
	state, binding, err := p.issueState(ctx, c, prov.Name(), raw)
	if err != nil {
		return "", err
	}
	u := authURL(state.Reveal(), PKCEChallenge(meta.Verifier), p.callback(prov.Name()))
	c.Effects.BindFlow(binding, c.Auth.Now().Add(p.stateTTL))
	return u, nil
}

// cookieState is what StateInCookie seals into the flow cookie: the state
// the provider sends back, the provider it was issued for, its expiry and
// the flow's metadata.
type cookieState struct {
	State    string          `json:"s"`
	Provider string          `json:"p"`
	Expires  int64           `json:"e"`
	Meta     json.RawMessage `json:"m"`
}

// aadCookieState binds a sealed state to its purpose, so no other sealed
// value of this plugin opens as one.
const aadCookieState = "oauth-state"

// issueState stores a new flow's state and returns it with the value the
// flow cookie binds: the state itself, kept as a verification row, or under
// StateInCookie the sealed state and metadata, kept nowhere on the server.
func (p *Plugin) issueState(ctx context.Context, c *auth.Call, provider string, meta []byte) (state, binding auth.Token, err error) {
	if p.stateRing == nil {
		state, err = c.Auth.IssueVerification(ctx, PurposeState, provider, p.stateTTL, string(meta))
		return state, state, err
	}
	state = auth.NewToken()
	raw, err := json.Marshal(cookieState{State: state.Reveal(), Provider: provider, Expires: c.Auth.Now().Add(p.stateTTL).Unix(), Meta: meta})
	if err != nil {
		return "", "", err
	}
	return state, auth.Token(p.stateRing.Seal(raw, aadCookieState)), nil
}

// consumeState checks a callback's state against the browser's flow binding
// and returns the flow's metadata, single use: the verification row is
// consumed, or under StateInCookie the sealed cookie is opened (the callback
// clears it) and its expiry, provider and state are checked. Every refusal
// is ErrStateInvalid.
func (p *Plugin) consumeState(ctx context.Context, c *auth.Call, provider, state string) ([]byte, error) {
	if state == "" {
		return nil, ErrStateInvalid
	}
	if p.stateRing != nil {
		plain, err := p.stateRing.Open(c.Flow.Reveal(), aadCookieState)
		var cs cookieState
		if err != nil || json.Unmarshal(plain, &cs) != nil || cs.Provider != provider ||
			c.Auth.Now().Unix() > cs.Expires || subtle.ConstantTimeCompare([]byte(state), []byte(cs.State)) != 1 {
			return nil, ErrStateInvalid
		}
		return cs.Meta, nil
	}
	if !p.skipStateCookie && subtle.ConstantTimeCompare([]byte(state), []byte(c.Flow.Reveal())) != 1 {
		return nil, ErrStateInvalid
	}
	v, err := c.Auth.ConsumeVerification(ctx, PurposeState, auth.Token(state))
	if errors.Is(err, auth.ErrTokenInvalid) || (err == nil && v.Identifier != provider) {
		return nil, ErrStateInvalid
	}
	if err != nil {
		return nil, err
	}
	return []byte(v.Meta), nil
}

// StateInCookie is better-auth's account.storeStateStrategy "cookie": a
// flow's state and metadata (return address, PKCE verifier, flow data) are
// sealed into the __Host-auth_flow cookie instead of a verification row, so
// a sign-in writes nothing before the callback and needs no shared store
// between instances. The state is still random per flow, the cookie is
// sealed with a key derived from auth.WithSecret (auth.KeyLabelOAuthState,
// which Validate requires: ErrStateCookieKey), bound to the provider, and
// expires with WithStateTTL; the callback clears it, so a state is used
// once by the browser that holds it. It cannot be combined with
// SkipStateCookieCheck, which drops the very cookie that holds the state.
//
//ds:def id=stateincookie-8wn3kq5x owner=@khanakia stability=stable
func StateInCookie() Option { return func(p *Plugin) { p.stateInCookie = true } }

// ErrStateCookieKey is StateInCookie without auth.WithSecret to derive its
// key from, or combined with SkipStateCookieCheck.
var ErrStateCookieKey = errors.New("oauth: StateInCookie needs auth.WithSecret, and cannot be combined with SkipStateCookieCheck")

// buildStateRing derives the StateInCookie key.
func (p *Plugin) buildStateRing(c *auth.Config) error {
	if !p.stateInCookie {
		return nil
	}
	if p.skipStateCookie {
		return ErrStateCookieKey
	}
	keys, err := c.DeriveKeys(auth.KeyLabelOAuthState)
	if err != nil {
		return ErrStateCookieKey
	}
	ring, err := auth.NewKeyRing(keys[0], keys[1:]...)
	if err != nil {
		return ErrStateCookieKey
	}
	p.stateRing = ring
	return nil
}

// RequestAuthURLer is a Provider whose authorization URL depends on the
// request that starts the flow: start calls AuthCodeURLForRequest with the
// request's context (auth.RequestHeader and auth.RequestHost read it) in
// place of AuthCodeURL or AuthCodeURLWithParams. rp is empty unless the
// request carried parameters, which start accepts only for a
// ParamsProvider. plugin/oauthproxy uses it for its per-request skip header.
//
//ds:def id=oauth-requestauthurler-3v9kq2wn owner=@khanakia stability=stable
type RequestAuthURLer interface {
	Provider
	AuthCodeURLForRequest(ctx context.Context, state, codeChallenge, redirectURI string, rp RequestParams) string
}

// authURLBuilder returns the function that builds the authorization URL for
// this start: the plain one when the request carries no parameters, the
// ParamsProvider one otherwise. The scopes are checked here, before any
// state is written, so a bad request costs no row.
func (p *Plugin) authURLBuilder(prov Provider, in StartRequest) (func(state, challenge, redirectURI string) string, error) {
	rp, err := requestParams(prov, in)
	if err != nil {
		return nil, err
	}
	return urlBuilder(prov, rp), nil
}

// urlBuilder is the provider's AuthCodeURL, or AuthCodeURLWithParams with
// rp when the start carried parameters; requestParams returns a non-nil rp
// only for a ParamsProvider.
func urlBuilder(prov Provider, rp *RequestParams) func(state, challenge, redirectURI string) string {
	pp, ok := prov.(ParamsProvider)
	if rp == nil || !ok {
		return prov.AuthCodeURL
	}
	return func(state, challenge, redirectURI string) string {
		return pp.AuthCodeURLWithParams(state, challenge, redirectURI, *rp)
	}
}

// requestParams checks a start's per-request parameters against the
// provider and returns them, or nil when the start carries none.
func requestParams(prov Provider, in StartRequest) (*RequestParams, error) {
	if in.Prompt == "" && in.LoginHint == "" && in.Scopes == "" && in.Params == "" {
		return nil, nil
	}
	pp, ok := prov.(ParamsProvider)
	if !ok {
		return nil, ErrRequestParams
	}
	rp := RequestParams{Prompt: in.Prompt, LoginHint: in.LoginHint, Scopes: strings.Fields(in.Scopes)}
	for _, sc := range rp.Scopes {
		if !slices.Contains(pp.OptionalScopeList(), sc) {
			return nil, ErrBadScope
		}
	}
	if in.Params != "" {
		al, ok := prov.(ParamsAllowLister)
		if !ok {
			return nil, ErrRequestParams
		}
		extra, err := url.ParseQuery(in.Params)
		if err != nil || len(in.Params) > maxFlowDataLength {
			return nil, ErrBadParam
		}
		for k := range extra {
			if slices.Contains(reservedAuthParams, k) || !slices.Contains(al.OptionalParamList(), k) {
				return nil, ErrBadParam
			}
		}
		rp.Extra = extra
	}
	return &rp, nil
}

func (p *Plugin) doCallback(ctx context.Context, c *auth.Call, prov Provider, in CallbackRequest) (CallbackResult, error) {
	c.Effects.BindFlow("", time.Time{}) // the binding is single use too
	p.redirectOnError(c, p.errorURL)
	if in.Error != "" {
		return CallbackResult{}, ErrProviderDenied
	}
	if in.State == "" && in.Code != "" {
		if slices.Contains(p.restart, prov.Name()) {
			return p.doRestart(ctx, c, prov)
		}
		if ie, ok := prov.(InitiatedExchanger); ok && slices.Contains(p.initiated, prov.Name()) {
			return p.doInitiated(ctx, c, ie, in)
		}
	}
	raw, err := p.consumeState(ctx, c, prov.Name(), in.State)
	if err != nil {
		return CallbackResult{}, err
	}
	var meta flowMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return CallbackResult{}, fmt.Errorf("oauth: state meta: %w", err)
	}
	if meta.ErrorTo != "" {
		p.redirectOnError(c, meta.ErrorTo)
	} else if meta.Reauth != "" {
		// A refused re-authentication returns to the page that asked.
		p.redirectOnError(c, meta.ReturnTo)
	}
	if meta.Reauth != "" {
		// Before the exchange: a refused session costs the provider nothing.
		if err := reauthSession(c, meta.Reauth); err != nil {
			return CallbackResult{}, err
		}
	}
	// RFC 9207: a provider that announces iss must send the configured one,
	// or the code may have come from another authorization server (mix-up).
	if ic, ok := prov.(IssuerChecker); ok {
		if want := ic.ExpectedIssuer(); want != "" && in.Iss != want {
			return CallbackResult{}, ErrStateInvalid
		}
	}
	// The exchange is a network call, so it runs outside any transaction.
	ctx = WithCallbackValues(ctx, CallbackValues{State: in.State, DeviceID: in.DeviceID})
	profile, err := prov.Exchange(ctx, p.hc, in.Code, meta.Verifier, p.callback(prov.Name()))
	if err != nil {
		c.Auth.Logger().Warn("oauth: exchange failed", "provider", prov.Name(), "error", err)
		return CallbackResult{}, ErrProviderFailed
	}
	if pp, ok := prov.(PostedProfile); ok {
		pp.ApplyPosted(in.User, &profile)
	}
	if meta.Reauth != "" {
		return p.reauthCallback(ctx, c, prov.Name(), profile, meta)
	}
	out, err := p.resolveTx(ctx, c, prov.Name(), profile, meta)
	if err != nil {
		return CallbackResult{}, err
	}
	out.Data, out.ServerContext = meta.Data, meta.Server
	landing := meta.ReturnTo
	if out.Created && meta.NewUserTo != "" {
		landing = meta.NewUserTo
	}
	if out.Linked {
		out.RedirectTo = landing
		c.Effects.Redirect(landing)
		return out, nil
	}
	if held, err := p.hold(ctx, c, &out, cmp.Or(meta.ErrorTo, p.errorURL, c.Auth.Config().ErrorURL, landing)); held || err != nil {
		return out, err
	}
	sess, tok, err := c.Auth.CreateSession(ctx, out.User.ID, c.Client)
	if err != nil {
		return CallbackResult{}, err
	}
	c.Effects.IssueSessionOf(sess, tok)
	c.Effects.Redirect(landing)
	out.Token, out.RedirectTo, out.SecondFactorRequired = tok, landing, sess.SecondFactorPending
	return out, nil
}

// hold applies VerifyEmailBeforeSignIn to a resolved sign-in: when the user
// has no verified email address it marks out, redirects the browser to page
// with the ErrEmailNotVerified code (page "" redirects nowhere, for the
// id-token route), and reports true, so the caller issues no session.
func (p *Plugin) hold(ctx context.Context, c *auth.Call, out *CallbackResult, page string) (bool, error) {
	if !p.holdUnverified {
		return false, nil
	}
	verified, err := c.Auth.VerifiedIdentities(ctx, out.User.ID, email.KindEmail)
	if err != nil || len(verified) > 0 {
		return false, err
	}
	out.EmailVerificationRequired = true
	if page != "" {
		out.RedirectTo = withErrorCode(page, ErrEmailNotVerified.Code)
		c.Effects.Redirect(out.RedirectTo)
	}
	return true, nil
}

// withErrorCode adds `error=code` to page's query, keeping what is there.
// page passed TrustsReturnURL (or is the configured error page), so it
// parses; one that does not is answered as it is.
func withErrorCode(page, code string) string {
	u, err := url.Parse(page)
	if err != nil {
		return page
	}
	q := u.Query()
	q.Set(paramError, code)
	u.RawQuery = q.Encode()
	return u.String()
}

// IssuerChecker is a Provider whose authorization responses carry the RFC
// 9207 iss parameter. *OAuth2 (AuthorizationIssuer) and *OIDCProvider (from
// discovery) implement it; the callback refuses a response whose iss is
// missing or another when AuthorizationIssuer is not "".
//
//ds:def id=issuerchecker-z6tn3xkq owner=@khanakia stability=stable
type IssuerChecker interface {
	Provider
	// ExpectedIssuer is the iss every authorization response must carry, or
	// "" when the provider sends none.
	ExpectedIssuer() string
}

// ExpectedIssuer returns the AuthorizationIssuer field.
func (o *OAuth2) ExpectedIssuer() string { return o.AuthorizationIssuer }

// resolveTx runs resolve and the OnResolved hooks in one transaction, so a
// hook that fails rolls the user back with it.
func (p *Plugin) resolveTx(ctx context.Context, c *auth.Call, provider string, profile Profile, meta flowMeta) (CallbackResult, error) {
	var out CallbackResult
	err := c.Auth.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		r, action, err := p.resolve(ctx, c, provider, profile, meta)
		if err != nil {
			return err
		}
		out = r
		c.Annotate(AnnotationAction, string(annotatedAction(action, r.Linked)))
		ev := ResolvedEvent{ProfileEvent: ProfileEvent{Provider: provider, Profile: profile, Action: action, UserID: r.User.ID, Data: meta.Data, ProviderInitiated: meta.initiated, ServerContext: meta.Server}, Created: r.Created, Linked: r.Linked}
		for _, fn := range p.resolved {
			if err := fn(ctx, c, ev); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// validateProfile runs the ValidateProfile hooks for one outcome. The first
// error refuses the flow: an *auth.Error as it is, anything else as
// ErrProfileRefused with the reason logged.
func (p *Plugin) validateProfile(ctx context.Context, c *auth.Call, ev ProfileEvent) error {
	for _, fn := range p.validate {
		err := fn(ctx, c, ev)
		if err == nil {
			continue
		}
		var ae *auth.Error
		if errors.As(err, &ae) {
			return err
		}
		c.Auth.Logger().Info("oauth: profile refused", "provider", ev.Provider, "action", ev.Action, "error", err)
		return ErrProfileRefused
	}
	return nil
}

// resolve decides whose account this is. In order:
//
//  1. a linked account signs its user in;
//  2. a link flow links the provider to the user who started it;
//  3. a verified provider email that matches a verified identity links to that
//     user — both sides verified, never one;
//  4. a matching identity where either side is unverified, or on a
//     provider-initiated sign-in, is refused with ErrAccountExists: linking
//     it would hand the account to whoever controls the provider account;
//  5. otherwise a new user is created.
//
// The ValidateProfile hooks run once the outcome is known and before any
// write, with that outcome; the ProfileAction returned is what happened.
func (p *Plugin) resolve(ctx context.Context, c *auth.Call, provider string, prof Profile, meta flowMeta) (CallbackResult, ProfileAction, error) {
	if meta.LinkUser == "" {
		if err := p.signInProfileRule(prof); err != nil {
			return CallbackResult{}, "", err
		}
	}
	validate := func(action ProfileAction, userID string) error {
		return p.validateProfile(ctx, c, ProfileEvent{Provider: provider, Profile: prof, Action: action, UserID: userID, Data: meta.Data, ProviderInitiated: meta.initiated, ServerContext: meta.Server})
	}
	acc, err := p.accountBySubject(ctx, provider, prof.Subject)
	switch {
	case err == nil:
		if meta.LinkUser != "" && acc.UserID != meta.LinkUser {
			return CallbackResult{}, "", ErrAccountLinkedElsewhere
		}
		action := ActionSignIn
		if meta.LinkUser != "" {
			action = ActionLink
		}
		if err := validate(action, acc.UserID); err != nil {
			return CallbackResult{}, "", err
		}
		if err := p.storeTokens(ctx, acc.ID, prof.Tokens); err != nil {
			return CallbackResult{}, "", err
		}
		u, err := p.userAfter(ctx, c, acc.UserID, prof)
		return CallbackResult{User: auth.ViewOf(u), Linked: meta.LinkUser != ""}, action, err
	case !errors.Is(err, sqlb.ErrNoRows):
		return CallbackResult{}, "", err
	}

	if meta.LinkUser != "" {
		if c.User == nil || c.User.ID != meta.LinkUser {
			return CallbackResult{}, "", ErrStateInvalid
		}
		if p.sameEmailLink {
			if err := p.checkSameEmail(ctx, c, meta.LinkUser, prof.Email); err != nil {
				return CallbackResult{}, "", err
			}
		}
		if err := validate(ActionLink, meta.LinkUser); err != nil {
			return CallbackResult{}, "", err
		}
		if err := p.createAccount(ctx, meta.LinkUser, provider, prof); err != nil {
			return CallbackResult{}, "", err
		}
		u, err := p.userAfter(ctx, c, meta.LinkUser, prof)
		return CallbackResult{User: auth.ViewOf(u), Linked: true}, ActionLink, err
	}

	hasEmail := prof.Email != "" && c.Auth.Config().HasIdentifier(email.KindEmail)
	if hasEmail {
		owner, err := c.Auth.FindIdentity(ctx, email.KindEmail, prof.Email, !p.linkUnverifiedLocal)
		switch {
		case err == nil:
			// A provider-initiated sign-in never links by email: nothing
			// ties the code to a person of this app, so it may only reach a
			// user through a subject already linked.
			if p.noImplicitLink || meta.initiated || !(prof.EmailVerified || slices.Contains(p.trusted, provider)) {
				return CallbackResult{}, "", ErrAccountExists
			}
			if err := validate(ActionLink, owner.UserID); err != nil {
				return CallbackResult{}, "", err
			}
			if err := p.createAccount(ctx, owner.UserID, provider, prof); err != nil {
				return CallbackResult{}, "", err
			}
			u, err := p.userAfter(ctx, c, owner.UserID, prof)
			return CallbackResult{User: auth.ViewOf(u)}, ActionLink, err
		case errors.Is(err, auth.ErrIdentifierInvalid):
			hasEmail = false
		case !errors.Is(err, auth.ErrIdentityNotFound):
			return CallbackResult{}, "", err
		}
	}

	if p.noSignUp || slices.Contains(p.noSignUpFor, provider) {
		return CallbackResult{}, "", ErrSignUpDisabled
	}
	if (p.explicitSignUp || slices.Contains(p.explicitFor, provider)) && !meta.SignUp {
		return CallbackResult{}, "", ErrSignUpNotRequested
	}
	if err := validate(ActionSignUp, ""); err != nil {
		return CallbackResult{}, "", err
	}
	u, err := c.Auth.CreateUser(ctx, auth.NewUser{Name: prof.Name, Image: prof.Image})
	if err != nil {
		return CallbackResult{}, "", err
	}
	if hasEmail {
		_, err := c.Auth.CreateIdentity(ctx, auth.NewIdentity{
			UserID: u.ID, Kind: email.KindEmail, Raw: prof.Email, Verified: prof.EmailVerified, Primary: prof.EmailVerified,
		})
		if err != nil {
			return CallbackResult{}, "", err
		}
	}
	if err := p.createAccount(ctx, u.ID, provider, prof); err != nil {
		return CallbackResult{}, "", err
	}
	return CallbackResult{User: auth.ViewOf(u), Created: true}, ActionSignUp, nil
}

// signInProfileRule is what a profile must carry to sign anyone in (a link
// flow is exempt): an address, and a verified one, as the options ask. A
// re-authentication applies it too, since it asks what sign-in asks.
// RequireVerifiedEmail answers a missing address as an unverified one, as it
// always has; the other two name it.
func (p *Plugin) signInProfileRule(prof Profile) error {
	if p.requireEmail && (prof.Email == "" || !prof.EmailVerified) {
		return ErrEmailUnverified
	}
	if prof.Email == "" && (p.requireAnyEmail || p.holdUnverified) {
		return ErrEmailNotFound
	}
	return nil
}

func (p *Plugin) createAccount(ctx context.Context, userID, provider string, prof Profile) error {
	id, err := p.core.NewID(idPrefixAccount)
	if err != nil {
		return err
	}
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableAccount).Row(
		sqlb.Set(AccountID, id), sqlb.Set(AccountUserID, userID), sqlb.Set(AccountProvider, provider),
		sqlb.Set(AccountSubject, prof.Subject), sqlb.Set(AccountEmail, prof.Email), sqlb.Set(AccountCreated, p.core.Now()),
	)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		// Another callback for the same provider account committed between
		// the lookup and this insert.
		if auth.IsUniqueViolation(err) {
			return ErrAccountLinkedElsewhere
		}
		return err
	}
	return p.storeTokens(ctx, id, prof.Tokens)
}

// storeTokens seals and writes an account's provider tokens, when StoreTokens
// is on. The account id is the sealing's additional data, so tokens copied to
// another account do not open.
func (p *Plugin) storeTokens(ctx context.Context, accountID string, ts TokenSet) error {
	if p.ring == nil {
		return nil
	}
	access, err := p.seal(ctx, ts.AccessToken, accountID)
	if err != nil {
		return err
	}
	refresh, err := p.seal(ctx, ts.RefreshToken, accountID)
	if err != nil {
		return err
	}
	idToken, err := p.seal(ctx, ts.IDToken, accountID)
	if err != nil {
		return err
	}
	var exp *time.Time
	if !ts.ExpiresAt.IsZero() {
		exp = &ts.ExpiresAt
	}
	set := []sqlb.Assignment{sqlb.Set(AccountAccess, access), sqlb.Set(AccountExpires, exp)}
	// A provider that sends no new refresh token keeps the old one valid,
	// and a refresh that returns no id_token keeps the sign-in's; a scope the
	// provider did not restate keeps the one it stated last.
	if refresh != "" {
		var rexp *time.Time
		if !ts.RefreshExpiresAt.IsZero() {
			rexp = &ts.RefreshExpiresAt
		}
		set = append(set, sqlb.Set(AccountRefresh, refresh), sqlb.Set(AccountRefreshExpires, rexp))
	}
	if ts.Scope != "" {
		set = append(set, sqlb.Set(AccountScope, ts.Scope))
	}
	if idToken != "" {
		set = append(set, sqlb.Set(AccountIDToken, &idToken))
	}
	// Parameters a refresh did not restate stay as the callback stored them.
	if len(ts.RefreshParams) > 0 {
		params, err := p.seal(ctx, auth.Token(ts.RefreshParams.Encode()), accountID)
		if err != nil {
			return err
		}
		set = append(set, sqlb.Set(AccountRefreshParams, &params))
	}
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableAccount).Set(set...).Where(sqlb.Eq(AccountID, accountID)))
	return err
}

// seal seals a provider token for the account, and keeps an absent token
// absent: an empty column means "none", which loadTokens reports as
// ErrNoTokens rather than handing out an empty access token.
func (p *Plugin) seal(ctx context.Context, t auth.Token, accountID string) (string, error) {
	if t == "" {
		return "", nil
	}
	sealed, err := p.ring.Seal(ctx, []byte(t.Reveal()), accountID)
	if err != nil {
		return "", fmt.Errorf("oauth: seal provider token: %w", err)
	}
	return sealed, nil
}

// open reverses seal. A value that does not open (a changed key, a tampered
// or copied column) is auth.ErrSealedCorrupt.
func (p *Plugin) open(ctx context.Context, sealed, accountID string) (auth.Token, error) {
	if sealed == "" {
		return "", nil
	}
	plain, err := p.ring.Open(ctx, sealed, accountID)
	if err != nil {
		return "", err
	}
	return auth.Token(plain), nil
}

// userAfter loads the user a callback resolved to, first copying the
// profile's name and image onto it when UpdateProfileOnSignIn is set. The
// name is cut to the core's limit and an image is copied only when the core
// would accept it, so a provider's odd value never fails a sign-in.
func (p *Plugin) userAfter(ctx context.Context, c *auth.Call, userID string, prof Profile) (auth.User, error) {
	if !p.refreshProfile {
		return c.Auth.User(ctx, userID)
	}
	upd := auth.UserUpdate{}
	if prof.Name != "" {
		name := auth.TruncateRunes(prof.Name, auth.MaxNameLength)
		upd.Name = &name
	}
	if prof.Image != "" && len(prof.Image) <= auth.MaxImageLength && strings.HasPrefix(prof.Image, httpsPrefix) {
		img := prof.Image
		upd.Image = &img
	}
	if upd.Name == nil && upd.Image == nil {
		return c.Auth.User(ctx, userID)
	}
	return c.Auth.UpdateUser(ctx, userID, upd)
}

// checkSameEmail refuses, under RequireSameEmailOnLink, a provider address
// that is not an identity of userID. An address the email kind cannot even
// parse counts as a mismatch: it is certainly not on the account.
func (p *Plugin) checkSameEmail(ctx context.Context, c *auth.Call, userID, addr string) error {
	if addr == "" || !c.Auth.Config().HasIdentifier(email.KindEmail) {
		return ErrEmailMismatch
	}
	idn, err := c.Auth.FindIdentity(ctx, email.KindEmail, addr, false)
	switch {
	case err == nil && idn.UserID == userID:
		return nil
	case err == nil, errors.Is(err, auth.ErrIdentityNotFound), errors.Is(err, auth.ErrIdentifierInvalid):
		return ErrEmailMismatch
	}
	return err
}

// siteRoot is where a flow lands when nothing names another page: a start
// without returnTo, and every provider-initiated sign-in.
const siteRoot = "/"

// httpsPrefix is the only scheme the core accepts for a user image.
const httpsPrefix = "https://"

// RefreshMargin is how long before expiry Tokens refreshes an access token,
// so a token handed to a caller does not expire on its way to the provider.
//
//ds:def id=refreshmargin-xnszv5aq owner=@khanakia stability=stable
const RefreshMargin = time.Minute

// Tokens returns the stored provider tokens of userID's account at provider.
//
// An access token that expires within RefreshMargin is refreshed first when
// the account has a refresh token and the provider is a Refresher; the new
// tokens are stored. Two callers refreshing at once both succeed with a
// provider that keeps refresh tokens valid; with one that rotates them, the
// slower caller may get ErrRefreshFailed and should call again.
//
//ds:def id=plugin-tokens-ue968772 owner=@khanakia stability=stable
func (p *Plugin) Tokens(ctx context.Context, userID, provider string) (TokenSet, error) {
	id, ts, err := p.loadTokens(ctx, userID, provider)
	if err != nil {
		return TokenSet{}, err
	}
	if ts.ExpiresAt.IsZero() || ts.RefreshToken == "" || p.core.Now().Add(RefreshMargin).Before(ts.ExpiresAt) {
		return ts, nil
	}
	r, ok := p.provider(provider).(Refresher)
	if !ok {
		return ts, nil
	}
	return p.refresh(ctx, provider, r, id, ts)
}

// Refresh renews userID's tokens at provider now, whatever their expiry, and
// stores the result: for an app that was told the token was revoked, or that
// wants a token good for a long job. ErrNoTokens without stored tokens,
// ErrCannotRefresh without a refresh token or at a provider that is not a
// Refresher, ErrRefreshFailed when the provider refuses.
//
//ds:def id=plugin-refresh-k9wx2tnm owner=@khanakia stability=stable
func (p *Plugin) Refresh(ctx context.Context, userID, provider string) (TokenSet, error) {
	id, ts, err := p.loadTokens(ctx, userID, provider)
	if err != nil {
		return TokenSet{}, err
	}
	r, ok := p.provider(provider).(Refresher)
	if !ok || ts.RefreshToken == "" {
		return TokenSet{}, ErrCannotRefresh
	}
	return p.refresh(ctx, provider, r, id, ts)
}

// refresh runs the grant and stores what came back, keeping the old refresh
// token, and its expiry, when the provider sent none.
func (p *Plugin) refresh(ctx context.Context, provider string, r Refresher, accountID string, ts TokenSet) (TokenSet, error) {
	var fresh TokenSet
	var err error
	if pr, ok := r.(ParamRefresher); ok && len(ts.RefreshParams) > 0 {
		fresh, err = pr.RefreshWithParams(ctx, p.hc, ts.RefreshToken, ts.RefreshParams)
	} else {
		fresh, err = r.Refresh(ctx, p.hc, ts.RefreshToken)
	}
	if err != nil {
		p.core.Logger().Warn("oauth: refresh failed", "provider", provider, "error", err)
		return TokenSet{}, ErrRefreshFailed
	}
	if fresh.RefreshToken == "" {
		fresh.RefreshToken, fresh.RefreshExpiresAt = ts.RefreshToken, ts.RefreshExpiresAt
	}
	if err := p.storeTokens(ctx, accountID, fresh); err != nil {
		return TokenSet{}, err
	}
	return fresh, nil
}

// Profile reads userID's current profile at provider with the stored tokens
// (refreshing them as Tokens does), for an app that wants the provider's
// latest name, picture or claims without a new sign-in. The provider must be
// a ProfileFetcher (ErrProfileUnsupported otherwise); a failed call is
// ErrProviderFailed with the reason logged. Nothing is written to the user:
// what to copy is the app's decision.
//
//ds:def id=plugin-profile-a3zr7xpq owner=@khanakia stability=stable
func (p *Plugin) Profile(ctx context.Context, userID, provider string) (Profile, error) {
	f, ok := p.provider(provider).(ProfileFetcher)
	if !ok {
		return Profile{}, ErrProfileUnsupported
	}
	ts, err := p.Tokens(ctx, userID, provider)
	if err != nil {
		return Profile{}, err
	}
	prof, err := f.FetchProfileWith(ctx, p.hc, ts)
	switch {
	case errors.Is(err, ErrProfileUnsupported):
		return Profile{}, err
	case err != nil:
		p.core.Logger().Warn("oauth: profile failed", "provider", provider, "error", err)
		return Profile{}, ErrProviderFailed
	}
	prof.Tokens = ts
	return prof, nil
}

// provider finds a provider in use by name; nil when there is none, or
// when SkipBrokenProviders left it out.
func (p *Plugin) provider(name string) Provider {
	for _, prov := range p.live() {
		if prov.Name() == name {
			return prov
		}
	}
	return nil
}

// loadTokens reads and opens an account's stored tokens.
func (p *Plugin) loadTokens(ctx context.Context, userID, provider string) (string, TokenSet, error) {
	if p.ring == nil {
		return "", TokenSet{}, ErrNoTokens
	}
	var id, access, refresh, scope string
	var idToken, params *string
	var exp, rexp *time.Time
	q := p.core.Select().Columns(sqlb.Bind(AccountID, &id), sqlb.Bind(AccountAccess, &access), sqlb.Bind(AccountRefresh, &refresh), sqlb.Bind(AccountExpires, &exp), sqlb.Bind(AccountIDToken, &idToken),
		sqlb.Bind(AccountScope, &scope), sqlb.Bind(AccountRefreshExpires, &rexp), sqlb.Bind(AccountRefreshParams, &params)).
		From(TableAccount).Where(sqlb.Eq(AccountUserID, userID), sqlb.Eq(AccountProvider, provider)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return "", TokenSet{}, ErrNoTokens
		}
		return "", TokenSet{}, err
	}
	if access == "" {
		return "", TokenSet{}, ErrNoTokens
	}
	ts := TokenSet{Scope: scope}
	if rexp != nil {
		ts.RefreshExpiresAt = *rexp
	}
	var errAccess, errRefresh, errID error
	ts.AccessToken, errAccess = p.open(ctx, access, id)
	ts.RefreshToken, errRefresh = p.open(ctx, refresh, id)
	if idToken != nil {
		ts.IDToken, errID = p.open(ctx, *idToken, id)
	}
	var errParams error
	if params != nil {
		var raw auth.Token
		if raw, errParams = p.open(ctx, *params, id); errParams == nil {
			ts.RefreshParams, errParams = url.ParseQuery(raw.Reveal())
		}
	}
	if err := errors.Join(errAccess, errRefresh, errID, errParams); err != nil {
		return "", TokenSet{}, err
	}
	if exp != nil {
		ts.ExpiresAt = *exp
	}
	return id, ts, nil
}

func accountBindings(a *Account) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(AccountID, &a.ID), sqlb.Bind(AccountUserID, &a.UserID), sqlb.Bind(AccountProvider, &a.Provider),
		sqlb.Bind(AccountSubject, &a.Subject), sqlb.Bind(AccountEmail, &a.Email), sqlb.Bind(AccountCreated, &a.CreatedAt),
		sqlb.Bind(AccountScope, &a.scope),
	}
}

func (p *Plugin) accountBySubject(ctx context.Context, provider, subject string) (Account, error) {
	var a Account
	err := p.core.One(ctx, p.core.Select().Columns(accountBindings(&a)...).From(TableAccount).
		Where(sqlb.Eq(AccountProvider, provider), sqlb.Eq(AccountSubject, subject)).Limit(1))
	return a, err
}

// Accounts lists a user's linked accounts, oldest first; accounts linked in
// the same instant come in id order, so every engine returns one order. It takes the user
// id, for an app's admin pages; the accounts operation is the signed-in
// user's own view.
//
//ds:def id=plugin-accounts-2c9y8gse owner=@khanakia stability=stable
func (p *Plugin) Accounts(ctx context.Context, userID string) ([]Account, error) {
	var row Account
	out := []Account{}
	err := p.core.Each(ctx, p.core.Select().Columns(accountBindings(&row)...).From(TableAccount).
		Where(sqlb.Eq(AccountUserID, userID)).Order(sqlb.OrderBy(AccountCreated, sqlb.SortAsc), sqlb.OrderBy(AccountID, sqlb.SortAsc)),
		func() error {
			row.Scopes = strings.Fields(row.scope)
			out = append(out, row)
			return nil
		})
	return out, err
}

// ImportAccount is one linked account from another system, for ImportAccount.
//
//ds:def id=importaccount-v3kq8wnt owner=@khanakia stability=stable
type ImportAccount struct {
	// UserID is the user here the account belongs to; it must exist.
	UserID string
	// Provider is the configured provider's name (ErrProviderUnknown otherwise).
	Provider string
	// ProviderAccountID is the provider's stable id for the person, stored as
	// the subject; "Sign in with <provider>" then lands on UserID.
	ProviderAccountID string
	// Email is the address the provider reported there, kept as information.
	Email string
}

// ImportAccount links a provider account from another system to a user, from
// Go only: how an import writes auth_account without touching the table by
// hand, so a person who signed in with Google before keeps landing on the same
// user. The provider must be configured (ErrProviderUnknown), the user must
// exist (auth.ErrUserNotFound), and the provider account must not be linked
// already (ErrAccountLinkedElsewhere). No tokens are stored and no hook runs:
// the person did not sign in. It joins the transaction in ctx when there is
// one.
//
//ds:def id=plugin-importaccount-c7mw2xqk owner=@khanakia stability=stable
func (p *Plugin) ImportAccount(ctx context.Context, in ImportAccount) error {
	if in.UserID == "" || in.ProviderAccountID == "" {
		return ErrImportSubject
	}
	if p.provider(in.Provider) == nil {
		return fmt.Errorf("%w: %q", ErrProviderUnknown, in.Provider)
	}
	if _, err := p.core.User(ctx, in.UserID); err != nil {
		return err
	}
	return p.createAccount(ctx, in.UserID, in.Provider, Profile{Subject: in.ProviderAccountID, Email: in.Email})
}

// SignInCredentials counts linked accounts, for the core's last-way-in check.
func (p *Plugin) SignInCredentials(ctx context.Context, userID, exceptID string) (int, error) {
	list, err := p.Accounts(ctx, userID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range list {
		if a.ID != exceptID {
			n++
		}
	}
	return n, nil
}

func (p *Plugin) doAccounts(ctx context.Context, c *auth.Call, _ struct{}) (AccountsResult, error) {
	list, err := p.Accounts(ctx, c.User.ID)
	return AccountsResult{Accounts: list}, err
}

// Start begins a sign-in, sign-up or link flow at provider from Go code, the
// typed form of GET <prefix>/oauth/<provider>/start: a GraphQL resolver or a
// handler of the app's own that wants the authorization URL. The flow's state
// is bound to the browser with the flow cookie on the response of the request
// ctx carries, so ctx must carry one (the authhttp middleware, or a contrib
// adapter); without it the binding is dropped and the callback answers
// ErrStateInvalid. The result's URL is where to send the browser; over HTTP
// the operation also redirects there. ErrProviderUnknown for a provider that
// is not configured or that SkipBrokenProviders left out.
//
//ds:def id=plugin-start-q7nw3kxd owner=@khanakia stability=stable
func (p *Plugin) Start(ctx context.Context, provider string, in StartRequest) (StartResult, error) {
	return callProvider[StartRequest, StartResult](ctx, p, p.starts, provider, in)
}

// Callback finishes a flow from Go code, the typed form of GET
// <prefix>/oauth/<provider>/callback: in is what the provider sent back. The
// state must match the flow cookie of the request ctx carries, as it must
// over HTTP, so a callback received by the app's own handler passes that
// handler's request context. The session the callback issues reaches that
// request's response; the result carries it too (Token) for a caller with no
// response to write to. ErrProviderUnknown as for Start.
//
//ds:def id=plugin-callback-m4xk8wqz owner=@khanakia stability=stable
func (p *Plugin) Callback(ctx context.Context, provider string, in CallbackRequest) (CallbackResult, error) {
	return callProvider[CallbackRequest, CallbackResult](ctx, p, p.callbacks, provider, in)
}

// callProvider runs provider's operation from group through its typed Call,
// so a Go caller goes through the same pipeline, rate limits and hooks as an
// HTTP one. A provider that is not in use has no operation to run.
func callProvider[In, Out any](ctx context.Context, p *Plugin, group []providerOp, provider string, in In) (Out, error) {
	var zero Out
	if p.provider(provider) == nil {
		return zero, fmt.Errorf("%w: %q", ErrProviderUnknown, provider)
	}
	for _, po := range group {
		if op, ok := po.op.(*auth.Op[In, Out]); ok && po.provider == provider {
			return op.Call(ctx, in)
		}
	}
	return zero, fmt.Errorf("%w: %q", ErrProviderUnknown, provider)
}

// Unlink removes a linked provider from the signed-in user. It needs a
// fresh sign-in, and refuses to remove the last way into the account.
//
//ds:def id=plugin-unlink-x4mcynf2 owner=@khanakia stability=stable
func (p *Plugin) Unlink(ctx context.Context, provider string) error {
	_, err := p.unlink.Call(ctx, UnlinkRequest{Provider: provider})
	return err
}

// UnlinkAccount is Unlink for one of several accounts of a provider.
//
//ds:def id=plugin-unlinkaccount-h8xq2mkt owner=@khanakia stability=stable
func (p *Plugin) UnlinkAccount(ctx context.Context, provider, accountID string) error {
	_, err := p.unlink.Call(ctx, UnlinkRequest{Provider: provider, AccountID: accountID})
	return err
}

// doUnlink refuses to remove the last way into the account. An AccountID
// that is not one of the caller's accounts of that provider is ErrNotLinked,
// the same answer as a provider never linked, so the id reveals nothing.
func (p *Plugin) doUnlink(ctx context.Context, c *auth.Call, in UnlinkRequest) (auth.Done, error) {
	list, err := p.Accounts(ctx, c.User.ID)
	if err != nil {
		return auth.Done{}, err
	}
	for _, a := range list {
		if a.Provider != in.Provider || (in.AccountID != "" && a.ID != in.AccountID) {
			continue
		}
		if !p.unlinkAll {
			if err := c.Auth.CheckRemovable(ctx, c.User.ID, "", a.ID); err != nil {
				return auth.Done{}, err
			}
		}
		ts, err := p.tokensToRevoke(ctx, c.User.ID, in.Provider)
		if err != nil {
			return auth.Done{}, err
		}
		if _, err := p.core.Exec(ctx, sqlb.NewDelete(c.Auth.Dialect()).From(TableAccount).Where(sqlb.Eq(AccountID, a.ID))); err != nil {
			return auth.Done{}, err
		}
		p.revoke(ctx, c, in.Provider, ts)
		return auth.Done{OK: true}, nil
	}
	return auth.Done{}, ErrNotLinked
}

// tokensToRevoke loads the stored tokens an unlink will revoke, when the
// provider is a Revoker and tokens are stored; a zero TokenSet otherwise.
// Read before the delete, because the row is gone after it.
func (p *Plugin) tokensToRevoke(ctx context.Context, userID, provider string) (TokenSet, error) {
	if _, ok := p.provider(provider).(Revoker); !ok || p.ring == nil {
		return TokenSet{}, nil
	}
	_, ts, err := p.loadTokens(ctx, userID, provider)
	if errors.Is(err, ErrNoTokens) {
		return TokenSet{}, nil
	}
	return ts, err
}

// revoke revokes ts at the provider after an unlink, best effort: the row is
// already gone, so a provider that cannot be reached does not undo the
// unlink, and the failure is logged for the operator.
func (p *Plugin) revoke(ctx context.Context, c *auth.Call, provider string, ts TokenSet) {
	r, ok := p.provider(provider).(Revoker)
	if !ok || (ts.AccessToken == "" && ts.RefreshToken == "") {
		return
	}
	if err := r.Revoke(ctx, p.hc, ts); err != nil {
		c.Auth.Logger().Warn("oauth: revoke failed", "provider", provider, "error", err)
	}
}
