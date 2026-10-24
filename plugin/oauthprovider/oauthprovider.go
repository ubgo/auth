// Package oauthprovider makes the app an OAuth 2.1 authorization server and
// OpenID Connect provider: other applications ("clients") send their users
// here to sign in, and receive an authorization code, access and refresh
// tokens, and an ID token.
//
// It is opt-in and its own module. The protocol endpoints (authorize, token,
// userinfo, introspection, revocation, dynamic registration, discovery and
// the key set) are served by Plugin.Handler in the wire format the RFCs fix;
// each one is a self-served auth operation underneath (auth.OpInfo
// .SelfServed), so it runs the same pipeline as every other operation: rate
// limits, hooks, tracing. The management operations (consent, the owner's
// client registry, the user's consents) are ordinary operations every
// transport mounts under /oauthprovider.
//
// Security rules, each pinned by a test: a redirect URI matches a registered
// one exactly; PKCE (S256) is mandatory for public clients and the default
// for every client; a code is single use, bound to its client, redirect URI
// and PKCE verifier, and its reuse revokes every token issued from it; a
// refresh token rotates on every use and the reuse of a rotated one revokes
// its whole family; client secrets are compared in constant time; every
// secret (client secret, code, access and refresh token) is stored as its
// SHA-256 and shown once.
package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity, and the segment its
// management operations are served under.
const PluginName = "oauthprovider"

// Operation ids. The self-served ones are served by Handler; the others by
// every transport, under /oauthprovider.
const (
	EndpointAuthorize            auth.EndpointID = "oauthprovider.authorize"
	EndpointToken                auth.EndpointID = "oauthprovider.token"
	EndpointUserInfo             auth.EndpointID = "oauthprovider.userinfo"
	EndpointIntrospect           auth.EndpointID = "oauthprovider.introspect"
	EndpointRevoke               auth.EndpointID = "oauthprovider.revoke"
	EndpointRegister             auth.EndpointID = "oauthprovider.register"
	EndpointConsent              auth.EndpointID = "oauthprovider.consent"
	EndpointCreateClient         auth.EndpointID = "oauthprovider.create_client"
	EndpointListClients          auth.EndpointID = "oauthprovider.list_clients"
	EndpointGetClient            auth.EndpointID = "oauthprovider.get_client"
	EndpointUpdateClient         auth.EndpointID = "oauthprovider.update_client"
	EndpointRotateSecret         auth.EndpointID = "oauthprovider.rotate_secret"
	EndpointDeleteClient         auth.EndpointID = "oauthprovider.delete_client"
	EndpointPublicClient         auth.EndpointID = "oauthprovider.public_client"
	EndpointListConsents         auth.EndpointID = "oauthprovider.list_consents"
	EndpointRevokeConsent        auth.EndpointID = "oauthprovider.revoke_consent"
	EndpointGetConsent           auth.EndpointID = "oauthprovider.get_consent"
	EndpointUpdateConsent        auth.EndpointID = "oauthprovider.update_consent"
	EndpointEndSession           auth.EndpointID = "oauthprovider.end_session"
	EndpointEndSessionConfirm    auth.EndpointID = "oauthprovider.end_session_confirm"
	EndpointPublicClientPrelogin auth.EndpointID = "oauthprovider.public_client_prelogin"
	EndpointContinue             auth.EndpointID = "oauthprovider.continue"
)

// Standard scopes. ScopeOpenID asks for an ID token, ScopeOfflineAccess for
// a refresh token; ScopeProfile and ScopeEmail release the claims OpenID
// Connect Core section 5.4 assigns them.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

// DefaultScopes is what the provider supports unless Scopes replaces it.
//
//ds:def id=oauthprovider-defaultscopes-k3n8vq2m owner=@khanakia stability=stable
var DefaultScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess}

// userScopes are scopes that act for a user; a client_credentials token,
// which has none, can never carry them.
var userScopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail, ScopeOfflineAccess}

// Grant types.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
)

// DefaultGrantTypes is every grant the provider serves unless GrantTypes
// narrows it.
//
//ds:def id=oauthprovider-defaultgranttypes-w7p2xk4n owner=@khanakia stability=stable
var DefaultGrantTypes = []string{GrantAuthorizationCode, GrantClientCredentials, GrantRefreshToken}

// Client authentication methods at the token endpoint (RFC 7591 section 2).
const (
	AuthMethodBasic = "client_secret_basic"
	AuthMethodPost  = "client_secret_post"
	AuthMethodNone  = "none"
	// AuthMethodPrivateKeyJWT authenticates with a JWT the client signs
	// with a key from its registered JWKS (RFC 7523 section 2.2).
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

// AuthMethodValues is every client authentication method a client may
// register with.
var AuthMethodValues = []string{AuthMethodBasic, AuthMethodPost, AuthMethodNone, AuthMethodPrivateKeyJWT}

// Lifetimes. Each has an option.
const (
	// DefaultCodeTTL is how long an authorization code may wait to be
	// exchanged. RFC 6749 section 4.1.2 recommends at most ten minutes.
	//ds:def id=oauthprovider-defaultcodettl-r5m2qw8x owner=@khanakia stability=stable
	DefaultCodeTTL = 10 * time.Minute
	// DefaultAccessTokenTTL is an access token's lifetime.
	//ds:def id=oauthprovider-defaultaccessttl-h4k9zt3p owner=@khanakia stability=stable
	DefaultAccessTokenTTL = time.Hour
	// DefaultRefreshTokenTTL is a refresh token's lifetime; each rotation
	// starts a new one.
	//ds:def id=oauthprovider-defaultrefreshttl-b8x3nq6v owner=@khanakia stability=stable
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	// DefaultAssertionMaxLifetime is the longest a private_key_jwt client
	// assertion may live (exp minus now).
	DefaultAssertionMaxLifetime = 5 * time.Minute
	// DefaultIDTokenTTL is an ID token's lifetime: 10 hours, as the OpenID
	// Connect specification recommends.
	DefaultIDTokenTTL = 10 * time.Hour
)

// Token prefixes, so a leaked token is recognisable by secret scanners and
// by kind: uboa_ an access token, ubor_ a refresh token, uboc_ a code,
// ubos_ a client secret.
const (
	PrefixAccessToken  = "uboa_"
	PrefixRefreshToken = "ubor_"
	PrefixCode         = "uboc_"
	PrefixClientSecret = "ubos_"
)

// DefaultBasePath is where Handler serves the protocol endpoints, under the
// issuer's path: <issuer>/oauth2/token and so on. BasePath moves it.
//
//ds:def id=oauthprovider-defaultbasepath-p2v6mz9c owner=@khanakia stability=stable
const DefaultBasePath = "/oauth2"

// Errors. The part after "oauthprovider." is the RFC 6749 / 7591 / 6750
// error code Handler answers, so a Go caller and an HTTP client see the same
// reason.
var (
	ErrInvalidRequest          = auth.NewError("oauthprovider.invalid_request", http.StatusBadRequest, "The request is missing a parameter, repeats one, or is otherwise malformed.")
	ErrInvalidClient           = auth.NewError("oauthprovider.invalid_client", http.StatusUnauthorized, "Client authentication failed.")
	ErrInvalidGrant            = auth.NewError("oauthprovider.invalid_grant", http.StatusBadRequest, "The grant is invalid, expired, revoked, or was issued to another client.")
	ErrUnauthorizedClient      = auth.NewError("oauthprovider.unauthorized_client", http.StatusBadRequest, "This client may not use this grant type.")
	ErrUnsupportedGrantType    = auth.NewError("oauthprovider.unsupported_grant_type", http.StatusBadRequest, "The grant type is not supported.")
	ErrUnsupportedResponseType = auth.NewError("oauthprovider.unsupported_response_type", http.StatusBadRequest, "Only response_type=code is supported.")
	ErrInvalidScope            = auth.NewError("oauthprovider.invalid_scope", http.StatusBadRequest, "A requested scope is unknown or not allowed for this client.")
	ErrAccessDenied            = auth.NewError("oauthprovider.access_denied", http.StatusForbidden, "The user or the server denied the request.")
	ErrLoginRequired           = auth.NewError("oauthprovider.login_required", http.StatusUnauthorized, "The user must sign in.")
	ErrConsentRequired         = auth.NewError("oauthprovider.consent_required", http.StatusForbidden, "The user must consent.")
	ErrInvalidToken            = auth.NewError("oauthprovider.invalid_token", http.StatusUnauthorized, "The access token is invalid, expired or revoked.")
	ErrInsufficientScope       = auth.NewError("oauthprovider.insufficient_scope", http.StatusForbidden, "The access token lacks a required scope.")
	ErrInvalidRedirectURI      = auth.NewError("oauthprovider.invalid_redirect_uri", http.StatusBadRequest, "A redirect URI is not an absolute https URL, a loopback http URL or a private-use scheme, or carries a fragment.")
	ErrInvalidClientMetadata   = auth.NewError("oauthprovider.invalid_client_metadata", http.StatusBadRequest, "The client metadata is not valid.")
	ErrRegistrationClosed      = auth.NewError("oauthprovider.registration_closed", http.StatusForbidden, "Dynamic client registration is not open.")
	ErrInvalidTarget           = auth.NewError("oauthprovider.invalid_target", http.StatusBadRequest, "The requested resource is unknown or not allowed.")
	ErrRequestNotSupported     = auth.NewError("oauthprovider.request_not_supported", http.StatusBadRequest, "Request objects are not supported.")
	ErrInvalidRequestURI       = auth.NewError("oauthprovider.invalid_request_uri", http.StatusBadRequest, "request_uri is invalid or expired.")
	ErrRequestURINotSupported  = auth.NewError("oauthprovider.request_uri_not_supported", http.StatusBadRequest, "request_uri is not supported.")
	ErrClientNotFound          = auth.NewError("oauthprovider.not_found", http.StatusNotFound, "Not found.")
	// ErrClientDisabled is an authorization request for a client an admin
	// disabled. Like an unknown client (invalid_client) it is shown to the user
	// and never sent to the redirect URI; errors.Is also sees
	// ErrBadRedirectTarget.
	ErrClientDisabled = auth.NewError("oauthprovider.client_disabled", http.StatusBadRequest, "The client is disabled.")
	// ErrBadRedirectTarget is an authorize request whose client_id is
	// unknown or whose redirect_uri is not registered: the one case where the
	// error is never sent to the redirect URI, because sending it there
	// would make the provider an open redirector.
	ErrBadRedirectTarget = auth.NewError("oauthprovider.invalid_redirect_target", http.StatusBadRequest, "The client is unknown or the redirect URI is not registered for it.")
)

// Configuration errors, returned by auth.New.
var (
	ErrNoIssuer      = errors.New("oauthprovider: Issuer is required: an absolute https URL (http only for a loopback host) with no query or fragment")
	ErrNoLoginPage   = errors.New("oauthprovider: LoginPage is required: where the authorize endpoint sends a browser that is not signed in")
	ErrBadGrantTypes = errors.New("oauthprovider: GrantTypes needs authorization_code for refresh_token, and only known grants")
	ErrBadScopes     = errors.New("oauthprovider: a scope is non-empty and contains no whitespace")
	ErrBadTTL        = errors.New("oauthprovider: every lifetime is positive")
	ErrNoJWT         = errors.New("oauthprovider: a signer is required to sign ID tokens; pass the jwt plugin (or another Signer) to New, and list a signer that is a plugin in auth.WithPlugins before this one")
	ErrBadResource   = errors.New("oauthprovider: a ProtectedResource is an absolute https URL (http only for a loopback host) with no query or fragment")
	ErrIssuerMatch   = errors.New("oauthprovider: the jwt plugin's Issuer must equal the provider's Issuer, or ID tokens would name another issuer")
	// ErrNoSecret is a feature that signs with a key from auth.WithSecret,
	// configured without one: a client with EnableEndSession (the logout
	// confirmation cookie), AllowPublicClientPrelogin (it verifies the
	// signed authorization query) and PostLogin (its marker, joined with
	// ErrBadGate). auth.New refuses it, and CreateClient and UpdateClient
	// refuse EnableEndSession, rather than the first request answering 500.
	ErrNoSecret = errors.New("oauthprovider: auth.WithSecret is required by this feature")
)

// ClaimsFunc adds claims to the ID token and the userinfo answer for a user
// and the scopes they granted. A registered or standard claim it returns
// overrides the plugin's, except sub, iss, aud, exp, iat and nonce, which
// are always the plugin's.
type ClaimsFunc func(ctx context.Context, u auth.User, scopes []string) map[string]any

// Plugin is the OAuth 2.1 / OpenID Connect provider. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	// jwt signs ID and access tokens and publishes the keys at <base>/jwks;
	// the jwt plugin by default, any Signer otherwise.
	signer Signer

	issuer      string
	basePath    string
	loginPage   string
	consentPage string
	scopes      []string
	grantTypes  []string
	codeTTL     time.Duration
	accessTTL   time.Duration
	refreshTTL  time.Duration
	idTokenTTL  time.Duration
	claims      ClaimsFunc
	allowDCR    bool
	anonDCR     bool
	resources   []resourceSpec
	// resourceCache is CacheResources' cache; nil when it is off.
	resourceCache *resourceCache
	// limits and noDefaultLimits shape RateLimits.
	limits          map[auth.EndpointID]rateSpec
	noDefaultLimits bool
	// refreshReuse is RefreshReuseInterval.
	refreshReuse time.Duration
	// assertionMaxLifetime bounds a private_key_jwt assertion's exp.
	assertionMaxLifetime time.Duration
	// cimd is the client ID metadata document configuration; nil is off.
	cimd *cimdConfig
	// extensions are WithGrant grants; deviceEndpoint is
	// DeviceAuthorizationEndpoint. extensionFrom runs parallel to it and
	// names the option that added each grant (WithGrant or Extend), so a
	// refused grant names the option to fix.
	extensions    []ExtensionGrant
	extensionFrom []string
	// exts are the Extend extensions.
	exts []Extension
	// refreshFormat is FormatRefreshToken.
	refreshFormat *RefreshTokenFormat
	// The gates of gates.go.
	selectAccount  *SelectAccountGate
	postLogin      *PostLoginGate
	signupRedirect SignupRedirectFunc
	// trustedSpecs are TrustedClients; trusted their rows, built by Init.
	trustedSpecs   []TrustedClient
	trusted        map[string]clientRow
	deviceEndpoint string
	// The options of options.go.
	signupPage        string
	m2mTTL            time.Duration
	scopeTTLs         map[string]time.Duration
	redirectValidator RedirectValidator
	accessClaims      AccessTokenClaimsFunc
	advertisedScopes  []string
	advertisedClaims  []string
	genClientID       func() string
	genSecret         func() string
	// pairwise is PairwiseSecret.
	pairwise string
	// requestURIResolver is RequestURIResolver.
	requestURIResolver RequestURIResolverFunc
	// backchannelClient is BackchannelHTTPClient.
	backchannelClient *http.Client
	// dpopMaxAge is DPoPProofMaxAge; dpopAlgs DPoPSigningAlgorithms.
	dpopMaxAge time.Duration
	dpopAlgs   []string
	// jwksFetch is ClientJWKSFetch; jwksCache holds fetched client key
	// sets.
	jwksFetch JWKSFetcher
	jwksCache jwksCache
	// The opt-in behaviours of parity.go.
	revokeAccessOnly, refuseJWTRevoke, userInfoForbidden, selectViaLogin bool
	secretCrypt                                                          *SecretEncryption
	replay                                                               *SecretEncryption
	// secretHasher is HashStoredSecrets; genAccess and genRefresh the token
	// generators of storage.go.
	secretHasher          SecretHasher
	genAccess, genRefresh TokenGenerator
	// The resource registry options of registry.go.
	identifierValidator func(string) bool
	perClientOff        bool
	defaultResources    []string
	allowedResources    []string
	// dcrOptionalPKCE and dcrSecretTTL are the registration policy options.
	dcrOptionalPKCE bool
	dcrSecretTTL    time.Duration
	// dcrSecretAt, dcrDefaultScopes and dcrAllowedScopes are the
	// registration options of options.go.
	dcrSecretAt                        time.Time
	dcrDefaultScopes, dcrAllowedScopes []string
	// prelogin is AllowPublicClientPrelogin.
	prelogin bool
	// hasSecret is whether auth.WithSecret was given, read in Validate, so
	// the Go client API can refuse EnableEndSession without one.
	hasSecret bool
	// responseFields and initialToken are the options of the same names.
	responseFields func(ctx context.Context, info TokenFieldsInfo) (map[string]any, error)
	initialToken   InitialAccessTokenFunc
	// privileges and clientReference are the options of privileges.go.
	privileges      ClientPrivilegesFunc
	clientReference func(ctx context.Context, c *auth.Call) string

	core *auth.Auth

	authorize         *auth.Op[AuthorizeRequest, AuthorizeResult]
	token             *auth.Op[TokenRequest, TokenResponse]
	userinfo          *auth.Op[UserInfoRequest, map[string]any]
	introspect        *auth.Op[IntrospectRequest, Introspection]
	revoke            *auth.Op[RevokeRequest, auth.Done]
	register          *auth.Op[ClientMetadata, Registration]
	consent           *auth.Op[ConsentRequest, AuthorizeResult]
	createClient      *auth.Op[ClientMetadata, Registration]
	listClients       *auth.Op[struct{}, ClientList]
	getClient         *auth.Op[ClientIDRequest, Client]
	updateClient      *auth.Op[UpdateClientRequest, Client]
	rotateSecret      *auth.Op[ClientIDRequest, Registration]
	deleteClient      *auth.Op[ClientIDRequest, auth.Done]
	publicClient      *auth.Op[ClientIDRequest, PublicClient]
	listConsents      *auth.Op[struct{}, ConsentList]
	revokeConsent     *auth.Op[ClientIDRequest, auth.Done]
	getConsent        *auth.Op[ConsentIDRequest, Consent]
	updateConsent     *auth.Op[UpdateConsentRequest, Consent]
	endSession        *auth.Op[EndSessionRequest, EndSessionResult]
	endSessionConfirm *auth.Op[EndSessionConfirmRequest, EndSessionResult]
	preloginOp        *auth.Op[PreloginRequest, PublicClient]
	continueOp        *auth.Op[ContinueRequest, AuthorizeResult]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// Issuer is the provider's identifier, the iss of every ID token and the
// base of every endpoint URL: an absolute https URL with no query or
// fragment, such as "https://auth.example.com". Required. The jwt plugin's
// Issuer must be the same string.
func Issuer(iss string) Option { return func(p *Plugin) { p.issuer = strings.TrimSuffix(iss, "/") } }

// BasePath moves the protocol endpoints from DefaultBasePath under the
// issuer.
func BasePath(path string) Option { return func(p *Plugin) { p.basePath = path } }

// LoginPage is where the authorize endpoint sends a browser that is not
// signed in, with the authorize request's parameters appended to its query.
// After signing the user in, the page sends the browser to
// Plugin.ResumeURL(those parameters). Required: a same-site path or a URL
// on a trusted origin.
func LoginPage(u string) Option { return func(p *Plugin) { p.loginPage = u } }

// ConsentPage is where the authorize endpoint sends a signed-in user who has
// not yet consented to the client and scopes, with the authorize request's
// parameters appended. The page shows the client (PublicClient) and posts
// the user's answer to the consent operation, which answers the URL to send
// the browser to. Without a ConsentPage, a client that needs consent is
// answered consent_required; clients created with SkipConsent never need it.
func ConsentPage(u string) Option { return func(p *Plugin) { p.consentPage = u } }

// Scopes replaces DefaultScopes with every scope the provider supports.
// Leaving ScopeOpenID out makes it a plain OAuth 2.1 server: no ID tokens,
// no userinfo and no openid-configuration document.
func Scopes(scopes ...string) Option { return func(p *Plugin) { p.scopes = scopes } }

// GrantTypes narrows DefaultGrantTypes. refresh_token needs
// authorization_code (ErrBadGrantTypes otherwise).
func GrantTypes(grants ...string) Option { return func(p *Plugin) { p.grantTypes = grants } }

// CodeTTL overrides DefaultCodeTTL.
func CodeTTL(d time.Duration) Option { return func(p *Plugin) { p.codeTTL = d } }

// AccessTokenTTL overrides DefaultAccessTokenTTL.
func AccessTokenTTL(d time.Duration) Option { return func(p *Plugin) { p.accessTTL = d } }

// RefreshTokenTTL overrides DefaultRefreshTokenTTL.
func RefreshTokenTTL(d time.Duration) Option { return func(p *Plugin) { p.refreshTTL = d } }

// IDTokenTTL overrides DefaultIDTokenTTL.
func IDTokenTTL(d time.Duration) Option { return func(p *Plugin) { p.idTokenTTL = d } }

// RefreshReuseInterval lets a refresh token that was just rotated be
// presented again within d without revoking its family, for a client that
// refreshes from two tabs or retries after a lost response. Each such reuse
// issues a new pair; after d, reuse revokes the family as before. 0 (the
// default) allows no reuse. A reuse issues a new pair rather than replaying
// the earlier response, because this library keeps no plaintext token to
// replay.
func RefreshReuseInterval(d time.Duration) Option { return func(p *Plugin) { p.refreshReuse = d } }

// AssertionMaxLifetime overrides DefaultAssertionMaxLifetime.
func AssertionMaxLifetime(d time.Duration) Option {
	return func(p *Plugin) { p.assertionMaxLifetime = d }
}

// Claims adds the app's claims to ID tokens and userinfo answers.
func Claims(fn ClaimsFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("oauthprovider.Claims", fn) {
			return
		}
		p.claims = fn
	}
}

// AllowDynamicRegistration opens RFC 7591 registration at
// <base>/register to signed-in users. Off by default: anyone who can register a
// client can show your users a consent screen under a name they chose.
func AllowDynamicRegistration() Option { return func(p *Plugin) { p.allowDCR = true } }

// AllowUnauthenticatedRegistration lets a caller with no session register
// too, which MCP clients expect. It implies AllowDynamicRegistration. Such a
// client has no owner, so only the app's Go code can manage it.
func AllowUnauthenticatedRegistration() Option {
	return func(p *Plugin) { p.allowDCR, p.anonDCR = true, true }
}

// MCPRefreshReuseInterval is the refresh-token reuse window MCP sets, 30
// seconds: MCP clients often refresh from several processes at once.
const MCPRefreshReuseInterval = 30 * time.Second

// MCP configures the provider for Model Context Protocol clients: open
// unauthenticated dynamic registration (MCP clients register themselves) and a
// MCPRefreshReuseInterval reuse window. Options after it override either. There
// is no separate MCP plugin: the resource side is RequireToken (in process) or
// ResourceGuard (another process), and ProtectedResource declares the MCP
// server's URL and scopes.
func MCP() Option {
	return func(p *Plugin) {
		AllowUnauthenticatedRegistration()(p)
		p.refreshReuse = MCPRefreshReuseInterval
	}
}

var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
	_ auth.Dependent         = (*Plugin)(nil)
)

// Signer signs the provider's ID tokens and JWT access tokens and lists the
// public keys the provider publishes at <base>/jwks, so a relying party can
// verify what Sign produced. *jwt.Plugin is the default and satisfies it; a
// KMS, an HSM or a key service an app already runs can stand in, without
// registering the jwt plugin or serving its token route.
//
// The contract a custom Signer must keep, because relying parties check
// every part of it: the token's iss is SignRequest's issuer, which New
// verifies at start-up by signing a probe and comparing it with Issuer; the
// claims are sub, aud, iat, exp and the request's Claims, with typ the
// request's Type ("" is "JWT"); the header's kid names a key PublicKeys
// lists, and the first listed key's alg is the one ID tokens use, because
// at_hash is computed with its hash. Sign is called from trusted code only.
type Signer interface {
	Sign(ctx context.Context, in jwt.SignRequest) (jwt.TokenResult, error)
	PublicKeys() jwt.JWKS
}

var _ Signer = (*jwt.Plugin)(nil)

// New builds the provider. signer signs ID tokens and publishes its keys at
// <base>/jwks: usually the jwt plugin, which must then also be in
// auth.WithPlugins, before this plugin. Any other Signer that is itself a
// plugin must be registered before this one too; one that is not a plugin
// needs no registration.
func New(signer Signer, opts ...Option) *Plugin {
	if jp, ok := signer.(*jwt.Plugin); ok && jp == nil {
		// A typed nil is a missing signer, not a signer: Validate then
		// answers ErrNoJWT instead of a nil dereference at the first token.
		signer = nil
	}
	p := &Plugin{
		signer: signer, basePath: DefaultBasePath, scopes: DefaultScopes, grantTypes: DefaultGrantTypes,
		assertionMaxLifetime: DefaultAssertionMaxLifetime, dpopMaxAge: DefaultDPoPProofMaxAge, dpopAlgs: DPoPAlgorithms,
		codeTTL: DefaultCodeTTL, accessTTL: DefaultAccessTokenTTL, refreshTTL: DefaultRefreshTokenTTL, idTokenTTL: DefaultIDTokenTTL,
	}
	for _, o := range opts {
		o(p)
	}
	self := func(id auth.EndpointID, kind auth.OpKind, path string) auth.OpInfo {
		return auth.OpInfo{ID: id, Kind: kind, Require: auth.Public, Path: path, SelfServed: true}
	}
	p.authorize = auth.Define(self(EndpointAuthorize, auth.Query, pathAuthorize), p.doAuthorize)
	p.token = auth.Define(self(EndpointToken, auth.Mutation, pathToken), p.doToken)
	p.userinfo = auth.Define(self(EndpointUserInfo, auth.Query, pathUserInfo), p.doUserInfo)
	p.introspect = auth.Define(self(EndpointIntrospect, auth.Mutation, pathIntrospect), p.doIntrospect)
	p.revoke = auth.Define(self(EndpointRevoke, auth.Mutation, pathRevoke), p.doRevoke)
	p.register = auth.Define(self(EndpointRegister, auth.Mutation, pathRegister), p.doRegister)
	p.consent = auth.Define(auth.OpInfo{ID: EndpointConsent, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/consent"}, p.doConsent)
	p.createClient = auth.Define(auth.OpInfo{ID: EndpointCreateClient, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/create-client"}, p.doCreateClient)
	p.listClients = auth.Define(auth.OpInfo{ID: EndpointListClients, Kind: auth.Query, Require: auth.SignedIn, Path: "/clients"}, p.doListClients)
	p.getClient = auth.Define(auth.OpInfo{ID: EndpointGetClient, Kind: auth.Query, Require: auth.SignedIn, Path: "/client"}, p.doGetClient)
	p.updateClient = auth.Define(auth.OpInfo{ID: EndpointUpdateClient, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/update-client"}, p.doUpdateClient)
	p.rotateSecret = auth.Define(auth.OpInfo{ID: EndpointRotateSecret, Kind: auth.Mutation, Require: auth.FreshSignIn, Path: "/rotate-secret"}, p.doRotateSecret)
	p.deleteClient = auth.Define(auth.OpInfo{ID: EndpointDeleteClient, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/delete-client"}, p.doDeleteClient)
	p.publicClient = auth.Define(auth.OpInfo{ID: EndpointPublicClient, Kind: auth.Query, Require: auth.SignedIn, Path: "/public-client"}, p.doPublicClient)
	p.listConsents = auth.Define(auth.OpInfo{ID: EndpointListConsents, Kind: auth.Query, Require: auth.SignedIn, Path: "/consents"}, p.doListConsents)
	p.revokeConsent = auth.Define(auth.OpInfo{ID: EndpointRevokeConsent, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/revoke-consent"}, p.doRevokeConsent)
	p.getConsent = auth.Define(auth.OpInfo{ID: EndpointGetConsent, Kind: auth.Query, Require: auth.SignedIn, Path: "/get-consent"}, p.doGetConsent)
	p.updateConsent = auth.Define(auth.OpInfo{ID: EndpointUpdateConsent, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/update-consent"}, p.doUpdateConsent)
	p.endSession = auth.Define(self(EndpointEndSession, auth.Query, pathEndSession), p.doEndSession)
	p.continueOp = auth.Define(auth.OpInfo{ID: EndpointContinue, Kind: auth.Mutation, Require: auth.SignedIn, Path: "/continue"}, p.doContinue)
	p.preloginOp = auth.Define(auth.OpInfo{ID: EndpointPublicClientPrelogin, Kind: auth.Mutation, Require: auth.Public, Path: "/public-client-prelogin"}, p.doPublicClientPrelogin)
	p.endSessionConfirm = auth.Define(self(EndpointEndSessionConfirm, auth.Mutation, pathEndSessionConfirm), p.doEndSessionConfirm)
	return p
}

// Protocol paths under BasePath.
const (
	pathAuthorize         = "/authorize"
	pathToken             = "/token"
	pathUserInfo          = "/userinfo"
	pathIntrospect        = "/introspect"
	pathRevoke            = "/revoke"
	pathRegister          = "/register"
	pathJWKS              = "/jwks"
	pathEndSession        = "/end-session"
	pathEndSessionConfirm = "/end-session/confirm"
)

// Name is PluginName.
func (p *Plugin) Name() string { return PluginName }

// Requires names the signer when it is a plugin (the jwt plugin by
// default), so auth.New refuses a configuration that forgot to register it;
// a Signer that is not a plugin requires nothing.
func (p *Plugin) Requires() []string {
	if sp, ok := p.signer.(auth.Plugin); ok {
		return []string{sp.Name()}
	}
	return nil
}

// Operations lists every operation; the self-served ones are wired but
// mounted only by Handler.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{
		p.authorize, p.token, p.userinfo, p.introspect, p.revoke, p.register,
		p.consent, p.createClient, p.listClients, p.getClient, p.updateClient, p.rotateSecret,
		p.deleteClient, p.publicClient, p.listConsents, p.revokeConsent, p.getConsent, p.updateConsent, p.endSession, p.endSessionConfirm, p.preloginOp, p.continueOp,
	}
}

// Validate checks the issuer, the pages, the scopes, the grants, the
// lifetimes, and that every feature that signs has auth.WithSecret.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.signer == nil {
		return ErrNoJWT
	}
	p.hasSecret = c.HasSecret()
	if err := p.validateSecretUsers(); err != nil {
		return err
	}
	if !validIssuer(p.issuer) {
		return fmt.Errorf("%w: %q", ErrNoIssuer, p.issuer)
	}
	if !strings.HasPrefix(p.basePath, "/") || strings.Contains(p.basePath, "..") || strings.HasSuffix(p.basePath, "/") {
		return fmt.Errorf("oauthprovider: BasePath %q must start with / and not end with one", p.basePath)
	}
	if p.loginPage == "" {
		return ErrNoLoginPage
	}
	for _, s := range p.scopes {
		if s == "" || strings.ContainsAny(s, " \t\n") {
			return fmt.Errorf("%w: oauthprovider.Scopes: %q", ErrBadScopes, s)
		}
	}
	for _, g := range p.grantTypes {
		if !slices.Contains(DefaultGrantTypes, g) {
			return fmt.Errorf("%w: %q", ErrBadGrantTypes, g)
		}
	}
	if slices.Contains(p.grantTypes, GrantRefreshToken) && !slices.Contains(p.grantTypes, GrantAuthorizationCode) {
		return ErrBadGrantTypes
	}
	if err := p.resourceCache.validate(); err != nil {
		return err
	}
	for _, r := range p.resources {
		if !validResource(r.url) {
			return fmt.Errorf("%w: %q", ErrBadResource, r.url)
		}
		for _, s := range r.scopes {
			if !slices.Contains(p.scopes, s) {
				return fmt.Errorf("%w: oauthprovider.ProtectedResource: resource %q scope %q is not in Scopes", ErrBadScopes, r.url, s)
			}
		}
	}
	if p.pairwise != "" && len(p.pairwise) < minPairwiseSecret {
		return ErrBadPairwiseSecret
	}
	if err := p.validateOptions(); err != nil {
		return err
	}
	if err := p.validateExtensions(); err != nil {
		return err
	}
	if err := p.validateDPoPAlgs(); err != nil {
		return err
	}
	if err := p.validateSecretHasher(); err != nil {
		return err
	}
	if err := p.validateEncryption(); err != nil {
		return err
	}
	if p.cimd != nil && p.cimd.revalidate <= 0 {
		return fmt.Errorf("%w: oauthprovider.CIMDRevalidate(%v)", ErrBadTTL, p.cimd.revalidate)
	}
	if p.cimd != nil {
		for _, f := range p.cimd.originFields {
			if !slices.Contains(cimdOriginFieldNames, f) {
				return fmt.Errorf("%w: %q", ErrBadCIMDField, f)
			}
		}
	}
	return p.validateLifetimes()
}

// validateLifetimes refuses each lifetime under its own option's name, so
// the error says which setting to fix; ErrBadTTL stays the sentinel. The
// reuse interval may be zero (no reuse window); every other must be positive.
func (p *Plugin) validateLifetimes() error {
	for _, l := range []struct {
		option string
		d      time.Duration
		min    time.Duration
	}{
		{"oauthprovider.CodeTTL", p.codeTTL, 1},
		{"oauthprovider.AccessTokenTTL", p.accessTTL, 1},
		{"oauthprovider.RefreshTokenTTL", p.refreshTTL, 1},
		{"oauthprovider.IDTokenTTL", p.idTokenTTL, 1},
		{"oauthprovider.RefreshReuseInterval", p.refreshReuse, 0},
		{"oauthprovider.AssertionMaxLifetime", p.assertionMaxLifetime, 1},
		{"oauthprovider.DPoPProofMaxAge", p.dpopMaxAge, 1},
	} {
		if l.d < l.min {
			return fmt.Errorf("%w: %s(%v)", ErrBadTTL, l.option, l.d)
		}
	}
	return nil
}

// validateSecretUsers refuses, without auth.WithSecret, every feature that
// signs with a key derived from it, since each would otherwise fail on its
// first request: a trusted client with EnableEndSession, the pre-login
// lookup, and the post-login gate.
func (p *Plugin) validateSecretUsers() error {
	if p.hasSecret {
		return nil
	}
	for _, tc := range p.trustedSpecs {
		if tc.EnableEndSession {
			return fmt.Errorf("%w: trusted client %q has EnableEndSession, whose logout confirmation is a signed cookie", ErrNoSecret, tc.ClientID)
		}
	}
	if p.prelogin {
		return fmt.Errorf("%w: AllowPublicClientPrelogin verifies the signed authorization query", ErrNoSecret)
	}
	if p.postLogin != nil {
		return fmt.Errorf("%w: PostLogin signs the marker its page carries: %w", ErrBadGate, ErrNoSecret)
	}
	return nil
}

// validIssuer needs an absolute https URL (http for a loopback host) with a
// host and no query, fragment or user information, as OpenID Connect
// Discovery section 3 requires of an issuer.
func validIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return u.Scheme == schemeHTTPS || (u.Scheme == schemeHTTP && isLoopback(u.Hostname()))
}

// Init captures the core, checks the pages against the trusted origins, and
// checks that the jwt plugin signs with the provider's issuer.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	// The expiry instant is checked here rather than in Validate because
	// only Init sees the app's clock (auth.WithClock).
	if !p.dcrSecretAt.IsZero() && !p.dcrSecretAt.After(a.Now()) {
		return fmt.Errorf("%w: oauthprovider.RegistrationSecretExpiresAt(%v) is not in the future", ErrBadTTL, p.dcrSecretAt)
	}
	if !a.TrustsReturnURL(p.loginPage) {
		return fmt.Errorf("oauthprovider: LoginPage %q is neither a same-site path nor on a trusted origin", p.loginPage)
	}
	if p.signupPage != "" && !a.TrustsReturnURL(p.signupPage) {
		return fmt.Errorf("oauthprovider: SignupPage %q is neither a same-site path nor on a trusted origin", p.signupPage)
	}
	if p.consentPage != "" && !a.TrustsReturnURL(p.consentPage) {
		return fmt.Errorf("oauthprovider: ConsentPage %q is neither a same-site path nor on a trusted origin", p.consentPage)
	}
	if err := p.initGates(a); err != nil {
		return err
	}
	if err := p.initTrusted(a); err != nil {
		return err
	}
	p.warnOptIns(a)
	return p.checkSignerIssuer(a)
}

// checkSignerIssuer signs a probe token with the signer and compares its
// iss with Issuer. The jwt plugin keeps its issuer unexported, and an ID
// token naming another issuer is refused by every relying party, so the
// mismatch is caught here rather than at the first sign-in. A signer that is
// a plugin must be initialized before this one, so it must come first.
func (p *Plugin) checkSignerIssuer(a *auth.Auth) error {
	if sp, ok := p.signer.(auth.Plugin); ok {
		signerIndex, selfIndex := -1, -1
		for i, pl := range a.Plugins() {
			switch pl {
			case sp:
				signerIndex = i
			case auth.Plugin(p):
				selfIndex = i
			}
		}
		if signerIndex < 0 || signerIndex > selfIndex {
			return ErrNoJWT
		}
	}
	tok, err := p.signer.Sign(context.Background(), jwt.SignRequest{Subject: "probe", Audience: []string{}})
	if err != nil {
		return err
	}
	claims, err := payload(tok.Token)
	if err != nil {
		return err
	}
	if iss, _ := claims[claimIssuer].(string); iss != p.issuer {
		return fmt.Errorf("%w: jwt %q, provider %q", ErrIssuerMatch, iss, p.issuer)
	}
	return nil
}

// Sweep deletes codes and tokens that can no longer be used: expired codes,
// and token rows whose access and refresh tokens have both expired.
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	n, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableCode).Where(sqlb.Less(CodeExpires, cutoff)))
	if err != nil {
		return n, err
	}
	m, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableToken).Where(
		sqlb.Less(TokenAccessExpires, cutoff),
		sqlb.Or(sqlb.IsNull(TokenRefreshExpires), sqlb.Less(TokenRefreshExpires, &cutoff)),
	))
	if err != nil {
		return n + m, err
	}
	k, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableAssertion).Where(sqlb.Less(AssertionExpires, cutoff)))
	return n + m + k, err
}
