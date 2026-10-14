// Package sso is enterprise single sign-on: OpenID Connect and SAML 2.0
// identity providers that an app registers at run time, one per customer
// organization or email domain, the shape of better-auth's sso plugin.
//
// plugin/oauth signs people in with providers fixed at build time (Google,
// GitHub, one Okta). This plugin keeps providers as rows in auth_sso_provider,
// so a customer's admin can connect their own Okta, Entra ID or ADFS without
// a deploy, and routes a sign-in to the right one by provider id, email
// domain, domain or organization. OpenID Connect runs on plugin/oauth's
// OAuth2 type (PKCE, ID-token signature, issuer and nonce checks); SAML runs
// on the SAMLEngine interface, gosaml2 by default, with every assertion rule
// that decides who signs in (audience, recipient, time window, InResponseTo,
// replay) checked here, in code this package's tests break one by one.
//
// A provider account is linked to a user in auth_sso_account, keyed by the
// provider and the IdP's subject (the OIDC sub or the SAML NameID). An
// existing user with the same email is linked automatically only when the
// provider's domain is verified and the address is in it; otherwise the
// sign-in is refused, because linking would hand the account to whoever
// runs that IdP.
package sso

import (
	"errors"
	"net/http"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// PluginName is the plugin's permanent identity and its route segment.
const PluginName = "sso"

// Verification purposes. Each is a single-use core verification row.
const (
	// PurposeState is an OIDC flow's state; Identifier is the provider id,
	// Meta the JSON flowMeta.
	PurposeState auth.Purpose = "sso.state"
	// PurposeSAMLRequest is an SP-initiated AuthnRequest; the token is the
	// request ID, so the response's InResponseTo consumes it exactly once.
	PurposeSAMLRequest auth.Purpose = "sso.saml_request"
	// PurposeSAMLRelay is the RelayState of an SP-initiated SAML flow; Meta
	// is the JSON flowMeta.
	PurposeSAMLRelay auth.Purpose = "sso.saml_relay"
	// PurposeSAMLAssertion reserves an accepted assertion's ID until it
	// expires: a second response carrying the same ID is a replay.
	PurposeSAMLAssertion auth.Purpose = "sso.saml_assertion"
)

// Operation ids.
const (
	EndpointRegister      auth.EndpointID = "sso.register"
	EndpointSignIn        auth.EndpointID = "sso.sign-in"
	EndpointCallback      auth.EndpointID = "sso.callback"
	EndpointProviders     auth.EndpointID = "sso.providers"
	EndpointGetProvider   auth.EndpointID = "sso.get-provider"
	EndpointUpdate        auth.EndpointID = "sso.update-provider"
	EndpointDelete        auth.EndpointID = "sso.delete-provider"
	EndpointSPMetadata    auth.EndpointID = "sso.saml-metadata"
	EndpointACS           auth.EndpointID = "sso.saml-acs"
	EndpointRequestDomain auth.EndpointID = "sso.request-domain-verification"
	EndpointVerifyDomain  auth.EndpointID = "sso.verify-domain"
)

// Routes, relative to the plugin's mount ("/auth/sso" by default). The
// OIDC callback and the SAML ACS are shared by every provider: the core
// routes exact paths, so the provider travels in the state, the RelayState
// or (for an IdP-initiated sign-in) a providerId query parameter.
const (
	PathRegister      = "/register"
	PathSignIn        = "/sign-in"
	PathCallback      = "/callback"
	PathProviders     = "/providers"
	PathGetProvider   = "/get-provider"
	PathUpdate        = "/update-provider"
	PathDelete        = "/delete-provider"
	PathSPMetadata    = "/saml2/sp/metadata"
	PathACS           = "/saml2/sp/acs"
	PathRequestDomain = "/request-domain-verification"
	PathVerifyDomain  = "/verify-domain"
)

// DefaultMountPrefix is where authhttp mounts plugins by default; the
// callback and ACS URLs are built under it unless WithCallbackURL or
// WithACSURL say otherwise.
const DefaultMountPrefix = "/auth"

// Defaults, each better-auth's.
const (
	// DefaultProvidersLimit is how many providers one user may register.
	DefaultProvidersLimit = 10
	// DefaultStateTTL bounds an OIDC flow and an SP-initiated SAML request.
	DefaultStateTTL = 10 * time.Minute
	// DefaultSAMLRequestTTL is how long an AuthnRequest's ID is accepted
	// as InResponseTo.
	DefaultSAMLRequestTTL = 5 * time.Minute
	// DefaultClockSkew is the tolerance on every SAML timestamp.
	DefaultClockSkew = 5 * time.Minute
	// DefaultMaxResponseSize bounds a base64-decoded SAML response.
	DefaultMaxResponseSize = 256 * 1024
	// DefaultMaxMetadataSize bounds IdP or SP metadata XML.
	DefaultMaxMetadataSize = 100 * 1024
	// DefaultReplayWindow is how long an assertion ID stays reserved when
	// the assertion states no NotOnOrAfter.
	DefaultReplayWindow = 15 * time.Minute
	// DefaultDomainTokenTTL is how long a domain-verification token is
	// accepted (better-auth: one week).
	DefaultDomainTokenTTL = 7 * 24 * time.Hour
	// DefaultDomainTokenPrefix names the DNS TXT record of a domain
	// verification: _<prefix>-<providerId>.<domain>.
	DefaultDomainTokenPrefix = "ubgo-auth-token"
	// DefaultHTTPTimeout bounds every call to an identity provider.
	DefaultHTTPTimeout = 10 * time.Second
)

// Rate limits on the public operations. Each sign-in writes a state row and
// may fetch a discovery document; each ACS post verifies a signature.
const (
	signInIPLimit   = 30
	signInIPWindow  = time.Minute
	acsIPLimit      = 60
	acsIPWindow     = time.Minute
	verifyIPLimit   = 10
	verifyIPWindow  = time.Minute
	registerIPLimit = 10
	registerWindow  = time.Minute
)

// Errors a caller sees. Codes are permanent.
var (
	ErrProviderNotFound   = auth.NewError("sso.provider_not_found", http.StatusNotFound, "No sign-in provider was found for this account.")
	ErrProviderExists     = auth.NewError("sso.provider_exists", http.StatusUnprocessableEntity, "A sign-in provider with this id already exists.")
	ErrProviderIDReserved = auth.NewError("sso.provider_id_reserved", http.StatusUnprocessableEntity, "This provider id is reserved.")
	ErrBadProvider        = auth.NewError("sso.bad_provider", http.StatusBadRequest, "The provider configuration is not valid.")
	ErrRegistrationOff    = auth.NewError("sso.registration_disabled", http.StatusForbidden, "Sign-in provider registration is disabled.")
	ErrProvidersLimit     = auth.NewError("sso.providers_limit", http.StatusForbidden, "You have reached the maximum number of sign-in providers.")
	ErrForbidden          = auth.NewError("sso.forbidden", http.StatusForbidden, "You cannot manage this sign-in provider.")
	ErrNotMember          = auth.NewError("sso.not_member", http.StatusBadRequest, "You are not a member of this organization.")
	ErrSignInTarget       = auth.NewError("sso.target_required", http.StatusBadRequest, "Give an email, a domain, an organization or a provider id.")
	ErrDomainUnverified   = auth.NewError("sso.domain_unverified", http.StatusUnauthorized, "This provider's domain has not been verified.")
	ErrProtocol           = auth.NewError("sso.protocol_unavailable", http.StatusBadRequest, "This provider does not offer that sign-in protocol.")
	ErrBadParams          = auth.NewError("sso.bad_params", http.StatusBadRequest, "A sign-in parameter is not allowed.")
	ErrBadReturnTo        = auth.NewError("sso.bad_return_to", http.StatusBadRequest, "The return address must be a path on this site or a trusted origin.")
	ErrStateInvalid       = auth.NewError("sso.state_invalid", http.StatusBadRequest, "This sign-in link has expired. Start again.")
	ErrProviderChanged    = auth.NewError("sso.provider_changed", http.StatusConflict, "The sign-in provider changed during sign-in. Start again.")
	ErrProviderDenied     = auth.NewError("sso.denied", http.StatusBadRequest, "Sign-in was cancelled at the provider.")
	ErrTokenNotVerified   = auth.NewError("sso.token_not_verified", http.StatusUnauthorized, "The provider's sign-in token was not accepted.")
	ErrNoIDToken          = auth.NewError("sso.token_response_not_found", http.StatusBadGateway, "The provider's answer carried no sign-in token.")
	ErrNoPrivateKey       = auth.NewError("sso.no_private_key_available", http.StatusInternalServerError, "The sign-in key for this provider is not available.")
	ErrTokenExchange      = auth.NewError("sso.token_response_error", http.StatusBadGateway, "The provider did not complete the sign-in. Try again.")
	ErrProviderFailed     = auth.NewError("sso.provider_failed", http.StatusBadGateway, "The sign-in provider could not be reached. Try again.")
	ErrAccountExists      = auth.NewError("sso.account_exists", http.StatusConflict, "An account with this email already exists. Sign in, then link this provider.")
	ErrLinkedElsewhere    = auth.NewError("sso.linked_elsewhere", http.StatusConflict, "This provider account is linked to another user.")
	ErrSignUpDisabled     = auth.NewError("sso.sign_up_disabled", http.StatusForbidden, "No account exists for you here. Ask for an invitation or sign up first.")
	ErrUserRejected       = auth.NewError("sso.user_rejected", http.StatusForbidden, "This account cannot sign in here.")
	ErrBoundaryLocked     = auth.NewError("sso.boundary_locked", http.StatusConflict, "Cannot change a provider's identity fields while accounts are linked to it.")
	ErrMutationRejected   = auth.NewError("sso.mutation_rejected", http.StatusConflict, "This change to the sign-in provider was refused.")
	ErrSAMLInvalid        = auth.NewError("sso.saml_invalid", http.StatusBadRequest, "The sign-in response was not accepted.")
	ErrSAMLReplay         = auth.NewError("sso.saml_replay", http.StatusBadRequest, "This sign-in response was already used.")
	ErrSAMLUnsolicited    = auth.NewError("sso.saml_unsolicited", http.StatusBadRequest, "Sign-in must start on this site.")
	ErrSAMLTooLarge       = auth.NewError("sso.saml_too_large", http.StatusBadRequest, "The sign-in response is too large.")
	ErrNoIdentity         = auth.NewError("sso.no_identity", http.StatusBadRequest, "The provider sent no user id or email.")
	ErrDomainVerified     = auth.NewError("sso.domain_verified", http.StatusConflict, "This domain is already verified.")
	ErrDomainNotProven    = auth.NewError("sso.domain_not_proven", http.StatusBadGateway, "The domain's DNS record was not found. It can take a while to appear.")
	ErrNoPendingDomain    = auth.NewError("sso.no_pending_verification", http.StatusNotFound, "No domain verification is pending for this provider. Request a new token.")
	ErrIdentifierTooLong  = auth.NewError("sso.identifier_too_long", http.StatusBadRequest, "The provider id is too long for a DNS verification record.")
)

// Configuration errors, returned by auth.New.
var (
	ErrNoCallbackURL = errors.New("sso: callback URLs need auth.WithBaseURL or sso.WithCallbackURL")
	ErrBadDefault    = errors.New("sso: a default provider is not valid")
	ErrPrefixTooLong = errors.New("sso: the domain token prefix leaves no room for a provider id in a DNS label (63 bytes)")
	// ErrNoSAMLEngine was WithSAMLEngine(nil).
	//
	// Deprecated: no longer returned. WithSAMLEngine(nil) fails auth.New
	// with auth.ErrNilOption naming the option.
	ErrNoSAMLEngine    = errors.New("sso: SAML needs a SAMLEngine (sso.WithSAMLEngine)")
	ErrKeyDerivation   = errors.New("sso: provider secrets need auth.WithSecret, so they are sealed at rest")
	ErrBadAlgorithmSet = errors.New("sso: an allowed SAML algorithm is not one this plugin knows")
)

// Table labels and columns. auth_sso_provider holds the registered
// providers; auth_sso_account links an IdP subject to a user. Neither has a
// foreign key (ADR-0002): DeleteUser removes a user's sso accounts through
// UserTables, and a provider outlives the admin who registered it.
const (
	TableNameProvider  = "auth_sso_provider"
	TableAliasProvider = "ssop"
	TableNameAccount   = "auth_sso_account"
	TableAliasAccount  = "ssoa"

	ColID             = "id"
	ColProviderID     = "provider_id"
	ColIssuer         = "issuer"
	ColDomain         = "domain"
	ColOrganizationID = "organization_id"
	ColUserID         = "user_id"
	// ColOIDCConfig and ColSAMLConfig hold JSON. The OIDC client secret
	// inside is sealed (auth.KeyRing, additional data the provider id), so
	// a database dump does not hand out every customer's IdP credential.
	ColOIDCConfig     = "oidc_config"
	ColSAMLConfig     = "saml_config"
	ColDomainVerified = "domain_verified"
	ColCreatedAt      = "created_at"
	ColUpdatedAt      = "updated_at"
	ColSubject        = "subject"
	// ColDomainToken and ColDomainTokenExpires hold the pending
	// domain-verification token ('' and NULL when none).
	ColDomainToken        = "domain_token"
	ColDomainTokenExpires = "domain_token_expires_at"
	// ColFields holds the WithProviderFields values as a JSON object, NULL
	// when none is set.
	ColFields = "fields"
	ColEmail  = "email"
)

// Typed tables and columns, for an app that joins them.
var (
	TableProvider          = sqlb.Table{Name: TableNameProvider, Alias: TableAliasProvider}
	ProviderRowID          = sqlb.Col[string](TableProvider, ColID)
	ProviderProviderID     = sqlb.Col[string](TableProvider, ColProviderID)
	ProviderIssuer         = sqlb.Col[string](TableProvider, ColIssuer)
	ProviderDomain         = sqlb.Col[string](TableProvider, ColDomain)
	ProviderOrganizationID = sqlb.Col[string](TableProvider, ColOrganizationID)
	ProviderUserID         = sqlb.Col[string](TableProvider, ColUserID)
	ProviderOIDCConfig     = sqlb.Col[string](TableProvider, ColOIDCConfig)
	ProviderSAMLConfig     = sqlb.Col[string](TableProvider, ColSAMLConfig)
	ProviderDomainVerified = sqlb.Col[bool](TableProvider, ColDomainVerified)
	ProviderCreatedAt      = sqlb.Col[time.Time](TableProvider, ColCreatedAt)
	ProviderUpdatedAt      = sqlb.Col[time.Time](TableProvider, ColUpdatedAt)
	ProviderDomainToken    = sqlb.Col[string](TableProvider, ColDomainToken)
	ProviderDomainTokenExp = sqlb.Col[*time.Time](TableProvider, ColDomainTokenExpires)
	ProviderFields         = sqlb.Col[*string](TableProvider, ColFields)

	TableAccount      = sqlb.Table{Name: TableNameAccount, Alias: TableAliasAccount}
	AccountID         = sqlb.Col[string](TableAccount, ColID)
	AccountUserID     = sqlb.Col[string](TableAccount, ColUserID)
	AccountProviderID = sqlb.Col[string](TableAccount, ColProviderID)
	AccountIssuer     = sqlb.Col[string](TableAccount, ColIssuer)
	AccountSubject    = sqlb.Col[string](TableAccount, ColSubject)
	AccountEmail      = sqlb.Col[string](TableAccount, ColEmail)
	AccountCreatedAt  = sqlb.Col[time.Time](TableAccount, ColCreatedAt)
)

// Id prefixes and migration names.
const (
	idPrefixProvider     = "ssop"
	idPrefixAccount      = "ssoa"
	migrationProvider    = "0001_sso_provider"
	migrationAccount     = "0002_sso_account"
	migrationDomainToken = "0003_sso_domain_token"
	accountUserIndex     = "_user_idx"
	keyLabelSecrets      = "sso-provider-secrets"
	providerIDParam      = "providerId"
	domainListSep        = ","
	domainTokenBytes     = 24
)
