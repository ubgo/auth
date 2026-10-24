package oauthprovider

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// URL schemes and hosts a redirect URI may use.
const (
	schemeHTTPS   = "https"
	schemeHTTP    = "http"
	hostLocalhost = "localhost"
	// listSeparator joins scopes and grant types in their columns; a scope
	// with whitespace is refused, so the split is exact.
	listSeparator = " "
	// redirectSeparator joins redirect URIs: a newline cannot appear in a
	// parsed URL.
	redirectSeparator = "\n"
	// clientIDPrefix starts every generated client_id.
	clientIDPrefix = "oac"
	// maxRedirectURIs bounds the redirect URIs one client registers, so a
	// registration cannot fill the row.
	maxRedirectURIs = 20
	// maxContacts bounds the contacts list for the same reason.
	maxContacts = 10
	// maxClientsPerOwner bounds the clients one user may register through
	// the operations.
	maxClientsPerOwner = 50
	// maxNameRunes is the longest client name kept.
	maxNameRunes = 100
)

// ClientMetadata is a client's registration, RFC 7591 section 2: what dynamic
// registration and create-client accept, and what a client's owner may
// change. Restricted fields (skip consent, PKCE relaxation, introspection of
// other clients' tokens) are not here: only ClientSpec, from Go, sets them.
//
// It is an input only: the fields the provider defaults (client_name,
// grant_types, response_types, token_endpoint_auth_method, scope) are
// omitempty, so a generated client may leave them out. The answer carries
// RegisteredMetadata instead, where they are always present, because RFC
// 7591 section 3.2.1 returns every registered value. The two types have the
// same fields, so RegisteredMetadata(m) converts one to the other, and a
// field added to one and not the other stops that conversion compiling.
type ClientMetadata struct {
	Name         string   `json:"client_name,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	// GrantTypes defaults to authorization_code (and refresh_token when
	// the provider serves it).
	GrantTypes []string `json:"grant_types,omitempty"`
	// ResponseTypes may only be ["code"]; it is accepted for RFC 7591
	// clients that send it.
	ResponseTypes []string `json:"response_types,omitempty"`
	// AuthMethod defaults to client_secret_basic; none makes a public
	// client, which has no secret and must use PKCE.
	AuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	// Scope is the space-separated scopes the client may request; empty is
	// every scope the provider supports.
	Scope     string   `json:"scope,omitempty"`
	ClientURI string   `json:"client_uri,omitempty"`
	LogoURI   string   `json:"logo_uri,omitempty"`
	TosURI    string   `json:"tos_uri,omitempty"`
	PolicyURI string   `json:"policy_uri,omitempty"`
	Contacts  []string `json:"contacts,omitempty"`
	// PostLogoutRedirectURIs are where the end-session endpoint may send
	// the browser after signing the user out; exact match, as redirects.
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris,omitempty"`
	// JWKS is the client's public key set (RFC 7517 {"keys": [...]}), for
	// private_key_jwt, which requires it. Public asymmetric keys only.
	JWKS json.RawMessage `json:"jwks,omitempty"`
	// JWKSURI is where the client publishes its key set instead of JWKS
	// (one or the other, never both): an https URL on an origin the app
	// trusts, or on the client_id's origin for a metadata document client.
	// The set is fetched on first use and cached (see JWKSFetcher).
	JWKSURI string `json:"jwks_uri,omitempty"`
	// cimdOrigin is the client_id origin of a metadata document client,
	// where its jwks_uri may live; set by parseCIMD only.
	cimdOrigin string
	// SubjectType is "public" (the default) or "pairwise", which needs the
	// provider's PairwiseSecret and redirect URIs on one host.
	SubjectType string `json:"subject_type,omitempty"`
	// BackchannelLogoutURI receives a logout token when a session the
	// client holds tokens for ends (OpenID Connect Back-Channel Logout):
	// https, or http on a loopback host, no fragment.
	BackchannelLogoutURI string `json:"backchannel_logout_uri,omitempty"`
	// BackchannelLogoutSessionRequired says the client needs sid in the
	// logout token; this provider always sends it.
	BackchannelLogoutSessionRequired bool `json:"backchannel_logout_session_required,omitempty"`
	// DPoPBoundAccessTokens makes every token request carry a DPoP proof,
	// and every token the client gets bound to its key (RFC 9449 section 5).
	DPoPBoundAccessTokens bool `json:"dpop_bound_access_tokens,omitempty"`
	// Resources are the resources to link the new client to beyond
	// RegistrationDefaultResources; each must be a default or one of
	// RegistrationAllowedResources (invalid_target otherwise).
	Resources []string `json:"resources,omitempty"`
	// ApplicationType is "web" (the default) or "native", with these
	// redirect rules: a web client uses https on non-loopback hosts only; a
	// native one https on non-loopback hosts, http on exactly localhost,
	// 127.0.0.1 or [::1], or a reverse-domain private-use scheme.
	ApplicationType string `json:"application_type,omitempty"`
	// SoftwareID, SoftwareVersion and SoftwareStatement are RFC 7591's
	// software identifiers, stored as given.
	SoftwareID        string `json:"software_id,omitempty"`
	SoftwareVersion   string `json:"software_version,omitempty"`
	SoftwareStatement string `json:"software_statement,omitempty"`
	// CredentialsScopes asks for a client_credentials ceiling when an owner
	// creates a client through the operations: allowed only when
	// ClientPrivileges exists and grants ActionConfigureCCScopes, refused
	// (forbidden) for dynamic registration without a session, and never taken
	// from a metadata document. Go callers set
	// ClientSpec.ClientCredentialsScopes instead.
	CredentialsScopes []string `json:"client_credentials_scopes,omitempty"`
	// InitialAccessToken is the RFC 7591 Bearer token Handler read from the
	// registration request; never stored or returned.
	InitialAccessToken string `json:"-"`
	// Extra are the registration's members this provider does not define
	// (RFC 7591 extensions). Dynamic registration keeps them as the
	// client's Metadata, without the names the provider owns (the client's own
	// fields, public, type, metadata). Handler fills it.
	Extra map[string]any `json:"-"`
}

// RegisteredMetadata is a client's registration as the provider answers it,
// RFC 7591 section 3.2.1: ClientMetadata's fields after the provider applied
// its defaults, with those defaulted fields always present on the wire (see
// ClientMetadata for what each field means). Client embeds it.
type RegisteredMetadata struct {
	Name                             string          `json:"client_name"`
	RedirectURIs                     []string        `json:"redirect_uris"`
	GrantTypes                       []string        `json:"grant_types"`
	ResponseTypes                    []string        `json:"response_types"`
	AuthMethod                       string          `json:"token_endpoint_auth_method"`
	Scope                            string          `json:"scope"`
	ClientURI                        string          `json:"client_uri,omitempty"`
	LogoURI                          string          `json:"logo_uri,omitempty"`
	TosURI                           string          `json:"tos_uri,omitempty"`
	PolicyURI                        string          `json:"policy_uri,omitempty"`
	Contacts                         []string        `json:"contacts,omitempty"`
	PostLogoutRedirectURIs           []string        `json:"post_logout_redirect_uris,omitempty"`
	JWKS                             json.RawMessage `json:"jwks,omitempty"`
	JWKSURI                          string          `json:"jwks_uri,omitempty"`
	cimdOrigin                       string
	SubjectType                      string         `json:"subject_type,omitempty"`
	BackchannelLogoutURI             string         `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired bool           `json:"backchannel_logout_session_required,omitempty"`
	DPoPBoundAccessTokens            bool           `json:"dpop_bound_access_tokens,omitempty"`
	Resources                        []string       `json:"resources,omitempty"`
	ApplicationType                  string         `json:"application_type,omitempty"`
	SoftwareID                       string         `json:"software_id,omitempty"`
	SoftwareVersion                  string         `json:"software_version,omitempty"`
	SoftwareStatement                string         `json:"software_statement,omitempty"`
	CredentialsScopes                []string       `json:"client_credentials_scopes,omitempty"`
	InitialAccessToken               string         `json:"-"`
	Extra                            map[string]any `json:"-"`
}

// ClientSpec is ClientMetadata plus the restricted fields only the app's Go
// code may set.
type ClientSpec struct {
	ClientMetadata
	// SkipConsent marks a first-party client: the user is never asked.
	SkipConsent bool
	// OptionalPKCE lets a confidential client omit PKCE. A public client
	// always needs it, whatever this says.
	OptionalPKCE bool
	// IntrospectAny lets the client introspect tokens issued to any client:
	// a resource server.
	IntrospectAny bool
	// OwnerID is the user who manages the client through the operations;
	// "" is a client only Go code manages.
	OwnerID string
	// EnableEndSession lets the client sign the user out through the
	// end-session endpoint (RP-initiated logout). It needs auth.WithSecret,
	// which signs the logout confirmation; without one it is ErrNoSecret.
	EnableEndSession bool
	// ClientCredentialsScopes are the client_credentials ceiling: without them
	// the grant is unauthorized_client, and an omitted scope takes them all.
	// User scopes are never allowed.
	ClientCredentialsScopes []string
	// SecretExpiresAt ends the client secret; nil never does.
	SecretExpiresAt *time.Time
	// ReferenceID names an owner other than a user (an organization, a
	// team); Metadata is the app's JSON.
	ReferenceID string
	Metadata    json.RawMessage

	// discovery and fetchedAt are set by CIMD for the clients it creates;
	// they are unexported so no registration can claim them.
	discovery string
	fetchedAt *time.Time
	// id overrides the generated client_id (CIMD: the document's URL).
	id string
}

// Client is a registered client as its owner sees it, without the secret.
type Client struct {
	RegisteredMetadata
	ClientID      string `json:"client_id"`
	Public        bool   `json:"public"`
	SkipConsent   bool   `json:"skip_consent"`
	RequirePKCE   bool   `json:"require_pkce"`
	IntrospectAny bool   `json:"introspect_any"`
	// ClientCredentialsScopes is the client_credentials ceiling.
	ClientCredentialsScopes []string `json:"client_credentials_scopes,omitempty"`
	// SecretExpiresAt is when the secret stops; nil never.
	SecretExpiresAt *time.Time      `json:"client_secret_expires_at,omitempty"`
	ReferenceID     string          `json:"reference_id,omitempty"`
	Metadata        json.RawMessage `json:"metadata,omitempty"`
	EndSession      bool            `json:"enable_end_session"`
	Disabled        bool            `json:"disabled"`
	OwnerID         string          `json:"owner_id,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// Registration is the answer to a registration: the client and, for a
// confidential client, its secret, shown this once (RFC 7591 section 3.2.1).
type Registration struct {
	Client
	// Secret is a plain string on purpose: this is the one place it is
	// meant to be seen.
	Secret                string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`
}

// PublicClient is what a consent page may show about a client.
type PublicClient struct {
	ClientID  string   `json:"client_id"`
	Name      string   `json:"client_name"`
	ClientURI string   `json:"client_uri,omitempty"`
	LogoURI   string   `json:"logo_uri,omitempty"`
	TosURI    string   `json:"tos_uri,omitempty"`
	PolicyURI string   `json:"policy_uri,omitempty"`
	Contacts  []string `json:"contacts,omitempty"`
}

// ClientList is the owner's clients.
type ClientList struct {
	Clients []Client `json:"clients"`
}

// ClientIDRequest names one client.
type ClientIDRequest struct {
	ClientID string `json:"client_id"`
}

// UpdateClientRequest replaces an owned client's metadata. The
// authentication method cannot change: a public client that became confidential
// would have no secret.
type UpdateClientRequest struct {
	ClientID string         `json:"client_id"`
	Metadata ClientMetadata `json:"metadata"`
	// ClientCredentialsScopes, when set, replaces the client_credentials
	// ceiling; it needs ActionConfigureCCScopes, like CredentialsScopes at
	// creation.
	ClientCredentialsScopes *[]string `json:"client_credentials_scopes,omitempty"`
}

// clientRow is a client as stored, with its secret hash.
type clientRow struct {
	c          Client
	secretHash []byte
	redirects  string
	scopes     string
	grants     string
	owner      *string
	disabledAt *time.Time
	postLogout *string
	jwks       *string
	jwksURI    *string
	discovery  *string
	fetchedAt  *time.Time
	// subjectType is the subject_type column.
	subjectType *string
	// backchannel is the backchannel_logout_uri column.
	backchannel *string
	// The columns of migration 0008.
	appType, ccScopes, refID, meta *string
	secretExpires                  *time.Time
	// The software columns of migration 0010.
	softwareID, softwareVersion, softwareStatement *string
	// The CIMD freshness columns of migration 0009.
	cimdExpires           *time.Time
	cimdETag, cimdLastMod *string
	clientURI             *string
	// confirmation is what an extension ClientAuthMethod bound this
	// request's tokens to; set by authenticateClient, never stored.
	confirmation *Confirmation
	logoURI      *string
	contacts     *string
	tosURI       *string
	policyURI    *string
}

func (r *clientRow) bindings() []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(ClientIDCol, &r.c.ClientID), sqlb.Bind(ClientSecret, &r.secretHash), sqlb.Bind(ClientName, &r.c.Name),
		sqlb.Bind(ClientRedirs, &r.redirects), sqlb.Bind(ClientScopes, &r.scopes), sqlb.Bind(ClientGrants, &r.grants),
		sqlb.Bind(ClientMethod, &r.c.AuthMethod), sqlb.Bind(ClientSkip, &r.c.SkipConsent), sqlb.Bind(ClientPKCE, &r.c.RequirePKCE),
		sqlb.Bind(ClientIntro, &r.c.IntrospectAny), sqlb.Bind(ClientOwner, &r.owner), sqlb.Bind(ClientOff, &r.disabledAt),
		sqlb.Bind(ClientURI, &r.clientURI), sqlb.Bind(ClientLogo, &r.logoURI), sqlb.Bind(ClientContact, &r.contacts),
		sqlb.Bind(ClientTos, &r.tosURI), sqlb.Bind(ClientPolicy, &r.policyURI),
		sqlb.Bind(ClientCreated, &r.c.CreatedAt), sqlb.Bind(ClientUpdated, &r.c.UpdatedAt),
		sqlb.Bind(ClientPostLogout, &r.postLogout), sqlb.Bind(ClientEndSession, &r.c.EndSession), sqlb.Bind(ClientJWKS, &r.jwks),
		sqlb.Bind(ClientDiscovery, &r.discovery), sqlb.Bind(ClientFetchedAt, &r.fetchedAt), sqlb.Bind(ClientSubject, &r.subjectType),
		sqlb.Bind(ClientBackURI, &r.backchannel), sqlb.Bind(ClientBackSess, &r.c.BackchannelLogoutSessionRequired),
		sqlb.Bind(ClientDPoP, &r.c.DPoPBoundAccessTokens),
		sqlb.Bind(ClientAppType, &r.appType), sqlb.Bind(ClientCCScopes, &r.ccScopes), sqlb.Bind(ClientRefID, &r.refID),
		sqlb.Bind(ClientMeta, &r.meta), sqlb.Bind(ClientSecretExp, &r.secretExpires),
		sqlb.Bind(ClientCIMDExpires, &r.cimdExpires), sqlb.Bind(ClientCIMDETag, &r.cimdETag), sqlb.Bind(ClientCIMDLastMod, &r.cimdLastMod),
		sqlb.Bind(ClientSoftwareID, &r.softwareID), sqlb.Bind(ClientSoftwareVersion, &r.softwareVersion), sqlb.Bind(ClientSoftwareStatement, &r.softwareStatement),
		sqlb.Bind(ClientJWKSURI, &r.jwksURI),
	}
}

// client fills the derived fields of the stored row.
func (r *clientRow) client() Client {
	c := r.c
	c.RedirectURIs = splitList(r.redirects, redirectSeparator)
	c.Scope = r.scopes
	c.GrantTypes = splitList(r.grants, listSeparator)
	c.ResponseTypes = []string{responseTypeAuthorization}
	c.Public = c.AuthMethod == AuthMethodNone
	c.Disabled = r.disabledAt != nil
	c.OwnerID = deref(r.owner)
	c.ClientURI, c.LogoURI, c.TosURI, c.PolicyURI = deref(r.clientURI), deref(r.logoURI), deref(r.tosURI), deref(r.policyURI)
	c.Contacts = splitList(deref(r.contacts), listSeparator)
	c.PostLogoutRedirectURIs = splitList(deref(r.postLogout), redirectSeparator)
	c.SubjectType = deref(r.subjectType)
	c.BackchannelLogoutURI = deref(r.backchannel)
	c.ApplicationType = deref(r.appType)
	if r.ccScopes != nil {
		c.ClientCredentialsScopes = strings.Fields(*r.ccScopes)
	}
	c.SecretExpiresAt, c.ReferenceID = r.secretExpires, deref(r.refID)
	c.SoftwareID, c.SoftwareVersion, c.SoftwareStatement = deref(r.softwareID), deref(r.softwareVersion), deref(r.softwareStatement)
	if r.meta != nil {
		c.Metadata = json.RawMessage(*r.meta)
	}
	if r.jwks != nil {
		c.JWKS = json.RawMessage(*r.jwks)
	}
	c.JWKSURI = deref(r.jwksURI)
	return c
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func splitList(s, sep string) []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(s, sep)
}

// loadClient reads one client by id; ErrClientNotFound when there is none.
func (p *Plugin) loadClient(ctx context.Context, id string) (clientRow, error) {
	var r clientRow
	if id == "" {
		return r, ErrClientNotFound
	}
	if t, ok := p.trustedClient(id); ok {
		return t, nil
	}
	err := p.core.One(ctx, p.core.Select().Columns(r.bindings()...).From(TableClient).Where(sqlb.Eq(ClientIDCol, id)))
	if errors.Is(err, sqlb.ErrNoRows) {
		return r, ErrClientNotFound
	}
	return r, err
}

// resolveClient is loadClient for the endpoints a client calls (authorize,
// token, introspection, revocation): under ClientIDMetadataDocuments an
// https client_id is fetched or revalidated here. A registered client is
// returned as stored; its generated id is never a URL.
func (p *Plugin) resolveClient(ctx context.Context, id string) (clientRow, error) {
	r, err := p.loadClient(ctx, id)
	if d, ok := p.discoverer(id); ok {
		return p.discoveredClient(ctx, d, id, r, err)
	}
	if p.cimd == nil || !isCIMDCandidate(id) {
		return r, err
	}
	switch {
	case errors.Is(err, ErrClientNotFound):
		return p.cimdClient(ctx, id, nil)
	case err != nil:
		return r, err
	case deref(r.discovery) != discoveryCIMD:
		return r, nil
	}
	return p.cimdClient(ctx, id, &r)
}

// checkMetadata validates and normalizes a registration, RFC 7591 and the
// OAuth 2.1 rules: absolute redirect URIs without fragments, https or
// loopback http or a private-use scheme; only the code response type; grants
// and scopes the provider serves; client_credentials only for a confidential
// client.
func (p *Plugin) checkMetadata(m ClientMetadata) (ClientMetadata, error) {
	m.Name = strings.TrimSpace(auth.TruncateRunes(m.Name, maxNameRunes))
	if m.AuthMethod == "" {
		m.AuthMethod = AuthMethodBasic
	}
	if !slices.Contains(p.authMethods(), m.AuthMethod) {
		return m, ErrInvalidClientMetadata
	}
	if len(m.GrantTypes) == 0 {
		m.GrantTypes = []string{GrantAuthorizationCode}
		if slices.Contains(p.grantTypes, GrantRefreshToken) {
			m.GrantTypes = append(m.GrantTypes, GrantRefreshToken)
		}
	}
	for _, g := range m.GrantTypes {
		if !slices.Contains(p.servedGrants(), g) {
			return m, ErrInvalidClientMetadata
		}
	}
	if slices.Contains(m.GrantTypes, GrantClientCredentials) && m.AuthMethod == AuthMethodNone {
		return m, ErrInvalidClientMetadata
	}
	for _, rt := range m.ResponseTypes {
		if rt != responseTypeAuthorization {
			return m, ErrInvalidClientMetadata
		}
	}
	m.ResponseTypes = []string{responseTypeAuthorization}
	if slices.Contains(m.GrantTypes, GrantAuthorizationCode) && len(m.RedirectURIs) == 0 {
		return m, ErrInvalidRedirectURI
	}
	if len(m.RedirectURIs) > maxRedirectURIs || len(m.Contacts) > maxContacts {
		return m, ErrInvalidClientMetadata
	}
	switch m.ApplicationType {
	case "", appTypeWeb, appTypeNative:
	default:
		return m, ErrInvalidClientMetadata
	}
	for _, u := range m.RedirectURIs {
		if !validRedirectFor(m.ApplicationType, u) {
			return m, ErrInvalidRedirectURI
		}
	}
	if len(m.PostLogoutRedirectURIs) > maxRedirectURIs {
		return m, ErrInvalidClientMetadata
	}
	for _, u := range m.PostLogoutRedirectURIs {
		if !validRedirectFor(m.ApplicationType, u) {
			return m, ErrInvalidRedirectURI
		}
	}
	if err := p.checkSubjectType(m); err != nil {
		return m, err
	}
	if m.BackchannelLogoutURI != "" && !validBackchannelURI(m.BackchannelLogoutURI) {
		return m, ErrInvalidClientMetadata
	}
	if err := p.checkClientKeys(m); err != nil {
		return m, err
	}
	switch {
	case m.AuthMethod == AuthMethodPrivateKeyJWT:
		if len(m.JWKS) == 0 && m.JWKSURI == "" {
			return m, ErrInvalidClientMetadata
		}
	case p.isExtensionMethod(m.AuthMethod):
		// An extension method may verify with the client's keys.
	case len(m.JWKS) > 0 || m.JWKSURI != "":
		// A key set nothing would use is a key set nobody rotates.
		return m, ErrInvalidClientMetadata
	}
	for _, u := range []string{m.ClientURI, m.LogoURI, m.TosURI, m.PolicyURI} {
		if u != "" && !validWebURL(u) {
			return m, ErrInvalidClientMetadata
		}
	}
	for _, c := range m.Contacts {
		if c == "" || strings.ContainsAny(c, " \t\n") {
			return m, ErrInvalidClientMetadata
		}
	}
	scopes := strings.Fields(m.Scope)
	for _, s := range scopes {
		if !slices.Contains(p.scopes, s) {
			return m, ErrInvalidScope
		}
	}
	m.Scope = strings.Join(scopes, listSeparator)
	return m, nil
}

// validRedirectURI accepts an absolute URL with no fragment and no user
// information that is https, http on a loopback host (RFC 8252 section 7.3),
// or a private-use scheme in reverse-domain form such as com.example.app:/cb
// (RFC 8252 section 7.1). Matching is exact later, so no wildcard is ever
// accepted here.
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil || u.Scheme == "" {
		return false
	}
	switch u.Scheme {
	case schemeHTTPS:
		return u.Host != ""
	case schemeHTTP:
		return isLoopback(u.Hostname())
	}
	// A private-use scheme: reverse-domain, so it names its owner.
	return strings.Contains(u.Scheme, ".") && !strings.EqualFold(u.Scheme, "javascript") && !strings.EqualFold(u.Scheme, "data")
}

// Application types (OpenID Connect Dynamic Client Registration).
const (
	appTypeWeb    = "web"
	appTypeNative = "native"
)

// nativeLoopbackHosts are the only hosts a native client may use over
// http, spelled exactly so.
var nativeLoopbackHosts = []string{hostLocalhost, "127.0.0.1", "[::1]"}

// validRedirectFor applies the redirect rules for an application
// type ("" is web; "any" is the union a CIMD document without a type is
// held to, which is the native rules): a web client needs https on a
// non-loopback host; a native one https on a non-loopback host, http on an
// exact loopback host, or a reverse-domain private-use scheme.
func validRedirectFor(appType, raw string) bool {
	if !validRedirectURI(raw) {
		return false
	}
	u, _ := url.Parse(raw) // validRedirectURI parsed it
	loopback := isLoopback(u.Hostname())
	switch u.Scheme {
	case schemeHTTPS:
		return !loopback
	case schemeHTTP:
		return appType == appTypeNative && slices.Contains(nativeLoopbackHosts, u.Host[:len(u.Host)-len(portOf(u))])
	}
	return appType == appTypeNative
}

// portOf is ":port" of a URL's host, or "".
func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return ":" + p
	}
	return ""
}

// validBackchannelURI is a back-channel logout target: an absolute https
// URL, or http on a loopback host, with no fragment or credentials, since
// the provider posts to it from the server.
func validBackchannelURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || strings.Contains(raw, "#") || u.User != nil {
		return false
	}
	return u.Scheme == schemeHTTPS || (u.Scheme == schemeHTTP && isLoopback(u.Hostname()))
}

// validWebURL accepts an absolute http(s) URL with no user information, for
// the display URLs a consent page may link to.
func validWebURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == schemeHTTPS || u.Scheme == schemeHTTP) && u.Host != "" && u.User == nil
}

func isLoopback(host string) bool {
	if host == hostLocalhost {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CreateClient registers a client from Go, with the restricted fields only
// trusted code may set. It runs outside the operation pipeline on purpose, like
// jwt.Sign: nothing a request sends reaches it.
func (p *Plugin) CreateClient(ctx context.Context, spec ClientSpec) (Registration, error) {
	return p.insertClient(ctx, spec)
}

func (p *Plugin) insertClient(ctx context.Context, spec ClientSpec) (Registration, error) {
	if len(spec.CredentialsScopes) > 0 {
		// Only createOwned turns a requested ceiling into a granted one.
		return Registration{}, ErrInvalidClientMetadata
	}
	m, err := p.checkMetadata(spec.ClientMetadata)
	if err != nil {
		return Registration{}, err
	}
	id := spec.id
	if id == "" {
		if id, err = p.newClientID(); err != nil {
			return Registration{}, err
		}
	}
	now := p.core.Now()
	public := m.AuthMethod == AuthMethodNone
	c := Client{
		RegisteredMetadata: RegisteredMetadata(m), ClientID: id, Public: public, SkipConsent: spec.SkipConsent,
		RequirePKCE: public || !spec.OptionalPKCE, IntrospectAny: spec.IntrospectAny, OwnerID: spec.OwnerID,
		CreatedAt: now, UpdatedAt: now,
	}
	c.EndSession = spec.EnableEndSession
	ccScopes, meta, err := p.restrictedColumns(spec)
	if err != nil {
		return Registration{}, err
	}
	c.ClientCredentialsScopes, c.SecretExpiresAt, c.ReferenceID, c.Metadata = spec.ClientCredentialsScopes, spec.SecretExpiresAt, spec.ReferenceID, spec.Metadata
	reg := Registration{Client: c, ClientIDIssuedAt: now.Unix()}
	if spec.SecretExpiresAt != nil {
		reg.ClientSecretExpiresAt = spec.SecretExpiresAt.Unix()
	}
	var hash *[]byte
	if !public && m.AuthMethod != AuthMethodPrivateKeyJWT && !p.isExtensionMethod(m.AuthMethod) {
		if reg.Secret, err = p.newClientSecret(); err != nil {
			return Registration{}, err
		}
		h := p.hashSecret(SecretClient, reg.Secret)
		hash = &h
	}
	sealed, err := p.sealSecret(reg.Secret)
	if err != nil {
		return Registration{}, err
	}
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableClient).Row(
		sqlb.Set(ClientIDCol, id), sqlb.Set(sqlb.Col[*[]byte](TableClient, ColSecretHash), hash), sqlb.Set(ClientSecretEnc, sealed), sqlb.Set(ClientName, m.Name),
		sqlb.Set(ClientRedirs, strings.Join(m.RedirectURIs, redirectSeparator)), sqlb.Set(ClientScopes, m.Scope),
		sqlb.Set(ClientGrants, strings.Join(m.GrantTypes, listSeparator)), sqlb.Set(ClientMethod, m.AuthMethod),
		sqlb.Set(ClientSkip, c.SkipConsent), sqlb.Set(ClientPKCE, c.RequirePKCE), sqlb.Set(ClientIntro, c.IntrospectAny),
		sqlb.Set(ClientOwner, optional(spec.OwnerID)), sqlb.Set(ClientURI, optional(m.ClientURI)), sqlb.Set(ClientLogo, optional(m.LogoURI)),
		sqlb.Set(ClientContact, optional(strings.Join(m.Contacts, listSeparator))), sqlb.Set(ClientTos, optional(m.TosURI)),
		sqlb.Set(ClientPolicy, optional(m.PolicyURI)), sqlb.Set(ClientCreated, now), sqlb.Set(ClientUpdated, now),
		sqlb.Set(ClientPostLogout, optional(strings.Join(m.PostLogoutRedirectURIs, redirectSeparator))),
		sqlb.Set(ClientEndSession, spec.EnableEndSession), sqlb.Set(ClientJWKS, optional(string(m.JWKS))), sqlb.Set(ClientJWKSURI, optional(m.JWKSURI)),
		sqlb.Set(ClientDiscovery, optional(spec.discovery)), sqlb.Set(ClientFetchedAt, spec.fetchedAt),
		sqlb.Set(ClientSubject, optional(m.SubjectType)),
		sqlb.Set(ClientBackURI, optional(m.BackchannelLogoutURI)), sqlb.Set(ClientBackSess, m.BackchannelLogoutSessionRequired),
		sqlb.Set(ClientDPoP, m.DPoPBoundAccessTokens),
		sqlb.Set(ClientAppType, optional(m.ApplicationType)), sqlb.Set(ClientCCScopes, ccScopes), sqlb.Set(ClientRefID, optional(spec.ReferenceID)),
		sqlb.Set(ClientMeta, meta), sqlb.Set(ClientSecretExp, spec.SecretExpiresAt),
		sqlb.Set(ClientSoftwareID, optional(m.SoftwareID)), sqlb.Set(ClientSoftwareVersion, optional(m.SoftwareVersion)),
		sqlb.Set(ClientSoftwareStatement, optional(m.SoftwareStatement)),
	))
	if err != nil {
		return Registration{}, err
	}
	if err := p.linkDefaults(ctx, id, m.Resources); err != nil {
		return Registration{}, err
	}
	return reg, nil
}

// SetClientDisabled pauses or resumes a client from Go. A disabled client
// fails authentication and its authorize requests; its tokens stop at
// introspection and userinfo.
func (p *Plugin) SetClientDisabled(ctx context.Context, clientID string, disabled bool) error {
	if err := p.refuseTrusted(clientID); err != nil {
		return err
	}
	var at *time.Time
	if disabled {
		now := p.core.Now()
		at = &now
	}
	n, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableClient).Set(sqlb.Set(ClientOff, at)).Where(sqlb.Eq(ClientIDCol, clientID)))
	if err == nil && n == 0 {
		return ErrClientNotFound
	}
	return err
}

// Client returns any client by id, from Go.
func (p *Plugin) Client(ctx context.Context, clientID string) (Client, error) {
	r, err := p.loadClient(ctx, clientID)
	if err != nil {
		return Client{}, err
	}
	return r.client(), nil
}

// ownedClient loads a client the caller owns; another user's client is
// ErrClientNotFound, the same as an unknown one.
func (p *Plugin) ownedClient(ctx context.Context, c *auth.Call, id string) (clientRow, error) {
	r, err := p.loadClient(ctx, id)
	if err != nil {
		return r, err
	}
	if !p.owns(ctx, c, r) {
		return clientRow{}, ErrClientNotFound
	}
	return r, nil
}

func (p *Plugin) doCreateClient(ctx context.Context, c *auth.Call, in ClientMetadata) (Registration, error) {
	return p.createOwned(ctx, c, ClientSpec{ClientMetadata: in})
}

// createOwned creates a client the signed-in user owns, within the
// per-owner cap.
func (p *Plugin) createOwned(ctx context.Context, c *auth.Call, spec ClientSpec) (Registration, error) {
	if err := p.allowed(ctx, ActionCreate, c, nil); err != nil {
		return Registration{}, err
	}
	var held int64
	if err := p.core.One(ctx, p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &held)).From(TableClient).Where(p.ownerPredicate(ctx, c))); err != nil {
		return Registration{}, err
	}
	if held >= maxClientsPerOwner {
		return Registration{}, ErrInvalidClientMetadata
	}
	if ref := p.reference(ctx, c); ref != "" {
		spec.ReferenceID = ref
	} else {
		spec.OwnerID = c.User.ID
	}
	if len(spec.CredentialsScopes) > 0 {
		if err := p.allowCCScopes(ctx, c, nil); err != nil {
			return Registration{}, err
		}
		spec.ClientCredentialsScopes, spec.CredentialsScopes = spec.CredentialsScopes, nil
	}
	return p.insertClient(ctx, spec)
}

func (p *Plugin) doRegister(ctx context.Context, c *auth.Call, in ClientMetadata) (Registration, error) {
	if len(in.CredentialsScopes) > 0 && c.User == nil {
		// A client_credentials ceiling is a privilege, and an anonymous
		// registration has nobody to grant it to.
		return Registration{}, ErrForbidden
	}
	if in.InitialAccessToken != "" {
		// A presented token is validated or refused, never
		// ignored in favour of open registration.
		if p.initialToken == nil {
			return Registration{}, ErrInvalidToken
		}
		ref, ok := p.initialToken(ctx, in.InitialAccessToken)
		if !ok {
			return Registration{}, ErrInvalidToken
		}
		spec, err := p.registrationSpec(in)
		if err != nil {
			return Registration{}, err
		}
		spec.ReferenceID = ref
		if c.User != nil {
			return p.createOwned(ctx, c, spec)
		}
		return p.insertClient(ctx, spec)
	}
	if !p.allowDCR {
		return Registration{}, ErrRegistrationClosed
	}
	spec, err := p.registrationSpec(in)
	if err != nil {
		return Registration{}, err
	}
	if c.User == nil {
		if !p.anonDCR {
			return Registration{}, ErrRegistrationClosed
		}
		return p.insertClient(ctx, spec)
	}
	return p.createOwned(ctx, c, spec)
}

// registrationSpec applies the server-owned registration policy (required
// PKCE, client secret expiration) to a dynamically registered client.
func (p *Plugin) registrationSpec(in ClientMetadata) (ClientSpec, error) {
	scope, err := p.registrationScopes(in.Scope)
	if err != nil {
		return ClientSpec{}, err
	}
	in.Scope = scope
	spec := ClientSpec{ClientMetadata: in, OptionalPKCE: p.dcrOptionalPKCE}
	spec.Metadata = extraMetadata(in.Extra)
	if in.AuthMethod != AuthMethodNone {
		var exp time.Time
		if p.dcrSecretTTL > 0 {
			exp = p.core.Now().Add(p.dcrSecretTTL)
		}
		if !p.dcrSecretAt.IsZero() && (exp.IsZero() || p.dcrSecretAt.Before(exp)) {
			exp = p.dcrSecretAt
		}
		if !exp.IsZero() {
			spec.SecretExpiresAt = &exp
		}
	}
	return spec, nil
}

func (p *Plugin) doListClients(ctx context.Context, c *auth.Call, _ struct{}) (ClientList, error) {
	if err := p.allowed(ctx, ActionList, c, nil); err != nil {
		return ClientList{}, err
	}
	var r clientRow
	out := ClientList{Clients: []Client{}}
	q := p.core.Select().Columns(r.bindings()...).From(TableClient).Where(p.ownerPredicate(ctx, c)).
		Order(sqlb.OrderBy(ClientCreated, sqlb.SortAsc), sqlb.OrderBy(ClientIDCol, sqlb.SortAsc))
	err := p.core.Each(ctx, q, func() error { out.Clients = append(out.Clients, r.client()); return nil })
	return out, err
}

func (p *Plugin) doGetClient(ctx context.Context, c *auth.Call, in ClientIDRequest) (Client, error) {
	r, err := p.ownedClient(ctx, c, in.ClientID)
	if err != nil {
		return Client{}, err
	}
	cl := r.client()
	if err := p.allowed(ctx, ActionRead, c, &cl); err != nil {
		return Client{}, err
	}
	return r.client(), nil
}

func (p *Plugin) doUpdateClient(ctx context.Context, c *auth.Call, in UpdateClientRequest) (Client, error) {
	r, err := p.ownedClient(ctx, c, in.ClientID)
	if err != nil {
		return Client{}, err
	}
	cl := r.client()
	if err := p.allowed(ctx, ActionUpdate, c, &cl); err != nil {
		return Client{}, err
	}
	if in.Metadata.AuthMethod == "" {
		in.Metadata.AuthMethod = r.c.AuthMethod
	}
	if in.Metadata.AuthMethod != r.c.AuthMethod {
		return Client{}, ErrInvalidClientMetadata
	}
	if len(in.Metadata.CredentialsScopes) > 0 {
		return Client{}, ErrInvalidClientMetadata // the update carries it as ClientCredentialsScopes
	}
	m, err := p.checkMetadata(in.Metadata)
	if err != nil {
		return Client{}, err
	}
	ccScopes := r.ccScopes
	if in.ClientCredentialsScopes != nil {
		if err := p.allowCCScopes(ctx, c, &cl); err != nil {
			return Client{}, err
		}
		if ccScopes, _, err = p.restrictedColumns(ClientSpec{ClientCredentialsScopes: *in.ClientCredentialsScopes}); err != nil {
			return Client{}, err
		}
	}
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableClient).Set(
		sqlb.Set(ClientName, m.Name), sqlb.Set(ClientRedirs, strings.Join(m.RedirectURIs, redirectSeparator)),
		sqlb.Set(ClientScopes, m.Scope), sqlb.Set(ClientGrants, strings.Join(m.GrantTypes, listSeparator)),
		sqlb.Set(ClientURI, optional(m.ClientURI)), sqlb.Set(ClientLogo, optional(m.LogoURI)),
		sqlb.Set(ClientContact, optional(strings.Join(m.Contacts, listSeparator))), sqlb.Set(ClientTos, optional(m.TosURI)),
		sqlb.Set(ClientPolicy, optional(m.PolicyURI)), sqlb.Set(ClientUpdated, now), sqlb.Set(ClientCCScopes, ccScopes),
		sqlb.Set(ClientPostLogout, optional(strings.Join(m.PostLogoutRedirectURIs, redirectSeparator))),
		sqlb.Set(ClientJWKS, optional(string(m.JWKS))), sqlb.Set(ClientJWKSURI, optional(m.JWKSURI)), sqlb.Set(ClientSubject, optional(m.SubjectType)),
		sqlb.Set(ClientBackURI, optional(m.BackchannelLogoutURI)), sqlb.Set(ClientBackSess, m.BackchannelLogoutSessionRequired),
		sqlb.Set(ClientDPoP, m.DPoPBoundAccessTokens), sqlb.Set(ClientAppType, optional(m.ApplicationType)),
	).Where(sqlb.Eq(ClientIDCol, r.c.ClientID))); err != nil {
		return Client{}, err
	}
	return p.Client(ctx, r.c.ClientID)
}

// restrictedColumns encodes the restricted fields of a spec: the
// client_credentials ceiling (no user scope, every scope one the provider
// serves) and the metadata JSON. It also refuses EnableEndSession without
// auth.WithSecret, as Validate does for a trusted client, since every
// restricted spec (CreateClient, UpdateClient, a trusted client) passes here.
func (p *Plugin) restrictedColumns(spec ClientSpec) (ccScopes, meta *string, err error) {
	if spec.EnableEndSession && !p.hasSecret {
		return nil, nil, fmt.Errorf("%w: EnableEndSession signs its logout confirmation", ErrNoSecret)
	}
	if spec.ClientCredentialsScopes != nil {
		for _, sc := range spec.ClientCredentialsScopes {
			if slices.Contains(userScopes, sc) || !slices.Contains(p.scopes, sc) {
				return nil, nil, ErrInvalidScope
			}
		}
		j := strings.Join(spec.ClientCredentialsScopes, listSeparator)
		ccScopes = &j
	}
	if len(spec.Metadata) > 0 {
		if !json.Valid(spec.Metadata) {
			return nil, nil, ErrInvalidClientMetadata
		}
		j := string(spec.Metadata)
		meta = &j
	}
	return ccScopes, meta, nil
}

// UpdateClient replaces any client's metadata and restricted fields from
// Go. The authentication method cannot change, as for an owner.
func (p *Plugin) UpdateClient(ctx context.Context, clientID string, spec ClientSpec) (Client, error) {
	if err := p.refuseTrusted(clientID); err != nil {
		return Client{}, err
	}
	r, err := p.loadClient(ctx, clientID)
	if err != nil {
		return Client{}, err
	}
	if spec.AuthMethod == "" {
		spec.AuthMethod = r.c.AuthMethod
	}
	if spec.AuthMethod != r.c.AuthMethod {
		return Client{}, ErrInvalidClientMetadata
	}
	m, err := p.checkMetadata(spec.ClientMetadata)
	if err != nil {
		return Client{}, err
	}
	public := m.AuthMethod == AuthMethodNone
	ccScopes, meta, err := p.restrictedColumns(spec)
	if err != nil {
		return Client{}, err
	}
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableClient).Set(
		sqlb.Set(ClientName, m.Name), sqlb.Set(ClientRedirs, strings.Join(m.RedirectURIs, redirectSeparator)),
		sqlb.Set(ClientScopes, m.Scope), sqlb.Set(ClientGrants, strings.Join(m.GrantTypes, listSeparator)),
		sqlb.Set(ClientURI, optional(m.ClientURI)), sqlb.Set(ClientLogo, optional(m.LogoURI)),
		sqlb.Set(ClientContact, optional(strings.Join(m.Contacts, listSeparator))), sqlb.Set(ClientTos, optional(m.TosURI)),
		sqlb.Set(ClientPolicy, optional(m.PolicyURI)), sqlb.Set(ClientUpdated, p.core.Now()),
		sqlb.Set(ClientPostLogout, optional(strings.Join(m.PostLogoutRedirectURIs, redirectSeparator))),
		sqlb.Set(ClientJWKS, optional(string(m.JWKS))), sqlb.Set(ClientJWKSURI, optional(m.JWKSURI)), sqlb.Set(ClientSkip, spec.SkipConsent),
		sqlb.Set(ClientPKCE, public || !spec.OptionalPKCE), sqlb.Set(ClientIntro, spec.IntrospectAny),
		sqlb.Set(ClientEndSession, spec.EnableEndSession), sqlb.Set(ClientOwner, optional(spec.OwnerID)),
		sqlb.Set(ClientSubject, optional(m.SubjectType)),
		sqlb.Set(ClientBackURI, optional(m.BackchannelLogoutURI)), sqlb.Set(ClientBackSess, m.BackchannelLogoutSessionRequired),
		sqlb.Set(ClientDPoP, m.DPoPBoundAccessTokens), sqlb.Set(ClientAppType, optional(m.ApplicationType)),
		sqlb.Set(ClientCCScopes, ccScopes), sqlb.Set(ClientRefID, optional(spec.ReferenceID)), sqlb.Set(ClientMeta, meta),
		sqlb.Set(ClientSecretExp, spec.SecretExpiresAt),
	).Where(sqlb.Eq(ClientIDCol, clientID))); err != nil {
		return Client{}, err
	}
	return p.Client(ctx, clientID)
}

// doRotateSecret replaces a confidential client's secret at once; the old
// one stops working immediately.
func (p *Plugin) doRotateSecret(ctx context.Context, c *auth.Call, in ClientIDRequest) (Registration, error) {
	r, err := p.ownedClient(ctx, c, in.ClientID)
	if err != nil {
		return Registration{}, err
	}
	cl := r.client()
	if err := p.allowed(ctx, ActionRotate, c, &cl); err != nil {
		return Registration{}, err
	}
	if r.c.AuthMethod == AuthMethodNone || p.isExtensionMethod(r.c.AuthMethod) {
		return Registration{}, ErrInvalidClientMetadata
	}
	secret, err := p.newClientSecret()
	if err != nil {
		return Registration{}, err
	}
	sealed, err := p.sealSecret(secret)
	if err != nil {
		return Registration{}, err
	}
	now := p.core.Now()
	if _, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableClient).Set(
		sqlb.Set(ClientSecret, p.hashSecret(SecretClient, secret)), sqlb.Set(ClientSecretEnc, sealed), sqlb.Set(ClientUpdated, now),
	).Where(sqlb.Eq(ClientIDCol, r.c.ClientID))); err != nil {
		return Registration{}, err
	}
	cl = r.client()
	cl.UpdatedAt = now
	return Registration{Client: cl, Secret: secret, ClientIDIssuedAt: cl.CreatedAt.Unix()}, nil
}

// doDeleteClient deletes an owned client with its codes, tokens and
// consents.
func (p *Plugin) doDeleteClient(ctx context.Context, c *auth.Call, in ClientIDRequest) (auth.Done, error) {
	r, err := p.ownedClient(ctx, c, in.ClientID)
	if err != nil {
		return auth.Done{}, err
	}
	cl := r.client()
	if err := p.allowed(ctx, ActionDelete, c, &cl); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.DeleteClient(ctx, r.c.ClientID)
}

// DeleteClient deletes any client from Go, with its codes, tokens and
// consents.
func (p *Plugin) DeleteClient(ctx context.Context, clientID string) error {
	if err := p.refuseTrusted(clientID); err != nil {
		return err
	}
	d := p.core.Dialect()
	for _, st := range []auth.Statement{
		sqlb.NewDelete(d).From(TableCode).Where(sqlb.Eq(CodeClient, clientID)),
		sqlb.NewDelete(d).From(TableToken).Where(sqlb.Eq(TokenClient, clientID)),
		sqlb.NewDelete(d).From(TableConsent).Where(sqlb.Eq(ConsentClient, clientID)),
		sqlb.NewDelete(d).From(TableClientResource).Where(sqlb.Eq(LinkClient, clientID)),
	} {
		if _, err := p.core.Exec(ctx, st); err != nil {
			return err
		}
	}
	n, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableClient).Where(sqlb.Eq(ClientIDCol, clientID)))
	if err == nil && n == 0 {
		return ErrClientNotFound
	}
	return err
}

func (p *Plugin) doPublicClient(ctx context.Context, _ *auth.Call, in ClientIDRequest) (PublicClient, error) {
	r, err := p.loadClient(ctx, in.ClientID)
	if err != nil {
		return PublicClient{}, err
	}
	if r.disabledAt != nil {
		return PublicClient{}, ErrClientNotFound
	}
	cl := r.client()
	return PublicClient{ClientID: cl.ClientID, Name: cl.Name, ClientURI: cl.ClientURI, LogoURI: cl.LogoURI, TosURI: cl.TosURI, PolicyURI: cl.PolicyURI, Contacts: cl.Contacts}, nil
}

// ClientCredentials is how a request authenticated its client at the token,
// revocation and introspection endpoints. Handler fills it from the
// Authorization header or the form; a Go caller fills it directly.
type ClientCredentials struct {
	// ID and Secret are the client_id and client_secret.
	ID     string `json:"client_id"`
	Secret string `json:"client_secret"`
	// Method is how they arrived: AuthMethodBasic for the Authorization
	// header, AuthMethodPost for the form, AuthMethodNone for a client_id
	// alone. Handler sets it; it must match the client's registered method.
	Method string `json:"client_auth_method"`
	// Assertion is a private_key_jwt client assertion (Method
	// AuthMethodPrivateKeyJWT), or an extension method's.
	Assertion string `json:"client_assertion"`
	// AssertionType is the client_assertion_type of an extension method's
	// assertion; "" for private_key_jwt.
	AssertionType string `json:"client_assertion_type,omitempty"`
	// Certificates are the TLS client certificates of the connection, for
	// a mutual-TLS ClientAuthMethod. Handler fills them.
	Certificates []*x509.Certificate `json:"-"`
}

// dummySecret is hashed and compared against when the client is unknown or
// public, so a wrong client_id costs the same time as a wrong secret.
const dummySecret = PrefixClientSecret + "dummy"

// authenticateClient checks a client's credentials: the client exists and
// is enabled, it used its registered method, and a confidential client's
// secret matches in constant time. Every failure is ErrInvalidClient, so the
// answer does not say which part was wrong.
func (p *Plugin) authenticateClient(ctx context.Context, cred ClientCredentials, audience string) (clientRow, error) {
	r, err := p.resolveClient(ctx, cred.ID)
	if err != nil && !errors.Is(err, ErrClientNotFound) {
		return r, err
	}
	stored := p.hashSecret(SecretClient, dummySecret)
	if err == nil && r.secretHash != nil {
		stored = r.secretHash
	}
	given := p.hashSecret(SecretClient, cred.Secret)
	match := subtle.ConstantTimeCompare(given, stored) == 1
	if err == nil && r.disabledAt == nil {
		if m, ok := p.authMethod(r.c.AuthMethod); ok {
			return p.authenticateExtension(ctx, m, r, cred)
		}
	}
	switch {
	case err != nil, r.disabledAt != nil:
		return clientRow{}, ErrInvalidClient
	case cred.AssertionType != "":
		// An extension's assertion presented for a client registered with
		// another method.
		return clientRow{}, ErrInvalidClient
	case r.c.AuthMethod == AuthMethodNone:
		if cred.Secret != "" || cred.Assertion != "" || (cred.Method != AuthMethodNone && cred.Method != "") {
			return clientRow{}, ErrInvalidClient
		}
	case r.c.AuthMethod == AuthMethodPrivateKeyJWT:
		if cred.Method != AuthMethodPrivateKeyJWT || cred.Secret != "" {
			return clientRow{}, ErrInvalidClient
		}
		if err := p.verifyAssertion(ctx, r, cred.Assertion, audience); err != nil {
			return clientRow{}, err
		}
	case cred.Method != r.c.AuthMethod || !match:
		return clientRow{}, ErrInvalidClient
	case r.secretExpires != nil && !p.core.Now().Before(*r.secretExpires):
		// An expired secret authenticates nothing, as an unknown one.
		return clientRow{}, ErrInvalidClient
	}
	return r, nil
}

// metadataNames are the registration members the provider defines or owns:
// every json name of ClientMetadata and of the Registration answer, plus
// the removed type and public.
var metadataNames = append(jsonNames(reflect.TypeFor[Registration]()), "type", "public", "metadata", "registration_access_token", "registration_client_uri")

// jsonNames lists a struct's json names, through embedded structs.
func jsonNames(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			out = append(out, jsonNames(f.Type)...)
			continue
		}
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			out = append(out, name)
		}
	}
	return out
}

// unknownMembers keeps the members of a registration body the provider
// does not define.
func unknownMembers(members map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range members {
		if !slices.Contains(metadataNames, k) {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// extraMetadata is the Metadata JSON of a registration's extra members,
// without the reserved names; nil when none is left.
func extraMetadata(extra map[string]any) json.RawMessage {
	b, err := json.Marshal(unknownMembers(extra))
	if err != nil || string(b) == "null" {
		return nil
	}
	return b
}
