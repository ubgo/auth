package sso

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
)

// Protocol is how a provider signs people in.
type Protocol string

const (
	// ProtocolOIDC is OpenID Connect, authorization code with PKCE.
	ProtocolOIDC Protocol = "oidc"
	// ProtocolSAML is SAML 2.0 Web Browser SSO, this app as the SP.
	ProtocolSAML Protocol = "saml"
)

// ProtocolValues is every Protocol.
var ProtocolValues = []Protocol{ProtocolOIDC, ProtocolSAML}

// Provider is one registered identity provider: a row of auth_sso_provider,
// or a WithDefaultProviders entry. A provider may offer OIDC, SAML or both.
//
// Multi-shape fields: OIDC and SAML are each nil when the provider does not
// offer that protocol; at least one is set. Domain is one domain or a
// comma-separated list. UserID is who registered it ("" for a default
// provider); OrganizationID is "" for a provider not tied to one.
type Provider struct {
	// ID is the row id; "" for a default provider.
	ID string `json:"-"`
	// ProviderID is the app-chosen permanent name, unique across the app.
	ProviderID     string      `json:"providerId"`
	Issuer         string      `json:"issuer"`
	Domain         string      `json:"domain"`
	OrganizationID string      `json:"organizationId,omitempty"`
	UserID         string      `json:"userId,omitempty"`
	OIDC           *OIDCConfig `json:"oidcConfig,omitempty"`
	SAML           *SAMLConfig `json:"samlConfig,omitempty"`
	// DomainVerified is set once the domain's DNS record was found
	// (WithDomainVerification); a default provider counts as verified.
	DomainVerified bool      `json:"domainVerified"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	// DomainToken is the pending domain-verification token and
	// DomainTokenExpiresAt its expiry; "" and nil when none is pending.
	DomainToken string `json:"-"`
	// Fields are the WithProviderFields values.
	Fields               map[string]any `json:"additionalFields,omitempty"`
	DomainTokenExpiresAt *time.Time     `json:"-"`
	// Default marks a WithDefaultProviders entry: code, not a row.
	Default bool `json:"-"`
}

// OIDCConfig is an OpenID Connect provider's settings. Every endpoint left
// empty is filled from the issuer's discovery document at registration
// (and again at sign-in if still missing); a value set here wins.
type OIDCConfig struct {
	ClientID string `json:"clientId"`
	// ClientSecret is required unless TokenEndpointAuthentication is
	// private_key_jwt or none. Stored sealed; never returned by a read.
	ClientSecret          string `json:"clientSecret,omitempty"`
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint      string `json:"userInfoEndpoint,omitempty"`
	JWKSEndpoint          string `json:"jwksEndpoint,omitempty"`
	// DiscoveryEndpoint defaults to <issuer>/.well-known/openid-configuration.
	DiscoveryEndpoint string `json:"discoveryEndpoint,omitempty"`
	// SkipDiscovery never fetches the discovery document: the endpoints
	// above must all be given (JWKS included, since the ID token is
	// verified).
	SkipDiscovery bool `json:"skipDiscovery,omitempty"`
	// TokenEndpointAuthentication is client_secret_basic,
	// client_secret_post, private_key_jwt or none; empty takes the best
	// method the discovery document lists (basic, then post, then
	// private_key_jwt), and client_secret_basic without discovery.
	TokenEndpointAuthentication oauth.TokenAuth `json:"tokenEndpointAuthentication,omitempty"`
	// PrivateKeyID and PrivateKeyAlgorithm are handed to the
	// WithPrivateKeyResolver function for private_key_jwt; the key itself
	// never lives in the row.
	PrivateKeyID        string `json:"privateKeyId,omitempty"`
	PrivateKeyAlgorithm string `json:"privateKeyAlgorithm,omitempty"`
	// Scopes default to openid email profile offline_access.
	Scopes []string `json:"scopes,omitempty"`
	// PKCE defaults to true; false only for an IdP that refuses it.
	PKCE *bool `json:"pkce,omitempty"`
	// OverrideUserInfo copies the IdP's name and image onto the user at
	// every sign-in, not only at creation.
	OverrideUserInfo bool        `json:"overrideUserInfo,omitempty"`
	Mapping          OIDCMapping `json:"mapping,omitempty"`
	// AllowIdPInitiated answers a callback with a code and no state (an
	// IdP dashboard tile) by starting a fresh flow with new state and PKCE;
	// the code it carried is never redeemed.
	AllowIdPInitiated bool `json:"allowIdpInitiated,omitempty"`
}

// OIDCMapping names the claims read for each profile field; an empty name
// takes the standard claim (sub, email, email_verified, name, picture).
type OIDCMapping struct {
	ID            string `json:"id,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified string `json:"emailVerified,omitempty"`
	Name          string `json:"name,omitempty"`
	Image         string `json:"image,omitempty"`
	// ExtraFields copies claims into UserInfo.Extra, keyed by the map's
	// key: {"department": "dept"}.
	ExtraFields map[string]string `json:"extraFields,omitempty"`
}

// defaultOIDCScopes is better-auth's default scope set.
var defaultOIDCScopes = []string{"openid", "email", "profile", "offline_access"}

// Domains returns the provider's domains, lower-cased and trimmed, empty
// entries dropped.
func (p Provider) Domains() []string { return splitDomains(p.Domain) }

// splitDomains parses a comma-separated domain list.
func splitDomains(s string) []string {
	var out []string
	for _, d := range strings.Split(s, domainListSep) {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// Protocols lists what the provider offers, OIDC first.
func (p Provider) Protocols() []Protocol {
	var out []Protocol
	if p.OIDC != nil {
		out = append(out, ProtocolOIDC)
	}
	if p.SAML != nil {
		out = append(out, ProtocolSAML)
	}
	return out
}

// Reference is the provider's fingerprint: the SHA-256 of its
// authentication boundary (issuer, endpoints, client id, SAML entity ids,
// certificates), secrets left out. A flow carries it from start to callback
// and is refused when it changed in between, so an admin who repoints a
// provider mid-flow cannot have a response from the old IdP accepted under
// the new configuration.
func (p Provider) Reference() string {
	b := struct {
		ID, Issuer string
		OIDC       []string
		SAML       []string
	}{ID: p.ProviderID, Issuer: p.Issuer}
	if o := p.OIDC; o != nil {
		b.OIDC = []string{o.ClientID, o.AuthorizationEndpoint, o.TokenEndpoint, o.UserInfoEndpoint, o.JWKSEndpoint, o.DiscoveryEndpoint}
	}
	if s := p.SAML; s != nil {
		b.SAML = []string{s.EntryPoint, s.Audience, s.IdPMetadata.EntityID, s.IdPMetadata.Metadata, s.Cert, s.IdPMetadata.Cert, s.SPMetadata.EntityID, s.SPMetadata.Metadata, s.IdentifierFormat}
	}
	raw, _ := json.Marshal(b) // a struct of strings always marshals
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// boundaryChanged reports whether next changes an authentication-boundary
// field of prev: anything Reference covers.
func boundaryChanged(prev, next Provider) bool { return prev.Reference() != next.Reference() }

// SanitizedProvider is what a read returns: no secret, the client id cut to
// its last four characters.
type SanitizedProvider struct {
	ProviderID     string         `json:"providerId"`
	Type           Protocol       `json:"type"`
	Protocols      []Protocol     `json:"protocols"`
	Issuer         string         `json:"issuer"`
	Domain         string         `json:"domain"`
	OrganizationID string         `json:"organizationId,omitempty"`
	DomainVerified bool           `json:"domainVerified"`
	OIDC           *SanitizedOIDC `json:"oidcConfig,omitempty"`
	SAML           *SanitizedSAML `json:"samlConfig,omitempty"`
	// AdditionalFields are the WithProviderFields values.
	AdditionalFields map[string]any `json:"additionalFields,omitempty"`
	// RedirectURI is the OIDC redirect URI to register at the IdP.
	RedirectURI string `json:"redirectURI,omitempty"`
	// ACSURL and SPMetadataURL are what to enter at a SAML IdP.
	ACSURL        string `json:"acsURL,omitempty"`
	SPMetadataURL string `json:"spMetadataURL,omitempty"`
}

// SanitizedOIDC is an OIDCConfig without its secret.
type SanitizedOIDC struct {
	DiscoveryEndpoint           string          `json:"discoveryEndpoint,omitempty"`
	ClientIDLastFour            string          `json:"clientIdLastFour"`
	PKCE                        bool            `json:"pkce"`
	AuthorizationEndpoint       string          `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint               string          `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint            string          `json:"userInfoEndpoint,omitempty"`
	JWKSEndpoint                string          `json:"jwksEndpoint,omitempty"`
	Scopes                      []string        `json:"scopes,omitempty"`
	TokenEndpointAuthentication oauth.TokenAuth `json:"tokenEndpointAuthentication,omitempty"`
}

// SanitizedSAML is a SAMLConfig without its keys.
type SanitizedSAML struct {
	EntryPoint           string `json:"entryPoint,omitempty"`
	CallbackURL          string `json:"callbackUrl,omitempty"`
	Audience             string `json:"audience,omitempty"`
	IdPEntityID          string `json:"idpEntityId,omitempty"`
	SPEntityID           string `json:"spEntityId,omitempty"`
	WantAssertionsSigned bool   `json:"wantAssertionsSigned"`
	AuthnRequestsSigned  bool   `json:"authnRequestsSigned"`
	IdentifierFormat     string `json:"identifierFormat,omitempty"`
	// CertificatesCount is how many IdP signing certificates are on file.
	CertificatesCount int `json:"certificatesCount"`
}

// lastFour returns the last four characters of s, or s when shorter.
func lastFour(s string) string {
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}

// pkceOn reads the PKCE switch, default on.
func (o OIDCConfig) pkceOn() bool { return o.PKCE == nil || *o.PKCE }

// scopes returns the configured scopes or the default set.
func (o OIDCConfig) scopes() []string {
	if len(o.Scopes) > 0 {
		return slices.Clone(o.Scopes)
	}
	return slices.Clone(defaultOIDCScopes)
}

// storedOIDC is the JSON written to oidc_config: the config without its
// plaintext secret, plus the sealed one.
type storedOIDC struct {
	OIDCConfig
	SealedSecret string `json:"clientSecretSealed,omitempty"`
}

// storedSAML is the JSON written to saml_config, keys sealed the same way.
type storedSAML struct {
	SAMLConfig
	SealedPrivateKey    string `json:"privateKeySealed,omitempty"`
	SealedDecryptionKey string `json:"decryptionKeySealed,omitempty"`
}

// providerRow is a scanned row before its JSON is opened.
type providerRow struct {
	id, providerID, issuer, domain, orgID, userID, oidc, saml string
	verified                                                  bool
	created, updated                                          time.Time
	domainToken                                               string
	domainTokenExp                                            *time.Time
	fields                                                    *string
}

func providerBindings(r *providerRow) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(ProviderRowID, &r.id), sqlb.Bind(ProviderProviderID, &r.providerID), sqlb.Bind(ProviderIssuer, &r.issuer),
		sqlb.Bind(ProviderDomain, &r.domain), sqlb.Bind(ProviderOrganizationID, &r.orgID), sqlb.Bind(ProviderUserID, &r.userID),
		sqlb.Bind(ProviderOIDCConfig, &r.oidc), sqlb.Bind(ProviderSAMLConfig, &r.saml), sqlb.Bind(ProviderDomainVerified, &r.verified),
		sqlb.Bind(ProviderCreatedAt, &r.created), sqlb.Bind(ProviderUpdatedAt, &r.updated),
		sqlb.Bind(ProviderDomainToken, &r.domainToken), sqlb.Bind(ProviderDomainTokenExp, &r.domainTokenExp), sqlb.Bind(ProviderFields, &r.fields),
	}
}

// open turns a row into a Provider, opening the sealed secrets.
func (p *Plugin) open(r providerRow) (Provider, error) {
	out := Provider{ID: r.id, ProviderID: r.providerID, Issuer: r.issuer, Domain: r.domain, OrganizationID: r.orgID,
		UserID: r.userID, DomainVerified: r.verified, CreatedAt: r.created, UpdatedAt: r.updated,
		DomainToken: r.domainToken, DomainTokenExpiresAt: r.domainTokenExp}
	if r.fields != nil {
		if err := json.Unmarshal([]byte(*r.fields), &out.Fields); err != nil {
			return Provider{}, fmt.Errorf("sso: provider %q fields: %w", r.providerID, err)
		}
	}
	if r.oidc != "" {
		var s storedOIDC
		if err := json.Unmarshal([]byte(r.oidc), &s); err != nil {
			return Provider{}, fmt.Errorf("sso: provider %q oidc_config: %w", r.providerID, err)
		}
		if s.SealedSecret != "" {
			plain, err := p.ring.Open(s.SealedSecret, r.providerID)
			if err != nil {
				return Provider{}, fmt.Errorf("sso: provider %q client secret: %w", r.providerID, err)
			}
			s.ClientSecret = string(plain)
		}
		cfg := s.OIDCConfig
		out.OIDC = &cfg
	}
	if r.saml != "" {
		var s storedSAML
		if err := json.Unmarshal([]byte(r.saml), &s); err != nil {
			return Provider{}, fmt.Errorf("sso: provider %q saml_config: %w", r.providerID, err)
		}
		for _, k := range []struct {
			sealed string
			dst    *string
		}{{s.SealedPrivateKey, &s.PrivateKey}, {s.SealedDecryptionKey, &s.DecryptionKey}} {
			if k.sealed == "" {
				continue
			}
			plain, err := p.ring.Open(k.sealed, r.providerID)
			if err != nil {
				return Provider{}, fmt.Errorf("sso: provider %q saml key: %w", r.providerID, err)
			}
			*k.dst = string(plain)
		}
		cfg := s.SAMLConfig
		out.SAML = &cfg
	}
	return out, nil
}

// seal returns the JSON columns of pr, secrets sealed under its provider id.
// Both configs hold only strings, bools, string slices and string maps, so
// json.Marshal cannot fail on them.
func (p *Plugin) seal(pr Provider) (oidcJSON, samlJSON string) {
	if pr.OIDC != nil {
		s := storedOIDC{OIDCConfig: *pr.OIDC}
		if s.ClientSecret != "" {
			s.SealedSecret = p.ring.Seal([]byte(s.ClientSecret), pr.ProviderID)
			s.ClientSecret = ""
		}
		b, _ := json.Marshal(s) // a struct of strings, bools, slices and string maps always marshals
		oidcJSON = string(b)
	}
	if pr.SAML != nil {
		s := storedSAML{SAMLConfig: *pr.SAML}
		if s.PrivateKey != "" {
			s.SealedPrivateKey = p.ring.Seal([]byte(s.PrivateKey), pr.ProviderID)
			s.PrivateKey = ""
		}
		if s.DecryptionKey != "" {
			s.SealedDecryptionKey = p.ring.Seal([]byte(s.DecryptionKey), pr.ProviderID)
			s.DecryptionKey = ""
		}
		b, _ := json.Marshal(s) // as above
		samlJSON = string(b)
	}
	return oidcJSON, samlJSON
}

// errNoProvider is the internal not-found, mapped to ErrProviderNotFound at
// the operation boundary.
var errNoProvider = errors.New("sso: no provider")

// ProviderByID returns a provider by its provider id: a default provider
// first, then a row. Not found is ErrProviderNotFound.
func (p *Plugin) ProviderByID(ctx context.Context, providerID string) (Provider, error) {
	for _, d := range p.defaults {
		if d.ProviderID == providerID {
			return d, nil
		}
	}
	var r providerRow
	err := p.core.One(ctx, p.core.Select().Columns(providerBindings(&r)...).From(TableProvider).
		Where(sqlb.Eq(ProviderProviderID, providerID)).Limit(1))
	if errors.Is(err, sqlb.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, err
	}
	return p.open(r)
}

// providersWhere lists stored providers matching preds, oldest first.
func (p *Plugin) providersWhere(ctx context.Context, preds ...sqlb.Predicate) ([]Provider, error) {
	var r providerRow
	var out []Provider
	q := p.core.Select().Columns(providerBindings(&r)...).From(TableProvider)
	if len(preds) > 0 {
		q = q.Where(preds...)
	}
	err := p.core.Each(ctx, q.Order(sqlb.OrderBy(ProviderCreatedAt, sqlb.SortAsc), sqlb.OrderBy(ProviderRowID, sqlb.SortAsc)), func() error {
		pr, err := p.open(r)
		if err != nil {
			return err
		}
		out = append(out, pr)
		return nil
	})
	return out, err
}

// insertProvider writes a new row. A taken provider id is ErrProviderExists.
func (p *Plugin) insertProvider(ctx context.Context, pr *Provider) error {
	id, err := p.core.NewID(idPrefixProvider)
	if err != nil {
		return err
	}
	oidcJSON, samlJSON := p.seal(*pr)
	fields, err := encodeFields(pr.Fields)
	if err != nil {
		return err
	}
	now := p.core.Now()
	pr.ID, pr.CreatedAt, pr.UpdatedAt = id, now, now
	_, err = p.core.Exec(ctx, sqlb.NewInsert(p.core.Dialect()).Into(TableProvider).Row(
		sqlb.Set(ProviderRowID, id), sqlb.Set(ProviderProviderID, pr.ProviderID), sqlb.Set(ProviderIssuer, pr.Issuer),
		sqlb.Set(ProviderDomain, pr.Domain), sqlb.Set(ProviderOrganizationID, pr.OrganizationID), sqlb.Set(ProviderUserID, pr.UserID),
		sqlb.Set(ProviderOIDCConfig, oidcJSON), sqlb.Set(ProviderSAMLConfig, samlJSON), sqlb.Set(ProviderDomainVerified, pr.DomainVerified),
		sqlb.Set(ProviderCreatedAt, now), sqlb.Set(ProviderUpdatedAt, now), sqlb.Set(ProviderFields, fields),
	))
	if auth.IsUniqueViolation(err) {
		return ErrProviderExists
	}
	return err
}

// updateProvider rewrites a row's mutable columns.
func (p *Plugin) updateProvider(ctx context.Context, pr *Provider) error {
	oidcJSON, samlJSON := p.seal(*pr)
	fields, err := encodeFields(pr.Fields)
	if err != nil {
		return err
	}
	pr.UpdatedAt = p.core.Now()
	_, err = p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableProvider).Set(
		sqlb.Set(ProviderFields, fields), sqlb.Set(ProviderIssuer, pr.Issuer), sqlb.Set(ProviderDomain, pr.Domain), sqlb.Set(ProviderOIDCConfig, oidcJSON),
		sqlb.Set(ProviderSAMLConfig, samlJSON), sqlb.Set(ProviderDomainVerified, pr.DomainVerified), sqlb.Set(ProviderUpdatedAt, pr.UpdatedAt),
	).Where(sqlb.Eq(ProviderRowID, pr.ID)))
	return err
}

// setDomainVerified marks a stored provider's domain verified and spends
// its token.
func (p *Plugin) setDomainVerified(ctx context.Context, id string) error {
	var none *time.Time
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableProvider).Set(
		sqlb.Set(ProviderDomainVerified, true), sqlb.Set(ProviderDomainToken, ""), sqlb.Set(ProviderDomainTokenExp, none),
		sqlb.Set(ProviderUpdatedAt, p.core.Now()),
	).Where(sqlb.Eq(ProviderRowID, id)))
	return err
}

// setDomainToken stores a pending domain-verification token.
func (p *Plugin) setDomainToken(ctx context.Context, id, tok string, exp *time.Time) error {
	_, err := p.core.Exec(ctx, sqlb.NewUpdate(p.core.Dialect()).Table(TableProvider).Set(
		sqlb.Set(ProviderDomainToken, tok), sqlb.Set(ProviderDomainTokenExp, exp),
	).Where(sqlb.Eq(ProviderRowID, id)))
	return err
}

// sanitize builds the read view of pr.
func (p *Plugin) sanitize(pr Provider) SanitizedProvider {
	out := SanitizedProvider{ProviderID: pr.ProviderID, Protocols: pr.Protocols(), Issuer: pr.Issuer, Domain: pr.Domain,
		OrganizationID: pr.OrganizationID, DomainVerified: pr.DomainVerified || pr.Default, AdditionalFields: pr.Fields}
	if len(out.Protocols) > 0 {
		out.Type = out.Protocols[0]
	}
	if o := pr.OIDC; o != nil {
		out.OIDC = &SanitizedOIDC{DiscoveryEndpoint: o.DiscoveryEndpoint, ClientIDLastFour: lastFour(o.ClientID), PKCE: o.pkceOn(),
			AuthorizationEndpoint: o.AuthorizationEndpoint, TokenEndpoint: o.TokenEndpoint, UserInfoEndpoint: o.UserInfoEndpoint,
			JWKSEndpoint: o.JWKSEndpoint, Scopes: o.scopes(), TokenEndpointAuthentication: o.TokenEndpointAuthentication}
		out.RedirectURI = p.callbackURLFor(pr.ProviderID)
	}
	if s := pr.SAML; s != nil {
		certs, _ := parseCerts(s.certPEM()) // a stored provider's certificates were checked at registration
		out.SAML = &SanitizedSAML{EntryPoint: s.EntryPoint, CallbackURL: s.CallbackURL, Audience: s.Audience,
			IdPEntityID: s.IdPMetadata.EntityID, SPEntityID: s.spEntityID(pr), WantAssertionsSigned: s.WantAssertionsSigned,
			AuthnRequestsSigned: s.AuthnRequestsSigned, IdentifierFormat: s.IdentifierFormat, CertificatesCount: len(certs)}
		out.ACSURL, out.SPMetadataURL = p.acsURLFor(pr.ProviderID), p.metadataURL(pr.ProviderID)
	}
	return out
}
