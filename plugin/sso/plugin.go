package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
	"github.com/ubgo/sqlb"
)

// Plugin is the sso plugin. Build it with New.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs auth.OptionErrors
	core    *auth.Auth
	ring    *auth.KeyRing
	hc      *http.Client
	// hcSet is WithHTTPClient: the app's client replaces the guarded one.
	hcSet    bool
	trusted  []string
	defaults []Provider
	limit    func(ctx context.Context, u auth.User) int
	callback string
	acs      string
	errorURL string
	stateTTL time.Duration
	reserved []string

	keys               PrivateKeyResolver
	trustEmailVerified bool
	noImplicitSignUp   bool
	overrideUserInfo   bool
	trustedProviders   []string
	provision          ProvisionFunc
	provisionEvery     bool
	resolveUser        ResolveUserFunc
	orgs               Organizations
	orgProvisioning    OrganizationProvisioning
	guard              MutationGuard

	saml   SAMLOptions
	engine SAMLEngine

	domain   *DomainVerification
	metaBase string
	slo      string
	fields   []ProviderField
	// onlyTrusted is RequireTrustedOrigins.
	onlyTrusted bool
	// providerPaths is PerProviderPaths.
	providerPaths bool

	register    *auth.Op[RegisterRequest, RegisterResult]
	signIn      *auth.Op[SignInRequest, SignInResult]
	callbackOp  *auth.Op[CallbackRequest, CallbackResult]
	list        *auth.Op[struct{}, ProvidersResult]
	get         *auth.Op[ProviderRequest, SanitizedProvider]
	update      *auth.Op[UpdateRequest, SanitizedProvider]
	del         *auth.Op[ProviderRequest, auth.Done]
	metadata    *auth.Op[ProviderRequest, MetadataResult]
	acsOp       *auth.Op[ACSRequest, CallbackResult]
	logout      *auth.Op[LogoutRequest, LogoutResult]
	sloGet      *auth.Op[SLORequest, LogoutResult]
	sloPost     *auth.Op[SLORequest, LogoutResult]
	reqDomain   *auth.Op[ProviderRequest, DomainTokenResult]
	verifDomain *auth.Op[ProviderRequest, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin.
type Option func(*Plugin)

// WithDefaultProviders adds providers defined in code: matched by provider id
// or domain before any row, never stored, never editable through the API, and
// treated as domain-verified, since only the app's own code can add one.
//
//ds:def id=withdefaultproviders-qph6yfbg owner=@khanakia stability=stable
func WithDefaultProviders(ps ...Provider) Option {
	return func(p *Plugin) {
		for _, pr := range ps {
			pr.Default, pr.DomainVerified = true, true
			p.defaults = append(p.defaults, pr)
		}
	}
}

// ProvidersLimit caps how many providers one user may register; 0 turns
// registration off (ErrRegistrationOff). The default is
// DefaultProvidersLimit.
func ProvidersLimit(n int) Option {
	return func(p *Plugin) { p.limit = func(context.Context, auth.User) int { return n } }
}

// WithProvidersLimit computes the cap per user, for plans that differ.
func WithProvidersLimit(fn func(ctx context.Context, u auth.User) int) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sso.WithProvidersLimit", fn) {
			return
		}
		p.limit = fn
	}
}

// WithCallbackURL sets the OIDC redirect URI registered at every IdP.
// The default is BaseURL + DefaultMountPrefix + "/sso/callback".
func WithCallbackURL(u string) Option { return func(p *Plugin) { p.callback = u } }

// WithACSURL sets the SAML assertion consumer service URL. The default is
// BaseURL + DefaultMountPrefix + "/sso/saml2/sp/acs".
func WithACSURL(u string) Option { return func(p *Plugin) { p.acs = u } }

// WithErrorURL sends a failed sign-in's browser to path (with the error
// code) instead of answering JSON, as oauth.ErrorURL does.
func WithErrorURL(path string) Option { return func(p *Plugin) { p.errorURL = path } }

// WithStateTTL bounds an OIDC flow; the default is DefaultStateTTL.
func WithStateTTL(d time.Duration) Option { return func(p *Plugin) { p.stateTTL = d } }

// WithHTTPClient replaces the client every IdP call uses. The default
// refuses redirects and private, loopback and link-local addresses (the
// SSRF guard), resolved at connect time so a DNS answer that changes
// after a check cannot slip through. An app that replaces it owns that
// guard; WithTrustedOrigins is the narrower escape hatch.
func WithHTTPClient(hc *http.Client) Option { return func(p *Plugin) { p.hc, p.hcSet = hc, true } }

// WithTrustedOrigins lists IdP origins ("https://idp.internal:8443") the
// SSRF guard lets through even on a private address, and that may use
// plain http: an on-premises ADFS, a local test IdP.
func WithTrustedOrigins(origins ...string) Option {
	return func(p *Plugin) { p.trusted = append(p.trusted, origins...) }
}

// RequireTrustedOrigins accepts only IdP URLs whose origin
// WithTrustedOrigins lists, a trusted-origins rule for discovery:
// the discovery URL and every discovered endpoint. For an app whose
// customers' IdPs are known in advance.
func RequireTrustedOrigins() Option { return func(p *Plugin) { p.onlyTrusted = true } }

// ReserveProviderIDs refuses these provider ids at registration, besides
// every plugin name and every plugin/oauth provider name (always
// reserved, so an SSO provider can never shadow another sign-in method).
func ReserveProviderIDs(ids ...string) Option {
	return func(p *Plugin) { p.reserved = append(p.reserved, ids...) }
}

// TrustEmailVerified takes the IdP's email_verified claim (or the SAML
// mapping's emailVerified attribute) as proof the person controls the
// address. Off by default: an enterprise IdP often asserts an address it never
// verified.
func TrustEmailVerified() Option { return func(p *Plugin) { p.trustEmailVerified = true } }

// DisableImplicitSignUp refuses to create a user unless the sign-in asked
// for it (SignInRequest.RequestSignUp).
func DisableImplicitSignUp() Option { return func(p *Plugin) { p.noImplicitSignUp = true } }

// DefaultOverrideUserInfo turns OIDCConfig.OverrideUserInfo on for every
// provider: the IdP's name and image are copied at every sign-in.
func DefaultOverrideUserInfo() Option { return func(p *Plugin) { p.overrideUserInfo = true } }

// TrustProviders lets these providers link to an existing user with the
// same verified email in one of their domains even when domain
// verification is off. A default provider and a domain-verified one are
// trusted already.
func TrustProviders(ids ...string) Option {
	return func(p *Plugin) { p.trustedProviders = append(p.trustedProviders, ids...) }
}

// WithPrivateKeyResolver supplies the key for private_key_jwt token
// authentication, so the key can live in an HSM or KMS rather than a row.
func WithPrivateKeyResolver(fn PrivateKeyResolver) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sso.WithPrivateKeyResolver", fn) {
			return
		}
		p.keys = fn
	}
}

// WithProvisionUser runs fn after a user signs in through a provider for
// the first time (or every time, with ProvisionUserOnEveryLogin), inside
// the sign-in transaction: an error refuses the sign-in and rolls back the
// user it created.
func WithProvisionUser(fn ProvisionFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sso.WithProvisionUser", fn) {
			return
		}
		p.provision = fn
	}
}

// ProvisionUserOnEveryLogin runs the WithProvisionUser function at every
// sign-in, not only the first.
func ProvisionUserOnEveryLogin() Option { return func(p *Plugin) { p.provisionEvery = true } }

// WithResolveUser decides, before the built-in rules, whose account a
// first sign-in through a provider belongs to: continue with the rules,
// link to a user the app names, or refuse by returning an error (an
// *auth.Error is answered as it is). It runs in the sign-in transaction.
func WithResolveUser(fn ResolveUserFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sso.WithResolveUser", fn) {
			return
		}
		p.resolveUser = fn
	}
}

// WithOrganizations connects an organization system: registration under an
// organization then needs the caller to be its owner or admin, sign-in can
// name an organization by slug, and a user who signs in through an
// organization's provider joins it (OrganizationProvisioning).
func WithOrganizations(o Organizations, prov OrganizationProvisioning) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sso.WithOrganizations", o) {
			return
		}
		p.orgs, p.orgProvisioning = o, prov
	}
}

// WithMutationGuard runs fn before every provider update or delete; an
// error refuses it (an *auth.Error as it is, anything else as
// ErrMutationRejected).
func WithMutationGuard(fn MutationGuard) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sso.WithMutationGuard", fn) {
			return
		}
		p.guard = fn
	}
}

// New builds the plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{stateTTL: DefaultStateTTL, saml: defaultSAMLOptions(), engine: GoSAML2{}}
	p.limit = func(context.Context, auth.User) int { return DefaultProvidersLimit }
	for _, o := range opts {
		o(p)
	}
	p.register = auth.Define(auth.OpInfo{ID: EndpointRegister, Kind: auth.Mutation, Require: auth.SignedIn, Path: PathRegister}, p.doRegister)
	p.signIn = auth.Define(auth.OpInfo{ID: EndpointSignIn, Kind: auth.Mutation, Require: auth.Public, Path: PathSignIn}, p.doSignIn)
	p.callbackOp = auth.Define(auth.OpInfo{ID: EndpointCallback, Kind: auth.Query, Require: auth.Public, Path: PathCallback, SignIn: true}, p.doCallback)
	p.list = auth.Define(auth.OpInfo{ID: EndpointProviders, Kind: auth.Query, Require: auth.SignedIn, Path: PathProviders}, p.doList)
	p.get = auth.Define(auth.OpInfo{ID: EndpointGetProvider, Kind: auth.Query, Require: auth.SignedIn, Path: PathGetProvider}, p.doGet)
	p.update = auth.Define(auth.OpInfo{ID: EndpointUpdate, Kind: auth.Mutation, Require: auth.SignedIn, Path: PathUpdate}, p.doUpdate)
	p.del = auth.Define(auth.OpInfo{ID: EndpointDelete, Kind: auth.Mutation, Require: auth.SignedIn, Path: PathDelete}, p.doDelete)
	p.metadata = auth.Define(auth.OpInfo{ID: EndpointSPMetadata, Kind: auth.Query, Require: auth.Public, Path: PathSPMetadata}, p.doMetadata)
	p.acsOp = auth.Define(auth.OpInfo{ID: EndpointACS, Kind: auth.Mutation, Require: auth.Public, Path: PathACS, CrossSiteForm: true, SignIn: true}, p.doACS)
	p.logout = auth.Define(auth.OpInfo{ID: EndpointLogout, Kind: auth.Mutation, Require: auth.SignedIn, Path: PathLogout}, p.doLogout)
	p.sloGet = auth.Define(auth.OpInfo{ID: EndpointSLO, Kind: auth.Query, Require: auth.Public, Path: PathSLO}, p.doSLOGet)
	p.sloPost = auth.Define(auth.OpInfo{ID: EndpointSLOPost, Kind: auth.Mutation, Require: auth.Public, Path: PathSLO, CrossSiteForm: true}, p.doSLOPost)
	p.reqDomain = auth.Define(auth.OpInfo{ID: EndpointRequestDomain, Kind: auth.Mutation, Require: auth.SignedIn, Path: PathRequestDomain}, p.doRequestDomain)
	p.verifDomain = auth.Define(auth.OpInfo{ID: EndpointVerifyDomain, Kind: auth.Mutation, Require: auth.SignedIn, Path: PathVerifyDomain}, p.doVerifyDomain)
	return p
}

// Name is PluginName.
func (p *Plugin) Name() string { return PluginName }

// SignsIn reports that SSO is a way in.
func (p *Plugin) SignsIn() bool { return true }

// Tables declares both tables, so auth.New refuses a second owner.
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableProvider, TableAccount} }

// UserTables declares that auth_sso_account rows belong to their user, so
// DeleteUser removes them. Providers are not listed: an organization's
// provider must survive the admin who registered it.
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableAccount, Column: ColUserID}}
}

// providerIDPattern is what a provider id may be: it appears in a DNS
// label (domain verification), in URLs and in logs.
var providerIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)

// Validate checks the default providers, the callback URLs, the SAML
// options and the domain-verification prefix, and derives the key that
// seals provider secrets.
func (p *Plugin) Validate(c *auth.Config) error {
	if (p.callback == "" || p.acs == "") && c.BaseURL == "" {
		return ErrNoCallbackURL
	}
	keys, err := c.DeriveKeys(keyLabelSecrets)
	if err != nil {
		return ErrKeyDerivation
	}
	if p.ring, err = auth.NewKeyRing(keys[0], keys[1:]...); err != nil {
		return ErrKeyDerivation
	}
	seen := map[string]bool{}
	for _, d := range p.defaults {
		if seen[d.ProviderID] {
			return fmt.Errorf("%w: sso.WithDefaultProviders: provider id %q twice", ErrBadDefault, d.ProviderID)
		}
		seen[d.ProviderID] = true
		if err := p.checkShape(d); err != nil {
			return fmt.Errorf("%w: sso.WithDefaultProviders: %q: %v", ErrBadDefault, d.ProviderID, err)
		}
	}
	if err := p.saml.validate(); err != nil {
		return err
	}
	if err := p.validateFields(); err != nil {
		return err
	}
	if p.domain != nil && len(domainRecordLabel(p.domain.prefix(), "x")) > maxDNSLabel {
		return ErrPrefixTooLong
	}
	return nil
}

// Init captures the core, builds the guarded HTTP client and fills the
// default URLs.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if !p.hcSet {
		p.hc = guardedClient(DefaultHTTPTimeout, p.trusted)
	}
	base := strings.TrimSuffix(a.Config().BaseURL, "/") + DefaultMountPrefix + "/" + PluginName
	if p.callback == "" {
		p.callback = base + PathCallback
	}
	if p.acs == "" {
		p.acs = base + PathACS
	}
	p.metaBase = base + PathSPMetadata
	p.slo = base + PathSLO
	if p.saml.SkipInResponseTo {
		a.Logger().Warn("sso: SAMLOptions.SkipInResponseTo is on: SP-initiated SAML responses are not tied to their request")
	}
	if p.errorURL != "" && !a.TrustsReturnURL(p.errorURL) {
		return fmt.Errorf("sso: WithErrorURL %q: %w", p.errorURL, ErrBadReturnTo)
	}
	for _, pl := range a.Plugins() {
		p.reserved = append(p.reserved, pl.Name())
	}
	if op, err := auth.PluginOf[*oauth.Plugin](a); err == nil {
		for _, info := range op.Providers() {
			p.reserved = append(p.reserved, info.ID)
		}
	}
	return nil
}

// Operations lists every operation; the two domain-verification ones only
// under WithDomainVerification.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{p.register, p.signIn, p.callbackOp, p.list, p.get, p.update, p.del, p.metadata, p.acsOp}
	if p.domain != nil {
		ops = append(ops, p.reqDomain, p.verifDomain)
	}
	if p.saml.EnableSingleLogout {
		ops = append(ops, p.logout, p.sloGet, p.sloPost)
	}
	return ops
}

// RateLimits bounds the public flow starts, the ACS, registration and DNS
// verification, each of which costs a row, a network call or a signature
// check.
func (p *Plugin) RateLimits() []auth.RateRule {
	rules := []auth.RateRule{
		{Match: EndpointSignIn, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
		{Match: EndpointACS, Key: auth.ByIP, Limit: acsIPLimit, Window: acsIPWindow},
		{Match: EndpointCallback, Key: auth.ByIP, Limit: acsIPLimit, Window: acsIPWindow},
		{Match: EndpointRegister, Key: auth.ByIP, Limit: registerIPLimit, Window: registerWindow},
	}
	if p.saml.EnableSingleLogout {
		rules = append(rules, auth.RateRule{Match: EndpointSLO, Key: auth.ByIP, Limit: acsIPLimit, Window: acsIPWindow},
			auth.RateRule{Match: EndpointSLOPost, Key: auth.ByIP, Limit: acsIPLimit, Window: acsIPWindow})
	}
	if p.domain != nil {
		rules = append(rules, auth.RateRule{Match: EndpointVerifyDomain, Key: auth.ByIP, Limit: verifyIPLimit, Window: verifyIPWindow})
	}
	return rules
}

// TypedMigrations creates both tables for engine. provider_id is UNIQUE;
// (provider_id, subject) is UNIQUE: one IdP account belongs to one user.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	prov := p.core.TableName(TableProvider)
	acc := p.core.TableName(TableAccount)
	provSQL := "CREATE TABLE IF NOT EXISTS " + prov + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColProviderID + " " + t.Key + " NOT NULL UNIQUE, " +
		ColIssuer + " " + t.Long + " NOT NULL, " +
		ColDomain + " " + t.Long + " NOT NULL, " +
		ColOrganizationID + " " + t.Key + " NOT NULL DEFAULT '', " +
		ColUserID + " " + t.Key + " NOT NULL DEFAULT '', " +
		ColOIDCConfig + " " + t.Doc + " NOT NULL, " +
		ColSAMLConfig + " " + t.Doc + " NOT NULL, " +
		ColDomainVerified + " " + t.Bool + " NOT NULL DEFAULT FALSE, " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		ColUpdatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix
	accCreate := "CREATE TABLE IF NOT EXISTS " + acc + " (" +
		ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColUserID + " " + t.ID + " NOT NULL, " +
		ColProviderID + " " + t.Key + " NOT NULL, " +
		ColIssuer + " " + t.Long + " NOT NULL, " +
		ColSubject + " " + t.Key + " NOT NULL, " +
		ColEmail + " " + t.Value + " NOT NULL DEFAULT '', " +
		ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
		"UNIQUE (" + ColProviderID + ", " + ColSubject + ")"
	index := acc + accountUserIndex
	var accSQL []string
	if engine == auth.EngineMySQL {
		accSQL = []string{accCreate + ", INDEX " + index + " (" + ColUserID + "))" + t.TableSuffix}
	} else {
		accSQL = []string{accCreate + ")" + t.TableSuffix, "CREATE INDEX IF NOT EXISTS " + index + " ON " + acc + " (" + ColUserID + ")"}
	}
	return []auth.Migration{
		{Owner: PluginName, Name: migrationProvider, Statements: []string{provSQL}},
		{Owner: PluginName, Name: migrationAccount, Statements: accSQL},
		{Owner: PluginName, Name: migrationDomainToken, Statements: []string{
			"ALTER TABLE " + prov + " ADD COLUMN " + ColDomainToken + " " + t.Value + " NOT NULL DEFAULT ''",
			"ALTER TABLE " + prov + " ADD COLUMN " + ColDomainTokenExpires + " " + t.Timestamp + " NULL",
			"ALTER TABLE " + prov + " ADD COLUMN " + ColFields + " " + t.Doc + " NULL",
		}},
	}, nil
}

// callbackURLFor is the OIDC redirect URI of a provider: the shared one,
// or under PerProviderPaths the shared one plus "/<providerId>".
func (p *Plugin) callbackURLFor(providerID string) string {
	return p.perProvider(p.callback, providerID)
}

// acsURLFor is the SAML ACS URL of a provider, shaped like callbackURLFor.
func (p *Plugin) acsURLFor(providerID string) string { return p.perProvider(p.acs, providerID) }

// perProvider appends the provider id under PerProviderPaths.
func (p *Plugin) perProvider(base, providerID string) string {
	if !p.providerPaths {
		return base
	}
	return base + "/" + url.PathEscape(providerID)
}

// metadataURL is the SP metadata URL of a provider.
func (p *Plugin) metadataURL(providerID string) string {
	return p.metaBase + "?" + providerIDParam + "=" + providerID
}

// returnTo checks a landing address with the core's one rule; "" is the
// site root.
func (p *Plugin) returnTo(s string) (string, error) {
	if s == "" {
		return siteRoot, nil
	}
	if !p.core.TrustsReturnURL(s) {
		return "", ErrBadReturnTo
	}
	return s, nil
}

// siteRoot is where a flow lands when nothing names another page.
const siteRoot = "/"

// flowMeta is what a flow carries from start to callback or ACS, in the
// state or RelayState row's Meta.
type flowMeta struct {
	Provider  string   `json:"p"`
	Reference string   `json:"r"`
	Protocol  Protocol `json:"t"`
	Verifier  string   `json:"v,omitempty"`
	ReturnTo  string   `json:"u"`
	ErrorTo   string   `json:"e,omitempty"`
	NewUserTo string   `json:"n,omitempty"`
	SignUp    bool     `json:"s,omitempty"`
	// RequestID is the SAML AuthnRequest ID the response must answer.
	RequestID string `json:"q,omitempty"`
	// initiated marks an IdP-initiated SAML sign-in; never stored.
	initiated bool
}

// encode marshals a flowMeta; a struct of strings always marshals.
func (m flowMeta) encode() string {
	b, _ := json.Marshal(m)
	return string(b)
}

// reservedID reports whether id may not be registered.
func (p *Plugin) reservedID(id string) bool {
	for _, r := range p.reserved {
		if strings.EqualFold(r, id) {
			return true
		}
	}
	return slices.ContainsFunc(p.defaults, func(d Provider) bool { return strings.EqualFold(d.ProviderID, id) })
}
