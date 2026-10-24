// Package samlidp makes the app a SAML 2.0 identity provider: other
// services (SAML service providers, "SPs") send their users here to sign in,
// and receive a signed assertion naming the user. It is the SAML sibling of
// plugin/oauthprovider, and the mirror of plugin/sso, which makes the app a
// service provider of someone else's IdP.
//
// It is opt-in and its own module. The protocol endpoints (metadata, the
// single sign-on service in the HTTP-Redirect and HTTP-POST bindings, the
// continue step after sign-in, and IdP-initiated sign-on) are served by
// Plugin.Handler; each is a self-served auth operation underneath
// (auth.OpInfo.SelfServed), so it runs the same pipeline as every other
// operation: rate limits, hooks, tracing.
//
// Security rules, each pinned by a test: an AuthnRequest from an unknown
// issuer is refused; its AssertionConsumerServiceURL must equal a registered
// one exactly, and an error is never sent to an unregistered URL; its ID is
// single use (claimed in a store that refuses duplicates) and its
// IssueInstant must be recent; a signed request is verified against the SP's
// registered certificate and only the verified element is read (the defence
// against XML signature wrapping); a request whose SP requires signing is
// refused unsigned. Every assertion is signed (RSA-SHA256 by default), names
// the SP's entity ID as its only audience, the ACS URL as its recipient, the
// request's ID as InResponseTo, and expires after AssertionTTL. A browser
// that is not signed in is sent to LoginPage and never gets an assertion.
//
// Single logout (SLO) is not implemented yet: an SP's logout does not end
// the IdP session, and the metadata advertises no SingleLogoutService.
package samlidp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// PluginName is the plugin's permanent identity.
const PluginName = "samlidp"

// Operation ids. All are self-served: Handler serves them, no transport
// mounts a JSON copy.
const (
	EndpointSSO      auth.EndpointID = "samlidp.sso"
	EndpointContinue auth.EndpointID = "samlidp.continue"
	EndpointInitiate auth.EndpointID = "samlidp.initiate"
)

// Verification purposes this plugin files rows under.
const (
	// PurposeRequestID reserves an AuthnRequest's ID so it is answered at
	// most once; the token is the SP's entity ID and the request ID.
	PurposeRequestID auth.Purpose = "samlidp.request_id"
	// PurposePending is an accepted AuthnRequest waiting for the user to
	// sign in; the token is the handle in the continue URL, Meta the
	// request. It is spent when the assertion is issued, and rotated while
	// the browser is still signed out.
	PurposePending auth.Purpose = "samlidp.pending"
)

// Defaults. Each has an option.
const (
	// DefaultBasePath is where Handler serves the endpoints under the
	// issuer: <issuer>/saml/metadata, /saml/sso, /saml/continue,
	// /saml/initiate.
	//ds:def id=samlidp-defaultbasepath-q4m8zt2k owner=@khanakia stability=stable
	DefaultBasePath = "/saml"
	// DefaultAssertionTTL is how long an assertion is valid (Conditions and
	// SubjectConfirmationData NotOnOrAfter). Five minutes is what most IdPs
	// use: the browser posts it to the SP within seconds.
	//ds:def id=samlidp-defaultassertionttl-w7n3kp5x owner=@khanakia stability=stable
	DefaultAssertionTTL = 5 * time.Minute
	// DefaultRequestMaxAge is how old an AuthnRequest's IssueInstant may be
	// when it arrives. An SP builds the request just before redirecting.
	//ds:def id=samlidp-defaultrequestmaxage-h2v9qm4r owner=@khanakia stability=stable
	DefaultRequestMaxAge = 5 * time.Minute
	// DefaultClockSkew is the tolerance for an SP clock ahead of ours, and
	// how far NotBefore is set back for an SP clock behind ours.
	//ds:def id=samlidp-defaultclockskew-z5k8wn3t owner=@khanakia stability=stable
	DefaultClockSkew = time.Minute
	// DefaultLoginTTL is how long an accepted request waits for the user to
	// sign in before the continue link stops working.
	//ds:def id=samlidp-defaultloginttl-p3x7mq9v owner=@khanakia stability=stable
	DefaultLoginTTL = 15 * time.Minute
	// DefaultReturnParam is the query parameter LoginPage receives the
	// continue URL in.
	DefaultReturnParam = "return_to"
	// DefaultMaxMessageSize bounds an AuthnRequest after decoding and
	// inflating; real ones are a few kilobytes.
	DefaultMaxMessageSize = 64 << 10
	// MaxRelayState bounds the RelayState stored with a pending request.
	// SAML bindings 3.4.3 limits it to 80 bytes; real SPs send more, so the
	// bound is generous but finite.
	MaxRelayState = 1024
)

// ParamPrompt is added to the LoginPage URL as prompt=login when the SP
// asked for ForceAuthn and the current session is older than the request:
// the page must make the user authenticate again even though a session
// exists.
const (
	ParamPrompt = "prompt"
	PromptLogin = "login"
)

// Errors. Every one is shown to the user (Handler renders an error page) and
// never sent to an ACS URL, so an attacker cannot use the IdP to post to a
// URL of their choosing.
var (
	ErrInvalidRequest      = auth.NewError("samlidp.invalid_request", http.StatusBadRequest, "The SAML request is malformed.")
	ErrUnknownSP           = auth.NewError("samlidp.unknown_service_provider", http.StatusBadRequest, "The service provider is not registered.")
	ErrACSNotRegistered    = auth.NewError("samlidp.acs_not_registered", http.StatusBadRequest, "The assertion consumer service URL is not registered for this service provider.")
	ErrUnsupportedBinding  = auth.NewError("samlidp.unsupported_binding", http.StatusBadRequest, "Only the HTTP-POST binding is supported for the response.")
	ErrWrongDestination    = auth.NewError("samlidp.wrong_destination", http.StatusBadRequest, "The request is addressed to another endpoint.")
	ErrRequestExpired      = auth.NewError("samlidp.request_expired", http.StatusBadRequest, "The SAML request is too old or issued in the future.")
	ErrRequestReplayed     = auth.NewError("samlidp.request_replayed", http.StatusBadRequest, "The SAML request was already used.")
	ErrSignatureRequired   = auth.NewError("samlidp.signature_required", http.StatusBadRequest, "This service provider must sign its requests.")
	ErrInvalidSignature    = auth.NewError("samlidp.invalid_signature", http.StatusBadRequest, "The request signature does not verify.")
	ErrNameIDPolicy        = auth.NewError("samlidp.invalid_name_id_policy", http.StatusBadRequest, "The requested NameID format is not the one configured for this service provider.")
	ErrRequestNotFound     = auth.NewError("samlidp.request_not_found", http.StatusBadRequest, "The sign-in request is unknown, used or expired. Start again from the application.")
	ErrIdPInitiatedOff     = auth.NewError("samlidp.idp_initiated_disabled", http.StatusForbidden, "IdP-initiated sign-on is not enabled for this service provider.")
	ErrNameIDUnavailable   = auth.NewError("samlidp.name_id_unavailable", http.StatusForbidden, "Your account has no verified value for the identifier this service needs.")
	ErrAccessDenied        = auth.NewError("samlidp.access_denied", http.StatusForbidden, "You may not sign in to this service.")
	ErrRelayStateTooLong   = auth.NewError("samlidp.relay_state_too_long", http.StatusBadRequest, "The RelayState is too long.")
	ErrMessageTooLarge     = auth.NewError("samlidp.message_too_large", http.StatusRequestEntityTooLarge, "The SAML message is too large.")
	ErrUnsupportedSigAlg   = auth.NewError("samlidp.unsupported_signature_algorithm", http.StatusBadRequest, "The signature algorithm is not accepted.")
	ErrMissingRequestParam = auth.NewError("samlidp.missing_request", http.StatusBadRequest, "SAMLRequest is missing.")
)

// Configuration errors, returned by auth.New.
var (
	ErrNoIssuer     = errors.New("samlidp: Issuer is required: an absolute https URL (http only for a loopback host) with no query or fragment")
	ErrNoLoginPage  = errors.New("samlidp: LoginPage is required: where a browser that is not signed in is sent")
	ErrNoSigningKey = errors.New("samlidp: SigningKey is required: an RSA or ECDSA crypto.Signer and its certificate, whose public key must match")
	ErrBadSP        = errors.New("samlidp: invalid service provider")
	ErrBadTTL       = errors.New("samlidp: every lifetime is positive")
	ErrBadBasePath  = errors.New("samlidp: BasePath must start with / and not end with one")
	ErrNoExclusive  = errors.New("samlidp: the verification store does not refuse duplicate tokens (auth.ExclusiveVerificationStore), so a request ID cannot be claimed once; give its storage SetIfAbsent or pass samlidp.WithRequestIDGuard")
)

// AccessFunc decides whether a signed-in user may sign in to sp: a nil
// answer allows, an error refuses (ErrAccessDenied unless it is an
// *auth.Error of its own). It is the seam for any authorization model
// (roles, groups, an organization's app assignments, a policy engine).
type AccessFunc func(ctx context.Context, u auth.User, sp ServiceProvider) error

// Plugin is the SAML identity provider. Build it with New.
type Plugin struct {
	optErrs auth.OptionErrors

	issuer        string
	entityID      string
	basePath      string
	loginPage     string
	returnParam   string
	signer        crypto.Signer
	cert          *x509.Certificate
	sigAlg        string
	assertionTTL  time.Duration
	requestMaxAge time.Duration
	skew          time.Duration
	loginTTL      time.Duration
	maxSize       int
	wantSigned    bool
	access        AccessFunc
	guard         RequestIDGuard
	store         ServiceProviderStore
	static        []ServiceProvider
	limits        map[auth.EndpointID]rateSpec

	core *auth.Auth

	sso      *auth.Op[SSORequest, Result]
	cont     *auth.Op[ContinueRequest, Result]
	initiate *auth.Op[InitiateRequest, Result]
}

// OptionErr is every error the options recorded (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// Issuer is the app's public origin the endpoints live under, such as
// "https://id.example.com": an absolute https URL (http only for a loopback
// host) with no query or fragment. Required.
func Issuer(iss string) Option { return func(p *Plugin) { p.issuer = strings.TrimSuffix(iss, "/") } }

// EntityID replaces the IdP's SAML entity ID, which defaults to the
// metadata URL (<issuer><base>/metadata). Set it when SPs were configured
// with another value; it is the Issuer of every response.
func EntityID(id string) Option { return func(p *Plugin) { p.entityID = id } }

// BasePath moves the endpoints from DefaultBasePath under the issuer.
func BasePath(path string) Option { return func(p *Plugin) { p.basePath = path } }

// LoginPage is where a browser that is not signed in is sent, with the
// continue URL in the ReturnParam query parameter (and prompt=login when the
// SP asked for ForceAuthn). After signing the user in, the page sends the
// browser to that URL. Required: a same-site path or a URL on a trusted
// origin.
func LoginPage(u string) Option { return func(p *Plugin) { p.loginPage = u } }

// ReturnParam renames the query parameter LoginPage receives the continue
// URL in (DefaultReturnParam).
func ReturnParam(name string) Option { return func(p *Plugin) { p.returnParam = name } }

// SigningKey is the key that signs every response and assertion, and its
// certificate, published in the metadata for SPs to trust. key is any
// crypto.Signer (an *rsa.PrivateKey, or a KMS or HSM handle) whose public
// key is cert's. RSA signs with RSA-SHA256, ECDSA with ECDSA-SHA256.
// Required.
func SigningKey(key crypto.Signer, cert *x509.Certificate) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("samlidp.SigningKey", key) {
			return
		}
		if p.optErrs.RefuseNil("samlidp.SigningKey", cert) {
			return
		}
		p.signer, p.cert = key, cert
	}
}

// AssertionTTL overrides DefaultAssertionTTL.
func AssertionTTL(d time.Duration) Option { return func(p *Plugin) { p.assertionTTL = d } }

// RequestMaxAge overrides DefaultRequestMaxAge.
func RequestMaxAge(d time.Duration) Option { return func(p *Plugin) { p.requestMaxAge = d } }

// ClockSkew overrides DefaultClockSkew.
func ClockSkew(d time.Duration) Option { return func(p *Plugin) { p.skew = d } }

// LoginTTL overrides DefaultLoginTTL.
func LoginTTL(d time.Duration) Option { return func(p *Plugin) { p.loginTTL = d } }

// MaxMessageSize overrides DefaultMaxMessageSize.
func MaxMessageSize(n int) Option { return func(p *Plugin) { p.maxSize = n } }

// WantAuthnRequestsSigned requires every SP to sign its AuthnRequests and
// says so in the metadata. Every SP then needs a Certificate. A single SP
// can require it with ServiceProvider.RequireSignedRequests.
func WantAuthnRequestsSigned() Option { return func(p *Plugin) { p.wantSigned = true } }

// Access decides per user and SP whether an assertion may be issued; see
// AccessFunc. Without it every signed-in user may sign in to every
// registered SP.
func Access(fn AccessFunc) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("samlidp.Access", fn) {
			return
		}
		p.access = fn
	}
}

// ServiceProviders registers SPs in code. They are checked by auth.New.
func ServiceProviders(sps ...ServiceProvider) Option {
	return func(p *Plugin) { p.static = append(p.static, sps...) }
}

// WithServiceProviderStore looks SPs up in store (a database table, an
// admin UI's registry, a config service) instead of, or after, the ones
// ServiceProviders registered. Each SP it returns is checked on every
// lookup, as auth.New checks static ones.
func WithServiceProviderStore(store ServiceProviderStore) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("samlidp.WithServiceProviderStore", store) {
			return
		}
		p.store = store
	}
}

// WithRequestIDGuard replaces the default single-use claim of request IDs
// (a verification row that the store refuses to insert twice). Use it when
// the verification store cannot refuse duplicates.
func WithRequestIDGuard(g RequestIDGuard) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("samlidp.WithRequestIDGuard", g) {
			return
		}
		p.guard = g
	}
}

var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.OptionChecker     = (*Plugin)(nil)
)

// New builds the identity provider.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		basePath: DefaultBasePath, returnParam: DefaultReturnParam, assertionTTL: DefaultAssertionTTL,
		requestMaxAge: DefaultRequestMaxAge, skew: DefaultClockSkew, loginTTL: DefaultLoginTTL, maxSize: DefaultMaxMessageSize,
	}
	for _, o := range opts {
		o(p)
	}
	self := func(id auth.EndpointID, kind auth.OpKind, req auth.Requirement, path string) auth.OpInfo {
		return auth.OpInfo{ID: id, Kind: kind, Require: req, Path: path, SelfServed: true}
	}
	// sso is a Query although it writes: it acts with no credential (it
	// never reads the session; the SP's registration and signature are
	// what admit it), and the POST binding arrives cross-site by design,
	// which the origin check of a Mutation would refuse.
	p.sso = auth.Define(self(EndpointSSO, auth.Query, auth.Public, pathSSO), p.doSSO)
	// continue is a top-level GET navigation after sign-in; it reads the
	// session. A request another site starts can only post an assertion of
	// the user to an ACS URL its SP registered, which is what SP-initiated
	// SAML is.
	p.cont = auth.Define(self(EndpointContinue, auth.Query, auth.Public, pathContinue), p.doContinue)
	// initiate is a Mutation that needs the session, so the origin check
	// refuses a cross-site form that would sign the user in somewhere they
	// did not choose.
	p.initiate = auth.Define(self(EndpointInitiate, auth.Mutation, auth.SignedIn, pathInitiate), p.doInitiate)
	return p
}

// Endpoint paths under BasePath.
const (
	pathMetadata = "/metadata"
	pathSSO      = "/sso"
	pathContinue = "/continue"
	pathInitiate = "/initiate"
)

// Name is PluginName.
func (p *Plugin) Name() string { return PluginName }

// Operations lists the self-served operations.
func (p *Plugin) Operations() []auth.Operation {
	return []auth.Operation{p.sso, p.cont, p.initiate}
}

// endpoint is the absolute URL of a path under BasePath.
func (p *Plugin) endpoint(path string) string { return p.issuer + p.basePath + path }

// IdPEntityID is the entity ID the IdP signs as.
func (p *Plugin) IdPEntityID() string {
	if p.entityID != "" {
		return p.entityID
	}
	return p.endpoint(pathMetadata)
}

// SSOURL is the single sign-on service URL SPs send AuthnRequests to.
func (p *Plugin) SSOURL() string { return p.endpoint(pathSSO) }

// MetadataURL is where Handler serves the IdP metadata.
func (p *Plugin) MetadataURL() string { return p.endpoint(pathMetadata) }

// Validate checks the issuer, pages, key, lifetimes and static SPs.
func (p *Plugin) Validate(*auth.Config) error {
	if !validIssuer(p.issuer) {
		return fmt.Errorf("%w: %q", ErrNoIssuer, p.issuer)
	}
	if !strings.HasPrefix(p.basePath, "/") || strings.HasSuffix(p.basePath, "/") || strings.Contains(p.basePath, "..") {
		return fmt.Errorf("%w: %q", ErrBadBasePath, p.basePath)
	}
	if p.loginPage == "" {
		return ErrNoLoginPage
	}
	if p.returnParam == "" {
		return fmt.Errorf("samlidp: ReturnParam must not be empty")
	}
	if err := p.validateKey(); err != nil {
		return err
	}
	for _, l := range []struct {
		option string
		d      time.Duration
	}{
		{"samlidp.AssertionTTL", p.assertionTTL}, {"samlidp.RequestMaxAge", p.requestMaxAge},
		{"samlidp.LoginTTL", p.loginTTL}, {"samlidp.ClockSkew", p.skew + 1},
	} {
		if l.d <= 0 {
			return fmt.Errorf("%w: %s(%v)", ErrBadTTL, l.option, l.d)
		}
	}
	if p.maxSize <= 0 {
		return fmt.Errorf("%w: samlidp.MaxMessageSize(%d)", ErrBadTTL, p.maxSize)
	}
	seen := map[string]bool{}
	for _, sp := range p.static {
		if err := p.validateSP(sp); err != nil {
			// Named for the option, so the refusal says what to fix.
			return fmt.Errorf("samlidp.ServiceProviders: %w", err)
		}
		if seen[sp.EntityID] {
			return fmt.Errorf("samlidp.ServiceProviders: %w: entity ID %q registered twice", ErrBadSP, sp.EntityID)
		}
		seen[sp.EntityID] = true
	}
	if len(p.static) == 0 && p.store == nil {
		return fmt.Errorf("%w: register at least one with samlidp.ServiceProviders or samlidp.WithServiceProviderStore", ErrBadSP)
	}
	return nil
}

// validateKey checks that the key is RSA or ECDSA and matches the
// certificate, and picks the signature algorithm.
func (p *Plugin) validateKey() error {
	if p.signer == nil || p.cert == nil {
		return ErrNoSigningKey
	}
	switch pub := p.signer.Public().(type) {
	case *rsa.PublicKey:
		if !pub.Equal(p.cert.PublicKey) {
			return fmt.Errorf("%w: the key does not match the certificate", ErrNoSigningKey)
		}
		p.sigAlg = AlgRSASHA256
	case *ecdsa.PublicKey:
		if !pub.Equal(p.cert.PublicKey) {
			return fmt.Errorf("%w: the key does not match the certificate", ErrNoSigningKey)
		}
		p.sigAlg = AlgECDSASHA256
	default:
		return fmt.Errorf("%w: %T is neither RSA nor ECDSA", ErrNoSigningKey, pub)
	}
	return nil
}

// Init captures the core, checks the login page against the trusted
// origins, and installs the default request-ID guard.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if !a.TrustsReturnURL(p.loginPage) {
		return fmt.Errorf("samlidp: LoginPage %q is neither a same-site path nor on a trusted origin", p.loginPage)
	}
	if p.guard != nil {
		return nil
	}
	if s, ok := a.VerificationStore().(auth.ExclusiveVerificationStore); !ok || !s.RefusesDuplicateTokens() {
		return ErrNoExclusive
	}
	p.guard = storeGuard{a: a}
	return nil
}

// validIssuer needs an absolute https URL (http for a loopback host) with a
// host and no query, fragment or user information.
func validIssuer(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

// isLoopback reports whether host is localhost or a loopback address.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
