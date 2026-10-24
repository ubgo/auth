package samlidp

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/ubgo/auth"
)

// NameID formats (SAML core 8.3). The SP's NameIDFormat picks which one its
// assertions carry.
const (
	NameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
)

// NameIDFormats is every format the IdP can issue, in the order the metadata
// lists them.
var NameIDFormats = []string{NameIDPersistent, NameIDEmail, NameIDTransient, NameIDUnspecified}

// Attribute name formats.
const (
	AttrNameFormatBasic       = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	AttrNameFormatURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	AttrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

// Attribute is one SAML attribute an assertion releases to an SP.
type Attribute struct {
	Name         string
	NameFormat   string // AttrNameFormatBasic when empty
	FriendlyName string
	Values       []string
}

// Subject is what an SP's NameID and Attributes functions see about the
// user being signed in.
type Subject struct {
	User auth.User
	// Email is the user's primary verified email address, "" when there is
	// none. Unverified addresses are never released.
	Email string
	// Session is the IdP session the assertion is issued from.
	Session auth.Session
}

// AttributesFunc builds the attributes an SP receives. It runs on every
// assertion; an error refuses the sign-in.
type AttributesFunc func(ctx context.Context, sp ServiceProvider, s Subject) ([]Attribute, error)

// NameIDFunc replaces the NameID value an SP receives. It returns the value
// for sp.NameIDFormat; "" refuses the sign-in with ErrNameIDUnavailable.
type NameIDFunc func(ctx context.Context, sp ServiceProvider, s Subject) (string, error)

// ServiceProvider is one registered SAML SP.
type ServiceProvider struct {
	// EntityID is the SP's entity ID: the Issuer of its AuthnRequests and
	// the only Audience of the assertions it receives. Required.
	EntityID string
	// ACSURLs are the SP's assertion consumer service URLs (HTTP-POST
	// binding). A request's AssertionConsumerServiceURL must equal one of
	// them exactly; a request without one is answered at the first. An
	// AssertionConsumerServiceIndex selects by position. Required; each an
	// absolute https URL (http only for a loopback host).
	ACSURLs []string
	// Certificates verify the SP's signed AuthnRequests: a request that
	// carries a signature is verified against them, and refused when it
	// does not verify. Without Certificates a signature cannot be checked
	// and the request counts as unsigned. RequireSignedRequests refuses an
	// unsigned one.
	Certificates []*x509.Certificate
	// RequireSignedRequests refuses an AuthnRequest that is not signed by
	// one of Certificates.
	RequireSignedRequests bool
	// NameIDFormat is the NameID format the SP receives; NameIDPersistent
	// when empty. Persistent and unspecified carry the user's ID unless
	// NameID replaces it, email the primary verified email address,
	// transient a fresh random value per assertion.
	NameIDFormat string
	// NameID, when set, produces the NameID value (a pairwise identifier,
	// an employee number).
	NameID NameIDFunc
	// Attributes, when set, builds the attributes released to the SP.
	// Without it the assertion carries none. DefaultAttributes releases the
	// email address and the name.
	Attributes AttributesFunc
	// AllowIdPInitiated lets Plugin.Initiate send an unsolicited assertion
	// to this SP (IdP-initiated sign-on). Off by default: an unsolicited
	// assertion has no InResponseTo to bind it to, so an SP that accepts
	// them is open to assertion injection on its side.
	AllowIdPInitiated bool
	// UnsignedResponse signs only the assertion and leaves the Response
	// envelope unsigned, for an SP that refuses two signatures. By default
	// both are signed.
	UnsignedResponse bool
}

// DefaultAttributes releases "email" (when verified) and "name" in the
// basic name format, the attribute names most SPs map by default.
func DefaultAttributes(_ context.Context, _ ServiceProvider, s Subject) ([]Attribute, error) {
	var out []Attribute
	if s.Email != "" {
		out = append(out, Attribute{Name: "email", Values: []string{s.Email}})
	}
	if s.User.Name != "" {
		out = append(out, Attribute{Name: "name", Values: []string{s.User.Name}})
	}
	return out, nil
}

// nameIDFormat is the SP's format with the default applied.
func (sp ServiceProvider) nameIDFormat() string {
	if sp.NameIDFormat == "" {
		return NameIDPersistent
	}
	return sp.NameIDFormat
}

// ServiceProviderStore finds a registered SP by entity ID. It answers
// ErrUnknownSP (or an error wrapping it) for an entity ID it does not know.
type ServiceProviderStore interface {
	ServiceProvider(ctx context.Context, entityID string) (ServiceProvider, error)
}

// validateSP checks one SP's registration.
func (p *Plugin) validateSP(sp ServiceProvider) error {
	if sp.EntityID == "" {
		return fmt.Errorf("%w: EntityID is required", ErrBadSP)
	}
	if len(sp.ACSURLs) == 0 {
		return fmt.Errorf("%w: %q has no ACSURLs", ErrBadSP, sp.EntityID)
	}
	for _, acs := range sp.ACSURLs {
		if !validACS(acs) {
			return fmt.Errorf("%w: %q ACS URL %q is not an absolute https URL (http only for a loopback host) without a fragment", ErrBadSP, sp.EntityID, acs)
		}
	}
	if (sp.RequireSignedRequests || p.wantSigned) && len(sp.Certificates) == 0 {
		return fmt.Errorf("%w: %q must sign its requests but has no Certificates", ErrBadSP, sp.EntityID)
	}
	if slices.Contains(sp.Certificates, nil) {
		return fmt.Errorf("%w: %q has a nil certificate", ErrBadSP, sp.EntityID)
	}
	if !slices.Contains(NameIDFormats, sp.nameIDFormat()) {
		return fmt.Errorf("%w: %q NameIDFormat %q is not one of NameIDFormats", ErrBadSP, sp.EntityID, sp.NameIDFormat)
	}
	return nil
}

// validACS needs an absolute https URL (http for a loopback host) with a
// host and no fragment or user information.
func validACS(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

// lookupSP finds an SP among the static ones, then in the store, and checks
// a stored one as auth.New checks static ones.
func (p *Plugin) lookupSP(ctx context.Context, entityID string) (ServiceProvider, error) {
	for _, sp := range p.static {
		if sp.EntityID == entityID {
			return sp, nil
		}
	}
	if p.store == nil || entityID == "" {
		return ServiceProvider{}, ErrUnknownSP
	}
	sp, err := p.store.ServiceProvider(ctx, entityID)
	if err != nil {
		return ServiceProvider{}, err
	}
	if sp.EntityID != entityID {
		// A store that answers another SP than asked would release that
		// SP's assertions to whoever named this one.
		return ServiceProvider{}, ErrUnknownSP
	}
	if err := p.validateSP(sp); err != nil {
		return ServiceProvider{}, fmt.Errorf("samlidp: stored service provider: %w", err)
	}
	return sp, nil
}

// RequestClaim is one AuthnRequest ID to be answered at most once.
type RequestClaim struct {
	// SP is the requesting SP's entity ID; Request the request's ID.
	SP, Request string
	// Until is when the claim may be forgotten: past it the request's
	// IssueInstant is too old to be accepted anyway.
	Until time.Time
}

// RequestIDGuard claims request IDs. Claim answers nil the first time a
// claim is made and ErrRequestReplayed every later time, even under
// concurrent calls.
type RequestIDGuard interface {
	Claim(ctx context.Context, c RequestClaim) error
}

// storeGuard is the default guard: a verification row of PurposeRequestID
// whose token is the claim's key, in a store that refuses duplicates
// (checked by Init).
type storeGuard struct{ a *auth.Auth }

// Claim implements RequestIDGuard.
func (g storeGuard) Claim(ctx context.Context, c RequestClaim) error {
	ttl := max(c.Until.Sub(g.a.Now()), time.Second)
	err := g.a.IssueVerificationToken(ctx, PurposeRequestID, c.SP, auth.Token(requestKey(c.SP, c.Request)), ttl, "")
	if errors.Is(err, auth.ErrTokenExists) {
		return ErrRequestReplayed
	}
	return err
}

// requestKey is the claim key of a request: a hash, so an attacker-chosen
// ID of any length or content becomes a fixed-size token.
func requestKey(sp, id string) string {
	sum := sha256.Sum256([]byte(sp + "\x00" + id))
	return hex.EncodeToString(sum[:])
}
