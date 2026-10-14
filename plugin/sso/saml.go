package sso

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
)

// SAMLConfig is a SAML 2.0 provider's settings: this app is the service
// provider (SP), the customer's IdP signs the assertions.
type SAMLConfig struct {
	// EntryPoint is the IdP's single sign-on URL (HTTP-Redirect binding),
	// used when IdPMetadata names no SingleSignOnService.
	EntryPoint string `json:"entryPoint,omitempty"`
	// Cert is the IdP's signing certificate, PEM; several PEM blocks are
	// several certificates, any of which may sign (rotation).
	// IdPMetadata.Cert wins when both are set.
	Cert string `json:"cert,omitempty"`
	// Audience is the AudienceRestriction every assertion must carry;
	// empty is the SP entity id.
	Audience string `json:"audience,omitempty"`
	// CallbackURL is where an IdP-initiated sign-in lands; empty falls
	// back to SAMLOptions.IdPInitiatedCallbackURL, then the site root.
	CallbackURL string `json:"callbackUrl,omitempty"`
	// IdPInitiatedCallbackURL overrides CallbackURL for IdP-initiated
	// sign-ins only.
	IdPInitiatedCallbackURL string      `json:"idpInitiatedCallbackUrl,omitempty"`
	IdPMetadata             IdPMetadata `json:"idpMetadata,omitempty"`
	SPMetadata              SPMetadata  `json:"spMetadata,omitempty"`
	// WantAssertionsSigned requires the Assertion's own signature; a
	// signed Response around an unsigned Assertion is then refused.
	WantAssertionsSigned bool `json:"wantAssertionsSigned,omitempty"`
	// AuthnRequestsSigned signs every AuthnRequest with PrivateKey.
	AuthnRequestsSigned bool `json:"authnRequestsSigned,omitempty"`
	// SignatureAlgorithm signs AuthnRequests: a URI or a short form
	// (sha256, sha384, sha512); empty is RSA-SHA256.
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
	// DigestAlgorithm is advertised for AuthnRequest signatures.
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
	// IdentifierFormat is the NameID format requested and advertised.
	IdentifierFormat string `json:"identifierFormat,omitempty"`
	// PrivateKey and SPCertificate are the SP's key pair, PEM: they sign
	// AuthnRequests and decrypt an EncryptedAssertion. The key is stored
	// sealed and never returned by a read.
	PrivateKey    string `json:"privateKey,omitempty"`
	SPCertificate string `json:"spCertificate,omitempty"`
	// DecryptionKey is a separate decryption key, PEM, when the IdP
	// encrypts to another key than the signing one; sealed like PrivateKey.
	DecryptionKey string `json:"decryptionKey,omitempty"`
	// DecryptionCertificate goes with DecryptionKey (PEM); it is advertised
	// as the encryption key in SP metadata.
	DecryptionCertificate string      `json:"decryptionCertificate,omitempty"`
	Mapping               SAMLMapping `json:"mapping,omitempty"`
	// AllowIdPInitiated accepts an unsolicited response for this provider
	// even when SAMLOptions.AllowIdPInitiated is off.
	AllowIdPInitiated bool `json:"allowIdpInitiated,omitempty"`
}

// IdPMetadata is the IdP's side: its metadata XML, or the fields written
// out.
type IdPMetadata struct {
	// Metadata is the IdP's metadata XML; its entity id, signing
	// certificates and SSO endpoint are read from it.
	Metadata string `json:"metadata,omitempty"`
	// EntityID is required when Metadata is empty.
	EntityID            string     `json:"entityID,omitempty"`
	Cert                string     `json:"cert,omitempty"`
	SingleSignOnService []Endpoint `json:"singleSignOnService,omitempty"`
	// SingleLogoutService is the IdP's SLO endpoint (HTTP-Redirect).
	SingleLogoutService []Endpoint `json:"singleLogoutService,omitempty"`
}

// Endpoint is a SAML binding and location.
type Endpoint struct {
	Binding  string `json:"Binding"`
	Location string `json:"Location"`
}

// SPMetadata is this app's side.
type SPMetadata struct {
	// EntityID is the SP entity id; empty is the custom metadata's, then
	// the provider's Issuer.
	EntityID string `json:"entityID,omitempty"`
	// Metadata is custom SP metadata XML, served as it is instead of the
	// generated document. Its entity id, NameID format and
	// WantAssertionsSigned are read from it; it must list this app's ACS
	// URL with the POST binding, and may not advertise unsigned assertions
	// when WantAssertionsSigned is on (ErrSPMetadataMismatch).
	Metadata string `json:"metadata,omitempty"`
	// Binding is how AuthnRequests travel: "redirect" (the default, the
	// query signed) or "post" (an auto-submitting form, the XML signed,
	// which is where DigestAlgorithm applies).
	Binding string `json:"binding,omitempty"`
}

// SPPolicy is what custom SP metadata says.
type SPPolicy struct {
	EntityID             string
	WantAssertionsSigned bool
	NameIDFormat         string
	// ACSURLs are the HTTP-POST assertion consumer services it lists.
	ACSURLs []string
}

// spMetadataXML is the part of SP metadata DeriveSPPolicy reads.
type spMetadataXML struct {
	XMLName  xml.Name `xml:"EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	SP       struct {
		WantAssertionsSigned string `xml:"WantAssertionsSigned,attr"`
		NameIDFormat         string `xml:"NameIDFormat"`
		ACS                  []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"AssertionConsumerService"`
	} `xml:"SPSSODescriptor"`
}

// ErrSPMetadataMismatch is custom SP metadata that contradicts the config.
var ErrSPMetadataMismatch = auth.NewError("sso.sp_metadata_mismatch", http.StatusBadRequest, "The SP metadata does not match the provider's settings.")

// DeriveSPPolicy reads custom SP metadata (better-auth's
// deriveSAMLServiceProviderPolicy); empty metadata is the zero policy.
func DeriveSPPolicy(md string, maxSize int) (SPPolicy, error) {
	if md == "" {
		return SPPolicy{}, nil
	}
	if len(md) > maxSize || strings.Contains(md, "<!DOCTYPE") {
		return SPPolicy{}, fmt.Errorf("%w: SP metadata over %d bytes or with a DTD", ErrBadProvider, maxSize)
	}
	var m spMetadataXML
	if err := xml.Unmarshal([]byte(md), &m); err != nil {
		return SPPolicy{}, fmt.Errorf("%w: SP metadata: %v", ErrBadProvider, err)
	}
	out := SPPolicy{EntityID: m.EntityID, WantAssertionsSigned: m.SP.WantAssertionsSigned == "true" || m.SP.WantAssertionsSigned == "1",
		NameIDFormat: strings.TrimSpace(m.SP.NameIDFormat)}
	for _, a := range m.SP.ACS {
		if a.Binding == BindingPOST {
			out.ACSURLs = append(out.ACSURLs, a.Location)
		}
	}
	return out, nil
}

// DeriveIdPEntityID is the IdP entity id of a config, by the parser
// sign-in uses (better-auth's deriveSAMLIdentityProviderEntityID).
func DeriveIdPEntityID(cfg SAMLConfig, maxMetadata int) (string, error) {
	idp, err := cfg.IdP(maxMetadata)
	return idp.EntityID, err
}

// SAMLMapping names the attributes read for each profile field.
type SAMLMapping struct {
	// ID is the attribute taken as the subject instead of the NameID.
	ID string `json:"id,omitempty"`
	// Email defaults to "email", then the NameID when it is an address.
	Email string `json:"email,omitempty"`
	// EmailVerified is read only under TrustEmailVerified.
	EmailVerified string `json:"emailVerified,omitempty"`
	// Name defaults to "displayName", used when first and last are absent.
	Name string `json:"name,omitempty"`
	// FirstName defaults to "givenName", LastName to "surname".
	FirstName   string            `json:"firstName,omitempty"`
	LastName    string            `json:"lastName,omitempty"`
	ExtraFields map[string]string `json:"extraFields,omitempty"`
}

// SAML bindings and formats.
const (
	BindingRedirect     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST         = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	NameIDEmail         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDUnspecified   = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	NameIDPersistent    = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	samlAssertionNS     = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNS      = "urn:oasis:names:tc:SAML:2.0:protocol"
	samlMetadataNS      = "urn:oasis:names:tc:SAML:2.0:metadata"
	xmlDSigNS           = "http://www.w3.org/2000/09/xmldsig#"
	samlResponseParam   = "SAMLResponse"
	defaultSAMLEmail    = "email"
	defaultSAMLName     = "displayName"
	defaultSAMLFirst    = "givenName"
	defaultSAMLLast     = "surname"
	samlRequestIDPrefix = "_"
)

// Signature and digest algorithm URIs.
const (
	AlgRSASHA1     = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	AlgRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	AlgRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	AlgECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	AlgECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
	DigestSHA1     = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256   = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384   = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512   = "http://www.w3.org/2001/04/xmlenc#sha512"
)

// Key-transport and data-encryption algorithms of an EncryptedAssertion.
const (
	KeyEncRSA15       = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	KeyEncRSAOAEP     = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	KeyEncRSAOAEP11   = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	DataEnc3DESCBC    = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	DataEncAES128CBC  = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	DataEncAES192CBC  = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	DataEncAES256CBC  = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	DataEncAES128GCM  = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	DataEncAES192GCM  = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	DataEncAES256GCM  = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	xmlEncNS          = "http://www.w3.org/2001/04/xmlenc#"
	xmlEnc11NS        = "http://www.w3.org/2009/xmlenc11#"
	encryptedKeyLocal = "EncryptedKey"
)

// KeyEncryptionAlgorithms are the key-transport algorithms this plugin
// knows; RSA-1.5 is deprecated.
var KeyEncryptionAlgorithms = []string{KeyEncRSA15, KeyEncRSAOAEP, KeyEncRSAOAEP11}

// DataEncryptionAlgorithms are the data-encryption algorithms this plugin
// knows; 3DES is deprecated. AES-192-CBC is listed so a response naming it
// is refused as unsupported by the engine rather than as unknown.
var DataEncryptionAlgorithms = []string{DataEnc3DESCBC, DataEncAES128CBC, DataEncAES192CBC, DataEncAES256CBC, DataEncAES128GCM, DataEncAES192GCM, DataEncAES256GCM}

// SignatureAlgorithms are the signature algorithms this plugin knows;
// RSA-SHA1 is deprecated (SAMLOptions.OnDeprecated).
var SignatureAlgorithms = []string{AlgRSASHA1, AlgRSASHA256, AlgRSASHA384, AlgRSASHA512, AlgECDSASHA256, AlgECDSASHA384, AlgECDSASHA512}

// DigestAlgorithms are the digest algorithms this plugin knows; SHA-1 is
// deprecated.
var DigestAlgorithms = []string{DigestSHA1, DigestSHA256, DigestSHA384, DigestSHA512}

// deprecatedAlgorithms are SHA-1 based.
var deprecatedAlgorithms = []string{AlgRSASHA1, DigestSHA1, KeyEncRSA15, DataEnc3DESCBC}

// shortAlgorithms maps the short forms a config may use.
var shortAlgorithms = map[string]string{"sha256": AlgRSASHA256, "sha384": AlgRSASHA384, "sha512": AlgRSASHA512, "sha1": AlgRSASHA1}

// DeprecatedPolicy is what to do with a SHA-1 signature or digest.
type DeprecatedPolicy string

const (
	DeprecatedWarn   DeprecatedPolicy = "warn"
	DeprecatedReject DeprecatedPolicy = "reject"
	DeprecatedAllow  DeprecatedPolicy = "allow"
)

// DeprecatedPolicyValues is every DeprecatedPolicy.
var DeprecatedPolicyValues = []DeprecatedPolicy{DeprecatedWarn, DeprecatedReject, DeprecatedAllow}

// SAMLOptions are the plugin-wide SAML settings.
type SAMLOptions struct {
	// AllowIdPInitiated accepts unsolicited responses (an IdP dashboard
	// tile). Off by default: an unsolicited response has no request ID to
	// bind it to this browser, so only replay protection and the time
	// window stand between a stolen response and a session.
	AllowIdPInitiated bool
	// RequestTTL bounds an AuthnRequest; DefaultSAMLRequestTTL when zero.
	RequestTTL time.Duration
	// ClockSkew is tolerated on every timestamp; DefaultClockSkew when zero.
	ClockSkew time.Duration
	// RequireTimestamps refuses an assertion without NotBefore and
	// NotOnOrAfter conditions.
	RequireTimestamps bool
	// OnDeprecated decides SHA-1 signatures and digests; empty is warn.
	OnDeprecated DeprecatedPolicy
	// AllowedSignatureAlgorithms and AllowedDigestAlgorithms, when set,
	// refuse every other algorithm.
	AllowedSignatureAlgorithms []string
	AllowedDigestAlgorithms    []string
	// AllowedKeyEncryptionAlgorithms and AllowedDataEncryptionAlgorithms,
	// when set, refuse an EncryptedAssertion using any other.
	AllowedKeyEncryptionAlgorithms  []string
	AllowedDataEncryptionAlgorithms []string
	// MaxResponseSize and MaxMetadataSize bound the decoded XML.
	MaxResponseSize int
	MaxMetadataSize int
	// IdPInitiatedCallbackURL is where an IdP-initiated sign-in lands when
	// its provider names none.
	IdPInitiatedCallbackURL string
	// EnableSingleLogout turns on SAML single logout: the logout route, the
	// SLO endpoint, SLO in SP metadata, and the session records.
	EnableSingleLogout bool
	// LogoutRequestTTL bounds an SP-initiated LogoutRequest;
	// DefaultLogoutRequestTTL when zero.
	LogoutRequestTTL time.Duration
	// AllowUnsignedLogoutRequests and AllowUnsignedLogoutResponses accept
	// an IdP logout message without a signature. Off by default (better-auth
	// defaults to accepting): an unsigned LogoutRequest lets anyone who
	// knows a NameID and SessionIndex end that person's session. A message
	// that carries a signature is always checked.
	AllowUnsignedLogoutRequests  bool
	AllowUnsignedLogoutResponses bool
	// SkipInResponseTo accepts an SP-initiated response without matching it
	// to its AuthnRequest (better-auth's enableInResponseToValidation:
	// false), for an IdP that drops InResponseTo. Replay protection and the
	// time window still apply; a warning is logged at startup.
	SkipInResponseTo bool
}

func defaultSAMLOptions() SAMLOptions {
	return SAMLOptions{RequestTTL: DefaultSAMLRequestTTL, ClockSkew: DefaultClockSkew, OnDeprecated: DeprecatedWarn,
		MaxResponseSize: DefaultMaxResponseSize, MaxMetadataSize: DefaultMaxMetadataSize, LogoutRequestTTL: DefaultLogoutRequestTTL}
}

// WithSAMLOptions sets the plugin-wide SAML settings; zero fields keep
// their defaults.
func WithSAMLOptions(o SAMLOptions) Option {
	return func(p *Plugin) {
		d := defaultSAMLOptions()
		if o.RequestTTL == 0 {
			o.RequestTTL = d.RequestTTL
		}
		if o.ClockSkew == 0 {
			o.ClockSkew = d.ClockSkew
		}
		if o.OnDeprecated == "" {
			o.OnDeprecated = d.OnDeprecated
		}
		if o.MaxResponseSize == 0 {
			o.MaxResponseSize = d.MaxResponseSize
		}
		if o.MaxMetadataSize == 0 {
			o.MaxMetadataSize = d.MaxMetadataSize
		}
		if o.LogoutRequestTTL == 0 {
			o.LogoutRequestTTL = d.LogoutRequestTTL
		}
		p.saml = o
	}
}

// WithSAMLEngine replaces the XML-signature engine (GoSAML2 by default).
func WithSAMLEngine(e SAMLEngine) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("sso.WithSAMLEngine", e) {
			return
		}
		p.engine = e
	}
}

// validate checks the options' closed sets.
func (o SAMLOptions) validate() error {
	if !slices.Contains(DeprecatedPolicyValues, o.OnDeprecated) {
		return fmt.Errorf("%w: sso.WithSAMLOptions: OnDeprecated %q", ErrBadAlgorithmSet, o.OnDeprecated)
	}
	for _, a := range o.AllowedSignatureAlgorithms {
		if !slices.Contains(SignatureAlgorithms, a) {
			return fmt.Errorf("%w: sso.WithSAMLOptions: %q", ErrBadAlgorithmSet, a)
		}
	}
	for _, set := range []struct{ allowed, known []string }{
		{o.AllowedDigestAlgorithms, DigestAlgorithms},
		{o.AllowedKeyEncryptionAlgorithms, KeyEncryptionAlgorithms},
		{o.AllowedDataEncryptionAlgorithms, DataEncryptionAlgorithms},
	} {
		for _, a := range set.allowed {
			if !slices.Contains(set.known, a) {
				return fmt.Errorf("%w: sso.WithSAMLOptions: %q", ErrBadAlgorithmSet, a)
			}
		}
	}
	return nil
}

// SAMLEngine is the XML-signature work: building an AuthnRequest and
// verifying a response's signature. It returns what the signature covers;
// every rule about whether that content signs anyone in is checked by the
// plugin (CheckAssertion), so an engine swap cannot drop one.
type SAMLEngine interface {
	// AuthnRequestURL returns the IdP's SSO URL carrying an AuthnRequest
	// with requestID, HTTP-Redirect binding, signed when
	// sp.AuthnRequestsSigned.
	AuthnRequestURL(sp SPSettings, idp IdPSettings, requestID, relayState string) (string, error)
	// AuthnRequestPOST returns the form of an HTTP-POST AuthnRequest with
	// requestID, its enveloped signature made when sp.AuthnRequestsSigned.
	AuthnRequestPOST(sp SPSettings, idp IdPSettings, requestID, relayState string) (PostForm, error)
	// VerifyResponse decodes a base64 SAMLResponse, verifies its signature
	// (on the Response, or on each Assertion) against idp.Certs, decrypts an
	// EncryptedAssertion with sp.DecryptionKey, and returns only verified
	// content. Any failure is an error.
	VerifyResponse(sp SPSettings, idp IdPSettings, samlResponse string, now time.Time) (*SAMLResponse, error)
}

// PostForm is an HTTP-POST binding message: the browser posts SAMLRequest
// and RelayState to Action (an auto-submitting form).
type PostForm struct {
	Action      string `json:"action"`
	SAMLRequest string `json:"SAMLRequest"`
	RelayState  string `json:"RelayState"`
}

// Bindings an AuthnRequest may use (SPMetadata.Binding).
const (
	AuthnBindingRedirect = "redirect"
	AuthnBindingPOST     = "post"
)

// digestOf is the digest an enveloped signature with each signature
// algorithm carries: the XML-signature library hashes the references with
// the signature's own hash, so DigestAlgorithm must name that one.
var digestOf = map[string]string{
	AlgRSASHA1: DigestSHA1, AlgRSASHA256: DigestSHA256, AlgRSASHA384: DigestSHA384, AlgRSASHA512: DigestSHA512,
	AlgECDSASHA256: DigestSHA256, AlgECDSASHA384: DigestSHA384, AlgECDSASHA512: DigestSHA512,
}

// SPSettings are this app's SAML settings for one provider.
type SPSettings struct {
	EntityID             string
	ACSURL               string
	Audience             string
	NameIDFormat         string
	AuthnRequestsSigned  bool
	SignatureAlgorithm   string
	SigningKey           crypto.Signer
	Certificate          *x509.Certificate
	DecryptionKey        crypto.Signer
	DecryptionCert       *x509.Certificate
	WantAssertionsSigned bool
	MaxResponseSize      int
	// SLOURL is the SP's single logout endpoint; "" when single logout is
	// off, and then left out of the metadata.
	SLOURL string
	// CustomMetadata is SPMetadata.Metadata, served instead of the
	// generated document.
	CustomMetadata string
	// POSTBinding sends AuthnRequests by HTTP-POST (SPMetadata.Binding).
	POSTBinding bool
	// Now is the core's clock (auth.WithClock) when an AuthnRequest is
	// built, so its IssueInstant follows the injected clock.
	Now time.Time
}

// IdPSettings are the IdP's settings.
type IdPSettings struct {
	EntityID string
	SSOURL   string
	// SLOURL is the IdP's single logout URL (HTTP-Redirect); "" when it has
	// none.
	SLOURL string
	Certs  []*x509.Certificate
}

// SAMLResponse is a verified response.
type SAMLResponse struct {
	ID           string
	InResponseTo string
	Destination  string
	Issuer       string
	Signed       bool
	Assertions   []SAMLAssertion
}

// SAMLAssertion is a verified assertion.
type SAMLAssertion struct {
	ID           string
	Issuer       string
	Signed       bool
	NameID       string
	NameIDFormat string
	// HasConditions is false when the assertion has no Conditions element.
	HasConditions bool
	NotBefore     time.Time
	NotOnOrAfter  time.Time
	// Audiences holds each AudienceRestriction's audiences.
	Audiences     [][]string
	Confirmations []SubjectConfirmation
	SessionIndex  string
	Attributes    map[string][]string
}

// SubjectConfirmation is a SubjectConfirmation and its data.
type SubjectConfirmation struct {
	Method       string
	Recipient    string
	InResponseTo string
	NotOnOrAfter time.Time
	NotBefore    time.Time
}

// SAMLCode names why a response was refused; each is logged, the caller
// sees ErrSAMLInvalid (or ErrSAMLReplay, ErrSAMLUnsolicited,
// ErrSAMLTooLarge).
type SAMLCode string

const (
	SAMLInvalidEncoding        SAMLCode = "SAML_INVALID_ENCODING"
	SAMLInvalidXML             SAMLCode = "SAML_INVALID_XML"
	SAMLNoAssertion            SAMLCode = "SAML_NO_ASSERTION"
	SAMLMultipleAssertions     SAMLCode = "SAML_MULTIPLE_ASSERTIONS"
	SAMLSignatureInvalid       SAMLCode = "SAML_SIGNATURE_INVALID"
	SAMLAssertionSigRequired   SAMLCode = "SAML_ASSERTION_SIGNATURE_REQUIRED"
	SAMLIssuerMismatch         SAMLCode = "SAML_ISSUER_MISMATCH"
	SAMLAudienceMissing        SAMLCode = "SAML_AUDIENCE_MISSING"
	SAMLAudienceMismatch       SAMLCode = "SAML_AUDIENCE_MISMATCH"
	SAMLBearerMissing          SAMLCode = "SAML_BEARER_CONFIRMATION_MISSING"
	SAMLRecipientMismatch      SAMLCode = "SAML_RECIPIENT_MISMATCH"
	SAMLDestinationMismatch    SAMLCode = "SAML_DESTINATION_MISMATCH"
	SAMLNotYetValid            SAMLCode = "SAML_NOT_YET_VALID"
	SAMLExpired                SAMLCode = "SAML_EXPIRED"
	SAMLMissingTimestamps      SAMLCode = "SAML_MISSING_TIMESTAMPS"
	SAMLInResponseToMismatch   SAMLCode = "SAML_IN_RESPONSE_TO_MISMATCH"
	SAMLUnknownRequest         SAMLCode = "SAML_UNKNOWN_REQUEST"
	SAMLReplay                 SAMLCode = "SAML_REPLAY"
	SAMLUnsolicited            SAMLCode = "SAML_UNSOLICITED"
	SAMLDeprecatedAlgorithm    SAMLCode = "SAML_DEPRECATED_ALGORITHM"
	SAMLAlgorithmNotAllowed    SAMLCode = "SAML_ALGORITHM_NOT_ALLOWED"
	SAMLUnknownAlgorithm       SAMLCode = "SAML_UNKNOWN_ALGORITHM"
	SAMLTooLarge               SAMLCode = "SAML_TOO_LARGE"
	SAMLMissingSubjectOrEmail  SAMLCode = "SAML_MISSING_IDENTITY"
	SAMLCertificateUnavailable SAMLCode = "CERT_SOURCE_MISSING"
)

// SAMLError is a refused response: the code, and the cause for logs.
type SAMLError struct {
	Code SAMLCode
	Err  error
}

func (e *SAMLError) Error() string { return fmt.Sprintf("sso: saml %s: %v", e.Code, e.Err) }

// Unwrap returns the caller's answer, so the transport answers it.
func (e *SAMLError) Unwrap() []error {
	answer := ErrSAMLInvalid
	switch e.Code {
	case SAMLReplay:
		answer = ErrSAMLReplay
	case SAMLUnsolicited:
		answer = ErrSAMLUnsolicited
	case SAMLTooLarge:
		answer = ErrSAMLTooLarge
	}
	return []error{answer, e.Err}
}

func samlErr(code SAMLCode, format string, args ...any) error {
	return &SAMLError{Code: code, Err: fmt.Errorf(format, args...)}
}

// CheckRequest is what CheckAssertion compares a response against.
type CheckRequest struct {
	IdPEntityID string
	Audience    string
	ACSURL      string
	// RequestID is the AuthnRequest ID of an SP-initiated sign-in; "" for
	// an IdP-initiated one, whose InResponseTo must then be empty.
	RequestID            string
	WantAssertionsSigned bool
	Now                  time.Time
	ClockSkew            time.Duration
	RequireTimestamps    bool
}

// CheckAssertion applies every rule that decides whether a verified
// response signs anyone in, and returns its one assertion:
//
//   - exactly one assertion, signed itself when WantAssertionsSigned and
//     otherwise covered by a signed Response;
//   - the Response's and the Assertion's Issuer are the IdP entity id;
//   - the Response's Destination, when present, is the ACS URL;
//   - InResponseTo, on the Response and the bearer confirmation, is the
//     request this browser started, or absent for an IdP-initiated one;
//   - an AudienceRestriction exists and every one names the audience;
//   - a bearer SubjectConfirmation whose Recipient is the ACS URL and whose
//     NotOnOrAfter has not passed;
//   - Conditions NotBefore has come and NotOnOrAfter has not passed, each
//     with ClockSkew, and both present under RequireTimestamps.
//
//ds:def id=checkassertion-8evwc35n owner=@khanakia stability=stable
func CheckAssertion(r *SAMLResponse, req CheckRequest) (SAMLAssertion, error) {
	switch {
	case len(r.Assertions) == 0:
		return SAMLAssertion{}, samlErr(SAMLNoAssertion, "no assertion")
	case len(r.Assertions) > 1:
		return SAMLAssertion{}, samlErr(SAMLMultipleAssertions, "%d assertions", len(r.Assertions))
	}
	a := r.Assertions[0]
	switch {
	case !a.Signed && (req.WantAssertionsSigned || !r.Signed):
		return SAMLAssertion{}, samlErr(SAMLAssertionSigRequired, "assertion %q is not signed", a.ID)
	case r.Issuer != "" && r.Issuer != req.IdPEntityID:
		return SAMLAssertion{}, samlErr(SAMLIssuerMismatch, "response issuer %q", r.Issuer)
	case a.Issuer != req.IdPEntityID:
		return SAMLAssertion{}, samlErr(SAMLIssuerMismatch, "assertion issuer %q", a.Issuer)
	case r.Destination != "" && r.Destination != req.ACSURL:
		return SAMLAssertion{}, samlErr(SAMLDestinationMismatch, "destination %q", r.Destination)
	case r.InResponseTo != req.RequestID:
		return SAMLAssertion{}, samlErr(SAMLInResponseToMismatch, "response InResponseTo %q", r.InResponseTo)
	}
	if len(a.Audiences) == 0 {
		return SAMLAssertion{}, samlErr(SAMLAudienceMissing, "no AudienceRestriction")
	}
	for _, aud := range a.Audiences {
		if !slices.Contains(aud, req.Audience) {
			return SAMLAssertion{}, samlErr(SAMLAudienceMismatch, "audiences %q, want %q", aud, req.Audience)
		}
	}
	now, skew := req.Now, req.ClockSkew
	bearer := false
	for _, sc := range a.Confirmations {
		if sc.Method != subjectBearer {
			continue
		}
		switch {
		case sc.Recipient != req.ACSURL:
			return SAMLAssertion{}, samlErr(SAMLRecipientMismatch, "recipient %q", sc.Recipient)
		case sc.InResponseTo != req.RequestID:
			return SAMLAssertion{}, samlErr(SAMLInResponseToMismatch, "confirmation InResponseTo %q", sc.InResponseTo)
		case sc.NotOnOrAfter.IsZero() || !now.Add(-skew).Before(sc.NotOnOrAfter):
			return SAMLAssertion{}, samlErr(SAMLExpired, "confirmation NotOnOrAfter %s", sc.NotOnOrAfter)
		case !sc.NotBefore.IsZero() && now.Add(skew).Before(sc.NotBefore):
			return SAMLAssertion{}, samlErr(SAMLNotYetValid, "confirmation NotBefore %s", sc.NotBefore)
		}
		bearer = true
	}
	if !bearer {
		return SAMLAssertion{}, samlErr(SAMLBearerMissing, "no bearer SubjectConfirmation")
	}
	if req.RequireTimestamps && (a.NotBefore.IsZero() || a.NotOnOrAfter.IsZero()) {
		return SAMLAssertion{}, samlErr(SAMLMissingTimestamps, "Conditions lack NotBefore or NotOnOrAfter")
	}
	if !a.NotBefore.IsZero() && now.Add(skew).Before(a.NotBefore) {
		return SAMLAssertion{}, samlErr(SAMLNotYetValid, "NotBefore %s", a.NotBefore)
	}
	if !a.NotOnOrAfter.IsZero() && !now.Add(-skew).Before(a.NotOnOrAfter) {
		return SAMLAssertion{}, samlErr(SAMLExpired, "NotOnOrAfter %s", a.NotOnOrAfter)
	}
	return a, nil
}

// subjectBearer is the bearer confirmation method.
const subjectBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

// RawFacts are what InspectResponse reads from the undecoded XML, before
// any signature check: how many assertions it holds anywhere in the tree,
// and every signature and digest algorithm it names.
type RawFacts struct {
	Assertions          int
	SignatureAlgorithms []string
	DigestAlgorithms    []string
	// KeyEncryption and DataEncryption are the EncryptionMethod algorithms
	// of an EncryptedKey and of the EncryptedData around it.
	KeyEncryption  []string
	DataEncryption []string
}

// InspectResponse decodes a base64 SAMLResponse and scans its XML. Counting
// assertions over the whole tree, not only where a parser expects them, is
// the defence in depth against signature wrapping: a wrapped response
// carries a second Assertion (or EncryptedAssertion) somewhere, and is
// refused here whatever the signature engine makes of it.
func InspectResponse(encoded string, maxSize int) ([]byte, RawFacts, error) {
	var f RawFacts
	if base64.StdEncoding.DecodedLen(len(encoded)) > maxSize+3 {
		return nil, f, samlErr(SAMLTooLarge, "response over %d bytes", maxSize)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
	if err != nil {
		return nil, f, samlErr(SAMLInvalidEncoding, "%v", err)
	}
	if len(raw) > maxSize {
		return nil, f, samlErr(SAMLTooLarge, "response over %d bytes", maxSize)
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var stack []string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, f, samlErr(SAMLInvalidXML, "%v", err)
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.StartElement:
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, t.Name.Local)
			switch {
			case (t.Name.Space == xmlEncNS || t.Name.Space == xmlEnc11NS) && t.Name.Local == "EncryptionMethod" && parent == encryptedKeyLocal:
				f.KeyEncryption = append(f.KeyEncryption, attr(t, "Algorithm"))
			case (t.Name.Space == xmlEncNS || t.Name.Space == xmlEnc11NS) && t.Name.Local == "EncryptionMethod":
				f.DataEncryption = append(f.DataEncryption, attr(t, "Algorithm"))
			case t.Name.Space == samlAssertionNS && (t.Name.Local == "Assertion" || t.Name.Local == "EncryptedAssertion"):
				f.Assertions++
			case t.Name.Space == xmlDSigNS && t.Name.Local == "SignatureMethod" && parent == "SignedInfo":
				f.SignatureAlgorithms = append(f.SignatureAlgorithms, attr(t, "Algorithm"))
			case t.Name.Space == xmlDSigNS && t.Name.Local == "DigestMethod" && parent == "Reference":
				f.DigestAlgorithms = append(f.DigestAlgorithms, attr(t, "Algorithm"))
			}
		case xml.Directive:
			// A DOCTYPE can define entities: no SAML message needs one.
			return nil, f, samlErr(SAMLInvalidXML, "a DTD is not allowed")
		}
	}
	switch {
	case f.Assertions == 0:
		return nil, f, samlErr(SAMLNoAssertion, "no assertion")
	case f.Assertions > 1:
		return nil, f, samlErr(SAMLMultipleAssertions, "%d assertions in the document", f.Assertions)
	}
	return raw, f, nil
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// CheckAlgorithms applies the algorithm policy to what a response names: an
// unknown algorithm is refused, an allow-list refuses everything else, and a
// SHA-1 one follows OnDeprecated (warn logs and continues).
func (o SAMLOptions) CheckAlgorithms(f RawFacts, warn func(alg string)) error {
	check := func(algs, known, allowed []string) error {
		for _, a := range algs {
			switch {
			case !slices.Contains(known, a):
				return samlErr(SAMLUnknownAlgorithm, "%q", a)
			case len(allowed) > 0 && !slices.Contains(allowed, a):
				return samlErr(SAMLAlgorithmNotAllowed, "%q", a)
			case slices.Contains(deprecatedAlgorithms, a) && o.OnDeprecated == DeprecatedReject:
				return samlErr(SAMLDeprecatedAlgorithm, "%q", a)
			case slices.Contains(deprecatedAlgorithms, a) && o.OnDeprecated == DeprecatedWarn:
				warn(a)
			}
		}
		return nil
	}
	for _, c := range []struct{ algs, known, allowed []string }{
		{f.SignatureAlgorithms, SignatureAlgorithms, o.AllowedSignatureAlgorithms},
		{f.DigestAlgorithms, DigestAlgorithms, o.AllowedDigestAlgorithms},
		{f.KeyEncryption, KeyEncryptionAlgorithms, o.AllowedKeyEncryptionAlgorithms},
		{f.DataEncryption, DataEncryptionAlgorithms, o.AllowedDataEncryptionAlgorithms},
	} {
		if err := check(c.algs, c.known, c.allowed); err != nil {
			return err
		}
	}
	return nil
}

// MapAttributes turns a verified assertion into UserInfo: the subject is
// the NameID (or the mapping's id attribute), the email the mapped
// attribute or an address-shaped NameID.
func MapAttributes(m SAMLMapping, a SAMLAssertion) UserInfo {
	first := func(name, def string) string {
		if vs := a.Attributes[firstOf(name, def)]; len(vs) > 0 {
			return strings.TrimSpace(vs[0])
		}
		return ""
	}
	info := UserInfo{Subject: a.NameID, Attributes: a.Attributes, SessionIndex: a.SessionIndex, NameID: a.NameID, NameIDFormat: a.NameIDFormat}
	if m.ID != "" {
		info.Subject = first(m.ID, "")
	}
	info.Email = strings.ToLower(first(m.Email, defaultSAMLEmail))
	if info.Email == "" && strings.Contains(a.NameID, "@") {
		info.Email = strings.ToLower(a.NameID)
	}
	if m.EmailVerified != "" {
		v := strings.ToLower(first(m.EmailVerified, ""))
		info.EmailVerified = v == "true" || v == "1"
	}
	info.Name = strings.TrimSpace(first(m.FirstName, defaultSAMLFirst) + " " + first(m.LastName, defaultSAMLLast))
	if info.Name == "" {
		info.Name = first(m.Name, defaultSAMLName)
	}
	if len(m.ExtraFields) > 0 {
		info.Extra = map[string]any{}
		for k, attrName := range m.ExtraFields {
			if vs, ok := a.Attributes[attrName]; ok {
				info.Extra[k] = vs
			}
		}
	}
	return info
}

// certPEM is the IdP certificate source: IdPMetadata.Cert, then Cert.
func (s SAMLConfig) certPEM() string { return firstOf(s.IdPMetadata.Cert, s.Cert) }

// spEntityID is the SP entity id: SPMetadata.EntityID, the custom
// metadata's, or the provider's issuer.
func (s SAMLConfig) spEntityID(pr Provider) string {
	pol, _ := DeriveSPPolicy(s.SPMetadata.Metadata, len(s.SPMetadata.Metadata)) // checked at registration
	return firstOf(s.SPMetadata.EntityID, pol.EntityID, pr.Issuer)
}

// audience is the expected AudienceRestriction value.
func (s SAMLConfig) audience(pr Provider) string { return firstOf(s.Audience, s.spEntityID(pr)) }

// parseCerts reads every CERTIFICATE block of a PEM string. A bare base64
// body (as metadata carries) is accepted too.
func parseCerts(s string) ([]*x509.Certificate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if !strings.Contains(s, "-----BEGIN") {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, err
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{c}, nil
	}
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// parseKey reads a PEM private key (PKCS #8, PKCS #1 or EC).
func parseKey(s string) (crypto.Signer, error) {
	b, _ := pem.Decode([]byte(s))
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if sg, ok := k.(crypto.Signer); ok {
			return sg, nil
		}
		return nil, errors.New("the key cannot sign")
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	return x509.ParseECPrivateKey(b.Bytes)
}

// idpMetadataXML is the part of IdP metadata the plugin reads.
type idpMetadataXML struct {
	XMLName  xml.Name `xml:"EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	IDPSSO   struct {
		Keys []struct {
			Use  string `xml:"use,attr"`
			Cert string `xml:"KeyInfo>X509Data>X509Certificate"`
		} `xml:"KeyDescriptor"`
		SSO []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleSignOnService"`
		SLO []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleLogoutService"`
	} `xml:"IDPSSODescriptor"`
}

// IdP returns the IdP's entity id, SSO URL and signing certificates,
// read from the metadata XML when set and from the written fields
// otherwise; fields written out win over metadata.
func (s SAMLConfig) IdP(maxMetadata int) (IdPSettings, error) {
	var out IdPSettings
	if md := s.IdPMetadata.Metadata; md != "" {
		if len(md) > maxMetadata {
			return out, fmt.Errorf("%w: IdP metadata over %d bytes", ErrBadProvider, maxMetadata)
		}
		if strings.Contains(md, "<!DOCTYPE") {
			return out, fmt.Errorf("%w: IdP metadata may not carry a DTD", ErrBadProvider)
		}
		var m idpMetadataXML
		if err := xml.Unmarshal([]byte(md), &m); err != nil {
			return out, fmt.Errorf("%w: IdP metadata: %v", ErrBadProvider, err)
		}
		out.EntityID = m.EntityID
		for _, k := range m.IDPSSO.Keys {
			if k.Use != "" && k.Use != "signing" {
				continue
			}
			cs, err := parseCerts(k.Cert)
			if err != nil {
				return out, fmt.Errorf("%w: IdP metadata certificate: %v", ErrBadProvider, err)
			}
			out.Certs = append(out.Certs, cs...)
		}
		for _, e := range m.IDPSSO.SSO {
			if e.Binding == BindingRedirect {
				out.SSOURL = e.Location
			}
		}
		for _, e := range m.IDPSSO.SLO {
			if e.Binding == BindingRedirect {
				out.SLOURL = e.Location
			}
		}
	}
	out.EntityID = firstOf(s.IdPMetadata.EntityID, out.EntityID)
	for _, e := range s.IdPMetadata.SingleSignOnService {
		if e.Binding == BindingRedirect || e.Binding == "" {
			out.SSOURL = e.Location
		}
	}
	for _, e := range s.IdPMetadata.SingleLogoutService {
		if e.Binding == BindingRedirect || e.Binding == "" {
			out.SLOURL = e.Location
		}
	}
	out.SSOURL = firstOf(out.SSOURL, s.EntryPoint)
	if pem := s.certPEM(); pem != "" {
		cs, err := parseCerts(pem)
		if err != nil {
			return out, fmt.Errorf("%w: cert: %v", ErrBadProvider, err)
		}
		out.Certs = cs
	}
	return out, nil
}

// checkSAMLShape checks a SAML config without the network.
func (p *Plugin) checkSAMLShape(pr Provider) error {
	s := pr.SAML
	idp, err := s.IdP(p.saml.MaxMetadataSize)
	switch {
	case err != nil:
		return err
	case idp.EntityID == "":
		return fmt.Errorf("%w: idpMetadata.entityID is required when IdP metadata XML is not provided", ErrBadProvider)
	case idp.SSOURL == "":
		return fmt.Errorf("%w: samlConfig needs entryPoint, idpMetadata.singleSignOnService or IdP metadata", ErrBadProvider)
	case len(idp.Certs) == 0:
		return &SAMLError{Code: SAMLCertificateUnavailable, Err: fmt.Errorf("%w: no IdP signing certificate", ErrBadProvider)}
	case s.AuthnRequestsSigned && (s.PrivateKey == "" || s.SPCertificate == ""):
		return fmt.Errorf("%w: authnRequestsSigned needs privateKey and spCertificate", ErrBadProvider)
	case s.SignatureAlgorithm != "" && !slices.Contains(SignatureAlgorithms, normalizeAlg(s.SignatureAlgorithm)):
		return fmt.Errorf("%w: signatureAlgorithm %q", ErrBadProvider, s.SignatureAlgorithm)
	case s.DigestAlgorithm != "" && !slices.Contains(DigestAlgorithms, s.DigestAlgorithm):
		return fmt.Errorf("%w: digestAlgorithm %q", ErrBadProvider, s.DigestAlgorithm)
	case s.SignatureAlgorithm != "" && slices.Contains(deprecatedAlgorithms, normalizeAlg(s.SignatureAlgorithm)) && p.saml.OnDeprecated == DeprecatedReject:
		return fmt.Errorf("%w: signatureAlgorithm %q is deprecated", ErrBadProvider, s.SignatureAlgorithm)
	}
	sp, err := p.spSettings(pr)
	if err != nil {
		return err
	}
	if b := s.SPMetadata.Binding; b != "" && b != AuthnBindingRedirect && b != AuthnBindingPOST {
		return fmt.Errorf("%w: spMetadata.binding %q: use %q or %q", ErrBadProvider, b, AuthnBindingRedirect, AuthnBindingPOST)
	}
	if err := s.checkDigest(); err != nil {
		return err
	}
	pol, err := DeriveSPPolicy(s.SPMetadata.Metadata, p.saml.MaxMetadataSize)
	switch {
	case err != nil:
		return err
	case s.SPMetadata.Metadata == "":
		return nil
	case s.SPMetadata.EntityID != "" && pol.EntityID != s.SPMetadata.EntityID:
		return fmt.Errorf("%w: entity id %q, spMetadata.entityID %q", ErrSPMetadataMismatch, pol.EntityID, s.SPMetadata.EntityID)
	case s.WantAssertionsSigned && !pol.WantAssertionsSigned:
		return fmt.Errorf("%w: WantAssertionsSigned", ErrSPMetadataMismatch)
	case !slices.Contains(pol.ACSURLs, sp.ACSURL):
		return fmt.Errorf("%w: no HTTP-POST AssertionConsumerService at %s", ErrSPMetadataMismatch, sp.ACSURL)
	}
	return nil
}

// checkDigest refuses a DigestAlgorithm that would have no effect: a
// digest exists only in the enveloped signature of a signed POST-binding
// AuthnRequest, and the signing library digests with the signature's own
// hash, so the digest must be that one. A setting that silently did
// nothing would let an admin believe SHA-512 was in use when it was not.
func (s SAMLConfig) checkDigest() error {
	if s.DigestAlgorithm == "" {
		return nil
	}
	sig := firstOf(normalizeAlg(s.SignatureAlgorithm), AlgRSASHA256)
	switch {
	case !s.AuthnRequestsSigned || s.SPMetadata.Binding != AuthnBindingPOST:
		return fmt.Errorf("%w: digestAlgorithm applies only to signed AuthnRequests over the POST binding (authnRequestsSigned and spMetadata.binding \"post\")", ErrBadProvider)
	case digestOf[sig] != s.DigestAlgorithm:
		return fmt.Errorf("%w: digestAlgorithm %q must be %q, the hash of signatureAlgorithm %q", ErrBadProvider, s.DigestAlgorithm, digestOf[sig], sig)
	}
	return nil
}

// normalizeAlg maps a short algorithm name to its URI.
func normalizeAlg(a string) string {
	if u, ok := shortAlgorithms[strings.ToLower(a)]; ok {
		return u
	}
	return a
}

// prepareSAML checks the URLs a SAML provider names. It runs after
// checkShape, which already refused a config whose IdP settings do not read.
func (p *Plugin) prepareSAML(pr *Provider) error {
	idp, _ := pr.SAML.IdP(p.saml.MaxMetadataSize) // checked by checkShape
	return p.checkURL(idp.SSOURL)
}

// spSettings builds this app's SAML settings for pr.
func (p *Plugin) spSettings(pr Provider) (SPSettings, error) {
	s := pr.SAML
	pol, _ := DeriveSPPolicy(s.SPMetadata.Metadata, p.saml.MaxMetadataSize) // checked at registration
	sp := SPSettings{EntityID: s.spEntityID(pr), ACSURL: p.acsURLFor(pr.ProviderID), Audience: s.audience(pr), NameIDFormat: firstOf(s.IdentifierFormat, pol.NameIDFormat),
		AuthnRequestsSigned: s.AuthnRequestsSigned, SignatureAlgorithm: firstOf(normalizeAlg(s.SignatureAlgorithm), AlgRSASHA256),
		WantAssertionsSigned: s.WantAssertionsSigned || pol.WantAssertionsSigned, MaxResponseSize: p.saml.MaxResponseSize, CustomMetadata: s.SPMetadata.Metadata,
		POSTBinding: s.SPMetadata.Binding == AuthnBindingPOST}
	if p.saml.EnableSingleLogout {
		sp.SLOURL = p.sloURLFor(pr.ProviderID)
	}
	if s.PrivateKey != "" {
		k, err := parseKey(s.PrivateKey)
		if err != nil {
			return sp, fmt.Errorf("%w: privateKey: %v", ErrBadProvider, err)
		}
		sp.SigningKey, sp.DecryptionKey = k, k
	}
	if s.SPCertificate != "" {
		cs, err := parseCerts(s.SPCertificate)
		if err != nil || len(cs) == 0 {
			return sp, fmt.Errorf("%w: spCertificate", ErrBadProvider)
		}
		sp.Certificate, sp.DecryptionCert = cs[0], cs[0]
	}
	if s.DecryptionKey != "" {
		k, err := parseKey(s.DecryptionKey)
		if err != nil {
			return sp, fmt.Errorf("%w: decryptionKey: %v", ErrBadProvider, err)
		}
		cs, err := parseCerts(s.DecryptionCertificate)
		if err != nil || len(cs) == 0 {
			return sp, fmt.Errorf("%w: decryptionKey needs decryptionCertificate", ErrBadProvider)
		}
		sp.DecryptionKey, sp.DecryptionCert = k, cs[0]
	}
	return sp, nil
}

// startSAML stores the request and relay rows and returns the IdP URL, or
// for the POST binding the form to post.
func (p *Plugin) startSAML(ctx context.Context, c *auth.Call, pr Provider, meta flowMeta) (string, *PostForm, error) {
	sp, err := p.spSettings(pr)
	if err != nil {
		return "", nil, err
	}
	idp, err := pr.SAML.IdP(p.saml.MaxMetadataSize)
	if err != nil {
		return "", nil, err
	}
	sp.Now = c.Auth.Now()
	meta.RequestID = samlRequestIDPrefix + auth.NewToken().Reveal()
	if err := c.Auth.IssueVerificationToken(ctx, PurposeSAMLRequest, pr.ProviderID, auth.Token(meta.RequestID), p.saml.RequestTTL, ""); err != nil {
		return "", nil, err
	}
	relay, err := c.Auth.IssueVerification(ctx, PurposeSAMLRelay, pr.ProviderID, p.saml.RequestTTL, meta.encode())
	if err != nil {
		return "", nil, err
	}
	if sp.POSTBinding {
		form, err := p.engine.AuthnRequestPOST(sp, idp, meta.RequestID, relay.Reveal())
		if err != nil {
			return "", nil, p.providerFailure(c, pr, err)
		}
		return form.Action, &form, nil
	}
	u, err := p.engine.AuthnRequestURL(sp, idp, meta.RequestID, relay.Reveal())
	if err != nil {
		return "", nil, p.providerFailure(c, pr, err)
	}
	return u, nil, nil
}

// ACSRequest is the IdP's POST to the assertion consumer service.
type ACSRequest struct {
	SAMLResponse string `json:"SAMLResponse"`
	RelayState   string `json:"RelayState,omitempty"`
	// ProviderID is set by ProviderPaths from a per-provider ACS URL.
	ProviderID string `json:"providerId,omitempty"`
}

func (p *Plugin) doACS(ctx context.Context, c *auth.Call, in ACSRequest) (CallbackResult, error) {
	c.RedirectOnError(p.errorURL)
	if in.SAMLResponse == "" {
		return CallbackResult{}, samlErr(SAMLInvalidEncoding, "no SAMLResponse")
	}
	meta, pr, err := p.acsTarget(ctx, c, in.RelayState, in.ProviderID)
	if err != nil {
		return CallbackResult{}, p.samlFailure(c, "", err)
	}
	if meta.ErrorTo != "" {
		c.RedirectOnError(meta.ErrorTo)
	}
	info, issuer, err := p.verifySAML(ctx, c, pr, in.SAMLResponse, meta)
	if err != nil {
		return CallbackResult{}, p.samlFailure(c, pr.ProviderID, err)
	}
	return p.complete(ctx, c, pr, ProtocolSAML, issuer, info, meta)
}

// samlFailure logs a refused response with its code.
func (p *Plugin) samlFailure(c *auth.Call, providerID string, err error) error {
	var se *SAMLError
	if errors.As(err, &se) {
		c.Auth.Logger().Warn("sso: saml response refused", "provider", providerID, "code", se.Code, "error", se.Err)
	}
	return err
}

// acsTarget resolves the flow of an ACS post. A RelayState this plugin
// issued names an SP-initiated flow, consumed once. Anything else is an
// IdP-initiated sign-in, whose RelayState may name the provider id (the
// IdP's "default relay state"); it is accepted only where allowed.
func (p *Plugin) acsTarget(ctx context.Context, c *auth.Call, relay, urlProvider string) (flowMeta, Provider, error) {
	if relay != "" {
		v, err := c.Auth.ConsumeVerification(ctx, PurposeSAMLRelay, auth.Token(relay))
		switch {
		case err == nil:
			var meta flowMeta
			if json.Unmarshal([]byte(v.Meta), &meta) != nil || meta.Provider != v.Identifier {
				return flowMeta{}, Provider{}, ErrStateInvalid
			}
			pr, err := p.ProviderByID(ctx, meta.Provider)
			if err != nil || pr.SAML == nil {
				return flowMeta{}, Provider{}, ErrStateInvalid
			}
			if subtle.ConstantTimeCompare([]byte(pr.Reference()), []byte(meta.Reference)) != 1 {
				return flowMeta{}, Provider{}, ErrProviderChanged
			}
			if urlProvider != "" && urlProvider != meta.Provider {
				return flowMeta{}, Provider{}, ErrStateInvalid
			}
			return meta, pr, nil
		case !errors.Is(err, auth.ErrTokenInvalid):
			return flowMeta{}, Provider{}, err
		}
	}
	target := firstOf(urlProvider, relay)
	if !providerIDPattern.MatchString(target) {
		return flowMeta{}, Provider{}, samlErr(SAMLUnsolicited, "no relay state this app issued and no provider id")
	}
	pr, err := p.ProviderByID(ctx, target)
	if err != nil || pr.SAML == nil {
		return flowMeta{}, Provider{}, samlErr(SAMLUnsolicited, "relay state names no SAML provider")
	}
	if !p.saml.AllowIdPInitiated && !pr.SAML.AllowIdPInitiated {
		return flowMeta{}, Provider{}, samlErr(SAMLUnsolicited, "IdP-initiated sign-in is not allowed for %q", pr.ProviderID)
	}
	if p.domain != nil && !pr.Default && !pr.DomainVerified {
		return flowMeta{}, Provider{}, ErrDomainUnverified
	}
	landing := firstOf(pr.SAML.IdPInitiatedCallbackURL, p.saml.IdPInitiatedCallbackURL, pr.SAML.CallbackURL, siteRoot)
	if !p.core.TrustsReturnURL(landing) {
		landing = siteRoot
	}
	return flowMeta{Provider: pr.ProviderID, Reference: pr.Reference(), Protocol: ProtocolSAML, ReturnTo: landing, initiated: true}, pr, nil
}

// verifySAML runs the raw scan, the algorithm policy, the engine's
// signature check, CheckAssertion, the InResponseTo consumption and the
// replay reservation, in that order, and maps the assertion.
func (p *Plugin) verifySAML(ctx context.Context, c *auth.Call, pr Provider, encoded string, meta flowMeta) (UserInfo, string, error) {
	_, facts, err := InspectResponse(encoded, p.saml.MaxResponseSize)
	if err != nil {
		return UserInfo{}, "", err
	}
	if err := p.saml.CheckAlgorithms(facts, func(alg string) {
		c.Auth.Logger().Warn("sso: saml response uses a deprecated algorithm", "provider", pr.ProviderID, "algorithm", alg)
	}); err != nil {
		return UserInfo{}, "", err
	}
	sp, err := p.spSettings(pr)
	if err != nil {
		return UserInfo{}, "", err
	}
	idp, err := pr.SAML.IdP(p.saml.MaxMetadataSize)
	if err != nil {
		return UserInfo{}, "", err
	}
	now := c.Auth.Now()
	// The engine's own expiry checks have no tolerance; it runs ClockSkew
	// behind, and CheckAssertion applies the window in both directions.
	res, err := p.engine.VerifyResponse(sp, idp, encoded, now.Add(-p.saml.ClockSkew))
	if err != nil {
		return UserInfo{}, "", &SAMLError{Code: SAMLSignatureInvalid, Err: err}
	}
	reqID := meta.RequestID
	if p.saml.SkipInResponseTo && !meta.initiated {
		reqID = res.InResponseTo
	}
	a, err := CheckAssertion(res, CheckRequest{IdPEntityID: idp.EntityID, Audience: sp.Audience, ACSURL: sp.ACSURL, RequestID: reqID,
		WantAssertionsSigned: sp.WantAssertionsSigned, Now: now, ClockSkew: p.saml.ClockSkew, RequireTimestamps: p.saml.RequireTimestamps})
	if err != nil {
		return UserInfo{}, "", err
	}
	if !meta.initiated && !p.saml.SkipInResponseTo {
		// The request ID is spent here, once: a second response to the
		// same request is refused even with a fresh assertion ID.
		v, err := c.Auth.ConsumeVerification(ctx, PurposeSAMLRequest, auth.Token(meta.RequestID))
		if errors.Is(err, auth.ErrTokenInvalid) || (err == nil && v.Identifier != pr.ProviderID) {
			return UserInfo{}, "", samlErr(SAMLUnknownRequest, "unknown or expired request ID")
		}
		if err != nil {
			return UserInfo{}, "", err
		}
	}
	if err := p.reserveAssertion(ctx, c, pr, a, now); err != nil {
		return UserInfo{}, "", err
	}
	if !p.saml.RequireTimestamps && (a.NotBefore.IsZero() || a.NotOnOrAfter.IsZero()) {
		c.Auth.Logger().Warn("sso: saml assertion without NotBefore/NotOnOrAfter", "provider", pr.ProviderID)
	}
	info := MapAttributes(pr.SAML.Mapping, a)
	if !p.trustEmailVerified {
		info.EmailVerified = false
	}
	if info.Subject == "" {
		return UserInfo{}, "", samlErr(SAMLMissingSubjectOrEmail, "no NameID")
	}
	return info, idp.EntityID, nil
}

// reserveAssertion records the assertion's ID until it expires (plus the
// skew), so the same assertion is accepted once: the verification store
// refuses a second token with the same hash. An assertion without an
// expiry is reserved for DefaultReplayWindow.
func (p *Plugin) reserveAssertion(ctx context.Context, c *auth.Call, pr Provider, a SAMLAssertion, now time.Time) error {
	if a.ID == "" {
		return samlErr(SAMLInvalidXML, "assertion has no ID")
	}
	until := a.NotOnOrAfter
	for _, sc := range a.Confirmations {
		if sc.NotOnOrAfter.After(until) {
			until = sc.NotOnOrAfter
		}
	}
	ttl := DefaultReplayWindow
	if !until.IsZero() {
		ttl = until.Add(p.saml.ClockSkew).Sub(now)
	}
	key := auth.Token(pr.ProviderID + "\x00" + a.ID)
	err := c.Auth.IssueVerificationToken(ctx, PurposeSAMLAssertion, pr.ProviderID, key, ttl, "")
	if err != nil && auth.IsUniqueViolation(err) {
		return samlErr(SAMLReplay, "assertion %q was already used", a.ID)
	}
	return err
}

// MetadataResult is SP metadata XML.
type MetadataResult struct {
	XML string `json:"metadata"`
}

func (p *Plugin) doMetadata(ctx context.Context, c *auth.Call, in ProviderRequest) (MetadataResult, error) {
	pr, err := p.ProviderByID(ctx, in.ProviderID)
	if err != nil {
		return MetadataResult{}, err
	}
	if pr.SAML == nil {
		return MetadataResult{}, ErrProtocol
	}
	sp, err := p.spSettings(pr)
	if err != nil {
		return MetadataResult{}, err
	}
	md, err := SPMetadataXML(sp)
	if err != nil {
		return MetadataResult{}, err
	}
	return MetadataResult{XML: string(md)}, nil
}

// spEntityDescriptor is the SP metadata document.
type spEntityDescriptor struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	SP       struct {
		AuthnRequestsSigned  bool   `xml:"AuthnRequestsSigned,attr"`
		WantAssertionsSigned bool   `xml:"WantAssertionsSigned,attr"`
		Protocols            string `xml:"protocolSupportEnumeration,attr"`
		Keys                 []struct {
			Use  string `xml:"use,attr"`
			Cert string `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo>X509Data>X509Certificate"`
		} `xml:"KeyDescriptor"`
		SLO []struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
		} `xml:"SingleLogoutService"`
		NameIDFormat string `xml:"NameIDFormat,omitempty"`
		ACS          struct {
			Binding  string `xml:"Binding,attr"`
			Location string `xml:"Location,attr"`
			Index    int    `xml:"index,attr"`
		} `xml:"AssertionConsumerService"`
	} `xml:"SPSSODescriptor"`
}

// SPMetadataXML renders this app's metadata for one provider: entity id,
// POST ACS, the NameID format, the signing and encryption certificate when
// set, and the two signing flags.
func SPMetadataXML(sp SPSettings) ([]byte, error) {
	if sp.CustomMetadata != "" {
		return []byte(sp.CustomMetadata), nil
	}
	var d spEntityDescriptor
	d.EntityID = sp.EntityID
	d.SP.AuthnRequestsSigned, d.SP.WantAssertionsSigned = sp.AuthnRequestsSigned, sp.WantAssertionsSigned
	d.SP.Protocols = samlProtocolNS
	d.SP.NameIDFormat = sp.NameIDFormat
	d.SP.ACS.Binding, d.SP.ACS.Location, d.SP.ACS.Index = BindingPOST, sp.ACSURL, 1
	if sp.SLOURL != "" {
		for _, b := range []string{BindingRedirect, BindingPOST} {
			d.SP.SLO = append(d.SP.SLO, struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
			}{b, sp.SLOURL})
		}
	}
	type key = struct {
		Use  string `xml:"use,attr"`
		Cert string `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo>X509Data>X509Certificate"`
	}
	if sp.Certificate != nil {
		d.SP.Keys = append(d.SP.Keys, key{"signing", base64.StdEncoding.EncodeToString(sp.Certificate.Raw)})
	}
	if sp.DecryptionCert != nil {
		d.SP.Keys = append(d.SP.Keys, key{"encryption", base64.StdEncoding.EncodeToString(sp.DecryptionCert.Raw)})
	}
	out, err := xml.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}
