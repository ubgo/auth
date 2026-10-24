package sso

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
)

// GoSAML2 is the default SAMLEngine, on github.com/russellhaering/gosaml2
// and its XML-signature library goxmldsig.
//
// Why this library: it keeps every setting on a per-provider struct (no
// package-level clock or skew, which crewjam/saml has), it returns only
// the content its signature check covered (the unverified element is
// replaced by the verified one, the defence against signature wrapping),
// it bounds decompression and XML token counts, and it is fuzzed in
// OSS-Fuzz. It is built per call from the provider's settings and holds no
// state.
type GoSAML2 struct{}

// serviceProvider builds the library's settings at the clock now (the
// plugin passes its time less the clock skew, since the library's own
// expiry check has no tolerance).
func (GoSAML2) serviceProvider(sp SPSettings, idp IdPSettings, now time.Time) (*saml2.SAMLServiceProvider, error) {
	s := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL: idp.SSOURL, IdentityProviderSSOBinding: BindingRedirect, IdentityProviderIssuer: idp.EntityID,
		AssertionConsumerServiceURL: sp.ACSURL, ServiceProviderIssuer: sp.EntityID, AudienceURI: sp.Audience,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{Roots: idp.Certs}, NameIdFormat: sp.NameIDFormat,
		SignAuthnRequests: sp.AuthnRequestsSigned, SignAuthnRequestsAlgorithm: sp.SignatureAlgorithm,
		AllowMissingAttributes: true, Clock: dsig.NewFakeClockAt(now),
		MaximumDecompressedBodySize: int64(sp.MaxResponseSize),
	}
	if sp.DecryptionKey != nil && sp.DecryptionCert != nil {
		// The decryption path of gosaml2 v0.12.0 reads only the SPKeyStore
		// field (getDecryptCert ignores SetSPKeyStore), so the key goes
		// there, as a TLS certificate. Pinned by
		// TestSAML_EncryptedAssertionDecrypts.
		s.SPKeyStore = dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{sp.DecryptionCert.Raw}, PrivateKey: sp.DecryptionKey})
	}
	if sp.AuthnRequestsSigned {
		if sp.SigningKey == nil || sp.Certificate == nil {
			return nil, errors.New("sso: signed AuthnRequests need a key and certificate")
		}
		// SetSPSigningKeyStore fails only on a nil signer, refused above.
		_ = s.SetSPSigningKeyStore(&saml2.KeyStore{Signer: sp.SigningKey, Cert: sp.Certificate.Raw})
	}
	return s, nil
}

// issueAt is the instant an AuthnRequest is issued at: sp.Now, which the
// plugin sets from the core's clock, or the wall clock for a caller that
// builds SPSettings by hand and leaves it zero.
func (sp SPSettings) issueAt() time.Time {
	if sp.Now.IsZero() {
		return time.Now()
	}
	return sp.Now
}

// AuthnRequestURL builds the HTTP-Redirect URL of an AuthnRequest whose ID
// is requestID; the library signs the query when asked.
func (g GoSAML2) AuthnRequestURL(sp SPSettings, idp IdPSettings, requestID, relayState string) (string, error) {
	s, err := g.serviceProvider(sp, idp, sp.issueAt())
	if err != nil {
		return "", err
	}
	doc, err := s.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return "", err
	}
	doc.Root().CreateAttr("ID", requestID)
	return s.BuildAuthURLRedirect(relayState, doc)
}

// AuthnRequestPOST builds the POST-binding form of an AuthnRequest whose
// ID is requestID, with an enveloped signature when asked.
func (g GoSAML2) AuthnRequestPOST(sp SPSettings, idp IdPSettings, requestID, relayState string) (PostForm, error) {
	s, err := g.serviceProvider(sp, idp, sp.issueAt())
	if err != nil {
		return PostForm{}, err
	}
	doc, err := s.BuildAuthRequestDocumentNoSig()
	if err != nil {
		return PostForm{}, err
	}
	doc.Root().CreateAttr("ID", requestID)
	if sp.AuthnRequestsSigned {
		signed, err := s.SignAuthnRequest(doc.Root())
		if err != nil {
			return PostForm{}, err
		}
		doc.SetRoot(signed)
	}
	b, _ := doc.WriteToBytes() // writing to memory cannot fail
	return PostForm{Action: idp.SSOURL, SAMLRequest: base64.StdEncoding.EncodeToString(b), RelayState: relayState}, nil
}

// VerifyResponse verifies the signature and returns the verified content.
// The library's own audience and time checks are warnings it leaves to the
// caller; CheckAssertion applies them.
func (g GoSAML2) VerifyResponse(sp SPSettings, idp IdPSettings, samlResponse string, now time.Time) (*SAMLResponse, error) {
	s, err := g.serviceProvider(sp, idp, now)
	if err != nil {
		return nil, err
	}
	res, err := s.ValidateEncodedResponse(samlResponse)
	if err != nil {
		return nil, err
	}
	out := &SAMLResponse{ID: res.ID, InResponseTo: res.InResponseTo, Destination: res.Destination, Signed: res.SignatureValidated}
	if res.Issuer != nil {
		out.Issuer = res.Issuer.Value
	}
	if len(res.EncryptedAssertions) > 0 {
		// The library decrypts into Assertions; an encrypted one left over
		// was not decrypted, so nothing about it is verified.
		return nil, errors.New("sso: an encrypted assertion could not be decrypted")
	}
	for _, a := range res.Assertions {
		sa, err := convertAssertion(a)
		if err != nil {
			return nil, err
		}
		out.Assertions = append(out.Assertions, sa)
	}
	return out, nil
}

// convertAssertion copies a verified library assertion.
func convertAssertion(a types.Assertion) (SAMLAssertion, error) {
	out := SAMLAssertion{ID: a.ID, Signed: a.SignatureValidated, Attributes: map[string][]string{}}
	if a.Issuer != nil {
		out.Issuer = a.Issuer.Value
	}
	if s := a.Subject; s != nil {
		if s.NameID != nil {
			out.NameID, out.NameIDFormat = s.NameID.Value, s.NameID.Format
		}
		if sc := s.SubjectConfirmation; sc != nil {
			c := SubjectConfirmation{Method: sc.Method}
			if d := sc.SubjectConfirmationData; d != nil {
				c.Recipient, c.InResponseTo = d.Recipient, d.InResponseTo
				t, err := parseSAMLTime(d.NotOnOrAfter)
				if err != nil {
					return out, err
				}
				c.NotOnOrAfter = t
			}
			out.Confirmations = append(out.Confirmations, c)
		}
	}
	if c := a.Conditions; c != nil {
		out.HasConditions = true
		var err error
		if out.NotBefore, err = parseSAMLTime(c.NotBefore); err != nil {
			return out, err
		}
		if out.NotOnOrAfter, err = parseSAMLTime(c.NotOnOrAfter); err != nil {
			return out, err
		}
		for _, ar := range c.AudienceRestrictions {
			var auds []string
			for _, au := range ar.Audiences {
				auds = append(auds, au.Value)
			}
			out.Audiences = append(out.Audiences, auds)
		}
	}
	if as := a.AttributeStatement; as != nil {
		for _, at := range as.Attributes {
			for _, v := range at.Values {
				out.Attributes[at.Name] = append(out.Attributes[at.Name], v.Value)
			}
		}
	}
	if a.AuthnStatement != nil {
		out.SessionIndex = a.AuthnStatement.SessionIndex
	}
	return out, nil
}

// parseSAMLTime parses an xs:dateTime; "" is the zero time.
func parseSAMLTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, &SAMLError{Code: SAMLInvalidXML, Err: fmt.Errorf("timestamp %q: %w", s, err)}
	}
	return t, nil
}
