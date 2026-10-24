package sso

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // RSA-SHA1 verifies only under OnDeprecated warn or allow; never chosen for signing
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Logout message kinds.
const (
	KindLogoutRequest  = "LogoutRequest"
	KindLogoutResponse = "LogoutResponse"
	paramSAMLRequest   = "SAMLRequest"
	paramSAMLResponse  = "SAMLResponse"
	paramRelayState    = "RelayState"
	paramSigAlg        = "SigAlg"
	paramSignature     = "Signature"
	// StatusSuccess is the SAML success status.
	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
	// statusResponder is the status of a logout this SP could not complete.
	statusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
)

// LogoutMessage is a LogoutRequest or LogoutResponse, after its signature
// was checked (Signed says whether it carried one).
type LogoutMessage struct {
	Kind           string
	ID             string
	InResponseTo   string
	Issuer         string
	Destination    string
	NameID         string
	NameIDFormat   string
	SessionIndexes []string
	NotOnOrAfter   time.Time
	Status         string
	Signed         bool
}

// BindingMessage is a SAML message as it arrived: the redirect binding's
// query values, or the POST binding's form values.
type BindingMessage struct {
	// Redirect is true for HTTP-Redirect (deflated, query-signed), false
	// for HTTP-POST (enveloped XML signature).
	Redirect   bool
	Value      string
	Param      string
	RelayState string
	SigAlg     string
	Signature  string
}

// errLogoutSignature is a logout message whose signature did not verify.
var errLogoutSignature = errors.New("sso: logout signature does not verify")

// DecodeLogout reads a logout message and checks its signature against
// the IdP's certificates: the query signature for the redirect binding,
// the enveloped XML signature for POST, whose verified element is the only
// content read. An unsigned message comes back with Signed false; the
// caller decides whether that is acceptable. maxSize bounds the XML.
func DecodeLogout(m BindingMessage, certs []*x509.Certificate, now time.Time, maxSize int) (*LogoutMessage, error) {
	root, err := readLogoutXML(m, maxSize)
	if err != nil {
		return nil, err
	}
	signed := false
	switch {
	case m.Redirect && m.Signature != "":
		if err := verifyQuerySignature(m, certs); err != nil {
			return nil, samlErr(SAMLSignatureInvalid, "%v", err)
		}
		signed = true
	case !m.Redirect:
		vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
		vc.Clock = dsig.NewFakeClockAt(now)
		verified, err := vc.Validate(root)
		switch {
		case err == nil:
			root, signed = verified, true
		case !errors.Is(err, dsig.ErrMissingSignature):
			return nil, samlErr(SAMLSignatureInvalid, "%v", err)
		}
	}
	out, err := parseLogout(root)
	if err != nil {
		return nil, err
	}
	out.Signed = signed
	return out, nil
}

// PeekLogout reads a logout message without checking its signature, only
// to learn which provider's certificates must check it.
func PeekLogout(m BindingMessage, maxSize int) (*LogoutMessage, error) {
	root, err := readLogoutXML(m, maxSize)
	if err != nil {
		return nil, err
	}
	return parseLogout(root)
}

// readLogoutXML decodes (and for the redirect binding inflates) a logout
// message, bounded and with no DTD.
func readLogoutXML(m BindingMessage, maxSize int) (*etree.Element, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(m.Value), ""))
	if err != nil {
		return nil, samlErr(SAMLInvalidEncoding, "%v", err)
	}
	if m.Redirect {
		if raw, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), int64(maxSize)+1)); err != nil {
			return nil, samlErr(SAMLInvalidEncoding, "inflate: %v", err)
		}
	}
	if len(raw) > maxSize {
		return nil, samlErr(SAMLTooLarge, "logout message over %d bytes", maxSize)
	}
	if bytes.Contains(raw, []byte("<!DOCTYPE")) {
		return nil, samlErr(SAMLInvalidXML, "a DTD is not allowed")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, samlErr(SAMLInvalidXML, "%v", err)
	}
	return doc.Root(), nil
}

// logoutXML is the part of a logout message the plugin reads.
type logoutXML struct {
	XMLName      xml.Name
	ID           string   `xml:"ID,attr"`
	InResponseTo string   `xml:"InResponseTo,attr"`
	Destination  string   `xml:"Destination,attr"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr"`
	Issuer       string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	SessionIndex []string `xml:"urn:oasis:names:tc:SAML:2.0:protocol SessionIndex"`
	NameID       struct {
		Format string `xml:"Format,attr"`
		Value  string `xml:",chardata"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Status struct {
		Code struct {
			Value string `xml:"Value,attr"`
		} `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
}

func parseLogout(el *etree.Element) (*LogoutMessage, error) {
	d := etree.NewDocument()
	d.SetRoot(el.Copy())
	b, _ := d.WriteToBytes() // writing to memory cannot fail
	var x logoutXML
	if err := xml.Unmarshal(b, &x); err != nil {
		return nil, samlErr(SAMLInvalidXML, "%v", err)
	}
	if x.XMLName.Space != samlProtocolNS || (x.XMLName.Local != KindLogoutRequest && x.XMLName.Local != KindLogoutResponse) {
		return nil, samlErr(SAMLInvalidXML, "not a logout message: %s", x.XMLName.Local)
	}
	nooa, err := parseSAMLTime(x.NotOnOrAfter)
	if err != nil {
		return nil, err
	}
	return &LogoutMessage{Kind: x.XMLName.Local, ID: x.ID, InResponseTo: x.InResponseTo, Issuer: strings.TrimSpace(x.Issuer),
		Destination: x.Destination, NameID: strings.TrimSpace(x.NameID.Value), NameIDFormat: x.NameID.Format,
		SessionIndexes: x.SessionIndex, NotOnOrAfter: nooa, Status: x.Status.Code.Value}, nil
}

// hashFor returns the hash of a signature algorithm.
func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgRSASHA1:
		return crypto.SHA1, nil
	case AlgRSASHA256, AlgECDSASHA256:
		return crypto.SHA256, nil
	case AlgRSASHA384, AlgECDSASHA384:
		return crypto.SHA384, nil
	case AlgRSASHA512, AlgECDSASHA512:
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unknown signature algorithm %q", alg)
}

// signedQuery is the octet string a redirect-binding signature covers
// (SAML bindings 3.4.4.1): the parameters in this order, each URL-encoded.
func signedQuery(param, value, relay, sigAlg string) string {
	s := param + "=" + url.QueryEscape(value)
	if relay != "" {
		s += "&" + paramRelayState + "=" + url.QueryEscape(relay)
	}
	return s + "&" + paramSigAlg + "=" + url.QueryEscape(sigAlg)
}

// verifyQuerySignature checks a redirect-binding signature with any of
// certs. The query is re-encoded from its decoded values, which matches
// every IdP that encodes as RFC 3986 does.
func verifyQuerySignature(m BindingMessage, certs []*x509.Certificate) error {
	h, err := hashFor(m.SigAlg)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return err
	}
	hh := h.New()
	hh.Write([]byte(signedQuery(m.Param, m.Value, m.RelayState, m.SigAlg)))
	sum := hh.Sum(nil)
	for _, c := range certs {
		switch pub := c.PublicKey.(type) {
		case *rsa.PublicKey:
			if rsa.VerifyPKCS1v15(pub, h, sum, sig) == nil {
				return nil
			}
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(pub, sum, sig) {
				return nil
			}
		}
	}
	return errLogoutSignature
}

// RedirectURL encodes a message for the HTTP-Redirect binding at dest,
// signing the query when key is set.
func RedirectURL(dest, param string, msg *etree.Document, relay string, key crypto.Signer, sigAlg string) (string, error) {
	// Writing to memory cannot fail, and NewWriter fails only on a bad level.
	raw, _ := msg.WriteToBytes()
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	value := base64.StdEncoding.EncodeToString(buf.Bytes())
	q := param + "=" + url.QueryEscape(value)
	if relay != "" {
		q += "&" + paramRelayState + "=" + url.QueryEscape(relay)
	}
	if key != nil {
		h, err := hashFor(sigAlg)
		if err != nil {
			return "", err
		}
		hh := h.New()
		hh.Write([]byte(signedQuery(param, value, relay, sigAlg)))
		sig, err := key.Sign(rand.Reader, hh.Sum(nil), h)
		if err != nil {
			return "", err
		}
		q += "&" + paramSigAlg + "=" + url.QueryEscape(sigAlg) + "&" + paramSignature + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	sep := "?"
	if strings.Contains(dest, "?") {
		sep = "&"
	}
	return dest + sep + q, nil
}

// LogoutDocument builds a LogoutRequest (nameID set) or LogoutResponse
// (inResponseTo and status set) from this SP.
func LogoutDocument(kind, id, issuer, destination, nameID, nameIDFormat string, sessionIndexes []string, inResponseTo, status string, now time.Time) *etree.Document {
	el := etree.NewElement("samlp:" + kind)
	el.CreateAttr("xmlns:samlp", samlProtocolNS)
	el.CreateAttr("xmlns:saml", samlAssertionNS)
	el.CreateAttr("ID", id)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", now.UTC().Format(time.RFC3339))
	el.CreateAttr("Destination", destination)
	if inResponseTo != "" {
		el.CreateAttr("InResponseTo", inResponseTo)
	}
	el.CreateElement("saml:Issuer").SetText(issuer)
	if kind == KindLogoutRequest {
		n := el.CreateElement("saml:NameID")
		if nameIDFormat != "" {
			n.CreateAttr("Format", nameIDFormat)
		}
		n.SetText(nameID)
		for _, si := range sessionIndexes {
			el.CreateElement("samlp:SessionIndex").SetText(si)
		}
	} else {
		el.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", status)
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	return doc
}
