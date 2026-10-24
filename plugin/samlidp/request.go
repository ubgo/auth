package samlidp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML bindings.
const (
	BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	BindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
)

// Signature algorithms (XML Signature, RFC 6931) accepted on a request and
// used on a response. SHA-1 is not accepted.
const (
	AlgRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	AlgECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
)

// XML namespaces.
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
	samlVersion = "2.0"
)

// Binding parameter names (SAML bindings 3.4.4 and 3.5.4).
const (
	ParamSAMLRequest  = "SAMLRequest"
	ParamSAMLResponse = "SAMLResponse"
	ParamRelayState   = "RelayState"
	ParamSigAlg       = "SigAlg"
	ParamSignature    = "Signature"
)

// maxRequestID bounds an AuthnRequest's ID; real ones are under 50 bytes.
const maxRequestID = 256

// SSORequest is an AuthnRequest as it arrived at the single sign-on service.
type SSORequest struct {
	// Binding is BindingRedirect (SAMLRequest deflated, any signature in
	// the query) or BindingPOST (SAMLRequest base64 XML, any signature
	// enveloped in it).
	Binding     string `json:"binding"`
	SAMLRequest string `json:"saml_request"`
	RelayState  string `json:"relay_state,omitempty"`
	// SigAlg and Signature are the redirect binding's query signature.
	SigAlg    string `json:"sig_alg,omitempty"`
	Signature string `json:"signature,omitempty"`
	// RawQuery is the redirect binding's query exactly as received, whose
	// octets the signature covers (SAML bindings 3.4.4.1). Without it the
	// signed string is rebuilt from the decoded values.
	RawQuery string `json:"raw_query,omitempty"`
}

// authnRequest is the part of an AuthnRequest the IdP acts on, read from
// the verified element only.
type authnRequest struct {
	ID, Issuer, Destination, ACSURL, ProtocolBinding, NameIDFormat string
	ACSIndex                                                       int // -1 when absent
	IssueInstant                                                   time.Time
	ForceAuthn, IsPassive, Signed                                  bool
}

// decodeMessage base64-decodes (and for the redirect binding inflates) a
// SAML message, bounded, with no DTD, and checks it survives an XML round
// trip unchanged (the defence against the encoding/xml namespace confusions
// signature-wrapping attacks used).
func decodeMessage(value string, redirect bool, maxSize int) (*etree.Element, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(value), ""))
	if err != nil {
		return nil, ErrInvalidRequest
	}
	if redirect {
		r := flate.NewReader(bytes.NewReader(raw))
		raw, err = io.ReadAll(io.LimitReader(r, int64(maxSize)+1))
		if err != nil {
			return nil, ErrInvalidRequest
		}
	}
	if len(raw) > maxSize {
		return nil, ErrMessageTooLarge
	}
	if bytes.Contains(raw, []byte("<!DOCTYPE")) || bytes.Contains(raw, []byte("<!ENTITY")) {
		return nil, ErrInvalidRequest
	}
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, ErrInvalidRequest
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return nil, ErrInvalidRequest
	}
	return doc.Root(), nil
}

// child returns el's first child element named tag in namespace ns.
func child(el *etree.Element, ns, tag string) *etree.Element {
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

// issuerOf is the trimmed text of el's saml:Issuer, "" when absent.
func issuerOf(el *etree.Element) string {
	if is := child(el, nsAssertion, "Issuer"); is != nil {
		return strings.TrimSpace(is.Text())
	}
	return ""
}

// isAuthnRequest reports whether el is a samlp:AuthnRequest of SAML 2.0.
func isAuthnRequest(el *etree.Element) bool {
	return el.Tag == "AuthnRequest" && el.NamespaceURI() == nsProtocol && el.SelectAttrValue("Version", "") == samlVersion
}

// readAuthnRequest reads the fields the IdP acts on from a verified (or
// knowingly unsigned) AuthnRequest element.
func readAuthnRequest(el *etree.Element, signed bool) (authnRequest, error) {
	r := authnRequest{
		ID: el.SelectAttrValue("ID", ""), Issuer: issuerOf(el), Destination: el.SelectAttrValue("Destination", ""),
		ACSURL: el.SelectAttrValue("AssertionConsumerServiceURL", ""), ProtocolBinding: el.SelectAttrValue("ProtocolBinding", ""),
		ACSIndex: -1, Signed: signed,
	}
	if r.ID == "" || len(r.ID) > maxRequestID || r.Issuer == "" {
		return r, ErrInvalidRequest
	}
	ii, err := time.Parse(time.RFC3339Nano, el.SelectAttrValue("IssueInstant", ""))
	if err != nil {
		return r, ErrInvalidRequest
	}
	r.IssueInstant = ii.UTC()
	if v := el.SelectAttrValue("AssertionConsumerServiceIndex", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return r, ErrInvalidRequest
		}
		r.ACSIndex = n
	}
	if r.ForceAuthn, err = xsBool(el.SelectAttrValue("ForceAuthn", "")); err != nil {
		return r, err
	}
	if r.IsPassive, err = xsBool(el.SelectAttrValue("IsPassive", "")); err != nil {
		return r, err
	}
	if pol := child(el, nsProtocol, "NameIDPolicy"); pol != nil {
		r.NameIDFormat = pol.SelectAttrValue("Format", "")
	}
	return r, nil
}

// xsBool parses an xs:boolean attribute; "" is false.
func xsBool(v string) (bool, error) {
	switch strings.TrimSpace(v) {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	}
	return false, ErrInvalidRequest
}

// verifyPOST checks an enveloped signature against certs and returns the
// verified element, which is the only element read afterwards. An unsigned
// element comes back unchanged with signed false.
func verifyPOST(el *etree.Element, certs []*x509.Certificate, now time.Time) (verified *etree.Element, signed bool, err error) {
	if child(el, nsDSig, "Signature") == nil {
		return el, false, nil
	}
	if len(certs) == 0 {
		// Nothing to verify with; the request counts as unsigned, which
		// RequireSignedRequests refuses.
		return el, false, nil
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	vc.Clock = dsig.NewFakeClockAt(now)
	out, err := vc.Validate(el)
	if err != nil {
		return nil, false, ErrInvalidSignature
	}
	return out, true, nil
}

// verifyRedirect checks a redirect-binding query signature. It answers
// signed false when the query carries no signature or the SP has no
// certificate to check one with.
func verifyRedirect(in SSORequest, certs []*x509.Certificate) (signed bool, err error) {
	if in.Signature == "" && in.SigAlg == "" {
		return false, nil
	}
	if len(certs) == 0 {
		return false, nil
	}
	h, err := hashFor(in.SigAlg)
	if err != nil {
		return false, err
	}
	sig, err := base64.StdEncoding.DecodeString(in.Signature)
	if err != nil || len(sig) == 0 {
		return false, ErrInvalidSignature
	}
	for _, octets := range signedOctets(in) {
		hh := h.New()
		hh.Write([]byte(octets))
		sum := hh.Sum(nil)
		for _, c := range certs {
			switch pub := c.PublicKey.(type) {
			case *rsa.PublicKey:
				if rsa.VerifyPKCS1v15(pub, h, sum, sig) == nil {
					return true, nil
				}
			case *ecdsa.PublicKey:
				if ecdsa.VerifyASN1(pub, sum, sig) {
					return true, nil
				}
			}
		}
	}
	return false, ErrInvalidSignature
}

// hashFor is the hash of an accepted signature algorithm.
func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case AlgRSASHA256, AlgECDSASHA256:
		return crypto.SHA256, nil
	case AlgRSASHA512:
		return crypto.SHA512, nil
	}
	return 0, ErrUnsupportedSigAlg
}

// signedOctets are the candidate strings a redirect signature covers: the
// raw query's own octets first (what the spec requires), then the values
// re-encoded, for a caller that has no raw query.
func signedOctets(in SSORequest) []string {
	var out []string
	if in.RawQuery != "" {
		if s, ok := rawSigned(in.RawQuery); ok {
			out = append(out, s)
		}
	}
	s := ParamSAMLRequest + "=" + url.QueryEscape(in.SAMLRequest)
	if in.RelayState != "" {
		s += "&" + ParamRelayState + "=" + url.QueryEscape(in.RelayState)
	}
	return append(out, s+"&"+ParamSigAlg+"="+url.QueryEscape(in.SigAlg))
}

// rawSigned rebuilds the signed string from the raw query's encoded
// parameters, in the order SAML bindings 3.4.4.1 fixes.
func rawSigned(rawQuery string) (string, bool) {
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		if _, dup := raw[k]; dup {
			return "", false
		}
		raw[k] = v
	}
	req, ok := raw[ParamSAMLRequest]
	alg, okAlg := raw[ParamSigAlg]
	if !ok || !okAlg {
		return "", false
	}
	s := ParamSAMLRequest + "=" + req
	if rs, ok := raw[ParamRelayState]; ok {
		s += "&" + ParamRelayState + "=" + rs
	}
	return s + "&" + ParamSigAlg + "=" + alg, true
}

// parseRequest decodes, authenticates and reads an AuthnRequest: the SP is
// found by the unverified Issuer only to learn which certificates check the
// signature; every field is then read from the verified element.
func (p *Plugin) parseRequest(ctx context.Context, in SSORequest) (authnRequest, ServiceProvider, error) {
	redirect := in.Binding == BindingRedirect
	if !redirect && in.Binding != BindingPOST {
		return authnRequest{}, ServiceProvider{}, ErrUnsupportedBinding
	}
	root, err := decodeMessage(in.SAMLRequest, redirect, p.maxSize)
	if err != nil {
		return authnRequest{}, ServiceProvider{}, err
	}
	if !isAuthnRequest(root) {
		return authnRequest{}, ServiceProvider{}, ErrInvalidRequest
	}
	sp, err := p.lookupSP(ctx, issuerOf(root))
	if err != nil {
		return authnRequest{}, ServiceProvider{}, err
	}
	var signed bool
	if redirect {
		signed, err = verifyRedirect(in, sp.Certificates)
	} else {
		root, signed, err = verifyPOST(root, sp.Certificates, p.core.Now())
	}
	if err != nil {
		return authnRequest{}, ServiceProvider{}, err
	}
	if (sp.RequireSignedRequests || p.wantSigned) && !signed {
		return authnRequest{}, ServiceProvider{}, ErrSignatureRequired
	}
	// goxmldsig verifies only a signature whose reference is the root's own
	// ID and returns that root, so the verified element is still the
	// AuthnRequest whose Issuer named sp; its fields are read from it.
	req, err := readAuthnRequest(root, signed)
	if err != nil {
		return authnRequest{}, ServiceProvider{}, err
	}
	return req, sp, nil
}

// checkRequest applies the IdP's rules to a read request: destination,
// response binding, ACS URL, NameID policy and freshness. It answers the
// ACS URL to respond at.
func (p *Plugin) checkRequest(req authnRequest, sp ServiceProvider, now time.Time) (string, error) {
	// A signed request must name its destination (SAML bindings 3.4.5.2,
	// 3.5.5.2), so a signature captured for another IdP is useless here.
	if (req.Destination != "" || req.Signed) && req.Destination != p.SSOURL() {
		return "", ErrWrongDestination
	}
	if req.ProtocolBinding != "" && req.ProtocolBinding != BindingPOST {
		return "", ErrUnsupportedBinding
	}
	acs, err := resolveACS(req, sp)
	if err != nil {
		return "", err
	}
	if f := req.NameIDFormat; f != "" && f != NameIDUnspecified && f != sp.nameIDFormat() {
		return "", ErrNameIDPolicy
	}
	if req.IssueInstant.Before(now.Add(-p.requestMaxAge)) || req.IssueInstant.After(now.Add(p.skew)) {
		return "", ErrRequestExpired
	}
	return acs, nil
}

// resolveACS picks the ACS URL: the request's, which must equal a registered
// one exactly; the registered one at the request's index; or the first.
func resolveACS(req authnRequest, sp ServiceProvider) (string, error) {
	switch {
	case req.ACSURL != "" && req.ACSIndex >= 0:
		// SAML core 3.4.1 makes them mutually exclusive.
		return "", ErrInvalidRequest
	case req.ACSURL != "":
		for _, u := range sp.ACSURLs {
			if u == req.ACSURL {
				return u, nil
			}
		}
		return "", ErrACSNotRegistered
	case req.ACSIndex >= 0:
		if req.ACSIndex >= len(sp.ACSURLs) {
			return "", ErrACSNotRegistered
		}
		return sp.ACSURLs[req.ACSIndex], nil
	}
	return sp.ACSURLs[0], nil
}
