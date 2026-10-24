package samlidp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// Status codes (SAML core 3.2.2.2).
const (
	StatusSuccess   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	StatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	StatusNoPassive = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
)

// Fixed SAML values.
const (
	cmBearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	// acPasswordProtected is the authentication context the assertion
	// names. The library does not know which method the session was made
	// with, so it names the generic one most SPs accept.
	acPasswordProtected = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	// samlTime is the xs:dateTime layout SAML uses: UTC, second precision.
	samlTime = "2006-01-02T15:04:05Z"
	// idBytes is the randomness of a generated ID: 160 bits, as SAML core
	// 1.3.4 asks.
	idBytes = 20
)

// ResponseForm is what the browser posts to the SP's ACS URL (HTTP-POST
// binding).
type ResponseForm struct {
	ACSURL       string `json:"acs_url"`
	SAMLResponse string `json:"saml_response"`
	RelayState   string `json:"relay_state,omitempty"`
}

// issue describes one response to build.
type issue struct {
	sp           ServiceProvider
	acs          string
	inResponseTo string
	relayState   string
	status       string // "" is StatusSuccess
	subStatus    string
}

// newID is a random SAML ID; it starts with "_" because an xs:ID must not
// start with a digit.
func newID() string {
	b := make([]byte, idBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return "_" + hex.EncodeToString(b)
}

// subjectOf collects what NameID and attribute functions see.
func (p *Plugin) subjectOf(ctx context.Context, u auth.User, s auth.Session) (Subject, error) {
	ids, err := p.core.VerifiedIdentities(ctx, u.ID, email.KindEmail)
	if err != nil {
		return Subject{}, err
	}
	sub := Subject{User: u, Session: s}
	for _, id := range ids {
		if sub.Email == "" || id.IsPrimary {
			sub.Email = id.Value
		}
	}
	return sub, nil
}

// nameID is the NameID value for the SP's format.
func (p *Plugin) nameID(ctx context.Context, sp ServiceProvider, s Subject) (string, error) {
	if sp.NameID != nil {
		v, err := sp.NameID(ctx, sp, s)
		if err != nil {
			return "", err
		}
		if v == "" {
			return "", ErrNameIDUnavailable
		}
		return v, nil
	}
	switch sp.nameIDFormat() {
	case NameIDEmail:
		if s.Email == "" {
			return "", ErrNameIDUnavailable
		}
		return s.Email, nil
	case NameIDTransient:
		return newID(), nil
	}
	return s.User.ID, nil
}

// sessionIndex names the IdP session in the AuthnStatement without
// revealing its ID, so a later single logout can find it.
func sessionIndex(sessionID string) string {
	sum := sha256.Sum256([]byte(PluginName + "\x00" + sessionID))
	return "_" + hex.EncodeToString(sum[:16])
}

// buildSuccess builds the signed Response carrying an assertion about the
// subject.
func (p *Plugin) buildSuccess(ctx context.Context, is issue, sub Subject) (string, error) {
	nid, err := p.nameID(ctx, is.sp, sub)
	if err != nil {
		return "", err
	}
	var attrs []Attribute
	if is.sp.Attributes != nil {
		if attrs, err = is.sp.Attributes(ctx, is.sp, sub); err != nil {
			return "", err
		}
	}
	now := p.core.Now()
	assertion := p.assertion(is, sub, nid, attrs, now)
	signed, err := p.sign(assertion, child(assertion, nsAssertion, "Issuer"))
	if err != nil {
		return "", err
	}
	return p.response(is, signed, now)
}

// buildFailure builds a signed Response with an error status and no
// assertion, for IsPassive with no session.
func (p *Plugin) buildFailure(is issue) (string, error) {
	return p.response(is, nil, p.core.Now())
}

// assertion builds the unsigned saml:Assertion.
func (p *Plugin) assertion(is issue, sub Subject, nameID string, attrs []Attribute, now time.Time) *etree.Element {
	notOnOrAfter := now.Add(p.assertionTTL).Format(samlTime)
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", newID())
	a.CreateAttr("Version", samlVersion)
	a.CreateAttr("IssueInstant", now.Format(samlTime))
	a.CreateElement("saml:Issuer").SetText(p.IdPEntityID())

	subject := a.CreateElement("saml:Subject")
	n := subject.CreateElement("saml:NameID")
	n.CreateAttr("Format", is.sp.nameIDFormat())
	n.CreateAttr("SPNameQualifier", is.sp.EntityID)
	n.SetText(nameID)
	sc := subject.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", cmBearer)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	if is.inResponseTo != "" {
		scd.CreateAttr("InResponseTo", is.inResponseTo)
	}
	scd.CreateAttr("NotOnOrAfter", notOnOrAfter)
	scd.CreateAttr("Recipient", is.acs)

	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", now.Add(-p.skew).Format(samlTime))
	cond.CreateAttr("NotOnOrAfter", notOnOrAfter)
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(is.sp.EntityID)

	st := a.CreateElement("saml:AuthnStatement")
	st.CreateAttr("AuthnInstant", sub.Session.CreatedAt.UTC().Format(samlTime))
	st.CreateAttr("SessionIndex", sessionIndex(sub.Session.ID))
	st.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText(acPasswordProtected)

	if len(attrs) > 0 {
		as := a.CreateElement("saml:AttributeStatement")
		for _, at := range attrs {
			el := as.CreateElement("saml:Attribute")
			el.CreateAttr("Name", at.Name)
			nf := at.NameFormat
			if nf == "" {
				nf = AttrNameFormatBasic
			}
			el.CreateAttr("NameFormat", nf)
			if at.FriendlyName != "" {
				el.CreateAttr("FriendlyName", at.FriendlyName)
			}
			for _, v := range at.Values {
				el.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	return a
}

// response wraps a signed assertion (nil for a failure) in a samlp:Response
// and signs it unless the SP asked for UnsignedResponse. It answers the
// base64 form value.
func (p *Plugin) response(is issue, signedAssertion *etree.Element, now time.Time) (string, error) {
	r := etree.NewElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", nsProtocol)
	r.CreateAttr("xmlns:saml", nsAssertion)
	r.CreateAttr("ID", newID())
	r.CreateAttr("Version", samlVersion)
	r.CreateAttr("IssueInstant", now.Format(samlTime))
	r.CreateAttr("Destination", is.acs)
	if is.inResponseTo != "" {
		r.CreateAttr("InResponseTo", is.inResponseTo)
	}
	issuer := r.CreateElement("saml:Issuer")
	issuer.SetText(p.IdPEntityID())
	sc := r.CreateElement("samlp:Status").CreateElement("samlp:StatusCode")
	status := is.status
	if status == "" {
		status = StatusSuccess
	}
	sc.CreateAttr("Value", status)
	if is.subStatus != "" {
		sc.CreateElement("samlp:StatusCode").CreateAttr("Value", is.subStatus)
	}
	if signedAssertion != nil {
		r.AddChild(signedAssertion)
	}
	out := r
	if !is.sp.UnsignedResponse || signedAssertion == nil {
		var err error
		if out, err = p.sign(r, issuer); err != nil {
			return "", err
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(out)
	b, _ := doc.WriteToBytes() // writing to memory cannot fail
	return base64.StdEncoding.EncodeToString(b), nil
}

// sign adds to el an enveloped signature (exclusive canonicalization,
// the configured algorithm, the certificate in KeyInfo) placed right after
// issuer, el's saml:Issuer, where SAML core 5.4.1 and the XSD put it.
func (p *Plugin) sign(el, issuer *etree.Element) (*etree.Element, error) {
	// NewSigningContext fails only on a nil signer and SetSignatureMethod
	// only on an algorithm goxmldsig does not know; Validate refused the
	// first and picked sigAlg from the two it supports.
	ctx, _ := dsig.NewSigningContext(p.signer, [][]byte{p.cert.Raw})
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	_ = ctx.SetSignatureMethod(p.sigAlg)
	// ConstructSignature rather than SignEnveloped: the latter appends the
	// signature without making el its parent, so it could not be moved.
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}
	el.InsertChildAt(issuer.Index()+1, sig)
	return el, nil
}
