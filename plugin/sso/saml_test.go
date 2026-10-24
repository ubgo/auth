package sso

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

const (
	testACS      = "https://app.example.com/auth/sso/saml2/sp/acs"
	testSPEntity = "https://app.example.com/sp"
	testIdP      = "https://idp.example.com/entity"
	testReqID    = "_req1"
)

// samlFixture is an IdP plus the SP settings that trust it.
type samlFixture struct {
	idp *ssotest.SAMLIdP
	sp  SPSettings
	ids IdPSettings
}

func newSAMLFixture(t *testing.T) samlFixture {
	idp := ssotest.NewSAMLIdP(t, testIdP)
	return samlFixture{idp: idp,
		sp:  SPSettings{EntityID: testSPEntity, ACSURL: testACS, Audience: testSPEntity, MaxResponseSize: DefaultMaxResponseSize},
		ids: IdPSettings{EntityID: testIdP, SSOURL: idp.SSOURL, Certs: []*x509.Certificate{idp.Cert}}}
}

func (f samlFixture) valid() ssotest.Assertion {
	return f.idp.Valid(testACS, testSPEntity, testReqID, "ada@acme.test")
}

func (f samlFixture) check(want CheckRequest) CheckRequest {
	want.IdPEntityID, want.Audience, want.ACSURL = testIdP, testSPEntity, testACS
	if want.Now.IsZero() {
		want.Now = time.Now()
	}
	if want.ClockSkew == 0 {
		want.ClockSkew = DefaultClockSkew
	}
	return want
}

// accept runs the full pipeline a response goes through in verifySAML,
// minus the database: the raw scan, the algorithm policy, the engine, and
// CheckAssertion.
func (f samlFixture) accept(t *testing.T, encoded string, req CheckRequest, opts SAMLOptions) (SAMLAssertion, error) {
	t.Helper()
	if opts.MaxResponseSize == 0 {
		opts.MaxResponseSize = DefaultMaxResponseSize
	}
	if opts.OnDeprecated == "" {
		opts.OnDeprecated = DeprecatedWarn
	}
	if _, facts, err := InspectResponse(encoded, opts.MaxResponseSize); err != nil {
		return SAMLAssertion{}, err
	} else if err := opts.CheckAlgorithms(facts, func(string) {}); err != nil {
		return SAMLAssertion{}, err
	}
	res, err := GoSAML2{}.VerifyResponse(f.sp, f.ids, encoded, time.Now().Add(-DefaultClockSkew))
	if err != nil {
		return SAMLAssertion{}, &SAMLError{Code: SAMLSignatureInvalid, Err: err}
	}
	return CheckAssertion(res, f.check(req))
}

func wantCode(t *testing.T, err error, code SAMLCode) {
	t.Helper()
	var se *SAMLError
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("got %v, want %s", err, code)
	}
}

func TestSAML_ValidResponseIsAccepted(t *testing.T) {
	f := newSAMLFixture(t)
	for name, mod := range map[string]func(*ssotest.Assertion){
		"assertion signed": func(*ssotest.Assertion) {},
		"response signed":  func(a *ssotest.Assertion) { a.SignAssertion, a.SignResponse = false, true },
		"both signed":      func(a *ssotest.Assertion) { a.SignResponse = true },
	} {
		t.Run(name, func(t *testing.T) {
			a := f.valid()
			mod(&a)
			got, err := f.accept(t, f.idp.Response(a), CheckRequest{RequestID: testReqID}, SAMLOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got.NameID != "ada@acme.test" || got.ID != a.ID || got.Attributes["givenName"][0] != "Ada" {
				t.Fatalf("assertion %+v", got)
			}
		})
	}
}

func TestSAML_UnsignedIsRefused(t *testing.T) {
	f := newSAMLFixture(t)
	a := f.valid()
	a.SignAssertion = false
	_, err := f.accept(t, f.idp.Response(a), CheckRequest{RequestID: testReqID}, SAMLOptions{})
	wantCode(t, err, SAMLSignatureInvalid)
}

func TestSAML_SignatureFromAnotherKeyIsRefused(t *testing.T) {
	f := newSAMLFixture(t)
	other := ssotest.NewSAMLIdP(t, testIdP)
	_, err := f.accept(t, other.Response(f.valid()), CheckRequest{RequestID: testReqID}, SAMLOptions{})
	wantCode(t, err, SAMLSignatureInvalid)
}

func TestSAML_TamperedNameIDIsRefused(t *testing.T) {
	f := newSAMLFixture(t)
	doc := f.idp.ResponseDocument(f.valid())
	doc.FindElement("//NameID").SetText("mallory@acme.test")
	_, err := f.accept(t, ssotest.Encode(doc), CheckRequest{RequestID: testReqID}, SAMLOptions{})
	wantCode(t, err, SAMLSignatureInvalid)
}

// The classic signature-wrapping attacks: a signed assertion for one
// person is kept for its valid signature while a forged one is placed
// where the SP reads. Each document carries two assertions, which the raw
// scan refuses before the engine sees it.
func TestSAML_SignatureWrappingIsRefused(t *testing.T) {
	f := newSAMLFixture(t)
	forged := func() *etree.Element {
		a := f.valid()
		a.NameID = "admin@acme.test"
		a.SignAssertion = false
		return f.idp.AssertionElement(a)
	}
	for name, wrap := range map[string]func(doc *etree.Document){
		"forged assertion before the signed one": func(doc *etree.Document) {
			root := doc.Root()
			signed := root.FindElement("Assertion")
			root.InsertChildAt(signed.Index(), forged())
		},
		"signed assertion hidden in an extension": func(doc *etree.Document) {
			root := doc.Root()
			signed := root.FindElement("Assertion")
			root.RemoveChild(signed)
			ext := root.CreateElement("samlp:Extensions")
			ext.AddChild(signed)
			root.AddChild(forged())
		},
		"forged assertion inside the signed one's signature object": func(doc *etree.Document) {
			sig := doc.Root().FindElement("Assertion/Signature")
			sig.CreateElement("ds:Object").AddChild(forged())
		},
	} {
		t.Run(name, func(t *testing.T) {
			doc := f.idp.ResponseDocument(f.valid())
			wrap(doc)
			_, err := f.accept(t, ssotest.Encode(doc), CheckRequest{RequestID: testReqID}, SAMLOptions{})
			wantCode(t, err, SAMLMultipleAssertions)
		})
	}
}

// The same wrap, with the raw count bypassed, is still refused by the
// engine or by CheckAssertion: two independent layers.
func TestSAML_WrappingIsRefusedBehindTheRawScanToo(t *testing.T) {
	f := newSAMLFixture(t)
	doc := f.idp.ResponseDocument(f.valid())
	a := f.valid()
	a.NameID, a.SignAssertion = "admin@acme.test", false
	root := doc.Root()
	root.InsertChildAt(root.FindElement("Assertion").Index(), f.idp.AssertionElement(a))
	res, err := GoSAML2{}.VerifyResponse(f.sp, f.ids, ssotest.Encode(doc), time.Now())
	if err == nil {
		_, err = CheckAssertion(res, f.check(CheckRequest{RequestID: testReqID}))
		if err == nil {
			t.Fatal("a wrapped response was accepted")
		}
	}
}

func TestSAML_WantAssertionsSignedRefusesAResponseOnlySignature(t *testing.T) {
	f := newSAMLFixture(t)
	a := f.valid()
	a.SignAssertion, a.SignResponse = false, true
	_, err := f.accept(t, f.idp.Response(a), CheckRequest{RequestID: testReqID, WantAssertionsSigned: true}, SAMLOptions{})
	wantCode(t, err, SAMLAssertionSigRequired)
}

func TestSAML_ConditionRefusals(t *testing.T) {
	f := newSAMLFixture(t)
	now := time.Now().UTC()
	cases := []struct {
		name string
		mod  func(*ssotest.Assertion)
		req  CheckRequest
		code SAMLCode
	}{
		{"audience missing", func(a *ssotest.Assertion) { a.NoAudience = true }, CheckRequest{}, SAMLAudienceMissing},
		{"audience of another SP", func(a *ssotest.Assertion) { a.Audience = "https://evil.example.com" }, CheckRequest{}, SAMLAudienceMismatch},
		{"recipient of another ACS", func(a *ssotest.Assertion) { a.Recipient = "https://evil.example.com/acs" }, CheckRequest{}, SAMLSignatureInvalid},
		{"expired", func(a *ssotest.Assertion) {
			a.NotBefore, a.NotOnOrAfter = now.Add(-time.Hour), now.Add(-DefaultClockSkew-time.Minute)
		}, CheckRequest{}, SAMLSignatureInvalid},
		{"expired within the engine's window", func(a *ssotest.Assertion) {
			a.NotBefore, a.NotOnOrAfter = now.Add(-time.Hour), now.Add(-time.Minute)
		}, CheckRequest{ClockSkew: time.Second}, SAMLExpired},
		{"not yet valid", func(a *ssotest.Assertion) {
			a.NotBefore, a.NotOnOrAfter = now.Add(DefaultClockSkew+time.Minute), now.Add(time.Hour)
		}, CheckRequest{}, SAMLNotYetValid},
		{"answers another request", func(a *ssotest.Assertion) { a.InResponseTo = "_other" }, CheckRequest{}, SAMLInResponseToMismatch},
		{"solicited response presented as unsolicited", func(*ssotest.Assertion) {}, CheckRequest{RequestID: ""}, SAMLInResponseToMismatch},
		{"issuer of another IdP", func(a *ssotest.Assertion) { a.Issuer = "https://evil.example.com" }, CheckRequest{}, SAMLSignatureInvalid},
		{"missing timestamps", func(a *ssotest.Assertion) { a.NotBefore = time.Time{} }, CheckRequest{RequireTimestamps: true}, SAMLMissingTimestamps},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := f.valid()
			tc.mod(&a)
			req := tc.req
			if req.RequestID == "" && tc.name != "solicited response presented as unsolicited" {
				req.RequestID = testReqID
			}
			_, err := f.accept(t, f.idp.Response(a), req, SAMLOptions{})
			wantCode(t, err, tc.code)
		})
	}
}

// The engine refuses a wrong recipient, expiry or issuer on its own; these
// pin CheckAssertion's own refusal of each, on a response the engine would
// pass, so neither layer depends on the other.
func TestCheckAssertion_EachRule(t *testing.T) {
	now := time.Now()
	good := func() *SAMLResponse {
		return &SAMLResponse{Issuer: testIdP, Destination: testACS, InResponseTo: testReqID, Signed: true, Assertions: []SAMLAssertion{{
			ID: "_a", Issuer: testIdP, Signed: true, NameID: "ada", NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Minute),
			Audiences:     [][]string{{testSPEntity}},
			Confirmations: []SubjectConfirmation{{Method: subjectBearer, Recipient: testACS, InResponseTo: testReqID, NotOnOrAfter: now.Add(time.Minute)}},
		}}}
	}
	req := CheckRequest{IdPEntityID: testIdP, Audience: testSPEntity, ACSURL: testACS, RequestID: testReqID, Now: now, ClockSkew: time.Second}
	if _, err := CheckAssertion(good(), req); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mod  func(r *SAMLResponse)
		code SAMLCode
	}{
		{"no assertion", func(r *SAMLResponse) { r.Assertions = nil }, SAMLNoAssertion},
		{"two assertions", func(r *SAMLResponse) { r.Assertions = append(r.Assertions, r.Assertions[0]) }, SAMLMultipleAssertions},
		{"nothing signed", func(r *SAMLResponse) { r.Signed, r.Assertions[0].Signed = false, false }, SAMLAssertionSigRequired},
		{"response issuer", func(r *SAMLResponse) { r.Issuer = "x" }, SAMLIssuerMismatch},
		{"assertion issuer", func(r *SAMLResponse) { r.Assertions[0].Issuer = "x" }, SAMLIssuerMismatch},
		{"destination", func(r *SAMLResponse) { r.Destination = "https://evil/acs" }, SAMLDestinationMismatch},
		{"response InResponseTo", func(r *SAMLResponse) { r.InResponseTo = "_x" }, SAMLInResponseToMismatch},
		{"confirmation InResponseTo", func(r *SAMLResponse) { r.Assertions[0].Confirmations[0].InResponseTo = "_x" }, SAMLInResponseToMismatch},
		{"recipient", func(r *SAMLResponse) { r.Assertions[0].Confirmations[0].Recipient = "https://evil/acs" }, SAMLRecipientMismatch},
		{"no bearer", func(r *SAMLResponse) { r.Assertions[0].Confirmations[0].Method = "urn:holder-of-key" }, SAMLBearerMissing},
		{"confirmation expired", func(r *SAMLResponse) { r.Assertions[0].Confirmations[0].NotOnOrAfter = now.Add(-time.Minute) }, SAMLExpired},
		{"confirmation without expiry", func(r *SAMLResponse) { r.Assertions[0].Confirmations[0].NotOnOrAfter = time.Time{} }, SAMLExpired},
		{"confirmation not yet valid", func(r *SAMLResponse) { r.Assertions[0].Confirmations[0].NotBefore = now.Add(time.Minute) }, SAMLNotYetValid},
		{"conditions expired", func(r *SAMLResponse) { r.Assertions[0].NotOnOrAfter = now.Add(-time.Minute) }, SAMLExpired},
		{"conditions not yet valid", func(r *SAMLResponse) { r.Assertions[0].NotBefore = now.Add(time.Minute) }, SAMLNotYetValid},
		{"no audience", func(r *SAMLResponse) { r.Assertions[0].Audiences = nil }, SAMLAudienceMissing},
		{"second restriction without us", func(r *SAMLResponse) {
			r.Assertions[0].Audiences = append(r.Assertions[0].Audiences, []string{"https://other"})
		}, SAMLAudienceMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := good()
			tc.mod(r)
			_, err := CheckAssertion(r, req)
			wantCode(t, err, tc.code)
		})
	}
	t.Run("skew tolerates a slightly early clock", func(t *testing.T) {
		r := good()
		r.Assertions[0].NotBefore = now.Add(30 * time.Second)
		if _, err := CheckAssertion(r, CheckRequest{IdPEntityID: testIdP, Audience: testSPEntity, ACSURL: testACS, RequestID: testReqID, Now: now, ClockSkew: time.Minute}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInspectResponse_Refusals(t *testing.T) {
	f := newSAMLFixture(t)
	enc := f.idp.Response(f.valid())
	if _, _, err := InspectResponse(enc, 100); err == nil {
		t.Fatal("an oversize response was accepted")
	} else {
		wantCode(t, err, SAMLTooLarge)
	}
	_, _, err := InspectResponse("%%%", DefaultMaxResponseSize)
	wantCode(t, err, SAMLInvalidEncoding)
	_, _, err = InspectResponse(b64("<a><b></a>"), DefaultMaxResponseSize)
	wantCode(t, err, SAMLInvalidXML)
	_, _, err = InspectResponse(b64(`<!DOCTYPE x [<!ENTITY e "x">]><r/>`), DefaultMaxResponseSize)
	wantCode(t, err, SAMLInvalidXML)
	_, _, err = InspectResponse(b64("<r/>"), DefaultMaxResponseSize)
	wantCode(t, err, SAMLNoAssertion)
	_, facts, err := InspectResponse(enc, DefaultMaxResponseSize)
	if err != nil || facts.Assertions != 1 || len(facts.SignatureAlgorithms) != 1 || facts.SignatureAlgorithms[0] != AlgRSASHA256 {
		t.Fatalf("facts %+v, %v", facts, err)
	}
}

func TestCheckAlgorithms_Policy(t *testing.T) {
	f := newSAMLFixture(t)
	a := f.valid()
	a.SHA1 = true
	enc := f.idp.Response(a)
	warned := ""
	_, facts, _ := InspectResponse(enc, DefaultMaxResponseSize)
	if err := (SAMLOptions{OnDeprecated: DeprecatedWarn}).CheckAlgorithms(facts, func(alg string) { warned = alg }); err != nil || warned == "" {
		t.Fatalf("warn: %v %q", err, warned)
	}
	err := (SAMLOptions{OnDeprecated: DeprecatedReject}).CheckAlgorithms(facts, func(string) {})
	wantCode(t, err, SAMLDeprecatedAlgorithm)
	if err := (SAMLOptions{OnDeprecated: DeprecatedAllow}).CheckAlgorithms(facts, func(string) { t.Fatal("warned under allow") }); err != nil {
		t.Fatal(err)
	}
	err = (SAMLOptions{OnDeprecated: DeprecatedAllow, AllowedSignatureAlgorithms: []string{AlgRSASHA512}}).CheckAlgorithms(facts, func(string) {})
	wantCode(t, err, SAMLAlgorithmNotAllowed)
	err = (SAMLOptions{OnDeprecated: DeprecatedAllow}).CheckAlgorithms(RawFacts{DigestAlgorithms: []string{"urn:made-up"}}, func(string) {})
	wantCode(t, err, SAMLUnknownAlgorithm)
	if err := (SAMLOptions{OnDeprecated: "loud"}).validate(); !errors.Is(err, ErrBadAlgorithmSet) {
		t.Fatal(err)
	}
	if err := (SAMLOptions{OnDeprecated: DeprecatedWarn, AllowedDigestAlgorithms: []string{"md5"}}).validate(); !errors.Is(err, ErrBadAlgorithmSet) {
		t.Fatal(err)
	}
}

func TestMapAttributes(t *testing.T) {
	a := SAMLAssertion{NameID: "Ada@Acme.test", SessionIndex: "s1", Attributes: map[string][]string{
		"givenName": {"Ada"}, "surname": {"Lovelace"}, "dept": {"r&d", "eng"}, "uid": {"u-7"}, "verified": {"true"}, "mail": {"a@x.test"},
	}}
	got := MapAttributes(SAMLMapping{ExtraFields: map[string]string{"department": "dept"}}, a)
	if got.Subject != "Ada@Acme.test" || got.Email != "ada@acme.test" || got.Name != "Ada Lovelace" || got.SessionIndex != "s1" || len(got.Extra["department"].([]string)) != 2 {
		t.Fatalf("%+v", got)
	}
	got = MapAttributes(SAMLMapping{ID: "uid", Email: "mail", EmailVerified: "verified", Name: "cn"}, SAMLAssertion{Attributes: map[string][]string{"uid": {"u-7"}, "mail": {"A@X.test"}, "verified": {"true"}, "cn": {"Ada L"}}})
	if got.Subject != "u-7" || got.Email != "a@x.test" || !got.EmailVerified || got.Name != "Ada L" {
		t.Fatalf("%+v", got)
	}
}

func TestSAMLConfig_IdPFromMetadataAndFields(t *testing.T) {
	idp := ssotest.NewSAMLIdP(t, testIdP)
	body := strings.TrimSpace(strings.NewReplacer("-----BEGIN CERTIFICATE-----", "", "-----END CERTIFICATE-----", "").Replace(idp.CertPEM))
	md := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + testIdP + `"><IDPSSODescriptor>` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + body + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<SingleSignOnService Binding="` + BindingRedirect + `" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`
	got, err := SAMLConfig{IdPMetadata: IdPMetadata{Metadata: md}}.IdP(DefaultMaxMetadataSize)
	if err != nil || got.EntityID != testIdP || got.SSOURL != "https://idp.example.com/sso" || len(got.Certs) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := (SAMLConfig{IdPMetadata: IdPMetadata{Metadata: md}}).IdP(10); !errors.Is(err, ErrBadProvider) {
		t.Fatalf("oversize metadata: %v", err)
	}
	if _, err := (SAMLConfig{IdPMetadata: IdPMetadata{Metadata: "<!DOCTYPE x><EntityDescriptor/>"}}).IdP(DefaultMaxMetadataSize); !errors.Is(err, ErrBadProvider) {
		t.Fatalf("DTD: %v", err)
	}
	got, err = SAMLConfig{EntryPoint: "https://idp/x", Cert: idp.CertPEM + idp.CertPEM, IdPMetadata: IdPMetadata{EntityID: "e"}}.IdP(DefaultMaxMetadataSize)
	if err != nil || got.SSOURL != "https://idp/x" || len(got.Certs) != 2 || got.EntityID != "e" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestSPMetadataXML(t *testing.T) {
	_, cert, _ := ssotest.KeyPair(t, "sp")
	md, err := SPMetadataXML(SPSettings{EntityID: testSPEntity, ACSURL: testACS, NameIDFormat: NameIDEmail, WantAssertionsSigned: true, AuthnRequestsSigned: true, Certificate: cert, DecryptionCert: cert, SLOURL: "https://app.example.com/slo"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`entityID="` + testSPEntity + `"`, `WantAssertionsSigned="true"`, `AuthnRequestsSigned="true"`, `Location="` + testACS + `"`, BindingPOST, NameIDEmail, `use="signing"`, `use="encryption"`, `SingleLogoutService`} {
		if !strings.Contains(string(md), want) {
			t.Fatalf("metadata lacks %q:\n%s", want, md)
		}
	}
}

func TestGoSAML2_AuthnRequestURL(t *testing.T) {
	f := newSAMLFixture(t)
	u, err := GoSAML2{}.AuthnRequestURL(f.sp, f.ids, "_myid", "relay-1")
	if err != nil {
		t.Fatal(err)
	}
	id, acs, relay := ssotest.AuthnRequest(t, u)
	if id != "_myid" || acs != testACS || relay != "relay-1" || !strings.HasPrefix(u, f.idp.SSOURL) {
		t.Fatalf("%s %s %s %s", id, acs, relay, u)
	}
	key, cert, _ := ssotest.KeyPair(t, "sp")
	sp := f.sp
	sp.AuthnRequestsSigned, sp.SigningKey, sp.Certificate, sp.SignatureAlgorithm = true, key, cert, AlgRSASHA256
	u, err = GoSAML2{}.AuthnRequestURL(sp, f.ids, "_myid", "relay-1")
	if err != nil || !strings.Contains(u, "Signature=") || !strings.Contains(u, "SigAlg=") {
		t.Fatalf("signed request URL %s: %v", u, err)
	}
	sp.SigningKey = nil
	if _, err := (GoSAML2{}).AuthnRequestURL(sp, f.ids, "_x", ""); err == nil {
		t.Fatal("a signed request without a key was built")
	}
}

func TestParseCertsAndKey(t *testing.T) {
	key, _, certPEM := ssotest.KeyPair(t, "x")
	cs, err := parseCerts(certPEM)
	if err != nil || len(cs) != 1 {
		t.Fatal(err)
	}
	if cs, err := parseCerts(""); err != nil || cs != nil {
		t.Fatal("empty")
	}
	if _, err := parseCerts("not base64!"); err == nil {
		t.Fatal("garbage parsed")
	}
	if _, err := parseKey(ssotest.KeyPEM(key)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseKey("nope"); err == nil {
		t.Fatal("garbage key parsed")
	}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
