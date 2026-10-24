package sso

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/gosaml2/types"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

// c2Base is a SAML provider checkSAMLShape accepts, and a plugin whose ACS
// URL is the one the SP metadata fixtures name.
func c2Base(t *testing.T) (*Plugin, Provider, *ssotest.SAMLIdP) {
	t.Helper()
	idp := ssotest.NewSAMLIdP(t, testIdP)
	p := New()
	p.acs = testACS
	pr := Provider{ProviderID: "x", Issuer: testSPEntity, Domain: "a.com",
		SAML: &SAMLConfig{EntryPoint: idp.SSOURL, Cert: idp.CertPEM, IdPMetadata: IdPMetadata{EntityID: testIdP}}}
	if err := p.checkShape(pr); err != nil {
		t.Fatalf("the base provider is refused: %v", err)
	}
	return p, pr, idp
}

func pemOf(typ string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))
}

// TestC2_SAMLShapeRefusals: every SAML configuration that could not work, or
// would silently work differently than it says, is refused at registration
// with ErrBadProvider (or the SP-metadata mismatch), naming the problem.
func TestC2_SAMLShapeRefusals(t *testing.T) {
	p, base, _ := c2Base(t)
	key, _, certPEM := ssotest.KeyPair(t, "sp")
	otherSP, _ := SPMetadataXML(SPSettings{EntityID: "https://other.example.com/sp", ACSURL: testACS})
	cases := []struct {
		name string
		mod  func(s *SAMLConfig)
		want error
		text string
	}{
		{"malformed IdP metadata", func(s *SAMLConfig) { s.IdPMetadata.Metadata = "<EntityDescriptor" }, ErrBadProvider, "IdP metadata"},
		{"IdP metadata certificate is garbage", func(s *SAMLConfig) {
			s.Cert = ""
			s.IdPMetadata.Metadata = `<EntityDescriptor entityID="e"><IDPSSODescriptor><KeyDescriptor use="signing"><KeyInfo><X509Data><X509Certificate>bm90IGEgY2VydA==</X509Certificate></X509Data></KeyInfo></KeyDescriptor></IDPSSODescriptor></EntityDescriptor>`
		}, ErrBadProvider, "IdP metadata certificate"},
		{"cert is garbage", func(s *SAMLConfig) {
			s.Cert = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"
		}, ErrBadProvider, "cert"},
		{"no SSO URL", func(s *SAMLConfig) { s.EntryPoint = "" }, ErrBadProvider, "entryPoint"},
		{"no IdP certificate", func(s *SAMLConfig) { s.Cert = "" }, ErrBadProvider, "no IdP signing certificate"},
		{"signed requests without a key", func(s *SAMLConfig) { s.AuthnRequestsSigned = true }, ErrBadProvider, "authnRequestsSigned"},
		{"unknown signature algorithm", func(s *SAMLConfig) { s.SignatureAlgorithm = "md5" }, ErrBadProvider, "signatureAlgorithm"},
		{"unknown digest algorithm", func(s *SAMLConfig) { s.DigestAlgorithm = "md5" }, ErrBadProvider, "digestAlgorithm"},
		{"private key is garbage", func(s *SAMLConfig) { s.PrivateKey = "nope" }, ErrBadProvider, "privateKey"},
		{"sp certificate is garbage", func(s *SAMLConfig) { s.SPCertificate = "nope" }, ErrBadProvider, "spCertificate"},
		{"decryption key is garbage", func(s *SAMLConfig) { s.DecryptionKey = "nope" }, ErrBadProvider, "decryptionKey"},
		{"decryption key without its certificate", func(s *SAMLConfig) { s.DecryptionKey = ssotest.KeyPEM(key) }, ErrBadProvider, "decryptionCertificate"},
		{"unknown AuthnRequest binding", func(s *SAMLConfig) { s.SPMetadata.Binding = "artifact" }, ErrBadProvider, "spMetadata.binding"},
		{"malformed SP metadata", func(s *SAMLConfig) { s.SPMetadata.Metadata = "<EntityDescriptor" }, ErrBadProvider, "SP metadata"},
		{"SP metadata names another entity", func(s *SAMLConfig) {
			s.SPMetadata.Metadata, s.SPMetadata.EntityID = string(otherSP), testSPEntity
		}, ErrSPMetadataMismatch, "entity id"},
	}
	for _, c := range cases {
		pr := base
		s := *base.SAML
		c.mod(&s)
		pr.SAML = &s
		err := p.checkShape(pr)
		if !errors.Is(err, c.want) || !strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: %v, want %v naming %q", c.name, err, c.want, c.text)
		}
	}
	// A missing certificate carries its own SAML code, so logs tell it apart.
	pr := base
	s := *base.SAML
	s.Cert = ""
	pr.SAML = &s
	var se *SAMLError
	if err := p.checkShape(pr); !errors.As(err, &se) || se.Code != SAMLCertificateUnavailable {
		t.Fatalf("no certificate: %v", err)
	}
	// A deprecated algorithm is refused only under OnDeprecated reject.
	s = *base.SAML
	s.SignatureAlgorithm = "sha1"
	pr.SAML = &s
	if err := p.checkShape(pr); err != nil {
		t.Fatalf("RSA-SHA1 refused under the default warn policy: %v", err)
	}
	strict := New(WithSAMLOptions(SAMLOptions{OnDeprecated: DeprecatedReject}))
	strict.acs = testACS
	if err := strict.checkShape(pr); !errors.Is(err, ErrBadProvider) || !strings.Contains(err.Error(), "deprecated") {
		t.Fatalf("RSA-SHA1 under reject: %v", err)
	}
	// A complete key, certificate and decryption pair is accepted.
	s = *base.SAML
	s.PrivateKey, s.SPCertificate, s.DecryptionKey, s.DecryptionCertificate = ssotest.KeyPEM(key), certPEM, ssotest.KeyPEM(key), certPEM
	pr.SAML = &s
	if err := p.checkShape(pr); err != nil {
		t.Fatalf("a complete key set is refused: %v", err)
	}
}

// TestC2_IdPSettingsSources: the IdP's endpoints come from metadata XML and
// from written fields, written fields winning; only signing keys (or keys
// with no use) are trusted, never an encryption key.
func TestC2_IdPSettingsSources(t *testing.T) {
	idp := ssotest.NewSAMLIdP(t, testIdP)
	enc := ssotest.NewSAMLIdP(t, "https://other")
	body := func(c *x509.Certificate) string { return base64.StdEncoding.EncodeToString(c.Raw) }
	md := `<EntityDescriptor entityID="` + testIdP + `"><IDPSSODescriptor>` +
		`<KeyDescriptor use="encryption"><KeyInfo><X509Data><X509Certificate>` + body(enc.Cert) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<KeyDescriptor use="signing"><KeyInfo><X509Data><X509Certificate>` + body(idp.Cert) + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<SingleSignOnService Binding="` + BindingPOST + `" Location="https://idp/post"/>` +
		`<SingleSignOnService Binding="` + BindingRedirect + `" Location="https://idp/sso"/>` +
		`<SingleLogoutService Binding="` + BindingPOST + `" Location="https://idp/slo-post"/>` +
		`<SingleLogoutService Binding="` + BindingRedirect + `" Location="https://idp/slo"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`
	got, err := SAMLConfig{IdPMetadata: IdPMetadata{Metadata: md}}.IdP(DefaultMaxMetadataSize)
	if err != nil || got.SSOURL != "https://idp/sso" || got.SLOURL != "https://idp/slo" || len(got.Certs) != 1 || !got.Certs[0].Equal(idp.Cert) {
		t.Fatalf("from metadata: %+v %v", got, err)
	}
	got, err = SAMLConfig{IdPMetadata: IdPMetadata{Metadata: md, SingleSignOnService: []Endpoint{{Binding: "", Location: "https://written/sso"}, {Binding: BindingPOST, Location: "https://written/post"}}}}.IdP(DefaultMaxMetadataSize)
	if err != nil || got.SSOURL != "https://written/sso" {
		t.Fatalf("a written SSO endpoint does not win: %+v %v", got, err)
	}
}

// TestC2_ParseCertsAndKeys: every key and certificate encoding an admin
// pastes is read, and anything else is an error, never an empty success.
func TestC2_ParseCertsAndKeys(t *testing.T) {
	_, cert, _ := ssotest.KeyPair(t, "x")
	if _, err := parseCerts(base64.StdEncoding.EncodeToString([]byte("not a certificate"))); err == nil {
		t.Fatal("a bare base64 body that is no certificate parsed")
	}
	if _, err := parseCerts(pemOf("CERTIFICATE", []byte("junk"))); err == nil {
		t.Fatal("a CERTIFICATE block of junk parsed")
	}
	cs, err := parseCerts(pemOf("RSA PRIVATE KEY", []byte("skipped")) + pemOf("CERTIFICATE", cert.Raw))
	if err != nil || len(cs) != 1 || !cs[0].Equal(cert) {
		t.Fatalf("a non-certificate block was not skipped: %d %v", len(cs), err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	if k, err := parseKey(pemOf("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk))); err != nil || k == nil {
		t.Fatalf("PKCS #1: %v", err)
	}
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(ek)
	if k, err := parseKey(pemOf("EC PRIVATE KEY", der)); err != nil || k == nil {
		t.Fatalf("SEC 1 EC: %v", err)
	}
	xk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(xk)
	if _, err := parseKey(pemOf("PRIVATE KEY", der)); err == nil || !strings.Contains(err.Error(), "cannot sign") {
		t.Fatalf("an X25519 key was taken as a signing key: %v", err)
	}
	if _, err := parseKey(pemOf("PRIVATE KEY", []byte("junk"))); err == nil {
		t.Fatal("a junk key block parsed")
	}
}

// TestC2_SAMLErrorsAndOptions: the error's text names its code, each code
// answers as its own sentinel, and an unknown algorithm in the allow-list
// is a configuration error.
func TestC2_SAMLErrorsAndOptions(t *testing.T) {
	e := &SAMLError{Code: SAMLTooLarge, Err: errors.New("big")}
	if !strings.Contains(e.Error(), string(SAMLTooLarge)) || !strings.Contains(e.Error(), "big") || !errors.Is(e, ErrSAMLTooLarge) {
		t.Fatalf("SAMLError: %q", e.Error())
	}
	o := defaultSAMLOptions()
	o.AllowedSignatureAlgorithms = []string{"md5"}
	if err := o.validate(); !errors.Is(err, ErrBadAlgorithmSet) {
		t.Fatalf("an unknown allowed algorithm: %v", err)
	}
}

// TestC2_InspectResponseEdges: a document a few bytes over the bound slips
// past the base64 length estimate and is still refused once decoded; an
// algorithm element without its attribute counts as the empty algorithm,
// which the policy then refuses as unknown.
func TestC2_InspectResponseEdges(t *testing.T) {
	doc := `<a xmlns="x">123456</a>` // 23 bytes
	if _, _, err := InspectResponse(base64.StdEncoding.EncodeToString([]byte(doc)), len(doc)-2); !errors.Is(err, ErrSAMLTooLarge) {
		t.Fatalf("over the bound by two: %v", err)
	}
	noAlg := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod/></ds:SignedInfo></ds:Signature></saml:Assertion></samlp:Response>`
	_, f, err := InspectResponse(base64.StdEncoding.EncodeToString([]byte(noAlg)), DefaultMaxResponseSize)
	if err != nil || len(f.SignatureAlgorithms) != 1 || f.SignatureAlgorithms[0] != "" {
		t.Fatalf("facts %+v %v", f, err)
	}
	if err := defaultSAMLOptions().CheckAlgorithms(f, func(string) {}); err == nil {
		t.Fatal("a signature with no algorithm passed the policy")
	}
}

// c2FailSigner is a key whose every signature fails, as a remote KMS can.
type c2FailSigner struct{ crypto.Signer }

var errC2Sign = errors.New("c2: signing unavailable")

func (c2FailSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, errC2Sign }

// deflate64 is the redirect binding's encoding of raw.
func deflate64(raw string) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(raw))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// TestC2_LogoutEncodingRefusals: a logout message that does not decode,
// inflate or parse, or whose signature cannot even be checked, is refused
// with the matching SAML code, never read as an unsigned message.
func TestC2_LogoutEncodingRefusals(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name string
		m    BindingMessage
		code SAMLCode
	}{
		{"not base64", BindingMessage{Redirect: true, Value: "%%%"}, SAMLInvalidEncoding},
		{"not deflated", BindingMessage{Redirect: true, Value: base64.StdEncoding.EncodeToString([]byte("plain"))}, SAMLInvalidEncoding},
		{"no root element", BindingMessage{Redirect: true, Value: deflate64("   ")}, SAMLInvalidXML},
		{"a bad timestamp", BindingMessage{Value: base64.StdEncoding.EncodeToString([]byte(`<samlp:LogoutRequest xmlns:samlp="` + samlProtocolNS + `" ID="_x" NotOnOrAfter="yesterday"/>`))}, SAMLInvalidXML},
	} {
		_, err := PeekLogout(c.m, DefaultMaxResponseSize)
		var se *SAMLError
		if !errors.As(err, &se) || se.Code != c.code {
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		}
	}
	doc := LogoutDocument(KindLogoutRequest, "_lr", testIdP, "https://sp/slo", "ada@acme.test", "", nil, "", "", now)
	u, err := RedirectURL("https://sp/slo", paramSAMLRequest, doc, "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	q, _ := url.Parse(u)
	value := q.Query().Get(paramSAMLRequest)
	for _, c := range []struct{ alg, sig string }{{"urn:unknown", "c2ln"}, {AlgRSASHA256, "%%%"}} {
		_, err := DecodeLogout(BindingMessage{Redirect: true, Param: paramSAMLRequest, Value: value, SigAlg: c.alg, Signature: c.sig}, nil, now, DefaultMaxResponseSize)
		var se *SAMLError
		if !errors.As(err, &se) || se.Code != SAMLSignatureInvalid {
			t.Errorf("signature %q over %q: %v", c.sig, c.alg, err)
		}
	}
}

// TestC2_LogoutSignatureAlgorithms: every SHA-2 size verifies over the
// redirect binding, ECDSA keys included; an unknown algorithm or a failing
// key is an error, never an unsigned URL.
func TestC2_LogoutSignatureAlgorithms(t *testing.T) {
	now := time.Now()
	rk, rc, _ := ssotest.KeyPair(t, "rsa")
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ek.PublicKey, ek)
	ec, _ := x509.ParseCertificate(der)
	doc := LogoutDocument(KindLogoutRequest, "_lr", testIdP, "https://sp/slo", "ada@acme.test", "", nil, "", "", now)
	for _, c := range []struct {
		key  crypto.Signer
		cert *x509.Certificate
		alg  string
	}{{rk, rc, AlgRSASHA384}, {rk, rc, AlgRSASHA512}, {ek, ec, AlgECDSASHA256}, {ek, ec, AlgECDSASHA384}, {ek, ec, AlgECDSASHA512}} {
		u, err := RedirectURL("https://sp/slo", paramSAMLRequest, doc, "r", c.key, c.alg)
		if err != nil {
			t.Fatal(c.alg, err)
		}
		q, _ := url.Parse(u)
		m := BindingMessage{Redirect: true, Param: paramSAMLRequest, Value: q.Query().Get(paramSAMLRequest), RelayState: "r", SigAlg: c.alg, Signature: q.Query().Get(paramSignature)}
		// The RSA certificate is tried first and fails; the right one passes.
		got, err := DecodeLogout(m, []*x509.Certificate{rc, ec}, now, DefaultMaxResponseSize)
		if err != nil || !got.Signed {
			t.Fatalf("%s: %+v %v", c.alg, got, err)
		}
	}
	if _, err := RedirectURL("https://sp/slo", paramSAMLRequest, doc, "", rk, "urn:unknown"); err == nil {
		t.Fatal("an unknown algorithm signed")
	}
	if _, err := RedirectURL("https://sp/slo", paramSAMLRequest, doc, "", c2FailSigner{rk}, AlgRSASHA256); !errors.Is(err, errC2Sign) {
		t.Fatalf("a failing key: %v", err)
	}
}

// TestC2_GoSAML2Failures: the engine refuses to build or verify with a
// signing setup that has no key, and a failing key fails the POST form.
func TestC2_GoSAML2Failures(t *testing.T) {
	f := newSAMLFixture(t)
	key, cert, _ := ssotest.KeyPair(t, "sp")
	sp := f.sp
	sp.AuthnRequestsSigned = true
	if _, err := (GoSAML2{}).AuthnRequestPOST(sp, f.ids, "_x", ""); err == nil {
		t.Fatal("a signed POST request without a key was built")
	}
	if _, err := (GoSAML2{}).VerifyResponse(sp, f.ids, f.idp.Response(f.valid()), time.Now()); err == nil {
		t.Fatal("a response was verified under a broken SP setup")
	}
	sp.SigningKey, sp.Certificate = c2FailSigner{key}, cert
	if _, err := (GoSAML2{}).AuthnRequestPOST(sp, f.ids, "_x", ""); !errors.Is(err, errC2Sign) {
		t.Fatalf("a failing key on the POST binding: %v", err)
	}
	// A signed assertion carrying a timestamp that is not a dateTime.
	for _, attr := range []string{"NotBefore", "NotOnOrAfter"} {
		a := f.valid()
		a.Tamper = func(as *etree.Element) { as.FindElement("Conditions").CreateAttr(attr, "soon") }
		_, err := (GoSAML2{}).VerifyResponse(f.sp, f.ids, f.idp.Response(a), time.Now())
		if err == nil {
			t.Fatalf("a %s of %q verified", attr, "soon")
		}
	}
}

// TestC2_ConvertAssertionTimestamps: a verified assertion whose timestamps
// do not parse is refused as invalid XML rather than read as "no bound".
func TestC2_ConvertAssertionTimestamps(t *testing.T) {
	for _, a := range []types.Assertion{
		{Subject: &types.Subject{SubjectConfirmation: &types.SubjectConfirmation{SubjectConfirmationData: &types.SubjectConfirmationData{NotOnOrAfter: "soon"}}}},
		{Conditions: &types.Conditions{NotBefore: "soon"}},
		{Conditions: &types.Conditions{NotOnOrAfter: "soon"}},
	} {
		_, err := convertAssertion(a)
		var se *SAMLError
		if !errors.As(err, &se) || se.Code != SAMLInvalidXML {
			t.Errorf("%+v: %v", a, err)
		}
	}
}

// TestC2_FetchDiscoveryEdges: a URL that cannot be requested, a body cut
// short, a redirect status the client did not follow, and a server too
// slow for the timeout each get their own discovery code.
func TestC2_FetchDiscoveryEdges(t *testing.T) {
	slow := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/short":
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("{"))
		case "/moved":
			w.WriteHeader(http.StatusFound) // no Location: the client cannot follow
		case "/slow":
			<-slow
		}
	}))
	t.Cleanup(func() { close(slow); srv.Close() })
	p := trustedPlugin(srv.URL)
	ctx := context.Background()
	_, err := p.FetchDiscoveryDocument(ctx, "http://[::1")
	wantDiscovery(t, err, DiscoveryInvalidURL)
	_, err = p.FetchDiscoveryDocument(ctx, srv.URL+"/short")
	wantDiscovery(t, err, DiscoveryUnexpectedFailed)
	_, err = p.FetchDiscoveryDocument(ctx, srv.URL+"/moved")
	wantDiscovery(t, err, DiscoveryRedirect)
	p.hc = guardedClient(50*time.Millisecond, p.trusted)
	_, err = p.FetchDiscoveryDocument(ctx, srv.URL+"/slow")
	wantDiscovery(t, err, DiscoveryTimeout)
}

// TestC2_DiscoveredEndpointRefusals: an endpoint the document names is
// held to the same rules as one written by hand: it must resolve, and
// must not be a private address.
func TestC2_DiscoveredEndpointRefusals(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "authorization_endpoint": auth, "token_endpoint": "/t", "jwks_uri": "/k"})
	}))
	t.Cleanup(srv.Close)
	p := trustedPlugin(srv.URL)
	for _, c := range []struct {
		endpoint string
		code     DiscoveryCode
	}{{"http://[::1", DiscoveryInvalidURL}, {"https://10.0.0.1/authorize", DiscoveryPrivateHost}} {
		auth = c.endpoint
		var cfg OIDCConfig
		wantDiscovery(t, p.Discover(context.Background(), srv.URL, &cfg), c.code)
	}
}

// TestC2_GuardedClientTrustAndPublicDial: a trusted origin without a port
// trusts its scheme's default port (so a loopback origin is dialled, not
// refused as private), and a public address passes the dial check.
func TestC2_GuardedClientTrustAndPublicDial(t *testing.T) {
	hc := guardedClient(200*time.Millisecond, []string{"http://127.0.0.1"})
	// Whether or not something listens on port 80, the dial is attempted.
	if res, err := hc.Get("http://127.0.0.1/x"); errors.Is(err, errPrivateHost) {
		t.Fatalf("a trusted loopback origin was refused as private: %v", err)
	} else if err == nil {
		res.Body.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://192.0.2.1/x", nil) // TEST-NET-1: public, unrouted
	if _, err := guardedClient(200*time.Millisecond, nil).Do(req); err == nil || errors.Is(err, errPrivateHost) {
		t.Fatalf("a public address was refused as private: %v", err)
	}
}

// TestC2_ProviderPathsRefusalsAndMetadata: a form body that does not parse
// is a 400; metadata is served for a SAML provider only, and a provider
// whose stored key cannot be read is a 500, not a document.
func TestC2_ProviderPathsRefusalsAndMetadata(t *testing.T) {
	_, base, _ := c2Base(t)
	p := New()
	p.metaBase, p.acs = "https://app/meta", testACS
	broken := base
	broken.ProviderID, broken.Default = "broken", true
	s := *base.SAML
	s.PrivateKey = "not a key"
	broken.SAML = &s
	good := base
	good.ProviderID, good.Default = "good", true
	oidc := Provider{ProviderID: "oidc", Default: true, OIDC: &OIDCConfig{ClientID: "c"}}
	p.defaults = []Provider{good, broken, oidc}
	var closed bool
	h := p.ProviderPaths("/auth/sso", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { closed = r.Body.Close() == nil }))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/sso/saml2/sp/acs/acme", strings.NewReader("SAMLResponse=%zz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a form that does not parse: %d", rec.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/auth/sso/saml2/sp/acs/acme", strings.NewReader("SAMLResponse=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !closed {
		t.Fatal("the rewritten body does not close")
	}
	for id, want := range map[string]int{"good": http.StatusOK, "broken": http.StatusInternalServerError, "oidc": http.StatusNotFound} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/sso"+PathSPMetadata+"?providerId="+id, nil))
		if rec.Code != want {
			t.Errorf("metadata of %s: %d, want %d", id, rec.Code, want)
		}
	}
}

// TestC2_SmallRules: the DNS resolver default, Validate's field and prefix
// checks, and the options that only set a value.
func TestC2_SmallRules(t *testing.T) {
	if (&DomainVerification{}).resolver() != net.DefaultResolver {
		t.Fatal("no resolver is not the system resolver")
	}
	build := func(opts ...Option) error {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithSecret([]byte("0123456789abcdef0123456789abcdef")), auth.WithPlugins(New(opts...)))
		return err
	}
	if err := build(WithProviderFields(ProviderField{Name: "issuer"})); !errors.Is(err, ErrBadFields) {
		t.Fatalf("a built-in field name: %v", err)
	}
	// "_" + prefix + "-" + a one-character id is 63 bytes at a 60-byte
	// prefix, the longest label DNS allows; one byte more is refused.
	if err := build(WithDomainVerification(DomainVerification{TokenPrefix: strings.Repeat("p", 60)})); err != nil {
		t.Fatalf("a prefix that fits a DNS label: %v", err)
	}
	if err := build(WithDomainVerification(DomainVerification{TokenPrefix: strings.Repeat("p", 61)})); !errors.Is(err, ErrPrefixTooLong) {
		t.Fatalf("a prefix too long for a DNS label: %v", err)
	}
	hc := &http.Client{}
	p := New(WithCallbackURL("https://app/cb"), WithACSURL("https://app/acs"), WithStateTTL(time.Minute), WithHTTPClient(hc))
	if p.callback != "https://app/cb" || p.acs != "https://app/acs" || p.stateTTL != time.Minute || p.hc != hc || !p.hcSet {
		t.Fatalf("options: %+v", p)
	}
}
