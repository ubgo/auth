// Package ssotest runs a fake OpenID Connect provider and a fake SAML
// identity provider for tests of an app's SSO wiring: the OIDC side serves
// discovery, JWKS, a token endpoint that checks PKCE and the client, and
// userinfo; the SAML side signs responses with a fresh certificate. Neither
// is for production.
package ssotest

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Person is who signs in at a fake IdP.
type Person struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	// Extra claims are added to the ID token and userinfo.
	Extra map[string]any
}

// OIDC is a fake OpenID Connect provider.
type OIDC struct {
	URL          string
	ClientID     string
	ClientSecret string
	// Person signs in at the next Authorize.
	Person Person
	// IDTokenClaims, when set, change the next ID token's claims (a test of
	// a wrong aud, iss or azp).
	IDTokenClaims func(claims map[string]any)
	// UserInfoSubject, when set, is the sub userinfo answers.
	UserInfoSubject string
	// OmitIDToken leaves the id_token out of the token response.
	OmitIDToken bool

	key  *rsa.PrivateKey
	srv  *httptest.Server
	mu   sync.Mutex
	pend map[string]pending
}

type pending struct {
	challenge, nonce, redirect string
	person                     Person
}

// keyID names the fake provider's signing key.
const keyID = "ssotest-1"

// NewOIDC starts a fake provider; it stops when the test ends.
func NewOIDC(t testing.TB) *OIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	o := &OIDC{ClientID: "client-1", ClientSecret: "secret-1", key: key, pend: map[string]pending{},
		Person: Person{Subject: "sub-1", Email: "ada@acme.test", EmailVerified: true, Name: "Ada"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", o.discovery)
	mux.HandleFunc("/jwks", o.jwks)
	mux.HandleFunc("/token", o.token)
	mux.HandleFunc("/userinfo", o.userinfo)
	o.srv = httptest.NewServer(mux)
	o.URL = o.srv.URL
	t.Cleanup(o.srv.Close)
	return o
}

// Issuer is the provider's issuer.
func (o *OIDC) Issuer() string { return o.URL }

func (o *OIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer": o.URL, "authorization_endpoint": o.URL + "/authorize", "token_endpoint": o.URL + "/token",
		"userinfo_endpoint": o.URL + "/userinfo", "jwks_uri": o.URL + "/jwks",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (o *OIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := o.key.PublicKey
	writeJSON(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": keyID, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// Authorize plays the person consenting at authURL: it records the PKCE
// challenge and nonce and returns the query the IdP would redirect back
// with (code and state).
func (o *OIDC) Authorize(t testing.TB, authURL string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("client_id") != o.ClientID {
		t.Fatalf("ssotest: client_id %q", q.Get("client_id"))
	}
	code := rand.Text()
	o.mu.Lock()
	o.pend[code] = pending{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri"), person: o.Person}
	o.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}}
}

func (o *OIDC) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != o.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(o.ClientSecret)) != 1 {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(w, map[string]any{"error": "invalid_client"})
		return
	}
	o.mu.Lock()
	p, found := o.pend[r.PostForm.Get("code")]
	delete(o.pend, r.PostForm.Get("code"))
	o.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || base64.RawURLEncoding.EncodeToString(sum[:]) != p.challenge || r.PostForm.Get("redirect_uri") != p.redirect {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]any{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	claims := map[string]any{"iss": o.URL, "aud": o.ClientID, "sub": p.person.Subject, "email": p.person.Email,
		"email_verified": p.person.EmailVerified, "name": p.person.Name, "nonce": p.nonce,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range p.person.Extra {
		claims[k] = v
	}
	if o.IDTokenClaims != nil {
		o.IDTokenClaims(claims)
	}
	out := map[string]any{"access_token": "at-" + p.person.Subject, "token_type": "Bearer", "expires_in": 3600, "id_token": o.sign(claims)}
	if o.OmitIDToken {
		delete(out, "id_token")
	}
	writeJSON(w, out)
}

func (o *OIDC) userinfo(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer at-")
	if o.UserInfoSubject != "" {
		sub = o.UserInfoSubject
	}
	out := map[string]any{"sub": sub, "email": o.Person.Email, "email_verified": o.Person.EmailVerified, "name": o.Person.Name}
	for k, v := range o.Person.Extra {
		out[k] = v
	}
	writeJSON(w, out)
}

// sign makes an RS256 JWT.
func (o *OIDC) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, o.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err) // a 2048-bit key always signs
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// SAMLIdP is a fake SAML identity provider.
type SAMLIdP struct {
	EntityID string
	SSOURL   string
	// CertPEM is the signing certificate, for SAMLConfig.Cert.
	CertPEM string
	Cert    *x509.Certificate
	key     *rsa.PrivateKey
}

// NewSAMLIdP makes an IdP with a fresh RSA key and self-signed certificate.
func NewSAMLIdP(t testing.TB, entityID string) *SAMLIdP {
	t.Helper()
	key, cert, certPEM := KeyPair(t, entityID)
	return &SAMLIdP{EntityID: entityID, SSOURL: "https://idp.example.com/sso", CertPEM: certPEM, Cert: cert, key: key}
}

// KeyPair makes an RSA key and a self-signed certificate valid for a day
// either side of now, and returns the certificate as PEM too.
func KeyPair(t testing.TB, cn string) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// KeyPEM encodes an RSA key as PKCS #8 PEM.
func KeyPEM(key *rsa.PrivateKey) string {
	der, _ := x509.MarshalPKCS8PrivateKey(key) // an RSA key always marshals
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// Assertion describes the response a test wants.
type Assertion struct {
	ID           string
	NameID       string
	Audience     string
	Recipient    string
	Destination  string
	InResponseTo string
	// Issuer defaults to the IdP's entity id.
	Issuer       string
	NotBefore    time.Time
	NotOnOrAfter time.Time
	// ConfirmationNotOnOrAfter bounds the SubjectConfirmationData instead
	// of NotOnOrAfter when set, so the two can differ.
	ConfirmationNotOnOrAfter time.Time
	Attributes               map[string][]string
	// SignAssertion and SignResponse choose what is signed.
	SignAssertion bool
	SignResponse  bool
	// NoAudience leaves the AudienceRestriction out.
	NoAudience bool
	// SHA1 signs with RSA-SHA1 and a SHA-1 digest.
	SHA1 bool
	// Tamper, when set, edits the assertion element before it is signed:
	// a test of content a real IdP would never send, signed all the same.
	Tamper func(assertion *etree.Element)
}

// Valid returns an Assertion that a correctly configured SP accepts now.
func (i *SAMLIdP) Valid(acs, audience, inResponseTo, nameID string) Assertion {
	now := time.Now().UTC()
	return Assertion{ID: "_a" + rand.Text(), NameID: nameID, Audience: audience, Recipient: acs, Destination: acs, InResponseTo: inResponseTo,
		NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(5 * time.Minute), SignAssertion: true,
		Attributes: map[string][]string{"email": {nameID}, "givenName": {"Ada"}, "surname": {"Lovelace"}}}
}

// samlTime formats a SAML timestamp.
func samlTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

const (
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
)

// AssertionElement builds the (unsigned) assertion element.
func (i *SAMLIdP) AssertionElement(a Assertion) *etree.Element {
	as := etree.NewElement("saml:Assertion")
	as.CreateAttr("xmlns:saml", nsAssertion)
	as.CreateAttr("ID", a.ID)
	as.CreateAttr("Version", "2.0")
	as.CreateAttr("IssueInstant", samlTime(time.Now()))
	as.CreateElement("saml:Issuer").SetText(firstOf(a.Issuer, i.EntityID))
	subj := as.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText(a.NameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("Recipient", a.Recipient)
	confirm := a.NotOnOrAfter
	if !a.ConfirmationNotOnOrAfter.IsZero() {
		confirm = a.ConfirmationNotOnOrAfter
	}
	scd.CreateAttr("NotOnOrAfter", samlTime(confirm))
	if a.InResponseTo != "" {
		scd.CreateAttr("InResponseTo", a.InResponseTo)
	}
	cond := as.CreateElement("saml:Conditions")
	if !a.NotBefore.IsZero() {
		cond.CreateAttr("NotBefore", samlTime(a.NotBefore))
	}
	if !a.NotOnOrAfter.IsZero() {
		cond.CreateAttr("NotOnOrAfter", samlTime(a.NotOnOrAfter))
	}
	if !a.NoAudience {
		cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(a.Audience)
	}
	authn := as.CreateElement("saml:AuthnStatement")
	authn.CreateAttr("AuthnInstant", samlTime(time.Now()))
	authn.CreateAttr("SessionIndex", "_s"+a.ID)
	if len(a.Attributes) > 0 {
		st := as.CreateElement("saml:AttributeStatement")
		for name, vs := range a.Attributes {
			at := st.CreateElement("saml:Attribute")
			at.CreateAttr("Name", name)
			for _, v := range vs {
				at.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	if a.Tamper != nil {
		a.Tamper(as)
	}
	return as
}

// signer returns a signing context for the IdP key.
func (i *SAMLIdP) signer(sha1 bool) *dsig.SigningContext {
	ctx, err := dsig.NewSigningContext(i.key, [][]byte{i.Cert.Raw})
	if err != nil {
		panic(err) // a non-nil RSA key always makes a context
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if sha1 {
		ctx.Hash = crypto.SHA1
		_ = ctx.SetSignatureMethod(dsig.RSASHA1SignatureMethod)
	}
	return ctx
}

// Sign signs el in place of itself (an enveloped signature).
func (i *SAMLIdP) Sign(el *etree.Element, sha1 bool) *etree.Element {
	signed, err := i.signer(sha1).SignEnveloped(el)
	if err != nil {
		panic(err)
	}
	return signed
}

// ResponseDocument builds the whole response document.
func (i *SAMLIdP) ResponseDocument(a Assertion) *etree.Document {
	as := i.AssertionElement(a)
	if a.SignAssertion {
		as = i.Sign(as, a.SHA1)
	}
	res := i.responseShell(a)
	res.AddChild(as)
	if a.SignResponse {
		res = i.Sign(res, a.SHA1)
	}
	doc := etree.NewDocument()
	doc.SetRoot(res)
	return doc
}

// responseShell is a Response with its issuer and status, no assertion.
func (i *SAMLIdP) responseShell(a Assertion) *etree.Element {
	res := etree.NewElement("samlp:Response")
	res.CreateAttr("xmlns:samlp", nsProtocol)
	res.CreateAttr("xmlns:saml", nsAssertion)
	res.CreateAttr("ID", "_r"+rand.Text())
	res.CreateAttr("Version", "2.0")
	res.CreateAttr("IssueInstant", samlTime(time.Now()))
	if a.Destination != "" {
		res.CreateAttr("Destination", a.Destination)
	}
	if a.InResponseTo != "" {
		res.CreateAttr("InResponseTo", a.InResponseTo)
	}
	res.CreateElement("saml:Issuer").SetText(firstOf(a.Issuer, i.EntityID))
	res.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	return res
}

// Response returns the base64 SAMLResponse an ACS post carries.
func (i *SAMLIdP) Response(a Assertion) string { return Encode(i.ResponseDocument(a)) }

// Encode base64-encodes a document.
func Encode(doc *etree.Document) string {
	b, err := doc.WriteToBytes()
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// AuthnRequest reads an HTTP-Redirect AuthnRequest URL: the request's ID,
// its ACS URL and the RelayState.
func AuthnRequest(t testing.TB, redirectURL string) (id, acs, relay string) {
	t.Helper()
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	xmlBytes, err := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil {
		t.Fatal(err)
	}
	return doc.Root().SelectAttrValue("ID", ""), doc.Root().SelectAttrValue("AssertionConsumerServiceURL", ""), u.Query().Get("RelayState")
}

func firstOf(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Encryption algorithms Encrypt can use.
const (
	EncAES256GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	EncAES128CBC = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	EncTripleDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	keyRSAOAEP   = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	nsXMLEnc     = "http://www.w3.org/2001/04/xmlenc#"
	nsXMLDSig    = "http://www.w3.org/2000/09/xmldsig#"
)

// Encrypt wraps a (usually signed) assertion in an EncryptedAssertion for
// the SP certificate: a fresh AES key under RSA-OAEP, the data under
// dataAlg (EncAES256GCM or EncAES128CBC). EncTripleDES only labels the
// data, for a test of the algorithm policy; it never decrypts.
func Encrypt(assertion *etree.Element, sp *x509.Certificate, dataAlg string) *etree.Element {
	d := etree.NewDocument()
	d.SetRoot(assertion.Copy())
	plain, err := d.WriteToBytes()
	if err != nil {
		panic(err)
	}
	keyLen := 32
	if dataAlg == EncAES128CBC {
		keyLen = 16
	}
	key := make([]byte, keyLen)
	_, _ = rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var data []byte
	switch dataAlg {
	case EncAES128CBC, EncTripleDES:
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
		iv := make([]byte, aes.BlockSize)
		_, _ = rand.Read(iv)
		out := make([]byte, len(plain))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
		data = append(iv, out...)
	default:
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}
		nonce := make([]byte, gcm.NonceSize())
		_, _ = rand.Read(nonce)
		data = gcm.Seal(nonce, nonce, plain, nil)
	}
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, sp.PublicKey.(*rsa.PublicKey), key, nil)
	if err != nil {
		panic(err)
	}
	ea := etree.NewElement("saml:EncryptedAssertion")
	ea.CreateAttr("xmlns:saml", nsAssertion)
	ed := ea.CreateElement("xenc:EncryptedData")
	ed.CreateAttr("xmlns:xenc", nsXMLEnc)
	ed.CreateAttr("Type", nsXMLEnc+"Element")
	ed.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", dataAlg)
	ki := ed.CreateElement("ds:KeyInfo")
	ki.CreateAttr("xmlns:ds", nsXMLDSig)
	ek := ki.CreateElement("xenc:EncryptedKey")
	ek.CreateElement("xenc:EncryptionMethod").CreateAttr("Algorithm", keyRSAOAEP)
	ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(wrapped))
	ed.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText(base64.StdEncoding.EncodeToString(data))
	return ea
}

// EncryptedResponse is ResponseDocument with its assertion encrypted for sp.
func (i *SAMLIdP) EncryptedResponse(a Assertion, sp *x509.Certificate, dataAlg string) string {
	as := i.AssertionElement(a)
	if a.SignAssertion {
		as = i.Sign(as, a.SHA1)
	}
	res := i.responseShell(a)
	res.AddChild(Encrypt(as, sp, dataAlg))
	if a.SignResponse {
		res = i.Sign(res, a.SHA1)
	}
	out := etree.NewDocument()
	out.SetRoot(res)
	return Encode(out)
}

// Signer is the IdP's signing key, for a test that signs its own messages
// (a LogoutRequest over the redirect binding).
func (i *SAMLIdP) Signer() crypto.Signer { return i.key }
