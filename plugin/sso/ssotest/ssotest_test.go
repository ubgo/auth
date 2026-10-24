package ssotest

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// fatalT records a Fatal instead of stopping the test, so a helper's own
// refusals can be asserted. Fatal panics to stop the helper as
// runtime.Goexit would.
type fatalT struct {
	testing.TB
	msg string
}

type fatalStop struct{}

func (f *fatalT) Helper() {}

func (f *fatalT) Fatal(args ...any) { f.msg = fmt.Sprint(args...); panic(fatalStop{}) }

func (f *fatalT) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	panic(fatalStop{})
}

// fails runs fn with a fatalT and returns what it failed with, "" if it
// did not fail.
func fails(t *testing.T, fn func(tb testing.TB)) (msg string) {
	t.Helper()
	f := &fatalT{TB: t}
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(fatalStop); !ok {
				panic(r)
			}
			msg = f.msg
		}
	}()
	fn(f)
	return ""
}

// TestOIDC_AuthorizeRefusesWhatARealIdPWould: a URL that does not parse and
// one for another client fail the test instead of minting a code.
func TestOIDC_AuthorizeRefusesWhatARealIdPWould(t *testing.T) {
	o := NewOIDC(t)
	if msg := fails(t, func(tb testing.TB) { o.Authorize(tb, "http://[::1") }); msg == "" {
		t.Fatal("an unparsable URL was authorized")
	}
	if msg := fails(t, func(tb testing.TB) { o.Authorize(tb, o.URL+"/authorize?client_id=other") }); !strings.Contains(msg, "client_id") {
		t.Fatalf("another client was authorized: %q", msg)
	}
	if msg := fails(t, func(tb testing.TB) { AuthnRequest(tb, "http://[::1") }); msg == "" {
		t.Fatal("an unparsable AuthnRequest URL was read")
	}
	for _, q := range []string{"SAMLRequest=%25%25", "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("not deflated"))), "SAMLRequest=" + deflated("<a><b></a>")} {
		if msg := fails(t, func(tb testing.TB) { AuthnRequest(tb, "https://idp/sso?"+q) }); msg == "" {
			t.Fatalf("a broken SAMLRequest was read: %s", q)
		}
	}
}

// TestOIDC_TokenEndpoint: the token endpoint takes client_secret_post as
// well as basic, refuses another client and a code it did not issue, and
// puts a person's extra claims in the ID token and userinfo.
func TestOIDC_TokenEndpoint(t *testing.T) {
	o := NewOIDC(t)
	o.Person.Extra = map[string]any{"department": "R&D"}
	post := func(form url.Values) (int, map[string]any) {
		t.Helper()
		res, err := http.PostForm(o.URL+"/token", form)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	if st, out := post(url.Values{"client_id": {"other"}, "client_secret": {o.ClientSecret}}); st != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Fatalf("another client: %d %v", st, out)
	}
	if st, out := post(url.Values{"client_id": {o.ClientID}, "client_secret": {o.ClientSecret}, "code": {"never-issued"}}); st != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Fatalf("an unknown code: %d %v", st, out)
	}
	verifier := "verifier-verifier-verifier-verifier-verifier"
	q := o.Authorize(t, o.URL+"/authorize?client_id="+o.ClientID+"&redirect_uri=https://app/cb&nonce=n1&code_challenge="+challenge(verifier))
	st, out := post(url.Values{"client_id": {o.ClientID}, "client_secret": {o.ClientSecret}, "code": {q.Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"https://app/cb"}})
	if st != http.StatusOK {
		t.Fatalf("client_secret_post: %d %v", st, out)
	}
	parts := strings.Split(out["id_token"].(string), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	if claims["department"] != "R&D" || claims["nonce"] != "n1" {
		t.Fatalf("ID token claims %v", claims)
	}
	req, _ := http.NewRequest(http.MethodGet, o.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer at-sub-1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var info map[string]any
	_ = json.NewDecoder(res.Body).Decode(&info)
	if info["department"] != "R&D" || info["sub"] != "sub-1" {
		t.Fatalf("userinfo %v", info)
	}
}

// TestSAMLIdP_SigningAndEncryptionVariants: a response-level signature, an
// RSA-SHA1 signature and the CBC data ciphers produce the documents a
// test asks for.
func TestSAMLIdP_SigningAndEncryptionVariants(t *testing.T) {
	i := NewSAMLIdP(t, "https://idp")
	a := i.Valid("https://sp/acs", "https://sp", "_r", "ada@acme.test")
	a.SignAssertion, a.SignResponse, a.SHA1 = false, true, true
	doc := decode(t, i.Response(a))
	sm := doc.FindElement("//SignatureMethod")
	if doc.Root().SelectElement("Signature") == nil || sm == nil || sm.SelectAttrValue("Algorithm", "") != "http://www.w3.org/2000/09/xmldsig#rsa-sha1" {
		t.Fatal("no RSA-SHA1 signature on the response")
	}
	_, spCert, _ := KeyPair(t, "sp")
	for _, alg := range []string{EncAES128CBC, EncTripleDES} {
		enc := decode(t, i.EncryptedResponse(a, spCert, alg))
		em := enc.FindElement("//EncryptedData/EncryptionMethod")
		if em == nil || em.SelectAttrValue("Algorithm", "") != alg || enc.Root().SelectElement("Signature") == nil {
			t.Fatalf("%s: not an encrypted, signed response", alg)
		}
	}
	if a.ConfirmationNotOnOrAfter = time.Now().Add(time.Hour); !strings.Contains(decode(t, i.Response(a)).FindElement("//SubjectConfirmationData").SelectAttrValue("NotOnOrAfter", ""), samlTime(a.ConfirmationNotOnOrAfter)) {
		t.Fatal("ConfirmationNotOnOrAfter is not the confirmation's bound")
	}
}

// challenge is the S256 PKCE challenge of verifier.
func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// deflated is the redirect binding's encoding of s.
func deflated(s string) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
}

func decode(t *testing.T, encoded string) *etree.Document {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestSAMLIdP_IssuerAndTamper: an Assertion's Issuer replaces the IdP's
// entity id, and Tamper edits the element before it is signed.
func TestSAMLIdP_IssuerAndTamper(t *testing.T) {
	i := NewSAMLIdP(t, "https://idp")
	a := i.Valid("https://sp/acs", "https://sp", "_r", "ada@acme.test")
	a.Issuer = "https://other-idp"
	a.Tamper = func(as *etree.Element) { as.CreateAttr("Tampered", "yes") }
	as := decode(t, i.Response(a)).FindElement("//Assertion")
	if as.FindElement("Issuer").Text() != "https://other-idp" || as.SelectAttrValue("Tampered", "") != "yes" || as.FindElement("Signature") == nil {
		t.Fatal("issuer or tamper not applied before signing")
	}
}

// TestOIDC_TokenEndpointRefusesABadForm: a body that is not a form is a
// 400, as a real token endpoint answers.
func TestOIDC_TokenEndpointRefusesABadForm(t *testing.T) {
	o := NewOIDC(t)
	res, err := http.Post(o.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader("code=%zz"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("a malformed form: %d", res.StatusCode)
	}
}
