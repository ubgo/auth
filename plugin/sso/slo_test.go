package sso

import (
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/sso/ssotest"
)

// encFixture is a samlFixture whose SP holds a decryption key pair.
func encFixture(t *testing.T) (samlFixture, *x509.Certificate) {
	f := newSAMLFixture(t)
	key, cert, _ := ssotest.KeyPair(t, "sp-enc")
	f.sp.DecryptionKey, f.sp.DecryptionCert = key, cert
	return f, cert
}

func TestSAML_EncryptedAssertionDecrypts(t *testing.T) {
	f, cert := encFixture(t)
	for _, alg := range []string{ssotest.EncAES256GCM, ssotest.EncAES128CBC} {
		for name, mod := range map[string]func(*ssotest.Assertion){
			"assertion signed": func(*ssotest.Assertion) {},
			"response signed":  func(a *ssotest.Assertion) { a.SignAssertion, a.SignResponse = false, true },
		} {
			a := f.valid()
			mod(&a)
			got, err := f.accept(t, f.idp.EncryptedResponse(a, cert, alg), CheckRequest{RequestID: testReqID}, SAMLOptions{})
			if err != nil || got.NameID != "ada@acme.test" {
				t.Fatalf("%s %s: %+v %v", alg, name, got, err)
			}
		}
	}
}

func TestSAML_EncryptedAssertionRefusals(t *testing.T) {
	f, cert := encFixture(t)
	// Encrypted but signed by nobody: refused, whatever the encryption.
	a := f.valid()
	a.SignAssertion = false
	_, err := f.accept(t, f.idp.EncryptedResponse(a, cert, ssotest.EncAES256GCM), CheckRequest{RequestID: testReqID}, SAMLOptions{})
	wantCode(t, err, SAMLSignatureInvalid)
	// Encrypted for another SP: cannot be decrypted, refused.
	_, other, _ := ssotest.KeyPair(t, "other-sp")
	_, err = f.accept(t, f.idp.EncryptedResponse(f.valid(), other, ssotest.EncAES256GCM), CheckRequest{RequestID: testReqID}, SAMLOptions{})
	wantCode(t, err, SAMLSignatureInvalid)
	// An SP with no decryption key refuses an encrypted assertion.
	plain := newSAMLFixture(t)
	plain.idp = f.idp
	_, err = plain.accept(t, f.idp.EncryptedResponse(f.valid(), cert, ssotest.EncAES256GCM), CheckRequest{RequestID: testReqID}, SAMLOptions{})
	wantCode(t, err, SAMLSignatureInvalid)
	// The algorithm policy sees the encryption methods.
	enc := f.idp.EncryptedResponse(f.valid(), cert, ssotest.EncTripleDES)
	_, err = f.accept(t, enc, CheckRequest{RequestID: testReqID}, SAMLOptions{OnDeprecated: DeprecatedReject})
	wantCode(t, err, SAMLDeprecatedAlgorithm)
	enc = f.idp.EncryptedResponse(f.valid(), cert, ssotest.EncAES128CBC)
	_, err = f.accept(t, enc, CheckRequest{RequestID: testReqID}, SAMLOptions{AllowedDataEncryptionAlgorithms: []string{DataEncAES256GCM}})
	wantCode(t, err, SAMLAlgorithmNotAllowed)
	_, err = f.accept(t, enc, CheckRequest{RequestID: testReqID}, SAMLOptions{AllowedKeyEncryptionAlgorithms: []string{KeyEncRSAOAEP11}})
	wantCode(t, err, SAMLAlgorithmNotAllowed)
	_, facts, _ := InspectResponse(enc, DefaultMaxResponseSize)
	if facts.Assertions != 1 || len(facts.KeyEncryption) != 1 || facts.KeyEncryption[0] != KeyEncRSAOAEP || facts.DataEncryption[0] != DataEncAES128CBC {
		t.Fatalf("%+v", facts)
	}
}

func TestLogout_RoundTripAndSignatures(t *testing.T) {
	idpKey, idpCert, _ := ssotest.KeyPair(t, "idp")
	_, otherCert, _ := ssotest.KeyPair(t, "other")
	now := time.Now()
	doc := LogoutDocument(KindLogoutRequest, "_lr1", testIdP, "https://sp/slo", "ada@acme.test", NameIDEmail, []string{"s1", "s2"}, "", "", now)
	for _, alg := range []string{AlgRSASHA256, AlgRSASHA1} {
		u, err := RedirectURL("https://sp/slo?providerId=x", paramSAMLRequest, doc, "relay 1", idpKey, alg)
		if err != nil {
			t.Fatal(err)
		}
		q, _ := url.Parse(u)
		m := BindingMessage{Redirect: true, Param: paramSAMLRequest, Value: q.Query().Get(paramSAMLRequest), RelayState: q.Query().Get(paramRelayState),
			SigAlg: q.Query().Get(paramSigAlg), Signature: q.Query().Get(paramSignature)}
		got, err := DecodeLogout(m, []*x509.Certificate{idpCert}, now, DefaultMaxResponseSize)
		if err != nil || !got.Signed || got.Kind != KindLogoutRequest || got.ID != "_lr1" || got.Issuer != testIdP || got.NameID != "ada@acme.test" || len(got.SessionIndexes) != 2 || got.Destination != "https://sp/slo" {
			t.Fatalf("%s: %+v %v", alg, got, err)
		}
		if _, err := DecodeLogout(m, []*x509.Certificate{otherCert}, now, DefaultMaxResponseSize); err == nil {
			t.Fatal("a signature by another key was accepted")
		}
		m.RelayState = "tampered"
		if _, err := DecodeLogout(m, []*x509.Certificate{idpCert}, now, DefaultMaxResponseSize); err == nil {
			t.Fatal("a tampered relay state kept its signature")
		}
	}
	// Unsigned redirect message: decodes, Signed false.
	u, _ := RedirectURL("https://sp/slo", paramSAMLResponse, LogoutDocument(KindLogoutResponse, "_r", testIdP, "https://sp/slo", "", "", nil, "_lr1", StatusSuccess, now), "", nil, "")
	q, _ := url.Parse(u)
	got, err := DecodeLogout(BindingMessage{Redirect: true, Param: paramSAMLResponse, Value: q.Query().Get(paramSAMLResponse)}, nil, now, DefaultMaxResponseSize)
	if err != nil || got.Signed || got.Kind != KindLogoutResponse || got.InResponseTo != "_lr1" || got.Status != StatusSuccess {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := DecodeLogout(BindingMessage{Redirect: true, Param: paramSAMLResponse, Value: q.Query().Get(paramSAMLResponse)}, nil, now, 10); err == nil {
		t.Fatal("oversize logout accepted")
	}
}

func TestLogout_POSTBindingSignature(t *testing.T) {
	idp := ssotest.NewSAMLIdP(t, testIdP)
	now := time.Now()
	doc := LogoutDocument(KindLogoutRequest, "_lr2", testIdP, "https://sp/slo", "ada@acme.test", "", nil, "", "", now)
	signed := idp.Sign(doc.Root(), false)
	doc.SetRoot(signed)
	enc := ssotest.Encode(doc)
	got, err := DecodeLogout(BindingMessage{Param: paramSAMLRequest, Value: enc}, []*x509.Certificate{idp.Cert}, now, DefaultMaxResponseSize)
	if err != nil || !got.Signed || got.NameID != "ada@acme.test" {
		t.Fatalf("%+v %v", got, err)
	}
	doc.FindElement("//NameID").SetText("victim@acme.test")
	_, err = DecodeLogout(BindingMessage{Param: paramSAMLRequest, Value: ssotest.Encode(doc)}, []*x509.Certificate{idp.Cert}, now, DefaultMaxResponseSize)
	wantCode(t, err, SAMLSignatureInvalid)
	_, err = DecodeLogout(BindingMessage{Param: paramSAMLRequest, Value: b64(`<!DOCTYPE x><r/>`)}, nil, now, DefaultMaxResponseSize)
	wantCode(t, err, SAMLInvalidXML)
	_, err = DecodeLogout(BindingMessage{Param: paramSAMLRequest, Value: b64(`<r xmlns="urn:x"/>`)}, nil, now, DefaultMaxResponseSize)
	wantCode(t, err, SAMLInvalidXML)
	if _, err := hashFor("urn:nope"); err == nil {
		t.Fatal("unknown algorithm")
	}
	_ = (*rsa.PrivateKey)(nil)
	if !strings.Contains(signedQuery("A", "b c", "", "s"), "b+c") {
		t.Fatal("signedQuery encoding")
	}
}
