package sso

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/ubgo/auth/plugin/sso/ssotest"
)

func TestCheckDigest(t *testing.T) {
	post := SAMLConfig{AuthnRequestsSigned: true, SPMetadata: SPMetadata{Binding: AuthnBindingPOST}}
	for _, tc := range []struct {
		cfg SAMLConfig
		ok  bool
	}{
		{SAMLConfig{}, true},
		{SAMLConfig{DigestAlgorithm: DigestSHA256}, false},                                                    // redirect binding: no digest exists
		{SAMLConfig{DigestAlgorithm: DigestSHA256, SPMetadata: SPMetadata{Binding: AuthnBindingPOST}}, false}, // unsigned
		{func() SAMLConfig { c := post; c.DigestAlgorithm = DigestSHA256; return c }(), true},
		{func() SAMLConfig { c := post; c.DigestAlgorithm = DigestSHA512; return c }(), false},
		{func() SAMLConfig {
			c := post
			c.SignatureAlgorithm, c.DigestAlgorithm = "sha512", DigestSHA512
			return c
		}(), true},
	} {
		err := tc.cfg.checkDigest()
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrBadProvider)) {
			t.Errorf("%+v: %v", tc.cfg, err)
		}
	}
}

func TestGoSAML2_AuthnRequestPOST(t *testing.T) {
	f := newSAMLFixture(t)
	form, err := GoSAML2{}.AuthnRequestPOST(f.sp, f.ids, "_pid", "relay-p")
	if err != nil || form.Action != f.idp.SSOURL || form.RelayState != "relay-p" {
		t.Fatalf("%+v %v", form, err)
	}
	key, cert, _ := ssotest.KeyPair(t, "sp")
	for _, alg := range []string{AlgRSASHA256, AlgRSASHA512} {
		sp := f.sp
		sp.AuthnRequestsSigned, sp.SigningKey, sp.Certificate, sp.SignatureAlgorithm = true, key, cert, alg
		form, err = GoSAML2{}.AuthnRequestPOST(sp, f.ids, "_pid", "")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(form.SAMLRequest)
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(raw); err != nil {
			t.Fatal(err)
		}
		if doc.Root().SelectAttrValue("ID", "") != "_pid" {
			t.Fatal("request id")
		}
		if _, err := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}).Validate(doc.Root()); err != nil {
			t.Fatalf("%s: signature does not verify: %v", alg, err)
		}
		if !strings.Contains(string(raw), `DigestMethod Algorithm="`+digestOf[alg]+`"`) {
			t.Fatalf("%s: digest is not %s:\n%s", alg, digestOf[alg], raw)
		}
	}
}
