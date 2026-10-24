package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// TestAlgOf_RefusesAPointOffTheCurve: a P-256 key whose point is not on the
// curve, or is missing, is no key: no algorithm, no key id, no JWK.
func TestAlgOf_RefusesAPointOffTheCurve(t *testing.T) {
	for name, k := range map[string]*ecdsa.PublicKey{
		"off the curve": {Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(1)},
		"no point":      {Curve: elliptic.P256()},
	} {
		if _, err := AlgOf(k); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("%s: AlgOf = %v", name, err)
		}
		if KeyID(k) != "" {
			t.Errorf("%s: has a key id", name)
		}
		if _, ok := jwkOf(k); ok {
			t.Errorf("%s: has a JWK", name)
		}
	}
	good, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if alg, err := AlgOf(&good.PublicKey); err != nil || alg != ES256 || KeyID(&good.PublicKey) == "" {
		t.Fatalf("a real P-256 key: %v %v", alg, err)
	}
}

// TestThumbprint_ECKey: an EC JWK's thumbprint covers crv, kty, x and y
// (RFC 7638), so two keys differing only in y differ.
func TestThumbprint_ECKey(t *testing.T) {
	a, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ja, _ := jwkOf(&a.PublicKey)
	jb, _ := jwkOf(&b.PublicKey)
	ta, err := Thumbprint(ja)
	if err != nil || ta == "" {
		t.Fatalf("thumbprint = %q %v", ta, err)
	}
	if again, _ := Thumbprint(ja); again != ta {
		t.Fatal("thumbprint is not deterministic")
	}
	if tb, _ := Thumbprint(jb); tb == ta {
		t.Fatal("two keys share a thumbprint")
	}
}

// TestVerifySignature_BadSegments: a header or payload that is not strict
// base64url is invalid, the payload one even under a valid signature.
func TestVerifySignature_BadSegments(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	enc := base64.RawURLEncoding
	if _, _, err := VerifySignature("!!.e30.sig", pub, "dpop+jwt"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "header") {
		t.Fatalf("bad header: %v", err)
	}
	head := enc.EncodeToString([]byte(`{"alg":"EdDSA","typ":"dpop+jwt"}`))
	input := head + ".@@"
	tok := input + "." + enc.EncodeToString(ed25519.Sign(priv, []byte(input)))
	if _, _, err := VerifySignature(tok, pub, "dpop+jwt"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("bad payload: %v", err)
	}
	ok := head + "." + enc.EncodeToString([]byte(`{}`))
	ok += "." + enc.EncodeToString(ed25519.Sign(priv, []byte(ok)))
	if _, p, err := VerifySignature(ok, pub, "dpop+jwt"); err != nil || string(p) != "{}" {
		t.Fatalf("good token: %s %v", p, err)
	}
}
