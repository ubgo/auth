package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"
)

// TestKeyOfJWK_ECRoundTripAndOffCurve pins the published P-256 key: a key
// exported by jwkOf parses back and verifies its signer's signature, and the
// same key with y+1 (a point off the curve, the invalid-curve attack) is
// refused.
func TestKeyOfJWK_ECRoundTripAndOffCurve(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, ok := jwkOf(&k.PublicKey)
	if !ok {
		t.Fatal("jwkOf refused a P-256 key")
	}
	pub, ok := keyOfJWK(j)
	if !ok {
		t.Fatal("keyOfJWK refused the published key")
	}
	input := []byte("header.claims")
	sig, err := signWithKey(k, input)
	if err != nil {
		t.Fatal(err)
	}
	if !verifySignature(pub, input, sig) {
		t.Fatal("the round-tripped key did not verify its signer's signature")
	}

	enc := base64.RawURLEncoding
	y, err := enc.DecodeString(j.Y)
	if err != nil {
		t.Fatal(err)
	}
	y = new(big.Int).Add(new(big.Int).SetBytes(y), big.NewInt(1)).FillBytes(make([]byte, p256CoordinateSize))
	off := j
	off.Y = enc.EncodeToString(y)
	if _, ok := keyOfJWK(off); ok {
		t.Fatal("a point off the curve was accepted")
	}
}
