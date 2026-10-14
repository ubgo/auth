package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

// ecJWK publishes a P-256 key with both coordinates at their fixed 32 bytes,
// as RFC 7518 section 6.2.1.2 requires.
func ecJWK(t *testing.T, k *ecdsa.PublicKey) jwk {
	t.Helper()
	e, err := k.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	b := e.Bytes()
	return jwk{Kty: jwkTypeEC, Crv: jwkCurveP256, X: b64(b[1 : 1+p256CoordinateSize]), Y: b64(b[1+p256CoordinateSize:])}
}

// TestParseJWK_ECRoundTripOffCurveAndShort pins the provider key parser: a
// published key parses and verifies an ES256 signature; the same key with
// y+1 (off the curve, the invalid-curve attack) and a coordinate shorter
// than 32 bytes are refused.
func TestParseJWK_ECRoundTripOffCurveAndShort(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j := ecJWK(t, &k.PublicKey)
	pk, ok := parseJWK(j)
	if !ok {
		t.Fatal("parseJWK refused the published key")
	}
	input := []byte("header.claims")
	sum := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 2*p256CoordinateSize)
	r.FillBytes(sig[:p256CoordinateSize])
	s.FillBytes(sig[p256CoordinateSize:])
	if !verifySignature(pk, algES256, input, sig) {
		t.Fatal("the round-tripped key did not verify its signer's signature")
	}

	y, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		t.Fatal(err)
	}
	off := j
	off.Y = b64(new(big.Int).Add(new(big.Int).SetBytes(y), big.NewInt(1)).FillBytes(make([]byte, p256CoordinateSize)))
	if _, ok := parseJWK(off); ok {
		t.Fatal("a point off the curve was accepted")
	}
	short := j
	short.Y = b64(y[1:])
	if _, ok := parseJWK(short); ok {
		t.Fatal("a 31-byte coordinate was accepted")
	}
}
