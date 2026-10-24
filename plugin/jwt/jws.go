package jwt

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// PublicKeyOfJWK parses a JWK into a public key with the rules KeysFromJWKS
// applies: Ed25519, RSA of at least MinRSABits, P-256 on the curve, and an
// alg, when given, that is the key's. false for anything else.
func PublicKeyOfJWK(k JWK) (crypto.PublicKey, bool) { return keyOfJWK(k) }

// PublicKeyForAlg parses another party's JWK for a signature made under
// alg, the header of a token that key signed: a DPoP proof's embedded key,
// or a private_key_jwt client's registered key. RFC 7517 section 4.4 makes
// a JWK's alg optional, and such keys often omit it; then the key's type
// decides the family (an RSA key verifies any RSA algorithm, an EC key only
// its curve's, an Ed25519 key only EdDSA), and the result is bound to alg so
// VerifySignature still pins the algorithm to the key. A JWK that names an
// alg must name this one. false for anything PublicKeyOfJWK refuses, and
// for an alg outside the key's family, so no header can turn a public key
// into an HMAC secret.
func PublicKeyForAlg(k JWK, alg Alg) (crypto.PublicKey, bool) {
	if k.Alg != "" && Alg(k.Alg) != alg {
		return nil, false
	}
	if k.Alg == "" && k.KeyType == KeyTypeRSA {
		k.Alg = string(alg)
	}
	pub, ok := keyOfJWK(k)
	if !ok {
		return nil, false
	}
	if got, _ := AlgOf(pub); got != alg { // keyOfJWK accepted it, so AlgOf does too
		return nil, false
	}
	return pub, true
}

// Thumbprint is the RFC 7638 JWK thumbprint, base64url of SHA-256 over the
// key's required members in lexicographic order with no whitespace: what a
// DPoP-bound token's cnf.jkt names. It refuses a key PublicKeyOfJWK would
// refuse, so a thumbprint always names a usable key.
func Thumbprint(k JWK) (string, error) {
	if _, ok := keyOfJWK(k); !ok {
		return "", fmt.Errorf("%w: not a usable public key", ErrInvalid)
	}
	var members map[string]string
	switch k.KeyType {
	case KeyTypeOKP:
		members = map[string]string{"crv": k.Curve, "kty": k.KeyType, "x": k.X}
	case KeyTypeEC:
		members = map[string]string{"crv": k.Curve, "kty": k.KeyType, "x": k.X, "y": k.Y}
	default:
		members = map[string]string{"e": k.E, "kty": k.KeyType, "n": k.N}
	}
	// encoding/json sorts map keys and writes no whitespace: exactly RFC
	// 7638's canonical form for these string members.
	b, _ := json.Marshal(members) // a map of strings always encodes
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// VerifySignature checks a compact JWS against one known key, for a token
// that is not one of this plugin's (a DPoP proof carries its key in its
// header and has no sub or exp, so Verifier does not fit). The typ must be
// one of types, the alg the key's, and the signature valid; it returns the
// decoded header and payload JSON for the caller's own claim checks, and
// checks no claim itself.
func VerifySignature(token string, pub crypto.PublicKey, types ...string) (header, payload []byte, err error) {
	parts := strings.Split(token, segmentSeparator)
	if len(parts) != segmentCount {
		return nil, nil, fmt.Errorf("%w: not three parts", ErrInvalid)
	}
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: header", ErrInvalid)
	}
	h, err := parseHeader(hb, types...)
	if err != nil {
		return nil, nil, err
	}
	if err := checkSignature(pub, h.Alg, parts, enc); err != nil {
		return nil, nil, err
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: payload", ErrInvalid)
	}
	return hb, pb, nil
}
