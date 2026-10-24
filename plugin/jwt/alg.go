package jwt

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // registers SHA-384 and SHA-512 for crypto.Hash.New
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
)

// Alg is a JWS signature algorithm (RFC 7518 section 3, RFC 8037) the plugin
// signs and verifies with. The algorithm is a property of the key, never of
// the token: an Ed25519 key signs EdDSA, an RSA key RS256 (or the algorithm
// RSAKey names), and an ECDSA key the algorithm of its curve (P-256 ES256,
// P-384 ES384, P-521 ES512); a verifier accepts a token only when its alg
// header names the algorithm of the key its kid points at. So a token cannot
// pick its own algorithm, which is how "alg: none" and the RS256-to-HS256
// confusion work.
type Alg string

// The algorithms. Symmetric (HS*) algorithms are deliberately absent: a key
// set is public, and a shared secret in one is a forgery waiting to happen.
const (
	// EdDSA is Ed25519 (RFC 8037): small keys, fast, deterministic
	// signatures, and the default.
	EdDSA Alg = "EdDSA"
	// RS256 is RSASSA-PKCS1-v1_5 with SHA-256, for a consumer that accepts
	// RSA only, such as the JWT authorizer of AWS API Gateway.
	RS256 Alg = "RS256"
	// RS384 and RS512 are RSASSA-PKCS1-v1_5 with SHA-384 and SHA-512; an
	// RSA key signs them only through RSAKey.
	RS384 Alg = "RS384"
	RS512 Alg = "RS512"
	// PS256, PS384 and PS512 are RSASSA-PSS with SHA-256, SHA-384 and
	// SHA-512, the salt as long as the hash (RFC 7518 section 3.5); an RSA
	// key signs them only through RSAKey.
	PS256 Alg = "PS256"
	PS384 Alg = "PS384"
	PS512 Alg = "PS512"
	// ES256 is ECDSA on P-256 with SHA-256, for a consumer or a KMS that
	// offers ECDSA and not Ed25519.
	ES256 Alg = "ES256"
	// ES384 is ECDSA on P-384 with SHA-384.
	ES384 Alg = "ES384"
	// ES512 is ECDSA on P-521 with SHA-512 (the name is the hash's, the
	// curve is 521 bits).
	ES512 Alg = "ES512"
)

// AlgValues is every algorithm the plugin signs and verifies, in the order
// the documentation lists them: the three original ones first, so a list
// built from it keeps its old prefix.
var AlgValues = []Alg{EdDSA, RS256, ES256, ES384, ES512, RS384, RS512, PS256, PS384, PS512}

// rsaAlgs are the algorithms an RSA key may sign; RS256 is what a bare
// *rsa.PublicKey signs.
var rsaAlgs = []Alg{RS256, RS384, RS512, PS256, PS384, PS512}

// DefaultAlgorithm is the algorithm of the key GenerateKey makes when given
// "", and of every token signed with an Ed25519 key, which is what the plugin
// was built on.
//
//ds:def id=algorithm-j38g35tv owner=@khanakia stability=stable
const DefaultAlgorithm = EdDSA

// JWK and JWS header values for each key type (RFC 7517, RFC 7518, RFC 8037).
const (
	// KeyTypeOKP is the JWK "kty" of an Edwards-curve key.
	//ds:def id=keytypeokp-cx2p5h5q owner=@khanakia stability=stable
	KeyTypeOKP = "OKP"
	// KeyTypeRSA is the JWK "kty" of an RSA key.
	KeyTypeRSA = "RSA"
	// KeyTypeEC is the JWK "kty" of an elliptic-curve (ECDSA) key.
	KeyTypeEC = "EC"
	// CurveEd25519 is the JWK "crv" of an EdDSA key.
	//ds:def id=curveed25519-w6kd4wru owner=@khanakia stability=stable
	CurveEd25519 = "Ed25519"
	// CurveP256 is the JWK "crv" of an ES256 key.
	CurveP256 = "P-256"
	// CurveP384 is the JWK "crv" of an ES384 key.
	CurveP384 = "P-384"
	// CurveP521 is the JWK "crv" of an ES512 key.
	CurveP521 = "P-521"
	// KeyUseSignature is the JWK "use" of a key that only signs.
	//ds:def id=keyusesignature-azygjgrb owner=@khanakia stability=stable
	KeyUseSignature = "sig"
)

// Key sizes.
const (
	// MinRSABits is the smallest RSA modulus signed or accepted. NIST SP
	// 800-131A has disallowed anything smaller since 2013, and a verifier
	// that took a 1024-bit key would trust a modulus that can be factored.
	//ds:def id=minrsabits-q8w2nd5k owner=@khanakia stability=stable
	MinRSABits = 2048
	// p256CoordinateSize is the byte length of a P-256 coordinate and of
	// each half (r, s) of an ES256 signature (RFC 7518 section 3.4).
	p256CoordinateSize = 32
	// p384CoordinateSize is the same length for P-384 and ES384.
	p384CoordinateSize = 48
	// p521CoordinateSize is the same length for P-521 and ES512: 521 bits
	// rounded up to whole bytes, not 64.
	p521CoordinateSize = 66
	// maxRSAExponentBytes caps a JWK's RSA exponent "e": a wider one is not
	// one any RSA library makes (65537 is 3 bytes), and would not fit
	// rsa.PublicKey's int on every platform.
	maxRSAExponentBytes = 4
	// uncompressedPoint prefixes an uncompressed elliptic-curve point (SEC 1
	// section 2.3.3), the form crypto/ecdh parses to check a point.
	uncompressedPoint = 0x04
)

// ecCurve is one supported ECDSA curve: its JWK name, the algorithm it
// signs, the byte length of a coordinate (and of r and s, RFC 7518 section
// 3.4), and the crypto/ecdh curve that checks a point is on it.
type ecCurve struct {
	curve elliptic.Curve
	crv   string
	alg   Alg
	size  int
	ecdh  ecdh.Curve
}

// ecCurves are the supported curves; P-224 and the Koblitz curves are not
// in RFC 7518 and are refused.
var ecCurves = []ecCurve{
	{elliptic.P256(), CurveP256, ES256, p256CoordinateSize, ecdh.P256()},
	{elliptic.P384(), CurveP384, ES384, p384CoordinateSize, ecdh.P384()},
	{elliptic.P521(), CurveP521, ES512, p521CoordinateSize, ecdh.P521()},
}

// curveOf finds a curve by its elliptic.Curve, its JWK name or its
// algorithm; the zero ecCurve and false when none matches.
func curveOf(match func(ecCurve) bool) (ecCurve, bool) {
	i := slices.IndexFunc(ecCurves, match)
	if i < 0 {
		return ecCurve{}, false
	}
	return ecCurves[i], true
}

// ErrUnsupportedKey is a key that is not Ed25519, RSA of at least MinRSABits
// or ECDSA on P-256, P-384 or P-521: WithSigningKey, PreviousKeys or a
// Signer's PublicKeys gave one, and auth.New refuses it, or GenerateKey or
// RSAKey was asked for an algorithm it does not know.
var ErrUnsupportedKey = errors.New("jwt: the key is not Ed25519, RSA of at least 2048 bits, or ECDSA on P-256, P-384 or P-521")

// RSAPublicKey is the public half of an RSA key that signs an algorithm
// other than RS256 (RS384, RS512, PS256, PS384, PS512): the public key of an
// RSAKey signer, and what PublicKeyOfJWK answers for an RSA JWK whose alg is
// one of them. Keeping the algorithm on the key keeps the rule that a token
// never chooses how its own signature is checked: the same modulus
// published as RS256 and as PS256 is two keys with two key ids.
type RSAPublicKey struct {
	Key *rsa.PublicKey
	Alg Alg
}

// rsaAlgSigner is an RSA crypto.Signer bound to one algorithm.
type rsaAlgSigner struct {
	inner crypto.Signer
	pub   RSAPublicKey
}

// Public is the algorithm-bound public key.
func (s rsaAlgSigner) Public() crypto.PublicKey { return s.pub }

// Sign delegates to the wrapped signer, which is what keeps a KMS key in
// the KMS.
func (s rsaAlgSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.inner.Sign(r, digest, opts)
}

// RSAKey binds an RSA signer (an *rsa.PrivateKey, or a KMS key behind
// crypto.Signer) to one RSA algorithm, such as PS256: the result signs alg,
// and its public key (an RSAPublicKey) is published with alg. RS256 returns
// the signer unchanged, since a bare RSA key already signs it. Anything other
// than an RSA key of at least MinRSABits and an RSA algorithm is
// ErrUnsupportedKey.
func RSAKey(k crypto.Signer, alg Alg) (crypto.Signer, error) {
	if k == nil || !slices.Contains(rsaAlgs, alg) {
		return nil, fmt.Errorf("%w: RSA algorithm %q", ErrUnsupportedKey, alg)
	}
	pub, ok := k.Public().(*rsa.PublicKey)
	if !ok || pub.N == nil || pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("%w: not an RSA key of at least %d bits", ErrUnsupportedKey, MinRSABits)
	}
	if alg == RS256 {
		return k, nil
	}
	return rsaAlgSigner{inner: k, pub: RSAPublicKey{Key: pub, Alg: alg}}, nil
}

// bindRSA is RSAKey over a key generator's answer, passing its error on.
func bindRSA(k *rsa.PrivateKey, err error, alg Alg) (crypto.Signer, error) {
	if err != nil {
		return nil, err
	}
	return RSAKey(k, alg)
}

// AlgOf returns the algorithm a public key signs with, or ErrUnsupportedKey.
// The parameter is crypto.PublicKey, the standard library's own type for "a
// public key of some algorithm", narrowed here in the one place every other
// function goes through.
func AlgOf(pub crypto.PublicKey) (Alg, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) == ed25519.PublicKeySize {
			return EdDSA, nil
		}
	case *rsa.PublicKey:
		if k.N != nil && k.N.BitLen() >= MinRSABits {
			return RS256, nil
		}
	case RSAPublicKey:
		if k.Key != nil && slices.Contains(rsaAlgs, k.Alg) {
			if _, err := AlgOf(k.Key); err == nil {
				return k.Alg, nil
			}
		}
	case *ecdsa.PublicKey:
		// The point must be on the curve: an invalid one would verify
		// nothing and has neither a PKIX nor a JWK form.
		c, ok := curveOf(func(c ecCurve) bool { return c.curve == k.Curve })
		if _, onCurve := ecPoint(k); ok && onCurve {
			return c.alg, nil
		}
	}
	return "", ErrUnsupportedKey
}

// ecPoint is a key's uncompressed point, 0x04||X||Y with each coordinate
// padded to the curve's size, through crypto/ecdh, which checks the point is
// on the curve; false for a point off it or none at all. It replaces the
// deprecated X and Y fields without Go 1.25's ecdsa.PublicKey.Bytes. A key
// with no point makes ECDH dereference nil inside crypto/elliptic, so that
// panic is recovered here as "no point" rather than taking a verifier down.
func ecPoint(k *ecdsa.PublicKey) (point []byte, ok bool) {
	defer func() {
		if recover() != nil {
			point, ok = nil, false
		}
	}()
	e, err := k.ECDH()
	if err != nil {
		return nil, false
	}
	return e.Bytes(), true
}

// HashOf is the hash an algorithm signs over, and the one OpenID Connect's
// at_hash and c_hash use (Core section 3.1.3.6): SHA-256, SHA-384 or SHA-512
// by the algorithm's suffix, and SHA-512 for EdDSA (Ed25519 hashes with it
// internally). 0 for an unknown algorithm.
func HashOf(alg Alg) crypto.Hash {
	switch alg {
	case RS256, PS256, ES256:
		return crypto.SHA256
	case RS384, PS384, ES384:
		return crypto.SHA384
	case EdDSA, RS512, PS512, ES512:
		return crypto.SHA512
	}
	return 0
}

// isPSS reports an RSASSA-PSS algorithm.
func isPSS(alg Alg) bool { return alg == PS256 || alg == PS384 || alg == PS512 }

// GenerateKey makes a new private key for alg ("" means DefaultAlgorithm):
// Ed25519, RSA of MinRSABits (bound to alg by RSAKey for an algorithm other
// than RS256), or ECDSA on the algorithm's curve. Pass it to WithSigningKey
// or AlgorithmKeys, and keep it in the app's secret store: a key generated
// at every start would sign out every verifier holding the old key set.
//
//ds:def id=generatekey-m4ps8tvx owner=@khanakia stability=stable
func GenerateKey(alg Alg) (crypto.Signer, error) {
	switch {
	case alg == EdDSA || alg == "":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	case slices.Contains(rsaAlgs, alg):
		k, err := rsa.GenerateKey(rand.Reader, MinRSABits)
		return bindRSA(k, err, alg)
	}
	if c, ok := curveOf(func(c ecCurve) bool { return c.alg == alg }); ok {
		return ecdsa.GenerateKey(c.curve, rand.Reader)
	}
	return nil, fmt.Errorf("%w: algorithm %q", ErrUnsupportedKey, alg)
}

// KeyID names a public key: the first 16 base64url characters of a SHA-256.
// For Ed25519 the hash is of the raw 32-byte key, as before RSA and ECDSA
// existed, so the ids of keys already published never change; for RSA and
// ECDSA it is of the key's PKIX (SubjectPublicKeyInfo) encoding, followed,
// for an RSAPublicKey, by its algorithm, so one modulus bound to two
// algorithms has two ids. An unsupported key has no id, "".
func KeyID(pub crypto.PublicKey) string {
	var h [sha256.Size]byte
	switch alg, err := AlgOf(pub); {
	case err != nil:
		return ""
	case alg == EdDSA:
		h = sha256.Sum256(pub.(ed25519.PublicKey))
	default:
		suffix := ""
		if k, ok := pub.(RSAPublicKey); ok {
			pub, suffix = k.Key, string(k.Alg)
		}
		// An RSA key, or an EC point AlgOf found on its curve, always has a
		// PKIX form.
		der, _ := x509.MarshalPKIXPublicKey(pub)
		h = sha256.Sum256(append(der, suffix...))
	}
	return base64.RawURLEncoding.EncodeToString(h[:])[:kidLength]
}

// jwkOf is the public JWK of a supported key, or false.
func jwkOf(pub crypto.PublicKey) (JWK, bool) {
	alg, err := AlgOf(pub)
	if err != nil {
		return JWK{}, false
	}
	enc := base64.RawURLEncoding
	out := JWK{KeyID: KeyID(pub), Use: KeyUseSignature, Alg: string(alg)}
	if k, ok := pub.(RSAPublicKey); ok {
		pub = k.Key
	}
	switch k := pub.(type) {
	case ed25519.PublicKey:
		out.KeyType, out.Curve, out.X = KeyTypeOKP, CurveEd25519, enc.EncodeToString(k)
	case *rsa.PublicKey:
		out.KeyType, out.N, out.E = KeyTypeRSA, enc.EncodeToString(k.N.Bytes()), enc.EncodeToString(big.NewInt(int64(k.E)).Bytes())
	case *ecdsa.PublicKey:
		// The ECDH form's Bytes is the uncompressed point 0x04||X||Y with
		// each coordinate padded to the curve's size; it replaces the
		// deprecated X and Y fields without needing Go 1.25's
		// ecdsa.PublicKey.Bytes.
		c, _ := curveOf(func(c ecCurve) bool { return c.alg == alg })
		point, _ := ecPoint(k) // AlgOf accepted it, so the point is on the curve
		out.KeyType, out.Curve = KeyTypeEC, c.crv
		out.X = enc.EncodeToString(point[1 : 1+c.size])
		out.Y = enc.EncodeToString(point[1+c.size:])
	}
	return out, true
}

// keyOfJWK parses a published JWK into a public key, or false for anything
// this plugin would not have published: another key type or curve, an alg
// that disagrees with the key, a short RSA modulus, a point off the curve.
// An RSA JWK with no alg, or RS256, is a bare *rsa.PublicKey; one naming
// another RSA algorithm is an RSAPublicKey bound to it.
func keyOfJWK(k JWK) (crypto.PublicKey, bool) {
	enc := base64.RawURLEncoding
	var pub crypto.PublicKey
	switch k.KeyType {
	case KeyTypeOKP:
		raw, err := enc.DecodeString(k.X)
		if err != nil || k.Curve != CurveEd25519 {
			return nil, false
		}
		pub = ed25519.PublicKey(raw)
	case KeyTypeRSA:
		n, err1 := enc.DecodeString(k.N)
		e, err2 := enc.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > maxRSAExponentBytes {
			return nil, false
		}
		rk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		pub = rk
		if a := Alg(k.Alg); a != "" && a != RS256 {
			pub = RSAPublicKey{Key: rk, Alg: a}
		}
	case KeyTypeEC:
		c, ok := curveOf(func(c ecCurve) bool { return c.crv == k.Curve })
		x, err1 := enc.DecodeString(k.X)
		y, err2 := enc.DecodeString(k.Y)
		if !ok || err1 != nil || err2 != nil || len(x) != c.size || len(y) != c.size {
			return nil, false
		}
		// crypto/ecdh checks the point is on the curve, which a forged key
		// set could otherwise use for an invalid-curve attack. The struct
		// literal below is safe only because of this check; never build
		// the key before it.
		if _, err := c.ecdh.NewPublicKey(append(append([]byte{uncompressedPoint}, x...), y...)); err != nil {
			return nil, false
		}
		pub = &ecdsa.PublicKey{Curve: c.curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	default:
		return nil, false
	}
	alg, err := AlgOf(pub)
	if err != nil || (k.Alg != "" && Alg(k.Alg) != alg) {
		return nil, false
	}
	return pub, true
}

// digest is the hash of input under h.
func digest(h crypto.Hash, input []byte) []byte {
	d := h.New()
	d.Write(input)
	return d.Sum(nil)
}

// pssOptions are RFC 7518 section 3.5's PSS parameters: MGF1 with the
// signing hash, and a salt as long as the hash.
func pssOptions(h crypto.Hash) *rsa.PSSOptions {
	return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
}

// verifySignature checks a JWS signature over input with pub, under the
// algorithm of pub. The caller has already pinned the token's alg to it. A
// key AlgOf refuses verifies nothing; crypto/ed25519 would panic on a short
// one. The key is bound by a type switch rather than asserted after AlgOf,
// so a key type AlgOf learns later without a case here verifies nothing
// instead of panicking inside a verifier.
func verifySignature(pub crypto.PublicKey, input, sig []byte) bool {
	alg, err := AlgOf(pub)
	if err != nil {
		return false
	}
	h := HashOf(alg)
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(k, input, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, h, digest(h, input), sig) == nil
	case RSAPublicKey:
		if isPSS(alg) {
			return rsa.VerifyPSS(k.Key, h, digest(h, input), sig, pssOptions(h)) == nil
		}
		return rsa.VerifyPKCS1v15(k.Key, h, digest(h, input), sig) == nil
	case *ecdsa.PublicKey:
		c, _ := curveOf(func(c ecCurve) bool { return c.alg == alg })
		if len(sig) != 2*c.size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:c.size])
		s := new(big.Int).SetBytes(sig[c.size:])
		return ecdsa.Verify(k, digest(h, input), r, s)
	}
	return false
}

// ecdsaSignature is the ASN.1 form crypto.Signer returns for ECDSA (RFC
// 3279 section 2.2.3).
type ecdsaSignature struct{ R, S *big.Int }

// signWithKey signs input with a crypto.Signer and returns the JWS form of
// the signature: Ed25519 signs the input itself, RSA and ECDSA its hash
// under the algorithm, PSS with RFC 7518's parameters, and an ECDSA
// signature is converted from ASN.1 to the fixed r||s form JWS requires (RFC
// 7518 section 3.4). A KMS that implements crypto.Signer works here
// unchanged.
func signWithKey(k crypto.Signer, input []byte) ([]byte, error) {
	alg, err := AlgOf(k.Public())
	if err != nil {
		return nil, err
	}
	if alg == EdDSA {
		return k.Sign(rand.Reader, input, crypto.Hash(0))
	}
	h := HashOf(alg)
	var opts crypto.SignerOpts = h
	if isPSS(alg) {
		opts = pssOptions(h)
	}
	sig, err := k.Sign(rand.Reader, digest(h, input), opts)
	if err != nil || slices.Contains(rsaAlgs, alg) {
		return sig, err
	}
	c, _ := curveOf(func(c ecCurve) bool { return c.alg == alg })
	var es ecdsaSignature
	if rest, err := asn1.Unmarshal(sig, &es); err != nil || len(rest) != 0 || es.R == nil || es.S == nil || es.R.Sign() <= 0 || es.S.Sign() <= 0 || es.R.BitLen() > 8*c.size || es.S.BitLen() > 8*c.size {
		return nil, fmt.Errorf("jwt: ECDSA signer returned a signature that is not ASN.1 (r, s)")
	}
	out := make([]byte, 2*c.size)
	es.R.FillBytes(out[:c.size])
	es.S.FillBytes(out[c.size:])
	return out, nil
}
