package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Client-assertion constants (RFC 7523 section 3).
const (
	// assertionLifetime bounds one client assertion: it is minted per token
	// request, so a few minutes covers clock drift and nothing more; a longer
	// one would let a captured assertion be replayed for longer.
	//ds:def id=assertionlifetime-x7nq4kwe owner=@khanakia stability=stable
	assertionLifetime = 5 * time.Minute
	// algRS256 is the RSA algorithm an assertion may use; ES256 is shared
	// with the ID-token verifier.
	algRS256Assertion = algRS256
	// jwtType is the typ header of an assertion.
	jwtType = "JWT"
)

// Client-assertion errors.
var (
	// ErrAssertionKey is a key that is neither an ECDSA P-256 nor an RSA
	// private key, the two kinds a token endpoint accepts for a client
	// assertion (ES256, RS256).
	ErrAssertionKey = errors.New("oauth: ClientAssertion needs an ECDSA P-256 or RSA private key")
	// ErrAssertionConfig is a configuration error: an *OAuth2 with
	// PrivateKeyJWT and no ClientAssertion, or a ClientAssertion with another
	// TokenAuth, where it would never be sent.
	ErrAssertionConfig = errors.New("oauth: ClientAssertion goes with TokenAuth PrivateKeyJWT, and PrivateKeyJWT needs one")
)

// ClientAssertion returns an OAuth2.ClientAssertion that signs the RFC 7523
// client assertion for TokenAuth PrivateKeyJWT: a JWT with the client id as
// issuer and subject, the token endpoint as audience, a fresh jti and a
// lifetime of assertionLifetime, signed ES256 with a P-256 key or RS256 with
// an RSA key. kid is the key id registered at the provider, written in the
// header so the provider picks the right public key. Entra ID (workload
// identity federation, certificate credentials) and any issuer that refuses
// shared secrets take this form.
//
//ds:def id=clientassertion-f2mq9xkn owner=@khanakia stability=stable
func ClientAssertion(clientID, kid string, key crypto.Signer) (func(ctx context.Context, tokenURL string) (string, error), error) {
	alg, err := assertionAlg(key)
	if err != nil {
		return nil, err
	}
	if clientID == "" {
		return nil, ErrAssertionConfig
	}
	s := &assertionSigner{clientID: clientID, kid: kid, key: key, alg: alg, now: time.Now}
	return s.assertion, nil
}

// assertionAlg names the JWS algorithm key signs with, or refuses the key.
func assertionAlg(key crypto.Signer) (string, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return "", ErrAssertionKey
		}
		return algES256, nil
	case *rsa.PrivateKey:
		return algRS256Assertion, nil
	}
	return "", ErrAssertionKey
}

// assertionSigner mints one assertion per call: unlike Apple's client
// secret, an assertion names the token endpoint it is for and is cheap, so
// nothing is cached.
type assertionSigner struct {
	clientID, kid, alg string
	key                crypto.Signer
	now                func() time.Time
}

func (s *assertionSigner) assertion(_ context.Context, tokenURL string) (string, error) {
	now := s.now()
	header, err := json.Marshal(map[string]string{"alg": s.alg, "typ": jwtType, "kid": s.kid})
	if err != nil {
		return "", err
	}
	// rand.Text is 128 random bits; a jti is what lets the provider refuse
	// a replayed assertion within its lifetime.
	claims, err := json.Marshal(map[string]any{
		"iss": s.clientID, "sub": s.clientID, "aud": tokenURL, "jti": rand.Text(),
		"iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	return signCompact(s.key, s.alg, header, claims)
}

// signCompact produces the compact JWS of header and claims with key under
// alg: ES256 as the raw r||s form RFC 7518 section 3.4 requires, RS256 as
// PKCS #1 v1.5 over SHA-256.
func signCompact(key crypto.Signer, alg string, header, claims []byte) (string, error) {
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	h := sha256.Sum256([]byte(signing))
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		r, sv, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			return "", fmt.Errorf("oauth: sign assertion: %w", err)
		}
		sig = make([]byte, es256SignatureSize)
		r.FillBytes(sig[:es256SignatureSize/2])
		sv.FillBytes(sig[es256SignatureSize/2:])
	default:
		var err error
		if sig, err = key.Sign(rand.Reader, h[:], crypto.SHA256); err != nil {
			return "", fmt.Errorf("oauth: sign assertion: %w", err)
		}
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
