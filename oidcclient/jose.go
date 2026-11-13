package oidcclient

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// This file verifies JWS-signed JWTs from the login server (ID tokens and
// back-channel logout tokens) against its published key set. The key-set
// parsing, the algorithm allow-list and the cache timings are the ones
// ubgo/auth's plugin/oauth verifier uses (plugin/oauth/idtoken.go), so the
// two relying parties in the repository accept exactly the same tokens.

// JWS algorithms accepted on a token (RFC 7518, RFC 8037). "none" and the
// HMAC family are refused by not being listed: an HMAC token could be forged
// by anyone who reads the public key set.
const (
	algRS256 = "RS256"
	algES256 = "ES256"
	algEdDSA = "EdDSA"
)

// allowedAlgs is every algorithm a token may be signed with. It is a floor:
// no option reaches it.
var allowedAlgs = []string{algRS256, algES256, algEdDSA}

// JWK members and values the key-set parser reads (RFC 7517, RFC 7518).
const (
	jwkTypeRSA      = "RSA"
	jwkTypeEC       = "EC"
	jwkTypeOKP      = "OKP"
	jwkCurveP256    = "P-256"
	jwkCurveEd25519 = "Ed25519"
	jwkUseSignature = "sig"
)

// Verification constants.
const (
	// tokenLeeway absorbs clock differences between the login server and
	// this app when checking exp, iat and nbf.
	tokenLeeway = 30 * time.Second
	// jwksMinRefresh bounds how often an unknown kid may refetch the key
	// set, so a flood of forged tokens cannot make the app hammer the server.
	jwksMinRefresh = time.Minute
	// jwksMaxAge is how long a fetched key set is trusted before the next
	// token refetches it, so a retired key is noticed within the day.
	jwksMaxAge = 24 * time.Hour
	// minRSABits is the smallest RSA modulus accepted (NIST SP 800-131A),
	// the same floor plugin/jwt signs and verifies with.
	minRSABits = 2048
	// es256SignatureSize is r||s of a P-256 signature (RFC 7518 section 3.4).
	es256SignatureSize = 64
	// p256CoordinateSize is one coordinate of a P-256 point.
	p256CoordinateSize = 32
	// uncompressedPointPrefix starts the SEC 1 uncompressed point encoding
	// crypto/ecdh parses to check a point is on the curve.
	uncompressedPointPrefix = 0x04
	// jwsSegments is the number of dot-separated parts of a compact JWS.
	jwsSegments = 3
	// jwsSeparator separates them.
	jwsSeparator = "."
)

// errTokenInvalid covers every token that must not be trusted: malformed,
// an algorithm outside the allow-list, an unknown key, a bad signature, a
// wrong issuer or audience, expired, a nonce or event mismatch. The reason
// is wrapped for the log. It is not ErrProviderUnavailable, so a bad token
// never starts the outage grace.
var errTokenInvalid = errors.New("oidcclient: token does not verify")

// invalid wraps errTokenInvalid with a reason.
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errTokenInvalid}, args...)...)
}

// jwsHeader is the protected header the verifier reads. crit lists header
// extensions the token says must be understood; the package understands
// none, so a token with any is refused (RFC 7515 section 4.1.11).
type jwsHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

// jwk is one key of the login server's key set, in the members the three
// accepted key types use.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwkSet is the published key set (RFC 7517 section 5).
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// publicKey is one parsed key with the one algorithm it may verify.
type publicKey struct {
	alg string
	key crypto.PublicKey
}

// jwksCache holds the login server's parsed keys for one Client and
// refetches them when a token names a key it does not know, at most once
// per jwksMinRefresh, and when they are older than jwksMaxAge.
type jwksCache struct {
	mu      sync.Mutex
	keys    map[string]publicKey
	fetched time.Time
}

// keyFor returns the key named kid, fetching the set when it is empty,
// stale or lacks kid (bounded by jwksMinRefresh). A set with exactly one key
// serves a token without a kid, which some servers issue. A fetch failure
// is ErrProviderUnavailable; an unknown kid after a fetch is errTokenInvalid.
func (p *Provider) keyFor(ctx context.Context, jwksURI, kid string) (publicKey, error) {
	c := &p.jwks
	c.mu.Lock()
	defer c.mu.Unlock()
	t := p.c.set.now()
	k, ok := c.lookup(kid)
	stale := c.keys == nil || t.Sub(c.fetched) > jwksMaxAge
	if ok && !stale {
		return k, nil
	}
	if !stale && t.Sub(c.fetched) < jwksMinRefresh {
		return publicKey{}, invalid("unknown key %q", kid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return publicKey{}, fmt.Errorf("%w: jwks_uri: %w", ErrInvalidConfig, err)
	}
	req.Header.Set(headerAccept, mediaTypeJSON)
	body, err := p.send(req)
	if err != nil {
		if errors.Is(err, ErrProviderRefused) {
			// A key set the server will not hand over is no answer about any
			// session; it is the server being unusable.
			return publicKey{}, fmt.Errorf("%w: %w", ErrProviderUnavailable, err)
		}
		return publicKey{}, err
	}
	var set jwkSet
	if err := decodeJSON(jwksURI, body, &set); err != nil {
		return publicKey{}, err
	}
	c.keys, c.fetched = parseJWKS(set), t
	if k, ok := c.lookup(kid); ok {
		return k, nil
	}
	return publicKey{}, invalid("unknown key %q", kid)
}

// lookup finds kid among the cached keys; the caller holds mu.
func (c *jwksCache) lookup(kid string) (publicKey, bool) {
	if kid == "" && len(c.keys) == 1 {
		for _, k := range c.keys {
			return k, true
		}
	}
	k, ok := c.keys[kid]
	return k, ok
}

// parseJWKS keeps every key of a type the verifier can use, skipping the
// rest (encryption keys, other curves, short RSA moduli, malformed values).
// A key without an alg takes the one its type implies.
func parseJWKS(set jwkSet) map[string]publicKey {
	out := map[string]publicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != jwkUseSignature {
			continue
		}
		if pk, ok := parseJWK(k); ok {
			out[k.Kid] = pk
		}
	}
	return out
}

// parseJWK turns one JWK into a public key bound to one algorithm, or
// reports it unusable. A JWK whose alg disagrees with its type (an RSA key
// labelled PS256, an EC key labelled ES384) is unusable rather than reread.
func parseJWK(k jwk) (publicKey, bool) {
	dec := func(s string) ([]byte, bool) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		return b, err == nil && len(b) > 0
	}
	switch k.Kty {
	case jwkTypeRSA:
		n, okN := dec(k.N)
		e, okE := dec(k.E)
		if !okN || !okE || (k.Alg != "" && k.Alg != algRS256) {
			return publicKey{}, false
		}
		mod := new(big.Int).SetBytes(n)
		exp := new(big.Int).SetBytes(e)
		if mod.BitLen() < minRSABits || !exp.IsInt64() || exp.Int64() < 3 || exp.Int64() > 1<<31-1 {
			return publicKey{}, false
		}
		return publicKey{alg: algRS256, key: &rsa.PublicKey{N: mod, E: int(exp.Int64())}}, true
	case jwkTypeEC:
		x, okX := dec(k.X)
		y, okY := dec(k.Y)
		if !okX || !okY || k.Crv != jwkCurveP256 || (k.Alg != "" && k.Alg != algES256) {
			return publicKey{}, false
		}
		// Exactly 32 bytes per coordinate, and the on-curve check through
		// crypto/ecdh, which refuses a point off P-256 (invalid-curve
		// attack). The struct literal below is safe only after this check.
		if len(x) != p256CoordinateSize || len(y) != p256CoordinateSize {
			return publicKey{}, false
		}
		if _, err := ecdh.P256().NewPublicKey(append(append([]byte{uncompressedPointPrefix}, x...), y...)); err != nil {
			return publicKey{}, false
		}
		return publicKey{alg: algES256, key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}}, true
	case jwkTypeOKP:
		x, okX := dec(k.X)
		if !okX || k.Crv != jwkCurveEd25519 || len(x) != ed25519.PublicKeySize || (k.Alg != "" && k.Alg != algEdDSA) {
			return publicKey{}, false
		}
		return publicKey{alg: algEdDSA, key: ed25519.PublicKey(x)}, true
	}
	return publicKey{}, false
}

// verifySignature checks a JWS signature with the key's algorithm. The
// header's alg must be the key's: a key is never asked to verify under
// another algorithm, which is the algorithm-confusion defence.
func verifySignature(k publicKey, alg string, signingInput, sig []byte) bool {
	if alg != k.alg {
		return false
	}
	switch key := k.key.(type) {
	case *rsa.PublicKey:
		h := sha256.Sum256(signingInput)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, h[:], sig) == nil
	case *ecdsa.PublicKey:
		if len(sig) != es256SignatureSize {
			return false
		}
		h := sha256.Sum256(signingInput)
		r := new(big.Int).SetBytes(sig[:es256SignatureSize/2])
		s := new(big.Int).SetBytes(sig[es256SignatureSize/2:])
		return ecdsa.Verify(key, h[:], r, s)
	case ed25519.PublicKey:
		return ed25519.Verify(key, signingInput, sig)
	}
	return false
}

// verifiedJWS is a token whose signature verified: its header and its
// payload's members. Nothing in it has been checked beyond the signature.
type verifiedJWS struct {
	header  jwsHeader
	payload []byte
	claims  Claims
}

// verifyJWS checks a compact JWS's structure, algorithm and signature
// against the key set at jwksURI. Strict base64url, so one token has one
// spelling and a signature covers exactly one text.
func (p *Provider) verifyJWS(ctx context.Context, jwksURI, raw string) (verifiedJWS, error) {
	parts := strings.Split(raw, jwsSeparator)
	if len(parts) != jwsSegments {
		return verifiedJWS{}, invalid("not a compact JWS")
	}
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return verifiedJWS{}, invalid("header encoding")
	}
	var h jwsHeader
	if err := json.Unmarshal(hb, &h); err != nil || !slices.Contains(allowedAlgs, h.Alg) {
		return verifiedJWS{}, invalid("algorithm %q", h.Alg)
	}
	if len(h.Crit) > 0 {
		return verifiedJWS{}, invalid("critical header %q", h.Crit)
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return verifiedJWS{}, invalid("signature encoding")
	}
	key, err := p.keyFor(ctx, jwksURI, h.Kid)
	if err != nil {
		return verifiedJWS{}, err
	}
	if !verifySignature(key, h.Alg, []byte(parts[0]+jwsSeparator+parts[1]), sig) {
		return verifiedJWS{}, invalid("signature")
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return verifiedJWS{}, invalid("payload encoding")
	}
	var claims Claims
	if err := json.Unmarshal(pb, &claims); err != nil || claims == nil {
		return verifiedJWS{}, invalid("payload is not a JSON object")
	}
	return verifiedJWS{header: h, payload: pb, claims: claims}, nil
}

// audience is the aud claim: one string or an array of strings (RFC 7519
// section 4.1.3); both decode into the list form.
type audience []string

// UnmarshalJSON accepts a string or an array of strings; the parameter is
// the JSON boundary the standard library mandates.
func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// numericDate is a JWT NumericDate (RFC 7519 section 2): seconds since the
// epoch, possibly with a fraction, which some servers send.
type numericDate float64

// time returns d as a time; zero for an absent claim.
func (d numericDate) time() time.Time {
	if d == 0 {
		return time.Time{}
	}
	sec := int64(d)
	return time.Unix(sec, int64((float64(d)-float64(sec))*float64(time.Second)))
}

// registeredClaims are the members every token the package verifies is
// checked on (RFC 7519 section 4.1, OpenID Connect Core section 2,
// Back-Channel Logout section 2.4).
type registeredClaims struct {
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
	Audience  audience    `json:"aud"`
	ExpiresAt numericDate `json:"exp"`
	IssuedAt  numericDate `json:"iat"`
	NotBefore numericDate `json:"nbf"`
	AZP       string      `json:"azp"`
	Nonce     *string     `json:"nonce"`
	AtHash    string      `json:"at_hash"`
	SessionID string      `json:"sid"`
	TokenID   string      `json:"jti"`
	Events    Claims      `json:"events"`
	// EmailVerified is a boolish: some servers send the string "true".
	EmailVerified boolish `json:"email_verified"`
	Email         string  `json:"email"`
	Name          string  `json:"name"`
}

// boolish is a JSON boolean some servers send as the strings "true" and
// "false". Anything else reads false: an unverified claim is the safe
// reading.
type boolish bool

// UnmarshalJSON reads true and "true" as true, everything else as false;
// the parameter is the JSON boundary the standard library mandates.
func (b *boolish) UnmarshalJSON(raw []byte) error {
	var v bool
	if json.Unmarshal(raw, &v) == nil {
		*b = boolish(v)
		return nil
	}
	var s string
	*b = boolish(json.Unmarshal(raw, &s) == nil && s == "true")
	return nil
}

// checkCommon applies the checks every token shares: iss exactly the
// discovered issuer, aud naming the client, azp the client when present
// (and present when there are several audiences, OpenID Connect Core
// section 3.1.3.7), iat present and not in the future, nbf passed. exp is
// required by an ID token and optional on a logout token, so the caller
// says.
func (p *Provider) checkCommon(rc registeredClaims, issuer string, requireExp bool) error {
	now := p.c.set.now()
	clientID := p.c.cfg.ClientID
	switch {
	case rc.Issuer != issuer:
		return invalid("issuer %q", rc.Issuer)
	case !slices.Contains(rc.Audience, clientID):
		return invalid("audience %q", []string(rc.Audience))
	case rc.AZP != "" && rc.AZP != clientID:
		return invalid("azp %q", rc.AZP)
	case len(rc.Audience) > 1 && rc.AZP == "":
		return invalid("several audiences and no azp")
	case rc.IssuedAt == 0:
		return invalid("no iat")
	case now.Add(tokenLeeway).Before(rc.IssuedAt.time()):
		return invalid("issued in the future")
	case rc.NotBefore != 0 && now.Add(tokenLeeway).Before(rc.NotBefore.time()):
		return invalid("not yet valid")
	case requireExp && rc.ExpiresAt == 0:
		return invalid("no exp")
	case rc.ExpiresAt != 0 && now.After(rc.ExpiresAt.time().Add(tokenLeeway)):
		return invalid("expired")
	}
	return nil
}

// idTokenCheck is what one ID token is checked against besides the
// common floors.
type idTokenCheck struct {
	// nonce is the sign-in flow's nonce; the token must carry exactly it.
	// Empty for a refresh, which carries none of its own.
	nonce string
	// subject is the session's sub at a refresh: the new token must name
	// the same person. Empty at sign-in.
	subject string
	// accessToken, when the answer carried one and the token has at_hash,
	// must hash to it (OpenID Connect Core section 3.1.3.8).
	accessToken Secret
}

// verifyIDToken verifies an ID token from the token endpoint and returns
// the Identity it names. Every refusal is errTokenInvalid with the reason;
// a key-set fetch failure is ErrProviderUnavailable.
func (p *Provider) verifyIDToken(ctx context.Context, raw string, chk idTokenCheck) (Identity, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return Identity{}, err
	}
	v, err := p.verifyJWS(ctx, meta.JWKSURI, raw)
	if err != nil {
		return Identity{}, err
	}
	var rc registeredClaims
	if err := json.Unmarshal(v.payload, &rc); err != nil {
		return Identity{}, invalid("claims: %v", err)
	}
	if err := p.checkCommon(rc, meta.Issuer, true); err != nil {
		return Identity{}, err
	}
	if rc.Subject == "" {
		return Identity{}, invalid("no sub")
	}
	if chk.subject != "" && rc.Subject != chk.subject {
		return Identity{}, invalid("sub changed at refresh")
	}
	if chk.nonce != "" {
		if rc.Nonce == nil || subtle.ConstantTimeCompare([]byte(*rc.Nonce), []byte(chk.nonce)) != 1 {
			return Identity{}, invalid("nonce")
		}
	}
	if rc.AtHash != "" && !chk.accessToken.IsZero() && !atHashMatches(v.header.Alg, rc.AtHash, chk.accessToken.Reveal()) {
		return Identity{}, invalid("at_hash")
	}
	return Identity{
		Issuer: rc.Issuer, Subject: rc.Subject, Email: rc.Email, EmailVerified: bool(rc.EmailVerified),
		Name: rc.Name, ProviderSessionID: rc.SessionID, Claims: v.claims,
	}, nil
}

// atHashMatches checks at_hash: the left half of the access token's hash
// under the signing algorithm's hash, base64url. SHA-256 for RS256 and
// ES256, SHA-512 for EdDSA, as ubgo/auth's provider computes it.
func atHashMatches(alg, claim, accessToken string) bool {
	var sum []byte
	switch alg {
	case algEdDSA:
		s := sha512.Sum512([]byte(accessToken))
		sum = s[:]
	default:
		s := sha256.Sum256([]byte(accessToken))
		sum = s[:]
	}
	want := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
	return subtle.ConstantTimeCompare([]byte(claim), []byte(want)) == 1
}
