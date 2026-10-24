package oauth

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ubgo/auth"
)

// IDTokenConfig makes a provider accept ID tokens: tokens a native SDK
// (Google One Tap, Sign in with Apple, the Android and iOS libraries) hands
// the app, verified here against the provider's published keys, and tokens
// the provider returns from its token endpoint, for a provider that has no
// userinfo endpoint (Apple). The zero value accepts none.
//
//ds:def id=idtokenconfig-k3mq7wzd owner=@khanakia stability=stable
type IDTokenConfig struct {
	// JWKSURL is where the provider publishes its signing keys. Required.
	JWKSURL string
	// Issuers are the iss values accepted; Google uses two spellings. At
	// least one is required.
	Issuers []string
	// Audiences are accepted aud values besides ClientID: an iOS bundle id,
	// an Android client id. The web ClientID is always accepted.
	Audiences []string
	// ProfileFromToken makes Exchange read the profile from the id_token in
	// the token response instead of calling FetchProfile, for a provider that
	// has no userinfo endpoint. The token's nonce is the flow's PKCE
	// challenge, which AuthCodeURL sends as the nonce parameter.
	ProfileFromToken bool
	// RequireNonce refuses an ID token that carries no nonce claim
	// (ErrNonceRequired), for an app whose clients always send one: a token
	// replayed from another app's sign-in then has no way in.
	RequireNonce bool
	// HostedDomain refuses a token whose hd claim is not this Google
	// Workspace domain (ErrIDTokenInvalid), the native counterpart of
	// GoogleProfileFor; empty accepts every account. Only Google sets hd.
	HostedDomain string
}

// Enabled reports whether the provider accepts ID tokens.
func (c IDTokenConfig) Enabled() bool { return c.JWKSURL != "" }

// IDTokenVerifier is a Provider that can verify a provider-issued ID token
// and turn its claims into a Profile. *OAuth2 and *OIDCProvider implement
// it; the id-token operation exists only for providers that do.
//
//ds:def id=idtokenverifier-pq8r2vfn owner=@khanakia stability=stable
type IDTokenVerifier interface {
	Provider
	// VerifyIDToken checks the token's signature, issuer, audience and
	// lifetime, and its nonce against nonce when the token carries one. A
	// token that must not be trusted is ErrIDTokenInvalid; a provider not
	// configured for ID tokens is ErrIDTokenUnsupported.
	VerifyIDToken(ctx context.Context, hc *http.Client, token, nonce string) (Profile, error)
}

// JWS algorithms accepted on an ID token (RFC 7518, RFC 8037). "none" and
// the HMAC family are refused by not being listed: an HMAC token could be
// forged by anyone who reads the public key set.
const (
	algRS256 = "RS256"
	algES256 = "ES256"
	algEdDSA = "EdDSA"
)

// idTokenAlgorithms is every algorithm an ID token may use.
var idTokenAlgorithms = []string{algRS256, algES256, algEdDSA}

// JWK fields and values the key-set parser reads (RFC 7517, RFC 7518).
const (
	jwkTypeRSA      = "RSA"
	jwkTypeEC       = "EC"
	jwkTypeOKP      = "OKP"
	jwkCurveP256    = "P-256"
	jwkCurveEd25519 = "Ed25519"
	jwkUseSignature = "sig"
)

// ID-token verification constants.
const (
	// idTokenLeeway absorbs clock differences between the provider and this
	// server when checking exp and iat.
	//ds:def id=idtokenleeway-vb6nz8kq owner=@khanakia stability=stable
	idTokenLeeway = 30 * time.Second
	// jwksMinRefresh bounds how often an unknown kid may trigger a key-set
	// fetch, so a flood of forged tokens cannot make this server hammer the
	// provider.
	//ds:def id=jwksminrefresh-c2hx4rtw owner=@khanakia stability=stable
	jwksMinRefresh = time.Minute
	// jwksMaxAge is how long a fetched key set is trusted before the next
	// token refetches it, so a provider that retires a key is noticed within
	// the day even when no unknown kid forces a fetch.
	//ds:def id=jwksmaxage-m7tq3pwd owner=@khanakia stability=stable
	jwksMaxAge = 24 * time.Hour
	// es256SignatureSize is r and s of a P-256 signature, 32 bytes each, in
	// the raw JWS form (RFC 7518 section 3.4); p256CoordinateSize is one
	// coordinate of a P-256 point, and uncompressedPointPrefix starts the
	// SEC 1 uncompressed encoding crypto/ecdh parses.
	es256SignatureSize      = 64
	p256CoordinateSize      = 32
	uncompressedPointPrefix = 0x04
	// paramNonce is the OpenID Connect nonce parameter and claim.
	paramNonce = "nonce"
)

// Errors of ID-token sign-in.
var (
	// ErrIDTokenInvalid covers every ID token that must not be trusted:
	// malformed, an unlisted algorithm, an unknown key, a bad signature,
	// expired, another issuer or audience, or a nonce mismatch. The reason is
	// wrapped for the log; the client sees one answer.
	ErrIDTokenInvalid = auth.NewError("oauth.id_token_invalid", http.StatusUnauthorized, "The sign-in token was not accepted.")
	// ErrIDTokenUnsupported is an id-token sign-in for a provider that has no
	// IDTokenConfig (an *OAuth2 without one, an OIDC issuer whose discovery
	// document has no jwks_uri).
	ErrIDTokenUnsupported = auth.NewError("oauth.id_token_unsupported", http.StatusBadRequest, "This provider does not accept sign-in tokens.")
	// ErrNonceRequired is an ID token without a nonce claim while
	// RequireIDTokenNonce is set.
	ErrNonceRequired = auth.NewError("oauth.nonce_required", http.StatusUnauthorized, "The sign-in token carries no nonce.")
	// ErrJWKSFailed is a key-set fetch or parse failure; the user sees
	// ErrProviderFailed and the log the reason.
	ErrJWKSFailed = errors.New("oauth: provider key set could not be read")
)

// idTokenClaims is the part of an ID token the plugin reads (OpenID Connect
// Core section 2 and 5.1).
type idTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Nonce     string   `json:"nonce"`
	Email     string   `json:"email"`
	// EmailVerified is a boolish: Apple sends the string "true".
	EmailVerified boolish `json:"email_verified"`
	Name          string  `json:"name"`
	GivenName     string  `json:"given_name"`
	FamilyName    string  `json:"family_name"`
	Picture       string  `json:"picture"`
	// HD is Google's hosted domain, checked against IDTokenConfig.HostedDomain.
	HD string `json:"hd"`

	// raw is every claim of the payload, handed on as Profile.Claims.
	raw map[string]json.RawMessage
}

// audience is the aud claim, one string or an array of strings (RFC 7519
// section 4.1.3); both decode into the list form.
type audience []string

// UnmarshalJSON accepts a string or an array of strings. The parameter is
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
	*a = audience(many)
	return nil
}

// boolish is a JSON boolean that some providers send as the strings "true"
// and "false" (Apple's email_verified). Anything else is false: an unverified
// claim is the safe reading.
type boolish bool

// UnmarshalJSON reads true, "true", false, "false" and treats any other value
// as false. The parameter is the JSON boundary the standard library mandates.
func (b *boolish) UnmarshalJSON(raw []byte) error {
	var v bool
	if err := json.Unmarshal(raw, &v); err == nil {
		*b = boolish(v)
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		*b = boolish(s == "true")
		return nil
	}
	*b = false
	return nil
}

// idTokenHeader is the JWS protected header the verifier reads.
type idTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwk is one key of a provider's key set, in the fields the three accepted
// key types use.
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

// jwkSet is a provider's published key set.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// publicKey is one parsed provider key with the algorithm it may verify.
type publicKey struct {
	alg string
	key crypto.PublicKey
}

// jwksCache holds a provider's parsed keys and refetches them when a token
// names a key it does not know, at most once per jwksMinRefresh.
type jwksCache struct {
	mu      sync.Mutex
	keys    map[string]publicKey
	fetched time.Time
	now     func() time.Time
}

// keyFor returns the key named kid, fetching the set when it is empty, stale
// or lacks kid (bounded by jwksMinRefresh). A set with exactly one key
// serves a token without a kid, which some providers issue.
func (c *jwksCache) keyFor(ctx context.Context, hc *http.Client, url, kid string) (publicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	t := now()
	k, ok := c.lookup(kid)
	stale := c.keys == nil || t.Sub(c.fetched) > jwksMaxAge
	if ok && !stale {
		return k, nil
	}
	if !stale && t.Sub(c.fetched) < jwksMinRefresh {
		return publicKey{}, fmt.Errorf("%w: unknown key %q", ErrIDTokenInvalid, kid)
	}
	if err := c.fetch(ctx, hc, url, t); err != nil {
		return publicKey{}, err
	}
	if k, ok := c.lookup(kid); ok {
		return k, nil
	}
	return publicKey{}, fmt.Errorf("%w: unknown key %q", ErrIDTokenInvalid, kid)
}

// fetch reads the key set into the cache, stamped t; the caller holds mu.
// A set that cannot be read, or that holds no key the verifier can use, is
// ErrJWKSFailed.
func (c *jwksCache) fetch(ctx context.Context, hc *http.Client, url string, t time.Time) error {
	set, err := getJSON[jwkSet](ctx, hc, url, "")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrJWKSFailed, err)
	}
	c.keys, c.fetched = parseJWKS(set), t
	return nil
}

// load fetches the key set now, for SkipBrokenProviders, and refuses one
// with no usable key: such a provider could verify no ID token.
func (c *jwksCache) load(ctx context.Context, hc *http.Client, url string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := time.Now()
	if c.now != nil {
		t = c.now()
	}
	if err := c.fetch(ctx, hc, url, t); err != nil {
		return err
	}
	if len(c.keys) == 0 {
		return fmt.Errorf("%w: no usable key at %s", ErrJWKSFailed, url)
	}
	return nil
}

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
// rest (encryption keys, unknown curves, malformed values). A key without
// an alg takes the one its type implies.
func parseJWKS(set jwkSet) map[string]publicKey {
	out := map[string]publicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != jwkUseSignature {
			continue
		}
		pk, ok := parseJWK(k)
		if ok {
			out[k.Kid] = pk
		}
	}
	return out
}

// parseJWK turns one JWK into a public key, or reports it unusable.
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
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() || exp.Int64() < 3 {
			return publicKey{}, false
		}
		return publicKey{alg: algRS256, key: &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp.Int64())}}, true
	case jwkTypeEC:
		x, okX := dec(k.X)
		y, okY := dec(k.Y)
		if !okX || !okY || k.Crv != jwkCurveP256 || (k.Alg != "" && k.Alg != algES256) {
			return publicKey{}, false
		}
		// Exactly 32 bytes per coordinate (RFC 7518 section 6.2.1.2), and the
		// on-curve check goes through crypto/ecdh, which refuses a point off
		// P-256 or at infinity; a forged key could otherwise make the
		// verification arithmetic meaningless (invalid-curve attack). The
		// struct literal below is safe only because of this check.
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
// another algorithm, which is the "algorithm confusion" defence.
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

// idTokenVerifier verifies ID tokens for one provider: the configuration,
// the key cache and a clock.
type idTokenVerifier struct {
	cfg      IDTokenConfig
	clientID string
	cache    jwksCache
}

// verify checks token and returns its claims. Every refusal is
// ErrIDTokenInvalid wrapped with the reason; a key-set fetch failure is
// ErrJWKSFailed. nonce is the value the client says it used; a token whose
// nonce claim is neither nonce nor its SHA-256 hex (Apple's native flow
// hashes the nonce before sending it) is refused. A token without a nonce
// claim passes only when the client sent none, unless RequireNonce.
func (v *idTokenVerifier) verify(ctx context.Context, hc *http.Client, token, nonce string) (idTokenClaims, error) {
	return v.verifyMode(ctx, hc, token, nonce, false)
}

// verifyInitiated verifies the ID token of a provider-initiated sign-in:
// every check of verify, except the nonce, which must be absent, since no
// request of this app sent one, and RequireNonce does not apply. A token
// carrying a nonce was issued for another flow and is refused.
func (v *idTokenVerifier) verifyInitiated(ctx context.Context, hc *http.Client, token string) (idTokenClaims, error) {
	return v.verifyMode(ctx, hc, token, "", true)
}

// verifyMode is verify, with initiated choosing the nonce rule.
func (v *idTokenVerifier) verifyMode(ctx context.Context, hc *http.Client, token, nonce string, initiated bool) (idTokenClaims, error) {
	if !v.cfg.Enabled() {
		return idTokenClaims{}, ErrIDTokenUnsupported
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return idTokenClaims{}, fmt.Errorf("%w: not three parts", ErrIDTokenInvalid)
	}
	// Strict: one spelling per segment, so a signature covers one text.
	enc := base64.RawURLEncoding.Strict()
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: header", ErrIDTokenInvalid)
	}
	var h idTokenHeader
	if err := json.Unmarshal(hb, &h); err != nil || !slices.Contains(idTokenAlgorithms, h.Alg) {
		return idTokenClaims{}, fmt.Errorf("%w: algorithm %q", ErrIDTokenInvalid, h.Alg)
	}
	key, err := v.cache.keyFor(ctx, hc, v.cfg.JWKSURL, h.Kid)
	if err != nil {
		return idTokenClaims{}, err
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil || !verifySignature(key, h.Alg, []byte(parts[0]+"."+parts[1]), sig) {
		return idTokenClaims{}, fmt.Errorf("%w: signature", ErrIDTokenInvalid)
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: payload", ErrIDTokenInvalid)
	}
	var c idTokenClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return idTokenClaims{}, fmt.Errorf("%w: claims", ErrIDTokenInvalid)
	}
	c.raw = claimsOf(pb)
	now := time.Now
	if v.cache.now != nil {
		now = v.cache.now
	}
	t := now()
	switch {
	case c.Subject == "" || c.ExpiresAt == 0:
		return idTokenClaims{}, fmt.Errorf("%w: missing sub or exp", ErrIDTokenInvalid)
	case t.After(time.Unix(c.ExpiresAt, 0).Add(idTokenLeeway)):
		return idTokenClaims{}, fmt.Errorf("%w: expired", ErrIDTokenInvalid)
	case c.IssuedAt != 0 && t.Add(idTokenLeeway).Before(time.Unix(c.IssuedAt, 0)):
		return idTokenClaims{}, fmt.Errorf("%w: issued in the future", ErrIDTokenInvalid)
	case c.NotBefore != 0 && t.Add(idTokenLeeway).Before(time.Unix(c.NotBefore, 0)):
		return idTokenClaims{}, fmt.Errorf("%w: not yet valid", ErrIDTokenInvalid)
	case !slices.Contains(v.cfg.Issuers, c.Issuer):
		return idTokenClaims{}, fmt.Errorf("%w: issuer %q", ErrIDTokenInvalid, c.Issuer)
	case !v.audienceOK(c.Audience):
		return idTokenClaims{}, fmt.Errorf("%w: audience %q", ErrIDTokenInvalid, []string(c.Audience))
	case v.cfg.HostedDomain != "" && !strings.EqualFold(c.HD, v.cfg.HostedDomain):
		return idTokenClaims{}, fmt.Errorf("%w: hd %q, want %q", ErrIDTokenInvalid, c.HD, v.cfg.HostedDomain)
	}
	if initiated {
		if c.Nonce != "" {
			return idTokenClaims{}, fmt.Errorf("%w: a provider-initiated token carries a nonce", ErrIDTokenInvalid)
		}
		return c, nil
	}
	if err := checkNonce(c.Nonce, nonce, v.cfg.RequireNonce); err != nil {
		return idTokenClaims{}, err
	}
	return c, nil
}

// audienceOK reports whether one of the token's audiences is the client id
// or a configured extra audience.
func (v *idTokenVerifier) audienceOK(aud audience) bool {
	for _, a := range aud {
		if a == v.clientID || slices.Contains(v.cfg.Audiences, a) {
			return true
		}
	}
	return false
}

// checkNonce compares the token's nonce claim with what the client used,
// accepting the claim as the value itself or its SHA-256 hex. Both
// comparisons run in constant time, like every comparison of a secret.
func checkNonce(claim, nonce string, required bool) error {
	switch {
	case claim == "" && nonce == "":
		if required {
			return ErrNonceRequired
		}
		return nil
	case claim == "" || nonce == "":
		return fmt.Errorf("%w: nonce", ErrIDTokenInvalid)
	}
	h := sha256.Sum256([]byte(nonce))
	hexed := hex.EncodeToString(h[:])
	if subtle.ConstantTimeCompare([]byte(claim), []byte(nonce)) == 1 || subtle.ConstantTimeCompare([]byte(claim), []byte(hexed)) == 1 {
		return nil
	}
	return fmt.Errorf("%w: nonce", ErrIDTokenInvalid)
}

// profileFromClaims maps the standard OpenID Connect claims onto a Profile.
// A missing name is built from given_name and family_name, which Apple's
// first callback and some issuers send instead.
func profileFromClaims(c idTokenClaims) Profile {
	name := c.Name
	if name == "" {
		name = strings.TrimSpace(c.GivenName + " " + c.FamilyName)
	}
	return Profile{Subject: c.Subject, Email: c.Email, EmailVerified: bool(c.EmailVerified), Name: name, Image: c.Picture, Claims: c.raw}
}

// VerifyIDToken implements IDTokenVerifier for a plain OAuth 2.0 provider
// with an IDTokenConfig.
func (o *OAuth2) VerifyIDToken(ctx context.Context, hc *http.Client, token, nonce string) (Profile, error) {
	c, err := o.idTokens().verify(ctx, hc, token, nonce)
	if err != nil {
		return Profile{}, err
	}
	return profileFromClaims(c), nil
}

// idTokens returns the provider's verifier, built once from the config.
func (o *OAuth2) idTokens() *idTokenVerifier {
	o.idOnce.Do(func() {
		o.idVerifier = &idTokenVerifier{cfg: o.IDToken, clientID: o.ClientID}
		o.idVerifier.cache.now = o.now
	})
	return o.idVerifier
}

// VerifyIDToken implements IDTokenVerifier for an OpenID Connect issuer: the
// key set is the discovery document's jwks_uri and the issuer the configured
// one, so no field needs filling by hand.
func (o *OIDCProvider) VerifyIDToken(ctx context.Context, hc *http.Client, token, nonce string) (Profile, error) {
	c, err := o.discover(ctx, hc)
	if err != nil {
		return Profile{}, err
	}
	return c.VerifyIDToken(ctx, hc, token, nonce)
}
