package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// testKeys is one signing key of each accepted kind, published as a JWKS.
type testKeys struct {
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
	// ecPub is ec's published JWK, coordinates padded to 32 bytes.
	ecPub jwk
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testKeys{rsa: r, ec: e, ed: ed, ecPub: ecJWK(t, &e.PublicKey)}
}

// Key ids of the three test keys.
const (
	kidRSA = "k-rsa"
	kidEC  = "k-ec"
	kidEd  = "k-ed"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwks is the published form of the test keys, with extra ignorable entries.
func (k *testKeys) jwks() jwkSet {
	return jwkSet{Keys: []jwk{
		{Kty: jwkTypeRSA, Kid: kidRSA, Use: jwkUseSignature, Alg: algRS256, N: b64(k.rsa.N.Bytes()), E: b64(big.NewInt(int64(k.rsa.E)).Bytes())},
		{Kty: jwkTypeEC, Kid: kidEC, Crv: jwkCurveP256, X: k.ecPub.X, Y: k.ecPub.Y},
		{Kty: jwkTypeOKP, Kid: kidEd, Crv: jwkCurveEd25519, X: b64(k.ed.Public().(ed25519.PublicKey))},
		// An encryption key, an unknown type and a malformed key are skipped.
		{Kty: jwkTypeRSA, Kid: "enc", Use: "enc", N: b64(k.rsa.N.Bytes()), E: "AQAB"},
		{Kty: "oct", Kid: "sym"},
		{Kty: jwkTypeRSA, Kid: "bad", N: "***", E: "AQAB"},
	}}
}

// sign produces a compact JWS of claims with the key named kid under alg.
func (k *testKeys) sign(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	hdr := map[string]string{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hb, _ := json.Marshal(hdr)
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := b64(hb) + "." + b64(cb)
	h := sha256.Sum256([]byte(signing))
	var sig []byte
	switch alg {
	case algRS256:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, h[:])
	case algES256:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k.ec, h[:])
		if err == nil {
			sig = make([]byte, es256SignatureSize)
			r.FillBytes(sig[:32])
			s.FillBytes(sig[32:])
		}
	case algEdDSA:
		sig = ed25519.Sign(k.ed, []byte(signing))
	default:
		sig = []byte("none")
	}
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

// idTokenEnv is a JWKS server, its keys and a verifier with a fixed clock.
type idTokenEnv struct {
	keys    *testKeys
	fetches atomic.Int32
	now     time.Time
	v       *idTokenVerifier
	hc      *http.Client
	set     jwkSet
}

func newIDTokenEnv(t *testing.T) *idTokenEnv {
	t.Helper()
	e := &idTokenEnv{keys: newTestKeys(t), now: time.Unix(1_800_000_000, 0)}
	e.set = e.keys.jwks()
	srv := providerServer(t, map[string]http.HandlerFunc{"/keys": func(w http.ResponseWriter, _ *http.Request) {
		e.fetches.Add(1)
		_ = json.NewEncoder(w).Encode(e.set)
	}})
	e.hc = srv.Client()
	e.v = &idTokenVerifier{cfg: IDTokenConfig{JWKSURL: srv.URL + "/keys", Issuers: []string{"https://idp.test"}, Audiences: []string{"ios.bundle"}}, clientID: "web-client"}
	e.v.cache.now = func() time.Time { return e.now }
	return e
}

// claims is a valid set of claims at the env's clock.
func (e *idTokenEnv) claims(over map[string]any) map[string]any {
	c := map[string]any{"iss": "https://idp.test", "sub": "apple-1", "aud": "web-client", "exp": e.now.Add(time.Hour).Unix(), "iat": e.now.Unix(),
		"email": "a@b.co", "email_verified": true, "name": "Ann", "picture": "https://img/a.png"}
	for k, v := range over {
		c[k] = v
	}
	return c
}

func TestIDToken_VerifiesEveryAcceptedAlgorithm(t *testing.T) {
	e := newIDTokenEnv(t)
	for alg, kid := range map[string]string{algRS256: kidRSA, algES256: kidEC, algEdDSA: kidEd} {
		got, err := e.v.verify(context.Background(), e.hc, e.keys.sign(t, alg, kid, e.claims(nil)), "")
		if err != nil || got.Subject != "apple-1" || got.Email != "a@b.co" || !bool(got.EmailVerified) {
			t.Fatalf("%s: %+v %v", alg, got, err)
		}
		p := profileFromClaims(got)
		if p.Subject != "apple-1" || p.Name != "Ann" || p.Image != "https://img/a.png" || !p.EmailVerified {
			t.Fatalf("%s profile = %+v", alg, p)
		}
	}
	if e.fetches.Load() != 1 {
		t.Fatalf("the key set was fetched %d times, want once", e.fetches.Load())
	}
	// A key is never asked to verify under another algorithm.
	cross := e.keys.sign(t, algRS256, kidEC, e.claims(nil))
	if _, err := e.v.verify(context.Background(), e.hc, cross, ""); !errors.Is(err, ErrIDTokenInvalid) {
		t.Fatalf("RS256 header on an EC key: %v", err)
	}
}

func TestIDToken_Rejections(t *testing.T) {
	e := newIDTokenEnv(t)
	ctx := context.Background()
	bad := map[string]string{
		"alg none":         e.keys.sign(t, "none", kidRSA, e.claims(nil)),
		"hmac":             e.keys.sign(t, "HS256", kidRSA, e.claims(nil)),
		"two parts":        "a.b",
		"header not json":  b64([]byte("x")) + ".e30.AA",
		"expired":          e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"exp": e.now.Add(-time.Hour).Unix()})),
		"future iat":       e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"iat": e.now.Add(time.Hour).Unix()})),
		"future nbf":       e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"nbf": e.now.Add(time.Hour).Unix()})),
		"other issuer":     e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"iss": "https://evil.test"})),
		"other audience":   e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"aud": "someone-else"})),
		"no sub":           e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"sub": ""})),
		"no exp":           e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"exp": 0})),
		"unknown kid":      e.keys.sign(t, algRS256, "nope", e.claims(nil)),
		"nonce not sent":   e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"nonce": "n1"})),
		"payload not json": strings.Join([]string{strings.Split(e.keys.sign(t, algRS256, kidRSA, e.claims(nil)), ".")[0], b64([]byte("x")), "AA"}, "."),
		"header not b64":   "!!!.e30.AA",
		"payload not b64":  strings.Split(e.keys.sign(t, algRS256, kidRSA, e.claims(nil)), ".")[0] + ".!!!.AA",
	}
	for name, tok := range bad {
		if _, err := e.v.verify(ctx, e.hc, tok, ""); !errors.Is(err, ErrIDTokenInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A payload that is not base64url fails after the signature passed over it.
	hdr := b64([]byte(`{"alg":"EdDSA","kid":"` + kidEd + `"}`))
	signing := hdr + ".!!!"
	notB64 := signing + "." + b64(ed25519.Sign(e.keys.ed, []byte(signing)))
	if _, err := e.v.verify(ctx, e.hc, notB64, ""); !errors.Is(err, ErrIDTokenInvalid) || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("payload not base64: %v", err)
	}
	// A tampered payload fails the signature.
	parts := strings.Split(e.keys.sign(t, algEdDSA, kidEd, e.claims(nil)), ".")
	forged, _ := json.Marshal(e.claims(map[string]any{"sub": "admin"}))
	if _, err := e.v.verify(ctx, e.hc, parts[0]+"."+b64(forged)+"."+parts[2], ""); !errors.Is(err, ErrIDTokenInvalid) {
		t.Fatalf("tampered: %v", err)
	}
	// A verifier without a configuration refuses everything.
	none := &idTokenVerifier{}
	if _, err := none.verify(ctx, e.hc, parts[0]+"."+parts[1]+"."+parts[2], ""); !errors.Is(err, ErrIDTokenUnsupported) {
		t.Fatalf("unconfigured: %v", err)
	}
	// aud as an array, with the native audience, is accepted.
	many := e.keys.sign(t, algES256, kidEC, e.claims(map[string]any{"aud": []string{"other", "ios.bundle"}}))
	if _, err := e.v.verify(ctx, e.hc, many, ""); err != nil {
		t.Fatalf("array audience: %v", err)
	}
	notString := e.keys.sign(t, algES256, kidEC, e.claims(map[string]any{"aud": 42}))
	if _, err := e.v.verify(ctx, e.hc, notString, ""); !errors.Is(err, ErrIDTokenInvalid) {
		t.Fatalf("numeric audience: %v", err)
	}
}

func TestIDToken_Nonce(t *testing.T) {
	e := newIDTokenEnv(t)
	ctx := context.Background()
	h := sha256.Sum256([]byte("n1"))
	exact := e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"nonce": "n1"}))
	hashed := e.keys.sign(t, algRS256, kidRSA, e.claims(map[string]any{"nonce": hex.EncodeToString(h[:])}))
	plain := e.keys.sign(t, algRS256, kidRSA, e.claims(nil))
	for name, tok := range map[string]string{"exact": exact, "sha256 hex": hashed} {
		if _, err := e.v.verify(ctx, e.hc, tok, "n1"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := e.v.verify(ctx, e.hc, tok, "n2"); !errors.Is(err, ErrIDTokenInvalid) {
			t.Errorf("%s with the wrong nonce: %v", name, err)
		}
	}
	// A nonce sent for a token that carries none is a mismatch; a token
	// without a nonce passes when none was sent, unless required.
	if _, err := e.v.verify(ctx, e.hc, plain, "n1"); !errors.Is(err, ErrIDTokenInvalid) {
		t.Fatalf("nonce sent, none in token: %v", err)
	}
	if _, err := e.v.verify(ctx, e.hc, plain, ""); err != nil {
		t.Fatalf("no nonce anywhere: %v", err)
	}
	e.v.cfg.RequireNonce = true
	if _, err := e.v.verify(ctx, e.hc, plain, ""); !errors.Is(err, ErrNonceRequired) {
		t.Fatalf("required nonce missing: %v", err)
	}
	if _, err := e.v.verify(ctx, e.hc, exact, "n1"); err != nil {
		t.Fatalf("required nonce present: %v", err)
	}
}

func TestIDToken_KeySetRefreshIsBounded(t *testing.T) {
	e := newIDTokenEnv(t)
	ctx := context.Background()
	if _, err := e.v.verify(ctx, e.hc, e.keys.sign(t, algRS256, kidRSA, e.claims(nil)), ""); err != nil {
		t.Fatal(err)
	}
	// A new key appears at the provider. Within jwksMinRefresh of the last
	// fetch an unknown kid is refused without a fetch; after it, one fetch
	// finds the key.
	fresh := newTestKeys(t)
	e.set.Keys = append(e.set.Keys, jwk{Kty: jwkTypeOKP, Kid: "k-new", Crv: jwkCurveEd25519, X: b64(fresh.ed.Public().(ed25519.PublicKey))})
	tok := fresh.sign(t, algEdDSA, "k-new", e.claims(nil))
	if _, err := e.v.verify(ctx, e.hc, tok, ""); !errors.Is(err, ErrIDTokenInvalid) || e.fetches.Load() != 1 {
		t.Fatalf("unknown kid inside the refresh window: %v, fetches %d", err, e.fetches.Load())
	}
	e.now = e.now.Add(jwksMinRefresh)
	if _, err := e.v.verify(ctx, e.hc, tok, ""); err != nil || e.fetches.Load() != 2 {
		t.Fatalf("unknown kid after the window: %v, fetches %d", err, e.fetches.Load())
	}
	// A kid the provider never published is refused after the fetch too.
	e.now = e.now.Add(jwksMinRefresh)
	never := fresh.sign(t, algRS256, "never-published", e.claims(nil))
	if _, err := e.v.verify(ctx, e.hc, never, ""); !errors.Is(err, ErrIDTokenInvalid) || e.fetches.Load() != 3 {
		t.Fatalf("never-published kid: %v, fetches %d", err, e.fetches.Load())
	}
	// A stale set is refetched for a known kid too.
	e.now = e.now.Add(jwksMaxAge + time.Second)
	tok = fresh.sign(t, algEdDSA, "k-new", e.claims(nil))
	if _, err := e.v.verify(ctx, e.hc, tok, ""); err != nil || e.fetches.Load() != 4 {
		t.Fatalf("stale set: %v, fetches %d", err, e.fetches.Load())
	}
	// A key set that cannot be read is ErrJWKSFailed, not "invalid".
	broken := &idTokenVerifier{cfg: IDTokenConfig{JWKSURL: "http://127.0.0.1:1/keys", Issuers: []string{"x"}}}
	if _, err := broken.verify(ctx, &http.Client{Timeout: time.Second}, tok, ""); !errors.Is(err, ErrJWKSFailed) {
		t.Fatalf("unreachable key set: %v", err)
	}
}

func TestIDToken_SingleKeySetServesATokenWithoutKid(t *testing.T) {
	e := newIDTokenEnv(t)
	e.set = jwkSet{Keys: []jwk{{Kty: jwkTypeOKP, Crv: jwkCurveEd25519, X: b64(e.keys.ed.Public().(ed25519.PublicKey))}}}
	if _, err := e.v.verify(context.Background(), e.hc, e.keys.sign(t, algEdDSA, "", e.claims(nil)), ""); err != nil {
		t.Fatal(err)
	}
}

func TestParseJWK_SkipsUnusableKeys(t *testing.T) {
	k := newTestKeys(t)
	good := k.jwks()
	if got := parseJWKS(good); len(got) != 3 {
		t.Fatalf("parsed %d keys, want the three signing keys", len(got))
	}
	for name, bad := range map[string]jwk{
		"rsa tiny exponent": {Kty: jwkTypeRSA, N: b64(k.rsa.N.Bytes()), E: b64([]byte{1})},
		"rsa wrong alg":     {Kty: jwkTypeRSA, N: b64(k.rsa.N.Bytes()), E: "AQAB", Alg: algES256},
		"ec other curve":    {Kty: jwkTypeEC, Crv: "P-384", X: k.ecPub.X, Y: k.ecPub.Y},
		"ec off curve":      {Kty: jwkTypeEC, Crv: jwkCurveP256, X: k.ecPub.X, Y: b64(big.NewInt(7).FillBytes(make([]byte, p256CoordinateSize)))},
		"ec oversized":      {Kty: jwkTypeEC, Crv: jwkCurveP256, X: b64(make([]byte, 33)), Y: k.ecPub.Y},
		"ec bad y":          {Kty: jwkTypeEC, Crv: jwkCurveP256, X: k.ecPub.X, Y: "***"},
		"okp other curve":   {Kty: jwkTypeOKP, Crv: "Ed448", X: b64(k.ed.Public().(ed25519.PublicKey))},
		"okp short":         {Kty: jwkTypeOKP, Crv: jwkCurveEd25519, X: b64([]byte("short"))},
		"okp wrong alg":     {Kty: jwkTypeOKP, Crv: jwkCurveEd25519, X: b64(k.ed.Public().(ed25519.PublicKey)), Alg: algRS256},
	} {
		if _, ok := parseJWK(bad); ok {
			t.Errorf("%s was accepted", name)
		}
	}
	if verifySignature(publicKey{alg: algES256, key: &k.ec.PublicKey}, algES256, []byte("m"), []byte("short")) {
		t.Fatal("a short ES256 signature verified")
	}
	if verifySignature(publicKey{alg: algRS256, key: "not a key"}, algRS256, []byte("m"), nil) {
		t.Fatal("an unknown key type verified")
	}
}

func TestBoolish(t *testing.T) {
	for in, want := range map[string]bool{`true`: true, `"true"`: true, `false`: false, `"false"`: false, `"yes"`: false, `1`: false, `null`: false} {
		var b boolish
		if err := json.Unmarshal([]byte(in), &b); err != nil || bool(b) != want {
			t.Errorf("boolish(%s) = %v %v", in, b, err)
		}
	}
	// A missing name is assembled from its parts.
	p := profileFromClaims(idTokenClaims{Subject: "s", GivenName: "Ann", FamilyName: "Lee"})
	if p.Name != "Ann Lee" {
		t.Fatalf("name = %q", p.Name)
	}
}

// applePEM encodes a P-256 key the way Apple's .p8 file does.
func applePEM(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8, Bytes: der})
}

func TestApple_KeyAndClientSecret(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key, err := ParseAppleKey(applePEM(t, ec))
	if err != nil || !key.Equal(ec) {
		t.Fatalf("parse = %v", err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for name, bad := range map[string][]byte{
		"not pem":    []byte("hello"),
		"wrong type": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}),
		"bad der":    pem.EncodeToMemory(&pem.Block{Type: pemTypePKCS8, Bytes: []byte{1, 2, 3}}),
		"rsa":        applePEM(t, rsaKey),
		"p384":       applePEM(t, p384),
	} {
		if _, err := ParseAppleKey(bad); !errors.Is(err, ErrAppleKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := AppleClientSecret("", "cid", "kid", key); !errors.Is(err, ErrAppleSecret) {
		t.Fatalf("empty team id: %v", err)
	}
	if _, err := AppleClientSecret("team", "cid", "kid", nil); !errors.Is(err, ErrAppleSecret) {
		t.Fatalf("nil key: %v", err)
	}
	secret, err := AppleClientSecret("team", "cid", "kid", key)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := secret(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The assertion verifies under the public key and carries Apple's claims.
	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !verifySignature(publicKey{alg: algES256, key: &key.PublicKey}, algES256, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("the client secret does not verify")
	}
	var c map[string]any
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(pb, &c)
	if c["iss"] != "team" || c["sub"] != "cid" || c["aud"] != AppleIssuer {
		t.Fatalf("claims = %v", c)
	}
	// The secret is cached until it is about to expire, then renewed.
	again, _ := secret(context.Background())
	if again != tok {
		t.Fatal("the secret was signed twice within its lifetime")
	}
	s := &appleSecret{teamID: "team", clientID: "cid", keyID: "kid", key: key, now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	first, _ := s.secret(context.Background())
	s.now = func() time.Time {
		return time.Unix(1_800_000_000, 0).Add(appleSecretLifetime - appleSecretRenewBefore + time.Second)
	}
	renewed, _ := s.secret(context.Background())
	if first == renewed {
		t.Fatal("the secret was not renewed before its expiry")
	}
	// Apple's provider is complete: it verifies ID tokens and has no
	// FetchProfile because the profile comes from the token.
	a := Apple("cid", secret, "ios.bundle")
	if !a.IDToken.ProfileFromToken || a.FetchProfile != nil || a.IDToken.Audiences[0] != "ios.bundle" {
		t.Fatalf("apple = %+v", a.IDToken)
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(a)))); err != nil {
		t.Fatal(err)
	}
}

func TestExchange_ProfileFromIDTokenUsesTheChallengeAsNonce(t *testing.T) {
	keys := newTestKeys(t)
	now := time.Unix(1_800_000_000, 0)
	var form url.Values
	nonce := ""
	var secretSeen string
	srv := providerServer(t, map[string]http.HandlerFunc{
		"/keys": func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(keys.jwks()) },
		"/token": func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			form = r.PostForm
			secretSeen = r.PostForm.Get(paramClientSecret)
			claims := map[string]any{"iss": "https://idp.test", "sub": "s1", "aud": "cid", "exp": now.Add(time.Hour).Unix(), "email": "s@x.co", "email_verified": "true"}
			if nonce != "" {
				claims["nonce"] = nonce
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "at", "id_token": keys.sign(t, algRS256, kidRSA, claims)})
		},
	})
	o := &OAuth2{ID: "idp", ClientID: "cid", TokenURL: srv.URL + "/token", AuthURL: srv.URL + "/authorize",
		ClientSecretFunc: func(context.Context) (string, error) { return "dynamic", nil },
		IDToken:          IDTokenConfig{JWKSURL: srv.URL + "/keys", Issuers: []string{"https://idp.test"}, ProfileFromToken: true},
		now:              func() time.Time { return now }}
	// The authorization URL carries the challenge as the nonce.
	u, _ := url.Parse(o.AuthCodeURL("st", "ch", "https://app/cb"))
	if u.Query().Get(paramNonce) != "ch" {
		t.Fatalf("nonce = %q", u.Query().Get(paramNonce))
	}
	// Without the nonce in the token, the exchange is refused.
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); !errors.Is(err, ErrExchange) {
		t.Fatalf("token without nonce: %v", err)
	}
	nonce = "wrong"
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); !errors.Is(err, ErrExchange) {
		t.Fatalf("token with another nonce: %v", err)
	}
	nonce = PKCEChallenge("ver")
	p, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb")
	if err != nil || p.Subject != "s1" || p.Email != "s@x.co" || !p.EmailVerified || p.Tokens.IDToken == "" {
		t.Fatalf("profile = %+v %v", p, err)
	}
	if secretSeen != "dynamic" || form.Get(paramClientID) != "cid" {
		t.Fatalf("form = %v", form)
	}
	// The same provider verifies a native ID token through the interface.
	native := keys.sign(t, algES256, kidEC, map[string]any{"iss": "https://idp.test", "sub": "s1", "aud": "cid", "exp": now.Add(time.Hour).Unix(), "nonce": "n"})
	if prof, err := o.VerifyIDToken(context.Background(), srv.Client(), native, "n"); err != nil || prof.Subject != "s1" {
		t.Fatalf("VerifyIDToken = %+v %v", prof, err)
	}
	// An *OAuth2 end-session endpoint is its field; a provider of each kind
	// yields its client id for the logout request.
	if end, err := (&OAuth2{EndSessionURL: "https://idp/logout"}).EndSession(context.Background(), nil); err != nil || end != "https://idp/logout" {
		t.Fatalf("EndSession = %q %v", end, err)
	}
	if clientIDOf(o) != "cid" || clientIDOf(OIDC("x", "https://x", "oidc-cid", "s")) != "oidc-cid" || clientIDOf(custom{}) != "" {
		t.Fatal("clientIDOf")
	}
	// A failing secret function fails the exchange.
	o.ClientSecretFunc = func(context.Context) (string, error) { return "", errors.New("kms down") }
	if _, err := o.Exchange(context.Background(), srv.Client(), "code", "ver", "https://app/cb"); !errors.Is(err, ErrExchange) {
		t.Fatalf("failing secret: %v", err)
	}
}

func TestOIDC_DiscoveryFillsIDTokenAndEndSession(t *testing.T) {
	var srv *http.Client
	var base string
	withJWKS := true
	s := providerServer(t, map[string]http.HandlerFunc{"/.well-known/openid-configuration": func(w http.ResponseWriter, _ *http.Request) {
		doc := map[string]string{"issuer": base, "authorization_endpoint": base + "/a", "token_endpoint": base + "/t", "userinfo_endpoint": base + "/u", "end_session_endpoint": base + "/logout"}
		if withJWKS {
			doc["jwks_uri"] = base + "/keys"
		}
		_ = json.NewEncoder(w).Encode(doc)
	}})
	base, srv = s.URL, s.Client()
	p := OIDC("corp", base, "cid", "sec")
	p.IDToken.Audiences = []string{"ios"}
	c, err := p.discover(context.Background(), srv)
	if err != nil || c.IDToken.JWKSURL != base+"/keys" || c.IDToken.Issuers[0] != base || c.IDToken.Audiences[0] != "ios" || c.EndSessionURL != base+"/logout" {
		t.Fatalf("discovered = %+v %v", c.IDToken, err)
	}
	end, err := p.EndSession(context.Background(), srv)
	if err != nil || end != base+"/logout" {
		t.Fatalf("end session = %q %v", end, err)
	}
	// A hand-set end-session URL wins; an issuer without jwks_uri does not
	// accept ID tokens.
	withJWKS = false
	q := OIDC("corp", base, "cid", "sec")
	q.EndSessionURL = "https://custom/logout"
	c, _ = q.discover(context.Background(), srv)
	if c.EndSessionURL != "https://custom/logout" || c.IDToken.Enabled() {
		t.Fatalf("discovered = %+v end %q", c.IDToken, c.EndSessionURL)
	}
	if _, err := q.VerifyIDToken(context.Background(), srv, "a.b.c", ""); !errors.Is(err, ErrIDTokenUnsupported) {
		t.Fatalf("id token at an issuer without jwks_uri: %v", err)
	}
	// An issuer that cannot be discovered fails both the ID token and the
	// end-session lookup with the discovery error.
	down := OIDC("down", "http://127.0.0.1:1", "cid", "sec")
	hc := &http.Client{Timeout: time.Second}
	if _, err := down.VerifyIDToken(context.Background(), hc, "a.b.c", ""); !errors.Is(err, ErrExchange) {
		t.Fatalf("id token at an unreachable issuer: %v", err)
	}
	if _, err := down.EndSession(context.Background(), hc); !errors.Is(err, ErrExchange) {
		t.Fatalf("end session at an unreachable issuer: %v", err)
	}
	var _ IDTokenVerifier = p
	var _ Logouter = p
	var _ Logouter = (*OAuth2)(nil)
}

func TestValidate_IDTokenAndLogoutConfiguration(t *testing.T) {
	wire := func(ps ...Provider) error {
		_, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(ps...))))
		return err
	}
	profile := func(context.Context, *http.Client, string) (Profile, error) { return Profile{}, nil }
	base := func() *OAuth2 {
		return &OAuth2{ID: "p", ClientID: "c", AuthURL: "https://a", TokenURL: "https://t", FetchProfile: profile}
	}
	noIssuers := base()
	noIssuers.IDToken = IDTokenConfig{JWKSURL: "https://k"}
	fromTokenNoJWKS := base()
	fromTokenNoJWKS.IDToken = IDTokenConfig{ProfileFromToken: true}
	for name, p := range map[string]*OAuth2{"jwks without issuers": noIssuers, "profile from token without jwks": fromTokenNoJWKS} {
		if err := wire(p); !errors.Is(err, ErrIDTokenConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	publicWithFunc := base()
	publicWithFunc.TokenAuth, publicWithFunc.ClientSecretFunc = PublicClient, func(context.Context) (string, error) { return "s", nil }
	if err := wire(publicWithFunc); !errors.Is(err, ErrProviderIncomplete) {
		t.Fatalf("public client with a secret function: %v", err)
	}
	noProfile := base()
	noProfile.FetchProfile = nil
	if err := wire(noProfile); !errors.Is(err, ErrProviderIncomplete) {
		t.Fatalf("no profile source: %v", err)
	}
	noProfile.IDToken = IDTokenConfig{JWKSURL: "https://k", Issuers: []string{"i"}, ProfileFromToken: true}
	if err := wire(noProfile); err != nil {
		t.Fatalf("profile from the token: %v", err)
	}
	oidc := OIDC("corp", "https://corp", "c", "s")
	oidc.IDToken.JWKSURL = "https://corp/keys"
	if err := wire(oidc); !errors.Is(err, ErrIDTokenConfig) {
		t.Fatalf("OIDC with a hand-set jwks and no issuers: %v", err)
	}
	// ErrorURL must be a path on this site.
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(base()), ErrorURL("https://evil")))); !errors.Is(err, ErrBadReturnTo) {
		t.Fatalf("absolute ErrorURL: %v", err)
	}
	// Operations: id-token and logout exist for the built-in provider
	// kinds, not for a custom Provider that implements neither.
	a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(New(WithProviders(base(), custom{}), ErrorURL("/sign-in"))))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []auth.EndpointID{IDTokenEndpoint("p"), LogoutEndpoint("p")} {
		if _, ok := a.Operation(id); !ok {
			t.Errorf("operation %s not registered", id)
		}
	}
	for _, id := range []auth.EndpointID{IDTokenEndpoint("custom"), LogoutEndpoint("custom")} {
		if _, ok := a.Operation(id); ok {
			t.Errorf("operation %s registered for a provider that cannot serve it", id)
		}
	}
	// Without a base URL the default post-logout URL cannot be built.
	if _, err := auth.New(auth.WithPlugins(New(WithProviders(base()), CallbackURL(func(string) string { return "https://cb" })))); !errors.Is(err, ErrNoCallbackURL) {
		t.Fatalf("no base URL and no PostLogoutURL: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(New(WithProviders(base()), CallbackURL(func(string) string { return "https://cb" }), PostLogoutURL(func(string) string { return "https://app" })))); err != nil {
		t.Fatalf("both URLs given by hand: %v", err)
	}
}

// custom is a Provider that is neither an IDTokenVerifier nor a Logouter.
type custom struct{}

func (custom) Name() string                              { return "custom" }
func (custom) AuthCodeURL(string, string, string) string { return "https://custom/a" }
func (custom) Exchange(context.Context, *http.Client, string, string, string) (Profile, error) {
	return Profile{Subject: "x"}, nil
}
