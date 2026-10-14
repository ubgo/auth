package jwt

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
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// keysByAlg generates one key per algorithm once: RSA generation costs a
// noticeable fraction of a second, and every test here wants all three.
var keysByAlg = sync.OnceValues(func() (map[Alg]crypto.Signer, error) {
	out := map[Alg]crypto.Signer{}
	for _, a := range AlgValues {
		k, err := GenerateKey(a)
		if err != nil {
			return nil, err
		}
		out[a] = k
	}
	return out, nil
})

func algKey(t *testing.T, a Alg) crypto.Signer {
	t.Helper()
	keys, err := keysByAlg()
	if err != nil {
		t.Fatal(err)
	}
	return keys[a]
}

// headerOf decodes a token's header.
func headerOf(t *testing.T, tok string) header {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var h header
	if err != nil || json.Unmarshal(b, &h) != nil {
		t.Fatalf("header of %q: %v", tok, err)
	}
	return h
}

func TestAlgorithms_EachSignsPublishesAndVerifies(t *testing.T) {
	want := map[Alg]struct{ kty, crv string }{EdDSA: {KeyTypeOKP, CurveEd25519}, ES256: {KeyTypeEC, CurveP256}, ES384: {KeyTypeEC, CurveP384}, ES512: {KeyTypeEC, CurveP521}}
	for _, a := range rsaAlgs {
		want[a] = struct{ kty, crv string }{KeyTypeRSA, ""}
	}
	for _, a := range AlgValues {
		t.Run(string(a), func(t *testing.T) {
			k := algKey(t, a)
			p := New(WithSigningKey(k), Issuer("https://iss"), Audience("api"))
			if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
				t.Fatal(err)
			}
			res, err := p.Sign(context.Background(), SignRequest{Subject: "usr_1"})
			if err != nil {
				t.Fatal(err)
			}
			h := headerOf(t, res.Token)
			if h.Alg != string(a) || h.Typ != tokenType || h.Kid != KeyID(k.Public()) {
				t.Fatalf("header = %+v", h)
			}
			set := p.PublicKeys()
			j := set.Keys[0]
			if len(set.Keys) != 1 || j.KeyType != want[a].kty || j.Curve != want[a].crv || j.Alg != string(a) || j.Use != KeyUseSignature || j.KeyID != h.Kid {
				t.Fatalf("JWK = %+v", j)
			}
			// The JSON of each type carries its own fields and none of the
			// others'.
			raw, _ := json.Marshal(j)
			isRSA, isEC := want[a].kty == KeyTypeRSA, want[a].kty == KeyTypeEC
			for field, present := range map[string]bool{`"x":`: !isRSA, `"y":`: isEC, `"n":`: isRSA, `"e":`: isRSA, `"crv":`: !isRSA} {
				if strings.Contains(string(raw), field) != present {
					t.Fatalf("JWK JSON %s: %s present=%v", raw, field, !present)
				}
			}
			if c, ok := curveOf(func(c ecCurve) bool { return c.alg == a }); ok {
				sig, _ := base64.RawURLEncoding.DecodeString(strings.Split(res.Token, ".")[2])
				if len(sig) != 2*c.size {
					t.Fatalf("%s signature is %d bytes, JWS wants r||s of %d", a, len(sig), 2*c.size)
				}
			}
			// A verifier with only the JSON key set accepts it.
			var fetched JWKS
			body, _ := json.Marshal(set)
			if err := json.Unmarshal(body, &fetched); err != nil {
				t.Fatal(err)
			}
			v := Verifier{Keys: KeysFromJWKS(fetched), Issuer: "https://iss", Audience: "api"}
			got, err := v.Verify(res.Token)
			if err != nil || got.Subject != "usr_1" {
				t.Fatalf("verify %s: %+v %v", a, got, err)
			}
		})
	}
}

func TestGenerateKey_DefaultAndUnknown(t *testing.T) {
	k, err := GenerateKey("")
	if err != nil {
		t.Fatal(err)
	}
	if alg, err := AlgOf(k.Public()); err != nil || alg != DefaultAlgorithm {
		t.Fatalf("default key = %s %v", alg, err)
	}
	if _, err := GenerateKey("HS256"); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("HS256: %v", err)
	}
	if rk, err := GenerateKey(RS256); err != nil || rk.Public().(*rsa.PublicKey).N.BitLen() != MinRSABits {
		t.Fatalf("RS256 key: %v", err)
	}
}

func TestAlgOf_RefusesUnsupportedKeys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]crypto.PublicKey{
		"RSA 1024":        &small.PublicKey,
		"RSA with no N":   &rsa.PublicKey{E: 65537},
		"P-224":           &p384.PublicKey,
		"short Ed25519":   ed25519.PublicKey("short"),
		"not a key":       "a string",
		"no key":          nil,
		"an RSA private":  small,
		"Ed25519 private": algKey(t, EdDSA),
	} {
		if _, err := AlgOf(k); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("%s: %v", name, err)
		}
		if KeyID(k) != "" {
			t.Errorf("%s has a key id", name)
		}
		if _, ok := jwkOf(k); ok {
			t.Errorf("%s has a JWK", name)
		}
		if verifySignature(k, []byte("in"), []byte("sig")) {
			t.Errorf("%s verified", name)
		}
	}
}

func TestKeyID_Ed25519IsUnchangedAndOthersHashTheirPKIX(t *testing.T) {
	ek := algKey(t, EdDSA).Public().(ed25519.PublicKey)
	h := sha256.Sum256(ek)
	if KeyID(ek) != base64.RawURLEncoding.EncodeToString(h[:])[:kidLength] {
		t.Fatal("an Ed25519 key id changed, which would orphan every token in flight")
	}
	for _, a := range []Alg{RS256, ES256} {
		pub := algKey(t, a).Public()
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256(der)
		if KeyID(pub) != base64.RawURLEncoding.EncodeToString(h[:])[:kidLength] {
			t.Fatalf("%s key id", a)
		}
	}
}

// signHeader signs an arbitrary header and claims with k under k's own
// algorithm, whatever the header says, to build tokens that lie about it.
func signHeader(t *testing.T, k crypto.Signer, hdr string, claims string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	in := enc.EncodeToString([]byte(hdr)) + "." + enc.EncodeToString([]byte(claims))
	sig, err := signWithKey(k, []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + enc.EncodeToString(sig)
}

// The alg header never picks how a signature is checked: the key the kid
// names does. A token whose header names another algorithm than its key's is
// refused even when its signature is valid under the key's own algorithm,
// and "none" or an HMAC algorithm is refused before any key is looked up.
func TestVerify_PinsTheAlgorithmToTheKey(t *testing.T) {
	keys := map[string]crypto.PublicKey{}
	for _, a := range AlgValues {
		keys[KeyID(algKey(t, a).Public())] = algKey(t, a).Public()
	}
	v := Verifier{Keys: keys}
	claims := `{"sub":"u","exp":` + big.NewInt(time.Now().Add(time.Minute).Unix()).String() + `}`
	for _, signer := range AlgValues {
		k := algKey(t, signer)
		kid := KeyID(k.Public())
		good := signHeader(t, k, `{"alg":"`+string(signer)+`","typ":"JWT","kid":"`+kid+`"}`, claims)
		if _, err := v.Verify(good); err != nil {
			t.Fatalf("%s: the honest token is refused: %v", signer, err)
		}
		for _, lie := range []string{"none", "HS256", "ES256K", "RS1"} {
			tok := signHeader(t, k, `{"alg":"`+lie+`","typ":"JWT","kid":"`+kid+`"}`, claims)
			if _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "algorithm") {
				t.Errorf("%s key, alg %s: %v", signer, lie, err)
			}
		}
		for _, other := range AlgValues {
			if other == signer {
				continue
			}
			tok := signHeader(t, k, `{"alg":"`+string(other)+`","typ":"JWT","kid":"`+kid+`"}`, claims)
			if _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "algorithm") {
				t.Errorf("%s key, alg %s: %v", signer, other, err)
			}
		}
	}
	// A key of no supported algorithm handed back by a Lookup is refused.
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weak := Verifier{Lookup: func(string) (crypto.PublicKey, bool) { return &small.PublicKey, true }}
	tok := signHeader(t, algKey(t, RS256), `{"alg":"RS256","typ":"JWT","kid":"x"}`, claims)
	if _, err := weak.Verify(tok); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a 1024-bit key: %v", err)
	}
}

func TestVerify_RequiresTheJWTType(t *testing.T) {
	k := algKey(t, EdDSA)
	kid := KeyID(k.Public())
	v := Verifier{Keys: map[string]crypto.PublicKey{kid: k.Public()}}
	claims := `{"sub":"u","exp":` + big.NewInt(time.Now().Add(time.Minute).Unix()).String() + `}`
	for name, typ := range map[string]string{"no typ": ``, "a session-cache snapshot": `,"typ":"` + SessionCacheType + `"`, "lower case": `,"typ":"jwt"`} {
		tok := signHeader(t, k, `{"alg":"EdDSA"`+typ+`,"kid":"`+kid+`"}`, claims)
		if _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "type") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKeysFromJWKS_RSAAndECKeys(t *testing.T) {
	rk, ek := algKey(t, RS256).Public(), algKey(t, ES256).Public()
	rj, _ := jwkOf(rk)
	ej, _ := jwkOf(ek)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	smallJ := rj
	smallJ.N = base64.RawURLEncoding.EncodeToString(small.N.Bytes())
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384ECDH, err := p384.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	p384X := p384ECDH.Bytes()[1:49] // 0x04||X||Y, 48-byte coordinates
	bad := func(base JWK, edit func(*JWK)) JWK { j := base; j.KeyID = "bad"; edit(&j); return j }
	enc := base64.RawURLEncoding
	set := JWKS{Keys: []JWK{
		rj, ej,
		bad(rj, func(j *JWK) { j.Alg = string(ES256) }),
		bad(rj, func(j *JWK) { j.N = "!!" }),
		bad(rj, func(j *JWK) { j.E = "" }),
		bad(rj, func(j *JWK) { j.E = enc.EncodeToString([]byte{1, 0, 0, 0, 1}) }),
		bad(smallJ, func(*JWK) {}),
		bad(ej, func(j *JWK) { j.Alg = string(RS256) }),
		bad(ej, func(j *JWK) { j.Curve = "P-384"; j.X = enc.EncodeToString(p384X) }),
		bad(ej, func(j *JWK) { j.Y = enc.EncodeToString(make([]byte, p256CoordinateSize)) }), // off the curve
		bad(ej, func(j *JWK) { j.X = "!!" }),
		bad(ej, func(j *JWK) { j.Y = enc.EncodeToString([]byte("short")) }),
		bad(ej, func(j *JWK) { j.KeyType = "oct" }),
	}}
	got := KeysFromJWKS(set)
	if len(got) != 2 || got[rj.KeyID] == nil || got[ej.KeyID] == nil || got["bad"] != nil {
		t.Fatalf("keys = %v", got)
	}
	if !got[rj.KeyID].(*rsa.PublicKey).Equal(rk) || !got[ej.KeyID].(*ecdsa.PublicKey).Equal(ek) {
		t.Fatal("a key changed through its JWK")
	}
}

// brokenSigner is a crypto.Signer that answers with the wrong encoding, as
// a KMS client might.
type brokenSigner struct {
	crypto.Signer
	sig []byte
	err error
}

func (b brokenSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return b.sig, b.err }

func TestSignWithKey_RefusesWhatASignerGetsWrong(t *testing.T) {
	ec := algKey(t, ES256)
	for name, s := range map[string]crypto.Signer{
		"not ASN.1":      brokenSigner{Signer: ec, sig: []byte("garbage")},
		"trailing bytes": brokenSigner{Signer: ec, sig: append(mustASN1(t, 1, 1), 0)},
		"zero r":         brokenSigner{Signer: ec, sig: mustASN1(t, 0, 1)},
		"negative s":     brokenSigner{Signer: ec, sig: mustASN1(t, 1, -1)},
		"r too long":     brokenSigner{Signer: ec, sig: mustASN1Big(t, new(big.Int).Lsh(big.NewInt(1), 300), big.NewInt(1))},
		"s too long":     brokenSigner{Signer: ec, sig: mustASN1Big(t, big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 300))},
	} {
		if _, err := signWithKey(s, []byte("in")); err == nil || !strings.Contains(err.Error(), "ASN.1") {
			t.Errorf("%s: %v", name, err)
		}
	}
	failing := errors.New("kms down")
	if _, err := signWithKey(brokenSigner{Signer: ec, err: failing}, []byte("in")); !errors.Is(err, failing) {
		t.Fatalf("failing ECDSA signer: %v", err)
	}
	if _, err := signWithKey(brokenSigner{Signer: algKey(t, RS256), err: failing}, []byte("in")); !errors.Is(err, failing) {
		t.Fatalf("failing RSA signer: %v", err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signWithKey(small, []byte("in")); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("1024-bit key: %v", err)
	}
	// A signature that decodes but is wrong is caught by signWith's own
	// check against the published key, before any token exists.
	wrong := keySigner{key: brokenSigner{Signer: ec, sig: mustASN1(t, 1, 1)}}
	if _, err := signWith(context.Background(), wrong, tokenType, map[string]any{claimSubject: "u"}); !errors.Is(err, ErrSignature) {
		t.Fatalf("a wrong signature: %v", err)
	}
	// A Signer that publishes a key of no supported algorithm mints nothing.
	unsupported := keySigner{key: small}
	if _, err := signWith(context.Background(), unsupported, tokenType, map[string]any{claimSubject: "u"}); !errors.Is(err, ErrSignerKey) || !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("unsupported signer key: %v", err)
	}
}

func mustASN1(t *testing.T, r, s int64) []byte { return mustASN1Big(t, big.NewInt(r), big.NewInt(s)) }

func mustASN1Big(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	b, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidate_RefusesUnsupportedKeys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string][]Option{
		"RSA 1024 signing key": {WithSigningKey(small)},
		"P-224 signing key":    {WithSigningKey(p384)},
		"P-224 previous key":   {WithSigningKey(algKey(t, EdDSA)), PreviousKeys(&p384.PublicKey)},
	} {
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(opts...))); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(WithSigningKey(nil)))); !errors.Is(err, auth.ErrNilOption) {
		t.Fatalf("nil key: %v", err)
	}
}

// Moving from EdDSA to RS256 keeps tokens in flight valid: the new RSA key
// signs, the old Ed25519 key stays published through PreviousKeys, and each
// token verifies under its own key's algorithm.
func TestPreviousKeys_MixAlgorithmsDuringAMigration(t *testing.T) {
	old, cur := algKey(t, EdDSA), algKey(t, RS256)
	before := New(WithSigningKey(old), Issuer("https://iss"))
	after := New(WithSigningKey(cur), Issuer("https://iss"), PreviousKeys(old.Public()))
	for _, p := range []*Plugin{before, after} {
		if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
			t.Fatal(err)
		}
	}
	inFlight, err := before.Sign(context.Background(), SignRequest{Subject: "u"})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := after.Sign(context.Background(), SignRequest{Subject: "u"})
	if err != nil {
		t.Fatal(err)
	}
	set := after.PublicKeys()
	if len(set.Keys) != 2 || set.Keys[0].Alg != string(RS256) || set.Keys[1].Alg != string(EdDSA) {
		t.Fatalf("key set = %+v", set)
	}
	v := Verifier{Keys: KeysFromJWKS(set)}
	for name, tok := range map[string]string{"in flight": inFlight.Token, "fresh": fresh.Token} {
		if _, err := v.Verify(tok); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if headerOf(t, fresh.Token).Alg != string(RS256) {
		t.Fatal("the fresh token is not RS256")
	}
}

func TestVerifySignature_ES256NeedsTheFixedLength(t *testing.T) {
	k := algKey(t, ES256)
	sig, err := signWithKey(k, []byte("in"))
	if err != nil || !verifySignature(k.Public(), []byte("in"), sig) {
		t.Fatalf("honest signature: %v", err)
	}
	// The ASN.1 form crypto.Signer returns, which a careless KMS Signer
	// would hand back, is refused rather than parsed.
	d := sha256.Sum256([]byte("in"))
	der, err := k.Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if verifySignature(k.Public(), []byte("in"), der) || verifySignature(k.Public(), []byte("in"), sig[:63]) {
		t.Fatal("an ES256 signature of the wrong length verified")
	}
}
