package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// headerAlg reads the alg header of a compact token.
func headerAlg(t *testing.T, tok string) (alg, kid string) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.SplitN(tok, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct{ Alg, Kid string }
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	return h.Alg, h.Kid
}

// TestAlgorithmKeys: Sign picks the key of the asked algorithm, the key set
// publishes every one (so a verifier checks each by kid), the session path
// keeps the main key, and an algorithm with no key is a descriptive error.
func TestAlgorithmKeys(t *testing.T) {
	gen := func(alg Alg) crypto.Signer {
		k, err := GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	main, rsaKey := gen(EdDSA), gen(RS256)
	p := New(WithSigningKey(main), AlgorithmKeys(rsaKey), Issuer("https://iss"))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	set := p.PublicKeys()
	if len(set.Keys) != 2 || set.Keys[0].Alg != string(EdDSA) || set.Keys[1].Alg != string(RS256) {
		t.Fatalf("key set = %+v", set)
	}
	v := Verifier{Keys: KeysFromJWKS(set), Issuer: "https://iss"}
	ctx := context.Background()
	for _, c := range []struct {
		alg  Alg
		want Alg
		key  crypto.PublicKey
	}{{"", EdDSA, main.Public()}, {EdDSA, EdDSA, main.Public()}, {RS256, RS256, rsaKey.Public()}} {
		res, err := p.Sign(ctx, SignRequest{Subject: "s", Alg: c.alg})
		if err != nil {
			t.Fatalf("%q: %v", c.alg, err)
		}
		if alg, kid := headerAlg(t, res.Token); alg != string(c.want) || kid != KeyID(c.key) {
			t.Fatalf("%q signed %s/%s", c.alg, alg, kid)
		}
		if _, err := v.Verify(res.Token); err != nil {
			t.Fatalf("%q: verify: %v", c.alg, err)
		}
	}
	if _, err := p.Sign(ctx, SignRequest{Subject: "s", Alg: ES256}); !errors.Is(err, ErrNoAlgorithmKey) || !strings.Contains(err.Error(), "ES256") {
		t.Fatalf("missing algorithm: %v", err)
	}
	// The published RSA key is found by kid like the main one.
	if k, ok := p.publishedKey(KeyID(rsaKey.Public())); !ok || KeyID(k) != KeyID(rsaKey.Public()) {
		t.Fatal("the algorithm key is not published")
	}
}

// TestAlgorithmKeys_Validate: a nil or short key, or one key given twice
// (the signing key included), fail auth.New.
func TestAlgorithmKeys_Validate(t *testing.T) {
	main, _ := GenerateKey(EdDSA)
	rs1, _ := GenerateKey(RS256)
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithSigningKey(main), Issuer("https://iss"), AlgorithmKeys(nil)))); !errors.Is(err, auth.ErrNilOption) {
		t.Errorf("nil: %v", err)
	}
	for name, opt := range map[string]Option{
		"short ed25519": AlgorithmKeys(ed25519.PrivateKey{1, 2, 3}),
		"one key twice": AlgorithmKeys(rs1, rs1),
		"the main key":  AlgorithmKeys(main),
	} {
		if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithSigningKey(main), Issuer("https://iss"), opt))); !errors.Is(err, ErrAlgorithmKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestAlgorithmKeys_UnsupportedKey: a key of no supported algorithm (P-224)
// is ErrUnsupportedKey, like a signing key would be.
func TestAlgorithmKeys_UnsupportedKey(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	main, _ := GenerateKey(EdDSA)
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithSigningKey(main), Issuer("https://iss"), AlgorithmKeys(p384)))); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("P-224: %v", err)
	}
}
