package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestRSAKey_BindsOneModulusToOneAlgorithm: RSAKey makes an RSA key sign
// one algorithm; RS256 is the bare key unchanged; the same modulus bound to
// two algorithms is two key ids, and a JWK names its algorithm so the parsed
// key verifies only that one.
func TestRSAKey_BindsOneModulusToOneAlgorithm(t *testing.T) {
	raw := algKey(t, RS256).(*rsa.PrivateKey)
	same, err := RSAKey(raw, RS256)
	if err != nil || same != crypto.Signer(raw) {
		t.Fatalf("RS256 = %v, %v", same, err)
	}
	pss, err := RSAKey(raw, PS256)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := AlgOf(pss.Public()); a != PS256 {
		t.Fatalf("alg = %s", a)
	}
	if KeyID(pss.Public()) == KeyID(raw.Public()) {
		t.Fatal("PS256 and RS256 share a key id")
	}
	j, ok := jwkOf(pss.Public())
	if !ok || j.Alg != string(PS256) || j.KeyType != KeyTypeRSA {
		t.Fatalf("JWK = %+v", j)
	}
	back, ok := keyOfJWK(j)
	if !ok || back.(RSAPublicKey).Alg != PS256 || !back.(RSAPublicKey).Key.Equal(&raw.PublicKey) {
		t.Fatalf("parsed = %v", back)
	}
	sig, err := signWithKey(pss, []byte("in"))
	if err != nil || !verifySignature(back, []byte("in"), sig) || verifySignature(&raw.PublicKey, []byte("in"), sig) {
		t.Fatalf("PSS signature: %v", err)
	}
	for name, c := range map[string]struct {
		k   crypto.Signer
		alg Alg
	}{
		"nil key":       {nil, PS256},
		"not RSA alg":   {raw, ES256},
		"EC key":        {algKey(t, ES256), PS256},
		"no algorithm":  {raw, ""},
		"unknown":       {raw, "PS1"},
		"already bound": {pss, RS384},
	} {
		if _, err := RSAKey(c.k, c.alg); !errors.Is(err, ErrUnsupportedKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, k := range map[string]crypto.PublicKey{
		"no key":      RSAPublicKey{Alg: PS256},
		"EC alg":      RSAPublicKey{Key: &raw.PublicKey, Alg: ES256},
		"short":       RSAPublicKey{Key: &rsa.PublicKey{E: 3}, Alg: PS256},
		"no alg type": RSAPublicKey{Key: &raw.PublicKey},
	} {
		if _, err := AlgOf(k); !errors.Is(err, ErrUnsupportedKey) || verifySignature(k, []byte("in"), sig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestHashOf: each algorithm's hash by its suffix, SHA-512 for EdDSA, none
// for an unknown one.
func TestHashOf(t *testing.T) {
	for alg, want := range map[Alg]crypto.Hash{
		EdDSA: crypto.SHA512, RS256: crypto.SHA256, PS256: crypto.SHA256, ES256: crypto.SHA256,
		RS384: crypto.SHA384, PS384: crypto.SHA384, ES384: crypto.SHA384,
		RS512: crypto.SHA512, PS512: crypto.SHA512, ES512: crypto.SHA512, "HS256": 0,
	} {
		if got := HashOf(alg); got != want {
			t.Errorf("%s = %v", alg, got)
		}
	}
}

// TestKeyOfJWK_EachCurveRoundTrips: P-384 and P-521 keys survive their JWK,
// and a coordinate of another curve's size is refused.
func TestKeyOfJWK_EachCurveRoundTrips(t *testing.T) {
	for _, a := range []Alg{ES384, ES512} {
		pub := algKey(t, a).Public().(*ecdsa.PublicKey)
		j, ok := jwkOf(pub)
		if !ok {
			t.Fatalf("%s: no JWK", a)
		}
		back, ok := keyOfJWK(j)
		if !ok || !back.(*ecdsa.PublicKey).Equal(pub) {
			t.Fatalf("%s: round trip", a)
		}
		j.Y = j.X[:len(j.X)-4]
		if _, ok := keyOfJWK(j); ok {
			t.Fatalf("%s: short coordinate accepted", a)
		}
	}
	if _, ok := keyOfJWK(JWK{KeyType: KeyTypeOKP, Curve: "X25519", X: "AA"}); ok {
		t.Fatal("X25519 accepted")
	}
}

// TestPublicKeyForAlg: a JWK with no alg verifies under the header's alg
// within its key family; a JWK with an alg verifies only that one; HMAC
// and a cross-family alg are refused.
func TestPublicKeyForAlg(t *testing.T) {
	rsaJ, _ := jwkOf(algKey(t, RS256).Public())
	rsaJ.Alg = ""
	pub, ok := PublicKeyForAlg(rsaJ, PS384)
	if !ok || pub.(RSAPublicKey).Alg != PS384 {
		t.Fatalf("RSA under PS384 = %v, %v", pub, ok)
	}
	if pub, ok := PublicKeyForAlg(rsaJ, RS256); !ok {
		t.Fatal("RSA under RS256 refused")
	} else if _, bare := pub.(*rsa.PublicKey); !bare {
		t.Fatalf("RS256 key = %T", pub)
	}
	ecJ, _ := jwkOf(algKey(t, ES512).Public())
	edJ, _ := jwkOf(algKey(t, EdDSA).Public())
	bound, _ := jwkOf(algKey(t, PS256).Public())
	if _, ok := PublicKeyForAlg(ecJ, ES512); !ok {
		t.Fatal("P-521 under ES512 refused")
	}
	if _, ok := PublicKeyForAlg(bound, PS256); !ok {
		t.Fatal("PS256 key under PS256 refused")
	}
	ecNoAlg := ecJ
	ecNoAlg.Alg = ""
	for name, c := range map[string]struct {
		k   JWK
		alg Alg
	}{
		"RSA under HS256":     {rsaJ, "HS256"},
		"RSA under ES256":     {rsaJ, ES256},
		"P-521 under ES256":   {ecNoAlg, ES256},
		"Ed25519 under RS256": {edJ, RS256},
		"bound key, other":    {bound, RS256},
		"broken key":          {JWK{KeyType: KeyTypeRSA, N: "!!", E: "AQAB"}, RS256},
	} {
		if _, ok := PublicKeyForAlg(c.k, c.alg); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestPayload_ClaimsFromUserAndSession: Payload sees the session as well as
// the user, its claims follow Claims' (replacing one of the same name), and
// a registered claim fails the mint.
func TestPayload_ClaimsFromUserAndSession(t *testing.T) {
	newP := func(fn PayloadFunc) (*Plugin, *auth.Auth) {
		p := New(WithSigningKey(algKey(t, EdDSA)), Issuer("https://iss"),
			Claims(func(context.Context, auth.User) map[string]any { return map[string]any{"role": "user", "keep": 1} }), Payload(fn))
		a, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, p))
		if err != nil {
			t.Fatal(err)
		}
		return p, a
	}
	p, a := newP(func(_ context.Context, u auth.User, s auth.Session) map[string]any {
		return map[string]any{"role": "admin", "org": s.ID + ":" + u.ID}
	})
	s := auth.Session{ID: "ses_1", UserID: "usr_1", ExpiresAt: a.Now().Add(time.Hour)}
	u := auth.User{ID: "usr_1"}
	res, err := p.mint(context.Background(), &auth.Call{Auth: a, Session: &s, User: &u, Effects: &auth.Effects{}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Issuer: "https://iss"}.Verify(res.Token)
	if err != nil || string(got.Extra["org"]) != `"ses_1:usr_1"` || string(got.Extra["role"]) != `"admin"` || string(got.Extra["keep"]) != `1` {
		t.Fatalf("claims = %v %v", got.Extra, err)
	}
	bad, a2 := newP(func(context.Context, auth.User, auth.Session) map[string]any {
		return map[string]any{claimSubject: "x"}
	})
	s.ExpiresAt = a2.Now().Add(time.Hour)
	if _, err := bad.mint(context.Background(), &auth.Call{Auth: a2, Session: &s, User: &u, Effects: &auth.Effects{}}); !errors.Is(err, ErrReservedClaim) {
		t.Fatalf("reserved claim from Payload: %v", err)
	}
}

// TestBindRSA_PassesTheGeneratorError: GenerateKey's RSA path hands a
// failed generation back rather than binding a nil key.
func TestBindRSA_PassesTheGeneratorError(t *testing.T) {
	boom := errors.New("no entropy")
	if _, err := bindRSA(nil, boom, PS256); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

// TestSign_KeyIDPicksAmongKeysOfOneAlgorithm: two keys may share an
// algorithm; Alg takes the first (the signing key), KeyID any one, and a
// key id the plugin does not sign with, or of another algorithm, is
// ErrNoSigningKey.
func TestSign_KeyIDPicksAmongKeysOfOneAlgorithm(t *testing.T) {
	main, _ := GenerateKey(EdDSA)
	second, _ := GenerateKey(EdDSA)
	rsa1, _ := GenerateKey(RS256)
	p := New(WithSigningKey(main), Issuer("https://iss"), AlgorithmKeys(second, rsa1))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	kidOf := func(in SignRequest) (string, error) {
		in.Subject = "s"
		res, err := p.Sign(ctx, in)
		if err != nil {
			return "", err
		}
		return headerOf(t, res.Token).Kid, nil
	}
	if kid, err := kidOf(SignRequest{Alg: EdDSA}); err != nil || kid != KeyID(main.Public()) {
		t.Fatalf("EdDSA = %s %v", kid, err)
	}
	if kid, err := kidOf(SignRequest{KeyID: KeyID(second.Public())}); err != nil || kid != KeyID(second.Public()) {
		t.Fatalf("second key = %s %v", kid, err)
	}
	if kid, err := kidOf(SignRequest{Alg: RS256, KeyID: KeyID(rsa1.Public())}); err != nil || kid != KeyID(rsa1.Public()) {
		t.Fatalf("rsa key = %s %v", kid, err)
	}
	for name, in := range map[string]SignRequest{"unknown": {KeyID: "nope"}, "wrong alg": {Alg: RS256, KeyID: KeyID(second.Public())}} {
		if _, err := kidOf(in); !errors.Is(err, ErrNoSigningKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
