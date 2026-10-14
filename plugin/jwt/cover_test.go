package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// signRaw signs an arbitrary header and payload segment, so a test can build
// a token whose signature is valid but whose contents are malformed: the only
// way to reach the checks that run after the signature.
func signRaw(k ed25519.PrivateKey, header, payloadSegment string) string {
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(header)) + "." + payloadSegment
	return signing + "." + enc.EncodeToString(ed25519.Sign(k, []byte(signing)))
}

// signIn is the minimum sign-in method auth.New demands, so these tests can
// wire the plugin without importing a real one.
type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

func headerFor(k ed25519.PrivateKey) string {
	return `{"alg":"` + string(EdDSA) + `","typ":"JWT","kid":"` + KeyID(k.Public().(ed25519.PublicKey)) + `"}`
}

func TestNew_OptionsAndTTLClamp(t *testing.T) {
	k, old := key(t), key(t)
	oldPub := old.Public().(ed25519.PublicKey)
	p := New(WithSigningKey(k), Issuer("https://iss"), Audience("api"), WithTTL(2*MaxTTL), PreviousKeys(oldPub))
	if p.ttl != MaxTTL || p.issuer != "https://iss" || strings.Join(p.audience, ",") != "api" || len(p.previous) != 1 {
		t.Fatalf("plugin = ttl %v issuer %q audience %q previous %d", p.ttl, p.issuer, p.audience, len(p.previous))
	}
	if New(WithSigningKey(k), WithTTL(-time.Second)).ttl != MaxTTL {
		t.Fatal("a negative TTL must become MaxTTL, not an already-expired token")
	}
	if New(WithSigningKey(k), WithTTL(time.Minute)).ttl != time.Minute {
		t.Fatal("a TTL inside the cap must be kept")
	}
	set := p.PublicKeys()
	if len(set.Keys) != 2 || set.Keys[1].KeyID != KeyID(oldPub) || set.Keys[0].KeyType != KeyTypeOKP || set.Keys[0].Use != KeyUseSignature {
		t.Fatalf("key set = %+v", set)
	}
}

func TestValidate_NeedsKeyAndIssuer(t *testing.T) {
	if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New())); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithSigningKey(key(t))))); !errors.Is(err, ErrNoIssuer) {
		t.Fatalf("no issuer: %v", err)
	}
	// An explicit Issuer stands in for the base URL, and Init keeps it.
	p := New(WithSigningKey(key(t)), Issuer("https://iss"))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil || p.issuer != "https://iss" {
		t.Fatalf("explicit issuer: %q %v", p.issuer, err)
	}
	// Without one, the issuer is the base URL's origin.
	p = New(WithSigningKey(key(t)))
	if _, err := auth.New(auth.WithBaseURL("https://a.example/app/"), auth.WithPlugins(signIn{}, p)); err != nil || p.issuer != "https://a.example" {
		t.Fatalf("issuer from base URL: %q %v", p.issuer, err)
	}
}

func TestKeysFromJWKS_KeepsOnlySupportedSigningKeys(t *testing.T) {
	k := key(t)
	good := (&Plugin{signer: keySigner{key: k}}).PublicKeys().Keys[0]
	noAlg := good
	noAlg.KeyID, noAlg.Alg = "no-alg", ""
	bad := func(edit func(*JWK)) JWK { j := good; j.KeyID = "bad"; edit(&j); return j }
	set := JWKS{Keys: []JWK{
		good, noAlg,
		bad(func(j *JWK) { j.KeyType = "RSA" }),
		bad(func(j *JWK) { j.Curve = "X25519" }),
		bad(func(j *JWK) { j.Alg = "RS256" }),
		bad(func(j *JWK) { j.X = "not base64!" }),
		bad(func(j *JWK) { j.X = base64.RawURLEncoding.EncodeToString([]byte("short")) }),
	}}
	got := KeysFromJWKS(set)
	if len(got) != 2 || got[good.KeyID] == nil || got["no-alg"] == nil || got["bad"] != nil {
		t.Fatalf("keys = %v", got)
	}
}

func TestVerify_RefusesMalformedTokens(t *testing.T) {
	k := key(t)
	now := time.Unix(1_800_000_000, 0)
	v := Verifier{Keys: KeysFromJWKS((&Plugin{signer: keySigner{key: k}}).PublicKeys()), Now: func() time.Time { return now }}
	enc := base64.RawURLEncoding
	payload := func(s string) string { return enc.EncodeToString([]byte(s)) }
	good := signRaw(k, headerFor(k), payload(`{"sub":"u","exp":1800000060}`))
	parts := strings.Split(good, ".")
	cases := map[string]string{
		"header not base64":    "!!." + parts[1] + "." + parts[2],
		"header not JSON":      payload("nope") + "." + parts[1] + "." + parts[2],
		"signature not base64": parts[0] + "." + parts[1] + ".!!",
		"payload not base64":   signRaw(k, headerFor(k), "!!"),
		"payload not object":   signRaw(k, headerFor(k), payload(`[1,2]`)),
		"claim of wrong type":  signRaw(k, headerFor(k), payload(`{"sub":"u","exp":"soon"}`)),
		"missing sub":          signRaw(k, headerFor(k), payload(`{"exp":1800000060}`)),
		"missing exp":          signRaw(k, headerFor(k), payload(`{"sub":"u"}`)),
		"not yet valid":        signRaw(k, headerFor(k), payload(`{"sub":"u","exp":1800009999,"nbf":1800000600}`)),
	}
	for name, tok := range cases {
		if _, err := v.Verify(tok); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same token inside the leeway verifies, which proves the cases above
	// fail for their stated reason and not for a broken fixture.
	got, err := v.Verify(good)
	if err != nil || got.Subject != "u" {
		t.Fatalf("well-formed token: %+v %v", got, err)
	}
	withinLeeway := signRaw(k, headerFor(k), payload(`{"sub":"u","exp":1800000060,"nbf":1800000010}`))
	if _, err := v.Verify(withinLeeway); err != nil {
		t.Fatalf("nbf inside DefaultLeeway must verify: %v", err)
	}
	strict := v
	strict.Leeway = time.Second
	if _, err := strict.Verify(withinLeeway); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nbf outside a custom leeway: %v", err)
	}
}

func TestSign_RefusesAClaimWithNoJSONForm(t *testing.T) {
	if _, err := sign(key(t), map[string]any{claimSubject: "u", "score": math.NaN()}); err == nil || !strings.Contains(err.Error(), "encode claims") {
		t.Fatalf("NaN claim: %v", err)
	}
}

func TestSign_HeaderNamesAlgorithmTypeAndKey(t *testing.T) {
	k := key(t)
	tok, err := sign(k, map[string]any{claimSubject: "u"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	want := `{"alg":"EdDSA","typ":"JWT","kid":"` + KeyID(k.Public().(ed25519.PublicKey)) + `"}`
	if err != nil || string(h) != want {
		t.Fatalf("header = %s, want %s (%v)", h, want, err)
	}
}

func TestVerify_ExpiresAtIsUTC(t *testing.T) {
	k := key(t)
	tok, err := sign(k, map[string]any{claimSubject: "u", claimExpires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verifier{Keys: KeysFromJWKS((&Plugin{signer: keySigner{key: k}}).PublicKeys())}.Verify(tok)
	if err != nil || got.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expires at %v (%v), want UTC", got.ExpiresAt, err)
	}
}

// A signature has exactly one spelling. An Ed25519 signature is 64 bytes, 86
// base64url characters whose last carries 4 unused bits; a lenient decoder
// ignores them, so 16 different strings would verify as the same token and a
// service that deduplicates tokens by their text would count one token as many.
func TestVerify_RefusesANonCanonicalSignature(t *testing.T) {
	k := key(t)
	tok, err := sign(k, map[string]any{claimSubject: "u", claimExpires: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{Keys: KeysFromJWKS((&Plugin{signer: keySigner{key: k}}).PublicKeys())}
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("canonical token refused: %v", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, tok[len(tok)-1])
	variant := tok[:len(tok)-1] + string(alphabet[last^1]) // flips an unused bit only
	if _, err := v.Verify(variant); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical signature accepted: err = %v", err)
	}
}
