package oauthprovider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/jwt"
)

// kmsSigner is a Signer that is not the jwt plugin and not a plugin at all:
// the shape of a KMS or HSM client an app already runs. It signs EdDSA
// tokens by hand, so nothing of the jwt plugin's routes or Init is involved.
type kmsSigner struct {
	issuer string
	key    ed25519.PrivateKey
	calls  int
}

func newKMSSigner(iss string) *kmsSigner {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return &kmsSigner{issuer: iss, key: key}
}

const kmsKeyID = "kms-1"

func (s *kmsSigner) Sign(_ context.Context, in jwt.SignRequest) (jwt.TokenResult, error) {
	s.calls++
	typ := in.Type
	if typ == "" {
		typ = "JWT"
	}
	exp := time.Now().Add(time.Minute)
	claims := map[string]any{"iss": s.issuer, "sub": in.Subject, "iat": time.Now().Unix(), "exp": exp.Unix()}
	for k, v := range in.Claims {
		claims[k] = v
	}
	if len(in.Audience) > 0 {
		claims["aud"] = in.Audience
	}
	h, _ := json.Marshal(map[string]string{"alg": string(jwt.EdDSA), "typ": typ, "kid": kmsKeyID})
	b, err := json.Marshal(claims)
	if err != nil {
		return jwt.TokenResult{}, err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(b)
	return jwt.TokenResult{Token: input + "." + enc.EncodeToString(ed25519.Sign(s.key, []byte(input))), ExpiresAt: exp}, nil
}

func (s *kmsSigner) PublicKeys() jwt.JWKS {
	pub, _ := s.key.Public().(ed25519.PublicKey)
	return jwt.JWKS{Keys: []jwt.JWK{{KeyType: "OKP", Curve: "Ed25519", X: base64.RawURLEncoding.EncodeToString(pub), KeyID: kmsKeyID, Use: "sig", Alg: string(jwt.EdDSA)}}}
}

// A Signer that is not the jwt plugin runs the provider with no jwt plugin
// registered: nothing is required, the start-up probe signs with it, and
// the JWKS route publishes its keys, which verify what it signed.
func TestNew_TakesASignerThatIsNotTheJWTPlugin(t *testing.T) {
	s := newKMSSigner(testIssuer)
	p := New(s, Issuer(testIssuer), LoginPage("/login"))
	if got := p.Requires(); len(got) != 0 {
		t.Fatalf("Requires = %v, want nothing for a signer that is not a plugin", got)
	}
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), p)); err != nil {
		t.Fatalf("auth.New without the jwt plugin: %v", err)
	}
	if s.calls != 1 {
		t.Fatalf("the start-up issuer probe signed %d times with the custom signer, want 1", s.calls)
	}
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, DefaultBasePath+pathJWKS, nil))
	var set jwt.JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 || set.Keys[0].KeyID != kmsKeyID {
		t.Fatalf("jwks = %d %s", w.Code, w.Body)
	}
	tok, err := s.Sign(context.Background(), jwt.SignRequest{Subject: "u1", Audience: []string{"c1"}})
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := jwt.PublicKeyOfJWK(set.Keys[0])
	if !ok {
		t.Fatal("the published key does not parse")
	}
	if _, _, err := jwt.VerifySignature(tok.Token, pub, "JWT"); err != nil {
		t.Fatalf("a token the custom signer made does not verify against the published key: %v", err)
	}
}

// The start-up issuer check holds for any signer, not only the jwt plugin.
func TestNew_CustomSignerIssuerMismatchRefused(t *testing.T) {
	p := New(newKMSSigner("https://other.example"), Issuer(testIssuer), LoginPage("/login"))
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), p)); !errors.Is(err, ErrIssuerMatch) {
		t.Fatalf("err = %v, want ErrIssuerMatch", err)
	}
}

// The jwt plugin still works as before: required by name, refused when it
// is missing or registered after the provider, and a typed nil is no signer.
func TestNew_JWTPluginStillRequired(t *testing.T) {
	j := newSigner(testIssuer)
	if got := New(j).Requires(); len(got) != 1 || got[0] != jwt.PluginName {
		t.Fatalf("Requires = %v, want [%s]", got, jwt.PluginName)
	}
	var none *jwt.Plugin
	p := New(none, Issuer(testIssuer), LoginPage("/login"))
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), p)); !errors.Is(err, ErrNoJWT) {
		t.Fatalf("typed nil signer: err = %v, want ErrNoJWT", err)
	}
}
