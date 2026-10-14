package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// SignRequest.Type sets the typ header, which a default Verifier refuses
// and one listing it in Types accepts; SessionID becomes sid.
func TestSign_TypeAndSessionID(t *testing.T) {
	k := algKey(t, EdDSA)
	p := New(WithSigningKey(k), Issuer("https://iss"))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	at, err := p.Sign(ctx, SignRequest{Subject: "u", Type: "at+jwt", SessionID: "ses_1"})
	if err != nil {
		t.Fatal(err)
	}
	if h := headerOf(t, at.Token); h.Typ != "at+jwt" {
		t.Fatalf("typ = %q", h.Typ)
	}
	keys := KeysFromJWKS(p.PublicKeys())
	if _, err := (Verifier{Keys: keys, Issuer: "https://iss"}).Verify(at.Token); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a default verifier accepted at+jwt: %v", err)
	}
	v, err := (Verifier{Keys: keys, Issuer: "https://iss", Types: []string{"at+jwt"}}).Verify(at.Token)
	if err != nil || v.SessionID != "ses_1" {
		t.Fatalf("at+jwt verifier = %+v %v", v, err)
	}
	plain, err := p.Sign(ctx, SignRequest{Subject: "u"})
	if err != nil || headerOf(t, plain.Token).Typ != tokenType {
		t.Fatalf("default type: %v", err)
	}
	if _, err := (Verifier{Keys: keys, Types: []string{"at+jwt"}}).Verify(plain.Token); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an at+jwt verifier accepted JWT: %v", err)
	}
	for _, bad := range []string{SessionCacheType, `a"b`, "a b", "a/b"} {
		if _, err := p.Sign(ctx, SignRequest{Subject: "u", Type: bad}); !errors.Is(err, ErrBadType) {
			t.Errorf("Sign type %q: %v", bad, err)
		}
		if _, err := (Verifier{Keys: keys, Types: []string{bad}}).Verify(plain.Token); !errors.Is(err, ErrBadType) {
			t.Errorf("Verifier type %q: %v", bad, err)
		}
	}
}

// RFC 7638 section 3.1's example RSA key and its thumbprint.
func TestThumbprint_RFC7638Example(t *testing.T) {
	k := JWK{KeyType: KeyTypeRSA, E: "AQAB", N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
	got, err := Thumbprint(k)
	if err != nil || got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint = %q %v", got, err)
	}
	if _, err := Thumbprint(JWK{KeyType: "oct"}); err == nil {
		t.Fatal("a symmetric key got a thumbprint")
	}
}

// VerifySignature checks typ, alg and signature against the given key only.
func TestVerifySignature(t *testing.T) {
	k := algKey(t, ES256)
	p := New(WithSigningKey(k), Issuer("https://iss"))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	tok, err := p.Sign(context.Background(), SignRequest{Subject: "u", Type: "dpop+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	if _, body, err := VerifySignature(tok.Token, k.Public(), "dpop+jwt"); err != nil || len(body) == 0 {
		t.Fatalf("verify: %v", err)
	}
	if _, _, err := VerifySignature(tok.Token, k.Public(), "JWT"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong type: %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifySignature(tok.Token, other.Public(), "dpop+jwt"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, _, err := VerifySignature("a.b", k.Public(), "dpop+jwt"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("two parts: %v", err)
	}
	j, _ := jwkOf(k.Public())
	if pub, ok := PublicKeyOfJWK(j); !ok || pub == nil {
		t.Fatal("PublicKeyOfJWK refused a published key")
	}
}

// An aud array longer than MaxAudienceValues is refused.
func TestVerify_AudienceCap(t *testing.T) {
	k := algKey(t, EdDSA)
	p := New(WithSigningKey(k), Issuer("https://iss"))
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	aud := make([]string, MaxAudienceValues+1)
	for i := range aud {
		aud[i] = "a"
	}
	big, err := p.Sign(context.Background(), SignRequest{Subject: "u", Audience: aud})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Audience: "a"}).Verify(big.Token); !errors.Is(err, ErrInvalid) {
		t.Fatalf("65 audiences: %v", err)
	}
	ok, _ := p.Sign(context.Background(), SignRequest{Subject: "u", Audience: aud[:MaxAudienceValues]})
	if _, err := (Verifier{Keys: KeysFromJWKS(p.PublicKeys()), Audience: "a"}).Verify(ok.Token); err != nil {
		t.Fatalf("64 audiences: %v", err)
	}
}
