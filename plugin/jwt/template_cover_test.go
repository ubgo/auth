package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// unsupportedSigner is a crypto.Signer whose key no algorithm signs (ECDSA
// on P-224, which RFC 7518 does not name).
type unsupportedSigner struct{ pub crypto.PublicKey }

func (s unsupportedSigner) Public() crypto.PublicKey { return s.pub }
func (unsupportedSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("never called")
}

// kmsSigner wraps a real key and fails or corrupts its signatures, the
// KMS that answers wrongly.
type kmsSigner struct {
	crypto.Signer
	fail bool
}

func (b kmsSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if b.fail {
		return nil, errors.New("kms down")
	}
	sig, err := b.Signer.Sign(r, d, o)
	sig[len(sig)-1] ^= 1
	return sig, err
}

// emptySigner publishes no key.
type emptySigner struct{}

func (emptySigner) PublicKeys() []crypto.PublicKey { return nil }
func (emptySigner) Sign(context.Context, crypto.PublicKey, []byte) ([]byte, error) {
	return nil, errors.New("never called")
}

// strayKey is a TemplateKey of a kind templateAlg has no case for, which
// only a type inside this package can be.
type strayKey struct{}

func (strayKey) templateKey() {}

func p224(t *testing.T) unsupportedSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return unsupportedSigner{pub: k.Public()}
}

// TestTemplate_ConfigurationEdges: the key kinds auth.New must refuse
// beyond the main matrix, and the marker methods that close the set.
func TestTemplate_ConfigurationEdges(t *testing.T) {
	for name, tc := range map[string]struct {
		opts []Option
		want error
	}{
		"unsupported private key": {[]Option{WithSigningKey(key(t)), WithTemplate("a", Template{Key: PrivateKey(p224(t), "")})}, ErrTemplateKey},
		"stray key kind":          {[]Option{WithSigningKey(key(t)), WithTemplate("a", Template{Key: strayKey{}})}, ErrTemplateKey},
		"signer with no key":      {[]Option{WithSigner(emptySigner{}), WithTemplate("a", Template{})}, ErrSignerKey},
	} {
		if _, err := auth.New(auth.WithBaseURL("https://a.example"), auth.WithPlugins(signIn{}, New(tc.opts...))); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// Each kind of key belongs to the closed set.
	for _, k := range []TemplateKey{publishedTemplateKey{}, hmacTemplateKey{}, privateTemplateKey{}} {
		k.templateKey()
	}
}

// TestTemplate_SigningFailuresMintNothing: a claim with no JSON form, a key
// that cannot sign, a KMS that fails or answers a wrong signature, and a
// template changed after auth.New validated it all fail the call; none
// yields a token.
func TestTemplate_SigningFailuresMintNothing(t *testing.T) {
	rsaKey := mustKey(t, RS256)
	noJSON := func(context.Context, auth.User, auth.Session) (map[string]any, error) {
		return map[string]any{"c": make(chan int)}, nil
	}
	p := New(WithSigningKey(key(t)),
		WithTemplate("hs", Template{Key: HMACKey(templateSecret), Claims: noJSON}),
		WithTemplate("ext", Template{Key: PrivateKey(rsaKey, ""), Claims: noJSON}),
		WithTemplate("main", Template{Claims: noJSON}),
	)
	c := templateCall(t, p)
	for _, name := range []string{"hs", "ext", "main"} {
		if _, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: name}); err == nil || !strings.Contains(err.Error(), "encode claims") {
			t.Errorf("%s with a channel claim: %v", name, err)
		}
	}
	// Templates swapped in after validation reach the signing-time checks.
	p.templates["type"] = Template{Type: "a b"}
	p.templates["nokey"] = Template{Key: PublishedKey(RS256, "")}
	p.templates["unsupported"] = Template{Key: PrivateKey(p224(t), "")}
	p.templates["kmsdown"] = Template{Key: PrivateKey(kmsSigner{Signer: rsaKey, fail: true}, "")}
	p.templates["kmswrong"] = Template{Key: PrivateKey(kmsSigner{Signer: rsaKey}, "")}
	for name, want := range map[string]error{"type": ErrBadType, "nokey": ErrNoAlgorithmKey, "unsupported": ErrTemplateKey, "kmswrong": ErrSignature} {
		if _, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: name}); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	if _, err := p.doTemplate(context.Background(), c, TemplateRequest{Template: "kmsdown"}); err == nil || !strings.Contains(err.Error(), "kms down") {
		t.Errorf("kmsdown: %v", err)
	}
}

// TestTemplateToken_GoAPISignedOut: the Go entry point runs the same
// operation, so a caller with no session is refused like the route.
func TestTemplateToken_GoAPISignedOut(t *testing.T) {
	p := New(WithSigningKey(key(t)), WithTemplate("t", Template{}))
	templateCall(t, p)
	if _, err := p.TemplateToken(context.Background(), "t"); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatalf("signed out: %v", err)
	}
}

// TestVerifyHS256_PayloadNotBase64: a correctly MACed token whose payload is
// not base64url is refused after the MAC check.
func TestVerifyHS256_PayloadNotBase64(t *testing.T) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := "!!"
	m := hmac.New(sha256.New, templateSecret)
	m.Write([]byte(head + "." + body))
	tok := head + "." + body + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if _, err := VerifyHS256(tok, templateSecret); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("payload not base64: %v", err)
	}
}
