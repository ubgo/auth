package twofactor

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// TestCode_RFC6238Vector checks the SHA-1 vector of RFC 6238 appendix B:
// secret "12345678901234567890", T = 59 s gives 94287082 in 8 digits, so the
// 6-digit code is its last six.
func TestCode_RFC6238Vector(t *testing.T) {
	secret := []byte("12345678901234567890")
	if got := code(secret, stepAt(time.Unix(59, 0), Step), Digits); got != "287082" {
		t.Fatalf("code = %s, want 287082", got)
	}
	if got := code(secret, stepAt(time.Unix(1111111109, 0), Step), Digits); got != "081804" {
		t.Fatalf("code = %s, want 081804", got)
	}
}

func TestOtpauthURL(t *testing.T) {
	u, err := url.Parse(otpauthURL("Acme App", "usr_1", []byte("12345678901234567890"), Digits, Step))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || u.Query().Get("issuer") != "Acme App" {
		t.Fatalf("url = %s", u)
	}
}

type signIn struct{}

func (signIn) Name() string  { return "stub" }
func (signIn) SignsIn() bool { return true }

func TestNew_NeedsAKey(t *testing.T) {
	if _, err := auth.New(auth.WithPlugins(signIn{}, New())); !errors.Is(err, ErrNoEncryptionKey) {
		t.Fatalf("no key: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, New(WithEncryptionKey([]byte("short"))))); !errors.Is(err, ErrNoEncryptionKey) {
		t.Fatalf("short key: %v", err)
	}
	a, err := auth.New(auth.WithPlugins(signIn{}, New(WithEncryptionKey([]byte(strings.Repeat("k", auth.SealKeySize))))))
	if err != nil {
		t.Fatal(err)
	}
	if op, ok := a.Operation(EndpointVerify); !ok || op.Info().Require != auth.PendingSecondFactor {
		t.Fatal("verify must run on a pending session")
	}
}
