package twofactor

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestNew_DerivesTheKeyFromTheAppSecret: no WithEncryptionKey but
// auth.WithSecret works, a rotation of the secret keeps old enrolments
// opening, and an explicit key wins over the secret.
func TestNew_DerivesTheKeyFromTheAppSecret(t *testing.T) {
	old := bytes.Repeat([]byte("o"), auth.MinSecretSize)
	cur := bytes.Repeat([]byte("n"), auth.MinSecretSize)
	wire := func(opts ...auth.Option) *Plugin {
		p := New()
		if _, err := auth.New(append(opts, auth.WithPlugins(signIn{}, p))...); err != nil {
			t.Fatal(err)
		}
		return p
	}
	before := wire(auth.WithSecret(old))
	sealed := mustSeal(t, before.ring, "totp-secret", "usr_1")

	rotated := wire(auth.WithSecret(cur, old))
	if got, err := rotated.ring.Open(t.Context(), sealed, "usr_1"); err != nil || string(got) != "totp-secret" {
		t.Fatalf("after rotation the old enrolment must open: %q %v", got, err)
	}
	// One key per secret: a value sealed under the current secret alone
	// opens too.
	if _, err := rotated.ring.Open(t.Context(), mustSeal(t, wire(auth.WithSecret(cur)).ring, "y", "usr_1"), "usr_1"); err != nil {
		t.Fatalf("ring must hold the current secret's key too: %v", err)
	}
	dropped := wire(auth.WithSecret(cur))
	if _, err := dropped.ring.Open(t.Context(), sealed, "usr_1"); err == nil {
		t.Fatal("with the old secret dropped the old enrolment must not open")
	}
	// The derived key is bound to the plugin's label: the stateless session
	// key from the same secret does not open it.
	cfg := wire(auth.WithSecret(old)).core.Config()
	other, err := cfg.DeriveKey(auth.KeyLabelStatelessSessions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Open(other, sealed, "usr_1"); err == nil {
		t.Fatal("another label's key opened a two-factor secret")
	}
}

func TestNew_ExplicitKeyWinsOverTheSecret(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), auth.MinSecretSize)
	key := bytes.Repeat([]byte("k"), auth.SealKeySize)
	p := New(WithEncryptionKey(key))
	if _, err := auth.New(auth.WithSecret(secret), auth.WithPlugins(signIn{}, p)); err != nil {
		t.Fatal(err)
	}
	sealed := mustSeal(t, p.ring, "x", "u")
	if got, err := auth.Open(key, sealed, "u"); err != nil || string(got) != "x" {
		t.Fatalf("the explicit key must seal: %q %v", got, err)
	}
	// The explicit key only: the key derived from the secret opens nothing.
	derived, err := p.core.Config().DeriveKey(auth.KeyLabelTwoFactor)
	if err != nil {
		t.Fatal(err)
	}
	fromSecret, err := auth.Seal(derived, []byte("x"), "u")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ring.Open(t.Context(), fromSecret, "u"); err == nil {
		t.Fatal("the ring must hold the explicit key only")
	}
	// A short explicit key is still refused even with a secret present.
	if _, err := auth.New(auth.WithSecret(secret), auth.WithPlugins(signIn{}, New(WithEncryptionKey([]byte("short"))))); !errors.Is(err, ErrNoEncryptionKey) {
		t.Fatalf("short key with a secret: %v", err)
	}
}

// mustSeal seals plain under aad with s, failing the test on an error.
func mustSeal(t *testing.T, s auth.Sealer, plain, aad string) string {
	t.Helper()
	sealed, err := s.Seal(t.Context(), []byte(plain), aad)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}
