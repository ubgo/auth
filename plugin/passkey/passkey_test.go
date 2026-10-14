package passkey_test

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/passkey"
)

func TestRelyingParty_OriginsFallBackAndAreRequired(t *testing.T) {
	// An id without origins borrows the BaseURL origin.
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(passkey.New(passkey.RelyingParty("example.com")))); err != nil {
		t.Fatalf("id without origins: %v", err)
	}
	// Neither a BaseURL nor origins: a clear error, not the library's.
	_, err := auth.New(auth.WithPlugins(passkey.New(passkey.RelyingParty("example.com"))))
	if !errors.Is(err, passkey.ErrNoRelyingParty) {
		t.Fatalf("no origins at all: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(passkey.New())); !errors.Is(err, passkey.ErrNoRelyingParty) {
		t.Fatalf("no relying party: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(passkey.New(passkey.RelyingParty("example.com", "https://example.com")))); err != nil {
		t.Fatalf("explicit id and origin: %v", err)
	}
}
