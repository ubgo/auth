package passkey

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestPresence_WithoutADatabaseIsAnError: each presence call reads the
// passkey table, so a core without a database reports the failure rather
// than a user with no passkeys.
func TestPresence_WithoutADatabaseIsAnError(t *testing.T) {
	p := New()
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if ok, err := p.PresenceEnrolled(ctx, "u1"); err == nil || ok {
		t.Fatalf("enrolled: %v %v", ok, err)
	}
	if _, _, err := p.BeginPresence(ctx, "u1", "scope"); err == nil {
		t.Fatal("begin: want an error")
	}
	if err := p.VerifyPresence(ctx, "u1", "scope", "", nil); err == nil || errors.Is(err, ErrPasskeyInvalid) {
		t.Fatalf("verify: %v", err)
	}
}
