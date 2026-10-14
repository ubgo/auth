package oauthprovider

import (
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// RegistrationSecretExpiresAt is judged against the app's clock, so an app
// that freezes time with auth.WithClock gets the same answer as production.
func TestRegistrationSecretExpiresAt_UsesAppClock(t *testing.T) {
	frozen := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	try := func(at time.Time, opts ...auth.Option) error {
		j := newSigner(testIssuer)
		p := New(j, Issuer(testIssuer), LoginPage("/login"), RegistrationSecretExpiresAt(at))
		_, err := auth.New(append([]auth.Option{auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), j, p)}, opts...)...)
		return err
	}
	// Past for the wall clock, future for the frozen one: accepted.
	if err := try(frozen.Add(time.Hour), auth.WithClock(func() time.Time { return frozen })); err != nil {
		t.Fatalf("future instant on the app clock refused: %v", err)
	}
	// Past for the frozen clock: refused.
	if err := try(frozen.Add(-time.Hour), auth.WithClock(func() time.Time { return frozen })); !errors.Is(err, ErrBadTTL) {
		t.Fatalf("past instant on the app clock: %v, want ErrBadTTL", err)
	}
	// The exact instant is not after now: refused, as before.
	if err := try(frozen, auth.WithClock(func() time.Time { return frozen })); !errors.Is(err, ErrBadTTL) {
		t.Fatalf("instant equal to now: %v, want ErrBadTTL", err)
	}
	// Default clock unchanged.
	if err := try(time.Now().Add(-time.Minute)); !errors.Is(err, ErrBadTTL) {
		t.Fatalf("past instant on the default clock: %v, want ErrBadTTL", err)
	}
	if err := try(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("future instant on the default clock: %v", err)
	}
}
