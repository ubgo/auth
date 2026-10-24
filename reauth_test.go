package auth

import (
	"context"
	"testing"
	"time"
)

// FreshAt is the later of the creation and the last re-authentication, so a
// re-authentication recorded before the creation (a clock step, a copied
// row) never makes a session look older than it is.
func TestSession_FreshAtIsTheLaterProof(t *testing.T) {
	created := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	later, earlier := created.Add(time.Hour), created.Add(-time.Hour)
	for name, tc := range map[string]struct {
		reauth *time.Time
		want   time.Time
	}{
		"never re-authenticated": {nil, created},
		"re-authenticated later": {&later, later},
		"a time before creation": {&earlier, created},
	} {
		if got := (Session{CreatedAt: created, ReauthenticatedAt: tc.reauth}).FreshAt(); !got.Equal(tc.want) {
			t.Errorf("%s: FreshAt = %v, want %v", name, got, tc.want)
		}
	}
}

// UserRateKey counts per signed-in user and leaves a signed-out call
// uncounted, which is what its paired ByIP rule is for.
func TestUserRateKey_CountsTheSignedInUser(t *testing.T) {
	if k, err := UserRateKey(context.Background(), &Call{}); k != "" || err != nil {
		t.Fatalf("signed out = %q, %v; want uncounted", k, err)
	}
	if k, err := UserRateKey(context.Background(), &Call{User: &User{ID: "usr_1"}}); k != "usr_1" || err != nil {
		t.Fatalf("signed in = %q, %v", k, err)
	}
}
