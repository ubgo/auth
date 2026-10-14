package sessiontest

import (
	"context"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// RunRevocations checks the SessionRevocations that open returns against
// the contract every revocation list must keep. open is called once per
// case, so every case starts empty; a list on a shared server returns one
// with a fresh key prefix. The core's memory list and contrib/redis run it.
//
// The rules: a revoked id is reported revoked until its instant and never
// at or after it, judged by the time the core passes, not a clock of the
// list's own; an id never revoked is not; revoking one id leaves every
// other alone; revoking again with a later instant extends the entry and
// with an earlier one never shortens it.
func RunRevocations(t *testing.T, open func(t *testing.T) auth.SessionRevocations) {
	t.Helper()
	for name, c := range revocationCases {
		t.Run(name, func(t *testing.T) { c(t, open(t)) })
	}
}

// revokedUntil is the instant the cases' entries stop mattering.
var revokedUntil = now.Add(time.Hour)

// revoked asserts what Revoked answers for id at at.
func revoked(t T, r auth.SessionRevocations, id string, at time.Time, want bool, why string) {
	got, err := r.Revoked(context.Background(), id, at)
	if err != nil {
		t.Fatalf("%s: Revoked: %v", why, err)
	}
	if got != want {
		t.Fatalf("%s: Revoked = %v, want %v", why, got, want)
	}
}

// revoke revokes id until until or fails the case.
func revoke(t T, r auth.SessionRevocations, id string, until time.Time) {
	if err := r.Revoke(context.Background(), id, until); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

// revocationCases is every revocation contract, by name.
var revocationCases = map[string]func(t T, r auth.SessionRevocations){
	"a revoked id is revoked and another is not": func(t T, r auth.SessionRevocations) {
		revoked(t, r, "ses_a", now, false, "before any revoke")
		revoke(t, r, "ses_a", revokedUntil)
		revoked(t, r, "ses_a", now, true, "after the revoke")
		revoked(t, r, "ses_b", now, false, "another id")
	},
	"an entry counts until its instant and never at or after it": func(t T, r auth.SessionRevocations) {
		revoke(t, r, "ses_a", revokedUntil)
		revoked(t, r, "ses_a", revokedUntil.Add(-time.Second), true, "a second before the instant")
		revoked(t, r, "ses_a", revokedUntil, false, "at the instant")
		revoked(t, r, "ses_a", revokedUntil.Add(time.Hour), false, "after the instant")
	},
	"a later revoke extends an entry and an earlier one never shortens it": func(t T, r auth.SessionRevocations) {
		revoke(t, r, "ses_a", revokedUntil)
		revoke(t, r, "ses_a", revokedUntil.Add(time.Hour))
		revoked(t, r, "ses_a", revokedUntil.Add(30*time.Minute), true, "after extending")
		revoke(t, r, "ses_a", now.Add(time.Minute))
		revoked(t, r, "ses_a", revokedUntil.Add(30*time.Minute), true, "after an earlier revoke")
	},
}
