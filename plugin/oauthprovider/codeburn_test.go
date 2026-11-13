package oauthprovider

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ubgo/auth"
)

// A refused grant answers exactly as the refusal would (invalid_grant,
// 400, the same message) while the burn of its code or refresh token has not failed; once it
// fails, the caller sees that failure instead, as a server error.
func TestGrantRefusal_ShapeAndBurnFailure(t *testing.T) {
	e := &grantRefusal{refusal: ErrInvalidGrant}
	if !errors.Is(e, ErrInvalidGrant) || e.Error() != ErrInvalidGrant.Error() || rfcCode(e) != rfcCode(ErrInvalidGrant) || auth.ErrorOf(e) != auth.ErrorOf(ErrInvalidGrant) {
		t.Fatalf("refusal = %v (%s), want invalid_grant unchanged", e, rfcCode(e))
	}
	down := errors.New("database down")
	e.burn = down
	if !errors.Is(e, down) || errors.Is(e, ErrInvalidGrant) || e.Error() != down.Error() || auth.ErrorOf(e).Status != http.StatusInternalServerError {
		t.Fatalf("after a failed burn = %v (status %d), want the database error", e, auth.ErrorOf(e).Status)
	}
}

// A proof of another key is invalid_dpop_proof to every caller and on the
// wire, and only it is told apart: a missing, stale or replayed proof is
// not, although errors.Is matches every invalid_dpop_proof by its code.
func TestDPoPOtherKey_ShapeAndMatch(t *testing.T) {
	var err error = dpopOtherKey{}
	if !errors.Is(err, ErrInvalidDPoPProof) || err.Error() != ErrInvalidDPoPProof.Error() || rfcCode(err) != rfcCode(ErrInvalidDPoPProof) || auth.ErrorOf(err) != auth.ErrorOf(ErrInvalidDPoPProof) {
		t.Fatalf("other key = %v (%s), want invalid_dpop_proof unchanged", err, rfcCode(err))
	}
	if !isDPoPOtherKey(err) || !isDPoPOtherKey(&grantRefusal{refusal: err}) {
		t.Fatal("a proof of another key is not told apart")
	}
	if isDPoPOtherKey(ErrInvalidDPoPProof) || isDPoPOtherKey(ErrInvalidGrant) || isDPoPOtherKey(nil) {
		t.Fatal("a plain invalid_dpop_proof was taken for a proof of another key")
	}
}
