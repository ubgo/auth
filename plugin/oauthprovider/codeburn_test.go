package oauthprovider

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ubgo/auth"
)

// A refused exchange answers exactly as the refusal would (invalid_grant,
// 400, the same message) while the code's burn has not failed; once it
// fails, the caller sees that failure instead, as a server error.
func TestCodeRefusal_ShapeAndBurnFailure(t *testing.T) {
	e := &codeRefusal{refusal: ErrInvalidGrant}
	if !errors.Is(e, ErrInvalidGrant) || e.Error() != ErrInvalidGrant.Error() || rfcCode(e) != rfcCode(ErrInvalidGrant) || auth.ErrorOf(e) != auth.ErrorOf(ErrInvalidGrant) {
		t.Fatalf("refusal = %v (%s), want invalid_grant unchanged", e, rfcCode(e))
	}
	down := errors.New("database down")
	e.burn = down
	if !errors.Is(e, down) || errors.Is(e, ErrInvalidGrant) || e.Error() != down.Error() || auth.ErrorOf(e).Status != http.StatusInternalServerError {
		t.Fatalf("after a failed burn = %v (status %d), want the database error", e, auth.ErrorOf(e).Status)
	}
}
