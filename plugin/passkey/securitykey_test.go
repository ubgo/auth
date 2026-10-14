package passkey

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/twofactor"
)

// TestSecurityKeys_NotWiredUntilInit: a store taken from a plugin auth.New
// never initialised answers ErrOperationNotWired from every method, instead
// of a nil-pointer panic at the first sign-in.
func TestSecurityKeys_NotWiredUntilInit(t *testing.T) {
	s := New().SecurityKeys()
	ctx := context.Background()
	_, e1 := s.BeginSecurityKeyRegistration(ctx, auth.User{ID: "usr_1"}, "")
	_, e2 := s.FinishSecurityKeyRegistration(ctx, "usr_1", twofactor.SecurityKeyRegistration{})
	_, e3 := s.BeginSecurityKeyAssertion(ctx, "usr_1")
	e4 := s.FinishSecurityKeyAssertion(ctx, "usr_1", twofactor.SecurityKeyResponse{})
	_, e5 := s.SecurityKeys(ctx, "usr_1")
	e6 := s.RemoveSecurityKey(ctx, "usr_1", "pks_1")
	e7 := s.RemoveSecurityKeys(ctx, "usr_1")
	for i, err := range []error{e1, e2, e3, e4, e5, e6, e7} {
		if !errors.Is(err, auth.ErrOperationNotWired) {
			t.Errorf("method %d: %v, want ErrOperationNotWired", i+1, err)
		}
	}
}
