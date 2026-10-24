package twofactor_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/twofactor"
)

// TestResetAndUnlock_NeedThePluginWired: before auth.New has initialised the
// plugin there is no database to write, and Reset, Unlock and the admin
// methods say so rather than panicking. Their behaviour on a database is in integration/r23_test.go.
func TestResetAndUnlock_NeedThePluginWired(t *testing.T) {
	p := twofactor.New()
	if err := p.Reset(context.Background(), "u1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Reset = %v", err)
	}
	if err := p.Unlock(context.Background(), "u1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("Unlock = %v", err)
	}
	if _, _, err := p.FactorOf(context.Background(), "u1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("FactorOf = %v", err)
	}
	if err := p.DisableFor(context.Background(), "u1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("DisableFor = %v", err)
	}
	if err := p.EnableFor(context.Background(), "u1"); !errors.Is(err, auth.ErrOperationNotWired) {
		t.Fatalf("EnableFor = %v", err)
	}
}
