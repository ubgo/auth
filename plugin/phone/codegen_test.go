package phone_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
)

// TestGenerateCode_RefusedBesideVerifier: with a Verifier the provider makes
// the code, so a generator would silently never run; New refuses the pair.
func TestGenerateCode_RefusedBesideVerifier(t *testing.T) {
	gen := phone.GenerateCode(func(context.Context, phone.CodeFor) (string, error) { return "1", nil })
	p := phone.New(phone.WithSMS(noSMS), phone.WithVerifier(nopVerifier{}), gen)
	if _, err := auth.New(auth.WithPlugins(signIn{}, p)); !errors.Is(err, phone.ErrGenerateWithVerifier) {
		t.Fatalf("GenerateCode with a Verifier: %v", err)
	}
	if _, err := auth.New(auth.WithPlugins(signIn{}, phone.New(phone.WithSMS(noSMS), gen))); err != nil {
		t.Fatalf("GenerateCode alone: %v", err)
	}
}
