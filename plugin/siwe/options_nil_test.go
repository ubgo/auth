package siwe_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/siwe"
)

// TestOptions_RefuseNil: every siwe option that takes a func or an interface
// refuses nil with auth.ErrNilOption naming the option, so auth.New fails at
// start-up instead of the first verify panicking. TestGuard_OptionsRefuseNil
// in the core module fails when such an option is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]siwe.Option{
		"siwe.WithVerifier":     siwe.WithVerifier(nil),
		"siwe.WithNameResolver": siwe.WithNameResolver(nil),
	} {
		err := siwe.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
