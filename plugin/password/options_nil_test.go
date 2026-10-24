package password_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
)

// TestOptions_RefuseNil: every password option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and the
// plugin's OptionErr, which auth.New checks before anything else, reports
// it, instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]password.Option{
		"password.AcceptLegacyHashes": password.AcceptLegacyHashes(nil),
		"password.CheckBreached":      password.CheckBreached(nil),
		"password.Policy":             password.Policy(nil),
		"password.ResetLinks":         password.ResetLinks(nil),
		"password.WithHasher":         password.WithHasher(nil),
	} {
		err := password.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
