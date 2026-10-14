package stale_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/stale"
)

// TestOptions_RefuseNil: the one stale option that takes a func refuses nil
// with auth.ErrNilOption naming it, and the plugin's OptionErr, which
// auth.New checks before anything else, reports it, instead of the first run
// that calls the nil value panicking. TestGuard_OptionsRefuseNil in the core
// module fails when an option that takes a func is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]stale.Option{
		"stale.Exempt": stale.Exempt(nil),
	} {
		err := stale.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
