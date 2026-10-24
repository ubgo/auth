package ldap_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/ldap"
)

// TestOptions_RefuseNil: every ldap option that takes a func or an interface
// refuses nil with auth.ErrNilOption naming the option, so auth.New fails at
// start-up instead of the first sign-in panicking. TestGuard_OptionsRefuseNil
// in the core module fails when such an option is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]ldap.Option{
		"ldap.WithDirectory": ldap.WithDirectory(nil),
		"ldap.MapProfile":    ldap.MapProfile(nil),
	} {
		err := ldap.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
