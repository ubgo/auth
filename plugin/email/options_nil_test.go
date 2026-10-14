package email_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

// TestOptions_RefuseNil: every email option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and the
// plugin's OptionErr, which auth.New checks before anything else, reports
// it, instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]email.Option{
		"email.CheckAddresses": email.CheckAddresses(nil),
		"email.GenerateCode":   email.GenerateCode(nil),
		"email.Links":          email.Links(nil),
		"email.Templates":      email.Templates(nil),
		"email.WithMailer":     email.WithMailer(nil),
		"email.WithNormalizer": email.WithNormalizer(nil),
	} {
		err := email.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
