package webhook_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/webhook"
)

// TestOptions_RefuseNil: every webhook option that takes an interface refuses
// nil with auth.ErrNilOption naming it, and OptionErr, which auth.New checks
// before anything else, reports it. TestGuard_OptionsRefuseNil in the core
// module fails when such an option is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]webhook.Option{
		"webhook.WithSealer": webhook.WithSealer(nil),
	} {
		err := webhook.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
