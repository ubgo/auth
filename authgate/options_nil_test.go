package authgate_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authgate"
)

// TestOptions_RefuseNil: every authgate option that takes a func or an
// interface refuses nil, and New returns auth.ErrNilOption naming the
// option instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when such an option is
// missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]authgate.Option{
		"authgate.Allow":         authgate.Allow(nil),
		"authgate.ErrorHandler":  authgate.ErrorHandler(nil),
		"authgate.WithClock":     authgate.WithClock(nil),
		"authgate.WithProviders": authgate.WithProviders(nil),
	} {
		if _, err := authgate.New(opt); !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): New = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
