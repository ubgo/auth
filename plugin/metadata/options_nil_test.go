package metadata_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/metadata"
)

// TestOptions_RefuseNil: every option that takes a func or an interface
// refuses nil with auth.ErrNilOption naming it. TestGuard_OptionsRefuseNil in
// the core module fails when such an option is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]metadata.Option{
		"metadata.WithAdmin":       metadata.WithAdmin(nil),
		"metadata.WithUnsafeCheck": metadata.WithUnsafeCheck(nil),
	} {
		err := metadata.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v", name, err)
		}
	}
}
