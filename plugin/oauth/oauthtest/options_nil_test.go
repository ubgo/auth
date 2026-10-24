package oauthtest

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// TestOptions_RefuseNil: every oauthtest option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and Run
// fails the test with it (newConfig) before starting a server.
// TestGuard_OptionsRefuseNil in the core module fails when such an option is
// missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]Option{
		"oauthtest.Route": Route("/x", nil),
	} {
		if _, err := newConfig([]Option{opt}); !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
