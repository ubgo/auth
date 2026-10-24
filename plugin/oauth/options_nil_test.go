package oauth_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// TestOptions_RefuseNil: every oauth option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and the
// plugin's OptionErr, which auth.New checks before anything else, reports
// it, instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]oauth.Option{
		"oauth.CallbackURL":       oauth.CallbackURL(nil),
		"oauth.OnResolved":        oauth.OnResolved(nil),
		"oauth.PostLogoutURL":     oauth.PostLogoutURL(nil),
		"oauth.StoreTokensWith":   oauth.StoreTokensWith(nil),
		"oauth.ValidateProfile":   oauth.ValidateProfile(nil),
		"oauth.WithProviders":     oauth.WithProviders(nil),
		"oauth.WithServerContext": oauth.WithServerContext(nil),
		// A nil guard is refused; turning the check off is
		// AllowIDTokenReplay.
		"oauth.WithIDTokenReplayGuard": oauth.WithIDTokenReplayGuard(nil),
	} {
		err := oauth.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
