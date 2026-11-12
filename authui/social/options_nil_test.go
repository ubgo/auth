package social

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

// TestOptions_RefuseNil: every option that takes a func or an interface
// refuses nil, and New returns auth.ErrNilOption naming it instead of
// panicking at the first request: "social.Texts", "social.Templates" and
// "social.HTTPOptions" (any nil entry). TestGuard_OptionsRefuseNil in the
// core module requires each name here.
func TestOptions_RefuseNil(t *testing.T) {
	f := newFixture(t, nil)
	for name, opt := range map[string]Option{
		"social.Texts":       Texts(nil),
		"social.Templates":   Templates(nil),
		"social.HTTPOptions": HTTPOptions(authhttp.TrustedProxies("10.0.0.0/8"), authhttp.Option(nil)),
	} {
		_, err := New(f.a, f.op, opt)
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s(nil): %v", name, err)
		}
	}
}
