package samlidp_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/samlidp"
)

// TestOptions_RefuseNil: every samlidp option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and the
// plugin's OptionErr, which auth.New checks before anything else, reports
// it, instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	key, cert := keyPair(t, "idp", time.Now())
	for name, opt := range map[string]samlidp.Option{
		"samlidp.Access":                   samlidp.Access(nil),
		"samlidp.SigningKey":               samlidp.SigningKey(nil, cert),
		"samlidp.WithRequestIDGuard":       samlidp.WithRequestIDGuard(nil),
		"samlidp.WithServiceProviderStore": samlidp.WithServiceProviderStore(nil),
	} {
		err := samlidp.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
	// A nil certificate beside a key is refused the same way.
	if err := samlidp.New(samlidp.SigningKey(key, nil)).OptionErr(); !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), "samlidp.SigningKey(nil)") {
		t.Errorf("SigningKey(key, nil): OptionErr = %v", err)
	}
}
