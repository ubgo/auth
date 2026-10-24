package apikey_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/apikey"
)

// TestOptions_RefuseNil: every apikey option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and the
// plugin's OptionErr, which auth.New checks before anything else, reports
// it, instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]apikey.Option{
		"apikey.Configuration":          apikey.Configuration("", nil),
		"apikey.DefaultPermissionsFunc": apikey.DefaultPermissionsFunc(nil),
		"apikey.DefaultScopesFunc":      apikey.DefaultScopesFunc(nil),
		"apikey.Generate":               apikey.Generate(nil),
		"apikey.PreCheck":               apikey.PreCheck(nil),
		"apikey.WithCache":              apikey.WithCache(nil, 0),
		"apikey.WithOrganizations":      apikey.WithOrganizations(nil),
	} {
		err := apikey.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}

// TestOptions_WithPermissionsNilTurnsThemOff: "apikey.WithPermissions" is
// the one apikey option that accepts nil, which turns permissions off (the
// default), so OptionErr stays nil. TestGuard_OptionsRefuseNil lists it in
// nilKeepsDefault.
func TestOptions_WithPermissionsNilTurnsThemOff(t *testing.T) {
	if err := apikey.New(apikey.WithPermissions(nil)).OptionErr(); err != nil {
		t.Fatalf("WithPermissions(nil): OptionErr = %v", err)
	}
}
