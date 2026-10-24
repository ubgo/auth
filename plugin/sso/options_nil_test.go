package sso_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/sso"
)

// TestOptions_RefuseNil: every sso option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and the
// plugin's OptionErr, which auth.New checks before anything else, reports
// it, instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]sso.Option{
		"sso.WithMutationGuard":      sso.WithMutationGuard(nil),
		"sso.WithOrganizations":      sso.WithOrganizations(nil, sso.OrganizationProvisioning{}),
		"sso.WithPrivateKeyResolver": sso.WithPrivateKeyResolver(nil),
		"sso.WithProvidersLimit":     sso.WithProvidersLimit(nil),
		"sso.WithProvisionUser":      sso.WithProvisionUser(nil),
		"sso.WithResolveUser":        sso.WithResolveUser(nil),
		"sso.WithSAMLEngine":         sso.WithSAMLEngine(nil),
	} {
		err := sso.New(opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
