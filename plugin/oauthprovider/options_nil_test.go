package oauthprovider_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// TestOptions_RefuseNil: every oauthprovider option that takes a func or an
// interface refuses nil with auth.ErrNilOption naming the option, and the
// plugin's OptionErr, which auth.New checks before anything else, reports
// it, instead of the first request that calls the nil value panicking.
// TestGuard_OptionsRefuseNil in the core module fails when an option that
// takes a func or an interface is missing from this table.
func TestOptions_RefuseNil(t *testing.T) {
	for name, opt := range map[string]oauthprovider.Option{
		"oauthprovider.AccessTokenClaims":          oauthprovider.AccessTokenClaims(nil),
		"oauthprovider.CIMDAllow":                  oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDAllow(nil)),
		"oauthprovider.CIMDFetch":                  oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDFetch(nil)),
		"oauthprovider.CIMDOnClientCreated":        oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDOnClientCreated(nil)),
		"oauthprovider.CIMDOnClientRefreshed":      oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDOnClientRefreshed(nil)),
		"oauthprovider.CIMDTransport":              oauthprovider.ClientIDMetadataDocuments(oauthprovider.CIMDTransport(nil)),
		"oauthprovider.Claims":                     oauthprovider.Claims(nil),
		"oauthprovider.ClientIDMetadataDocuments":  oauthprovider.ClientIDMetadataDocuments(nil),
		"oauthprovider.ClientJWKSFetch":            oauthprovider.ClientJWKSFetch(nil),
		"oauthprovider.ClientPrivileges":           oauthprovider.ClientPrivileges(nil),
		"oauthprovider.CacheResourcesIn":           oauthprovider.CacheResourcesIn(nil, 0),
		"oauthprovider.ClientReference":            oauthprovider.ClientReference(nil),
		"oauthprovider.GenerateAccessToken":        oauthprovider.GenerateAccessToken(nil),
		"oauthprovider.GenerateClientID":           oauthprovider.GenerateClientID(nil),
		"oauthprovider.GenerateClientSecret":       oauthprovider.GenerateClientSecret(nil),
		"oauthprovider.GenerateRefreshToken":       oauthprovider.GenerateRefreshToken(nil),
		"oauthprovider.HashStoredSecrets":          oauthprovider.HashStoredSecrets(nil),
		"oauthprovider.IdentifierValidator":        oauthprovider.IdentifierValidator(nil),
		"oauthprovider.RequestURIResolver":         oauthprovider.RequestURIResolver(nil),
		"oauthprovider.SignupRedirect":             oauthprovider.SignupRedirect(nil),
		"oauthprovider.TokenResponseFields":        oauthprovider.TokenResponseFields(nil),
		"oauthprovider.ValidateInitialAccessToken": oauthprovider.ValidateInitialAccessToken(nil),
		"oauthprovider.ValidateRedirectURI":        oauthprovider.ValidateRedirectURI(nil),
	} {
		err := oauthprovider.New(nil, opt).OptionErr()
		if !errors.Is(err, auth.ErrNilOption) || !strings.Contains(err.Error(), name+"(nil)") {
			t.Errorf("%s(nil): OptionErr = %v, want auth.ErrNilOption naming it", name, err)
		}
	}
}
