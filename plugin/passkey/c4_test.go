package passkey

import (
	"errors"
	"math"
	"testing"

	"github.com/ubgo/auth"
)

// TestValidate_RefusesExtensionsJSONCannotHold: an extension value JSON
// cannot encode would fail every ceremony, so start-up fails instead;
// JSON values pass.
func TestValidate_RefusesExtensionsJSONCannotHold(t *testing.T) {
	for name, opt := range map[string]Option{
		"registration":   RegistrationExtensions(Extensions{"x": math.NaN()}),
		"authentication": AuthenticationExtensions(Extensions{"x": make(chan int)}),
	} {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(New(opt)))
		if !errors.Is(err, ErrExtensionsInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := New(RegistrationExtensions(Extensions{"credProps": true}), AuthenticationExtensions(Extensions{"largeBlob": map[string]any{"read": true}}))
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(ok)); err != nil {
		t.Fatalf("JSON extensions: %v", err)
	}
}

// TestX5CChain_RefusesMalformedStatements: no certificate, a certificate
// that is not bytes, and bytes that are not a certificate are each refused.
func TestX5CChain_RefusesMalformedStatements(t *testing.T) {
	for name, stmt := range map[string]map[string]any{
		"none":       {},
		"empty":      {attStmtX5C: []any{}},
		"not bytes":  {attStmtX5C: []any{"cert"}},
		"not a cert": {attStmtX5C: []any{[]byte("garbage")}},
	} {
		if chain, err := x5cChain(stmt); err == nil {
			t.Errorf("%s: chain of %d", name, len(chain))
		}
	}
}
