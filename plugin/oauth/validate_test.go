package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// customProvider is a Provider of the app's own type, which ValidateProvider
// checks by name only.
type customProvider struct{ name string }

func (c customProvider) Name() string                            { return c.name }
func (customProvider) AuthCodeURL(string, string, string) string { return "" }
func (customProvider) Exchange(context.Context, *http.Client, string, string, string) (Profile, error) {
	return Profile{}, nil
}

// TestValidateProvider: the check exported for a flow that runs providers
// without the plugin refuses exactly what the plugin's Validate refuses.
func TestValidateProvider(t *testing.T) {
	if err := ValidateProvider(Google("id", "secret")); err != nil {
		t.Fatalf("Google: %v", err)
	}
	if err := ValidateProvider(OIDC("corp", "https://id.example.com", "id", "secret")); err != nil {
		t.Fatalf("OIDC: %v", err)
	}
	if err := ValidateProvider(customProvider{name: "mine"}); err != nil {
		t.Fatalf("custom: %v", err)
	}
	if err := ValidateProvider(customProvider{name: "Bad Name"}); err == nil || !strings.Contains(err.Error(), "must match") {
		t.Fatalf("bad name: %v", err)
	}
	if err := ValidateProvider(&OAuth2{ID: "half"}); !errors.Is(err, ErrProviderIncomplete) {
		t.Fatalf("incomplete OAuth2: %v", err)
	}
	broken := OIDC("corp", "https://id.example.com", "id", "secret")
	broken.IDToken.JWKSURL = "https://id.example.com/jwks"
	if err := ValidateProvider(broken); !errors.Is(err, ErrIDTokenConfig) {
		t.Fatalf("OIDC with a JWKS URL and no issuers: %v", err)
	}
}
