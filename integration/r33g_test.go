package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/oauthprovider"
)

// better-auth's client rules: the client_credentials ceiling, web and
// native redirect URIs, secret expiry, and the dynamic-registration policy.
func TestOAuthProvider_ClientPolicy(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "offline_access", "api:read", "api:write"),
			oauthprovider.AllowUnauthenticatedRegistration(), oauthprovider.RegistrationRequirePKCE(false), oauthprovider.RegistrationSecretExpiration(time.Hour))
		ctx := context.Background()
		cc := func(reg oauthprovider.Registration, scope string) (oauthprovider.TokenResponse, error) {
			return o.op.Token(anon(o.a), oauthprovider.TokenRequest{GrantType: "client_credentials", Scope: scope, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic})
		}
		noCeiling := o.client(t, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}, Scope: "api:read"}})
		if _, err := cc(noCeiling, "api:read"); !errors.Is(err, oauthprovider.ErrUnauthorizedClient) {
			t.Fatalf("no ceiling: %v", err)
		}
		m2m := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read", "api:write"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}}})
		if tok, err := cc(m2m, ""); err != nil || tok.Scope != "api:read api:write" {
			t.Fatalf("omitted scope = %+v %v", tok, err)
		}
		if _, err := o.op.CreateClient(ctx, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"openid"}, ClientMetadata: oauthprovider.ClientMetadata{Name: "x", GrantTypes: []string{"client_credentials"}}}); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("user scope in a ceiling: %v", err)
		}
		narrow := o.client(t, oauthprovider.ClientSpec{ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}}})
		if _, err := cc(narrow, "api:write"); !errors.Is(err, oauthprovider.ErrInvalidScope) {
			t.Fatalf("scope above the ceiling: %v", err)
		}
		// Web and native redirect URIs.
		for _, c := range []struct {
			app, uri string
			ok       bool
		}{
			{"", "http://127.0.0.1/cb", false}, {"web", "https://localhost/cb", false}, {"web", "com.example.app:/cb", false},
			{"native", "http://127.0.0.1:9/cb", true}, {"native", "http://[::1]/cb", true}, {"native", "http://127.0.0.2/cb", false},
			{"native", "https://127.0.0.1/cb", false}, {"native", "com.example.app:/cb", true}, {"native", "https://app.example.com/cb", true},
			{"desktop", "https://app.example.com/cb", false},
		} {
			_, err := o.op.CreateClient(ctx, oauthprovider.ClientSpec{ClientMetadata: oauthprovider.ClientMetadata{Name: "x", ApplicationType: c.app, RedirectURIs: []string{c.uri}}})
			if (err == nil) != c.ok {
				t.Fatalf("%s %s: %v", c.app, c.uri, err)
			}
		}
		// Secret expiry: an expired secret authenticates nothing.
		soon := e.clock.Now().Add(time.Minute)
		exp := o.client(t, oauthprovider.ClientSpec{SecretExpiresAt: &soon, ClientCredentialsScopes: []string{"api:read"}, ClientMetadata: oauthprovider.ClientMetadata{GrantTypes: []string{"client_credentials"}}})
		if exp.ClientSecretExpiresAt != soon.Unix() {
			t.Fatalf("client_secret_expires_at = %d", exp.ClientSecretExpiresAt)
		}
		if _, err := cc(exp, ""); err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(2 * time.Minute)
		if _, err := cc(exp, ""); !errors.Is(err, oauthprovider.ErrInvalidClient) {
			t.Fatalf("expired secret: %v", err)
		}
		// Dynamic registration: confidential clients get the secret lifetime
		// and, with RegistrationRequirePKCE(false), optional PKCE.
		dyn := must[oauthprovider.Registration](t)(o.op.Register(anon(o.a), oauthprovider.ClientMetadata{Name: "D", RedirectURIs: []string{opRedirect}}))
		if dyn.ClientSecretExpiresAt == 0 || dyn.RequirePKCE {
			t.Fatalf("dynamic client = %+v", dyn)
		}
		pub := must[oauthprovider.Registration](t)(o.op.Register(anon(o.a), oauthprovider.ClientMetadata{Name: "P", RedirectURIs: []string{opRedirect}, AuthMethod: oauthprovider.AuthMethodNone}))
		if !pub.RequirePKCE || pub.ClientSecretExpiresAt != 0 {
			t.Fatalf("dynamic public client = %+v", pub)
		}
		// Reference and metadata are kept.
		ref := o.client(t, oauthprovider.ClientSpec{ReferenceID: "org_1", Metadata: json.RawMessage(`{"team":"x"}`)})
		got := must[oauthprovider.Client](t)(o.op.Client(ctx, ref.ClientID))
		if got.ReferenceID != "org_1" || string(got.Metadata) != `{"team":"x"}` {
			t.Fatalf("reference and metadata = %+v", got)
		}
	})
}
