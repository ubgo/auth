package integration

import (
	"crypto"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/oauthprovider"
)

// A resource server in another process: ResourceGuard verifies JWT access
// tokens offline and opaque ones by introspection, checks scopes (with a
// custom matcher), and answers the MCP challenges.
func TestOAuthProvider_ResourceGuard(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const mcpURL = "https://mcp.example.com/mcp"
		o := newOPEnv(t, e, oauthprovider.Scopes("openid", "offline_access", "mcp:tools", "mcp:admin"), oauthprovider.ProtectedResource(mcpURL), oauthprovider.RegistrationDefaultResources(mcpURL))
		reg := o.client(t, oauthprovider.ClientSpec{SkipConsent: true})
		in := authzReq(reg.ClientID)
		in.Scope, in.Resource = "mcp:tools", mcpURL
		jwtTok := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		in.Resource = ""
		opaque := must[oauthprovider.TokenResponse](t)(o.op.Token(anon(o.a), exchange(reg, o.code(t, in), opVerifier)))
		keys := jwt.KeysFromJWKS(o.jw.PublicKeys())
		provider := httptest.NewServer(o.op.Handler())
		t.Cleanup(provider.Close)
		rs := o.client(t, oauthprovider.ClientSpec{IntrospectAny: true})
		guard := oauthprovider.ResourceGuard{
			Issuer: testBaseURL, Audience: mcpURL, Keys: func(kid string) (crypto.PublicKey, bool) { k, ok := keys[kid]; return k, ok },
			IntrospectURL: provider.URL + "/oauth2/introspect", ClientID: rs.ClientID, ClientSecret: rs.Secret,
			Scopes: []string{"mcp:tools"}, ResourceMetadataURL: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp", Now: e.clock.Now,
		}
		var seen oauthprovider.GuardedToken
		srv := httptest.NewServer(guard.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen, _ = oauthprovider.GuardedTokenFrom(r.Context())
			w.WriteHeader(204)
		})))
		t.Cleanup(srv.Close)
		call := func(url, token string) *http.Response {
			r := must[*http.Request](t)(http.NewRequest(http.MethodPost, url, nil))
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			res := must[*http.Response](t)(http.DefaultClient.Do(r))
			res.Body.Close()
			return res
		}
		if res := call(srv.URL, jwtTok.AccessToken); res.StatusCode != 204 || seen.Subject != o.user.ID || seen.ClientID != reg.ClientID {
			t.Fatalf("JWT through the guard = %d %+v", res.StatusCode, seen)
		}
		// An opaque token issued without a resource names no audience: the
		// guard refuses it unless AllowMissingAudience says such tokens are
		// meant for it.
		if res := call(srv.URL, opaque.AccessToken); res.StatusCode != 401 {
			t.Fatalf("opaque with no audience = %d", res.StatusCode)
		}
		lenient := guard
		lenient.AllowMissingAudience = true
		ls := httptest.NewServer(lenient.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
		t.Cleanup(ls.Close)
		if res := call(ls.URL, opaque.AccessToken); res.StatusCode != 204 {
			t.Fatalf("opaque through introspection = %d", res.StatusCode)
		}
		if res := call(srv.URL, ""); res.StatusCode != 401 || !strings.Contains(res.Header.Get("WWW-Authenticate"), "resource_metadata=") {
			t.Fatalf("no token = %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
		// Another audience, a revoked opaque token, and a missing scope.
		other := guard
		other.Audience = "https://other.example.com"
		os := httptest.NewServer(other.Middleware(http.NotFoundHandler()))
		t.Cleanup(os.Close)
		if res := call(os.URL, jwtTok.AccessToken); res.StatusCode != 401 {
			t.Fatalf("another audience = %d", res.StatusCode)
		}
		// Without keys, a resource token is introspected; its audience must be
		// this resource.
		intro := guard
		intro.Keys, intro.Audience = nil, "https://other.example.com"
		is := httptest.NewServer(intro.Middleware(http.NotFoundHandler()))
		t.Cleanup(is.Close)
		if res := call(is.URL, jwtTok.AccessToken); res.StatusCode != 401 {
			t.Fatalf("introspected token for another audience = %d", res.StatusCode)
		}
		if err := o.op.Revoke(anon(o.a), oauthprovider.RevokeRequest{Token: opaque.AccessToken, ClientID: reg.ClientID, ClientSecret: reg.Secret, ClientAuthMethod: oauthprovider.AuthMethodBasic}); err != nil {
			t.Fatal(err)
		}
		if res := call(srv.URL, opaque.AccessToken); res.StatusCode != 401 {
			t.Fatalf("revoked opaque = %d", res.StatusCode)
		}
		admin := guard
		admin.Scopes = []string{"mcp:admin"}
		as := httptest.NewServer(admin.Middleware(http.NotFoundHandler()))
		t.Cleanup(as.Close)
		if res := call(as.URL, jwtTok.AccessToken); res.StatusCode != 403 || !strings.Contains(res.Header.Get("WWW-Authenticate"), `scope="mcp:admin"`) {
			t.Fatalf("missing scope = %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
		admin.ScopeSatisfied = func(granted []string, required string) bool {
			return strings.HasPrefix(required, "mcp:") && len(granted) > 0
		}
		as2 := httptest.NewServer(admin.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })))
		t.Cleanup(as2.Close)
		if res := call(as2.URL, jwtTok.AccessToken); res.StatusCode != 204 {
			t.Fatalf("custom scope matcher = %d", res.StatusCode)
		}
		// RequireToken: a custom matcher replaces the exact one, and a
		// handler can answer insufficient_scope itself.
		o2 := oauthprovider.RequireOptions{Resource: mcpURL, Scopes: []string{"mcp:tools"}, ScopeSatisfied: func([]string, string) bool { return false }}
		rt := httptest.NewServer(o.op.RequireToken(o2)(http.NotFoundHandler()))
		t.Cleanup(rt.Close)
		if res := call(rt.URL, jwtTok.AccessToken); res.StatusCode != 403 {
			t.Fatalf("a matcher refusing an exact scope = %d", res.StatusCode)
		}
		o3 := oauthprovider.RequireOptions{Resource: mcpURL, Scopes: []string{"mcp:tools"}}
		wr := httptest.NewServer(o.op.RequireToken(o3)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			o.op.WriteInsufficientScope(w, o3, "mcp:admin")
		})))
		t.Cleanup(wr.Close)
		if res := call(wr.URL, jwtTok.AccessToken); res.StatusCode != 403 || !strings.Contains(res.Header.Get("WWW-Authenticate"), `scope="mcp:admin"`) {
			t.Fatalf("handler insufficient scope = %d %q", res.StatusCode, res.Header.Get("WWW-Authenticate"))
		}
		if _, err := oauthprovider.ProtectedResourceMetadata(mcpURL, []string{testBaseURL}, []string{"openid"}); !errors.Is(err, oauthprovider.ErrBadScopes) {
			t.Fatalf("openid in resource metadata: %v", err)
		}
	})
}
