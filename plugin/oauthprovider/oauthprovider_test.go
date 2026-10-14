package oauthprovider

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
)

const testIssuer = "https://app.example.com"

// signIn is a sign-in method from the core module (password is a module of
// its own), so auth.New accepts the configuration.
func signIn() auth.Plugin {
	return email.New(email.Login(), email.SignInWithCode(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil })))
}

func newSigner(iss string) *jwt.Plugin {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	return jwt.New(jwt.WithSigningKey(key), jwt.Issuer(iss))
}

func build(t *testing.T, plugins func(j *jwt.Plugin) []auth.Plugin) error {
	t.Helper()
	j := newSigner(testIssuer)
	_, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(append([]auth.Plugin{signIn()}, plugins(j)...)...))
	return err
}

// auth.New refuses every configuration that could not serve a client
// safely.
func TestValidate_RefusesBrokenConfigurations(t *testing.T) {
	ok := []Option{Issuer(testIssuer), LoginPage("/login")}
	cases := map[string]struct {
		plugins func(j *jwt.Plugin) []auth.Plugin
		want    error
	}{
		"no issuer": {func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{j, New(j, LoginPage("/login"))} }, ErrNoIssuer},
		"http issuer": {func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, Issuer("http://app.example.com"), LoginPage("/l"))}
		}, ErrNoIssuer},
		"issuer query": {func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, Issuer(testIssuer+"?a=1"), LoginPage("/l"))}
		}, ErrNoIssuer},
		"no login page": {func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{j, New(j, Issuer(testIssuer))} }, ErrNoLoginPage},
		"no jwt":        {func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{j, New(nil, ok...)} }, ErrNoJWT},
		"jwt after":     {func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{New(j, ok...), j} }, ErrNoJWT},
		"refresh alone": {func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, append(ok, GrantTypes(GrantRefreshToken))...)}
		}, ErrBadGrantTypes},
		"unknown grant": {func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, append(ok, GrantTypes("password"))...)}
		}, ErrBadGrantTypes},
		"spaced scope": {func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{j, New(j, append(ok, Scopes("a b"))...)} }, ErrBadScopes},
		"bad resource": {func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, append(ok, ProtectedResource("http://mcp.example.com"))...)}
		}, ErrBadResource},
		"resource scope": {func(j *jwt.Plugin) []auth.Plugin {
			return []auth.Plugin{j, New(j, append(ok, ProtectedResource("https://mcp.example.com", "nope"))...)}
		}, ErrBadScopes},
		"zero ttl": {func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{j, New(j, append(ok, CodeTTL(0))...)} }, ErrBadTTL},
		"issuer mismatch": {func(*jwt.Plugin) []auth.Plugin {
			j := newSigner("https://other.example")
			return []auth.Plugin{j, New(j, ok...)}
		}, ErrIssuerMatch},
	}
	for name, c := range cases {
		if err := build(t, c.plugins); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if err := build(t, func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{j, New(j, append(ok, BasePath("/x/"))...)} }); err == nil {
		t.Error("a BasePath ending in / was accepted")
	}
	if err := build(t, func(j *jwt.Plugin) []auth.Plugin {
		return []auth.Plugin{j, New(j, Issuer(testIssuer), LoginPage("https://evil.example/login"))}
	}); err == nil {
		t.Error("a login page on an untrusted origin was accepted")
	}
	if err := build(t, func(j *jwt.Plugin) []auth.Plugin {
		return []auth.Plugin{j, New(j, append(ok, ConsentPage("https://evil.example/c"))...)}
	}); err == nil {
		t.Error("a consent page on an untrusted origin was accepted")
	}
	if err := build(t, func(j *jwt.Plugin) []auth.Plugin { return []auth.Plugin{j, New(j, ok...)} }); err != nil {
		t.Fatalf("a valid configuration: %v", err)
	}
}

func TestValidRedirectURI(t *testing.T) {
	for uri, want := range map[string]bool{
		"https://client.example/cb":      true,
		"https://client.example/cb?x=1":  true,
		"http://127.0.0.1:8080/cb":       true,
		"http://[::1]/cb":                true,
		"http://localhost/cb":            true,
		"com.example.app:/cb":            true,
		"http://client.example/cb":       false,
		"https://client.example/cb#frag": false,
		"https://client.example/cb#":     false,
		"https://u:p@client.example/cb":  false,
		"javascript:alert(1)":            false,
		"data:text/html,x":               false,
		"/relative":                      false,
		"https:///nohost":                false,
		"customscheme:/cb":               false,
		"%zz":                            false,
	} {
		if got := validRedirectURI(uri); got != want {
			t.Errorf("%s = %v, want %v", uri, got, want)
		}
	}
}

// The expected challenge was computed apart, with Python's hashlib and
// base64.urlsafe_b64encode, unpadded.
func TestS256_MatchesAnIndependentComputation(t *testing.T) {
	if got := s256("dBjftJeZ4CVP-mJ92K9oAiBz7l3Pa3qL0w9bQ8xSaYk"); got != "qyFi1qGv0iPuZ8TZ1CPSIHL2kkxz_s0uErKv8C37TiM" {
		t.Fatalf("s256 = %s", got)
	}
	if validVerifier(strings.Repeat("a", 42)) || validVerifier(strings.Repeat("a", 129)) || validVerifier(strings.Repeat("a", 42)+"!") || !validVerifier(strings.Repeat("a", 43)) {
		t.Fatal("verifier bounds")
	}
}

func TestRFCCode(t *testing.T) {
	for err, want := range map[error]string{
		ErrInvalidGrant:       "invalid_grant",
		ErrBadRedirectTarget:  "invalid_redirect",
		ErrRegistrationClosed: "access_denied",
		auth.ErrRateLimited:   "temporarily_unavailable",
		auth.ErrInternal:      "server_error",
		errors.New("plain"):   "server_error",
		auth.ErrSignedOut:     "invalid_request",
	} {
		if got := rfcCode(err); got != want {
			t.Errorf("%v = %s, want %s", err, got, want)
		}
	}
}

func TestClientAuth(t *testing.T) {
	basic := func(id, secret string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id)+":"+url.QueryEscape(secret)))
	}
	cases := []struct {
		name   string
		header string
		form   url.Values
		want   ClientCredentials
		err    error
	}{
		{"basic", basic("c:1", "s%2"), url.Values{}, ClientCredentials{ID: "c:1", Secret: "s%2", Method: AuthMethodBasic}, nil},
		{"basic with the same form id", basic("c", "s"), url.Values{"client_id": {"c"}}, ClientCredentials{ID: "c", Secret: "s", Method: AuthMethodBasic}, nil},
		{"post", "", url.Values{"client_id": {"c"}, "client_secret": {"s"}}, ClientCredentials{ID: "c", Secret: "s", Method: AuthMethodPost}, nil},
		{"public", "", url.Values{"client_id": {"c"}}, ClientCredentials{ID: "c", Method: AuthMethodNone}, nil},
		{"two methods", basic("c", "s"), url.Values{"client_secret": {"s"}}, ClientCredentials{}, ErrInvalidRequest},
		{"ids disagree", basic("c", "s"), url.Values{"client_id": {"d"}}, ClientCredentials{}, ErrInvalidRequest},
		{"bearer", "Bearer x", url.Values{}, ClientCredentials{}, ErrInvalidClient},
		{"bad base64", "Basic !!!", url.Values{}, ClientCredentials{}, ErrInvalidClient},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("c")), url.Values{}, ClientCredentials{}, ErrInvalidClient},
		{"bad escape", "Basic " + base64.StdEncoding.EncodeToString([]byte("%zz:s")), url.Values{}, ClientCredentials{}, ErrInvalidClient},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		if c.header != "" {
			r.Header.Set("Authorization", c.header)
		}
		got, err := (&Plugin{}).clientAuth(r, c.form)
		if !errors.Is(err, c.err) || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v %v", c.name, got, err)
		}
	}
}

func TestDecodeAuthorize_RefusesRepeats(t *testing.T) {
	if _, err := decodeAuthorize(url.Values{"client_id": {"a", "b"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("repeated: %v", err)
	}
	in := AuthorizeRequest{ResponseType: "code", ClientID: "c", Scope: "openid", State: "s", Prompt: "none"}
	got, err := decodeAuthorize(authorizeValues(in))
	if err != nil || got != in {
		t.Fatalf("round trip = %+v %v", got, err)
	}
}

func TestPrimaryEmail(t *testing.T) {
	ids := []auth.Identity{{Kind: "phone", Value: "+1"}, {Kind: "email", Value: "a@x"}, {Kind: "email", Value: "b@x", IsPrimary: true}}
	if e, ok := primaryEmail(ids); !ok || e.Value != "b@x" {
		t.Fatalf("primary = %v", e)
	}
	if e, ok := primaryEmail(ids[:2]); !ok || e.Value != "a@x" {
		t.Fatalf("first = %v", e)
	}
	if _, ok := primaryEmail(ids[:1]); ok {
		t.Fatal("no email")
	}
}

func TestPayload(t *testing.T) {
	if _, err := payload("a.b"); err == nil {
		t.Fatal("two parts")
	}
	if _, err := payload("a.!!.c"); err == nil {
		t.Fatal("bad base64")
	}
	c, err := payload("x." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"i"}`)) + ".y")
	if err != nil || c["iss"] != "i" {
		t.Fatalf("payload = %v %v", c, err)
	}
}

// The handler: unknown paths 404, wrong methods 405 with Allow, CORS
// preflight, discovery without openid.
func TestHandler_RoutingAndMetadata(t *testing.T) {
	j := newSigner(testIssuer)
	p := New(j, Issuer(testIssuer), LoginPage("/login"), Scopes("api"), AllowDynamicRegistration())
	if _, err := auth.New(auth.WithBaseURL(testIssuer), auth.WithPlugins(signIn(), j, p)); err != nil {
		t.Fatal(err)
	}
	h := p.Handler()
	do := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	if w := do(http.MethodGet, "/nope"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d", w.Code)
	}
	if w := do(http.MethodGet, WellKnownOpenID); w.Code != http.StatusNotFound {
		t.Fatalf("openid-configuration without openid = %d", w.Code)
	}
	if w := do(http.MethodPut, WellKnownOAuth); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("PUT metadata = %d %v", w.Code, w.Header())
	}
	if w := do(http.MethodOptions, "/oauth2/token"); w.Code != http.StatusNoContent || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("preflight = %d %v", w.Code, w.Header())
	}
	m := p.Metadata()
	if m.RegistrationEndpoint != testIssuer+"/oauth2/register" || m.UserInfoEndpoint != "" || len(m.IDTokenSigningAlgValuesSupported) != 0 {
		t.Fatalf("metadata = %+v", m)
	}
	// A token request that is not a form is refused before anything runs.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(`{"grant_type":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"invalid_request"`) {
		t.Fatalf("JSON token request = %d %s", w.Code, w.Body)
	}
}
