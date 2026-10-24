package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/jwt"
	"github.com/ubgo/auth/plugin/jwt/jwtpreset"
	"github.com/ubgo/auth/plugin/metadata"
	"github.com/ubgo/auth/plugin/organization"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// testSecret is the Supabase JWT secret the tests share with "Supabase".
	testSecret = "super-secret-jwt-token-with-at-least-32-characters-long"
)

// TestTemplates_EachReceiverVerifies: over HTTP, a signed-in client gets a
// token from each template, and each one verifies the way its receiver
// verifies it: Supabase with the shared secret, Hasura and Convex through
// the key set the app publishes at /auth/jwt/jwks.
func TestTemplates_EachReceiverVerifies(t *testing.T) {
	b := newTestApp(t)
	signUp(t, b)
	var set jwt.JWKS
	decode(t, b.do(t, http.MethodGet, "/auth/jwt/jwks", nil, http.StatusOK), &set)
	keys := jwt.KeysFromJWKS(set)

	// Supabase: HS256, aud and role "authenticated", sub the user.
	tok := tokenFor(t, b, TemplateSupabase)
	payload, err := jwt.VerifyHS256(tok, []byte(testSecret))
	if err != nil {
		t.Fatalf("supabase: %v", err)
	}
	var sb map[string]any
	_ = json.Unmarshal(payload, &sb)
	if sb["aud"] != "authenticated" || sb["role"] != "authenticated" || sb["is_anonymous"] != false || !strings.HasPrefix(sb["sub"].(string), "usr_") || sb["session_id"] != sb["sid"] {
		t.Fatalf("supabase claims = %v", sb)
	}
	if _, err := (jwt.Verifier{Keys: keys}).Verify(tok); err == nil {
		t.Fatal("an HS256 token verified against the public key set")
	}

	// Hasura: the plugin's EdDSA key, the claims namespace.
	got, err := jwt.Verifier{Keys: keys, Issuer: baseURL, Audience: hasuraAudience}.Verify(tokenFor(t, b, TemplateHasura))
	if err != nil {
		t.Fatalf("hasura: %v", err)
	}
	var ns map[string]any
	_ = json.Unmarshal(got.Extra[jwtpreset.HasuraNamespace], &ns)
	if ns["x-hasura-user-id"] != got.Subject || ns["x-hasura-default-role"] != "user" {
		t.Fatalf("hasura namespace = %v", ns)
	}

	// Convex: ES256, the second published key, aud the application id.
	tok = tokenFor(t, b, TemplateConvex)
	if h := headerOf(t, tok); h["alg"] != "ES256" || h["kid"] == "" {
		t.Fatalf("convex header = %v", h)
	}
	if _, err := (jwt.Verifier{Keys: keys, Issuer: baseURL, Audience: convexApplicationID}).Verify(tok); err != nil {
		t.Fatalf("convex: %v", err)
	}

	// The key set holds the two public keys and no secret.
	raw, _ := json.Marshal(set)
	if len(set.Keys) != 2 || strings.Contains(string(raw), testSecret) || strings.Contains(string(raw), `"oct"`) {
		t.Fatalf("key set = %s", raw)
	}
}

// TestTemplates_OrganizationClaim: with no active organization the org
// template carries no claim; after creating one (which makes it active) the
// claim names it, the owner role and the owner's permissions.
func TestTemplates_OrganizationClaim(t *testing.T) {
	b := newTestApp(t)
	signUp(t, b)
	verify := func() map[string]json.RawMessage {
		var set jwt.JWKS
		decode(t, b.do(t, http.MethodGet, "/auth/jwt/jwks", nil, http.StatusOK), &set)
		got, err := jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: orgAudience}.Verify(tokenFor(t, b, TemplateOrg))
		if err != nil {
			t.Fatal(err)
		}
		return got.Extra
	}
	if extra := verify(); extra["org"] != nil {
		t.Fatalf("no organization yet, claim = %s", extra["org"])
	}
	var org organization.Org
	decode(t, b.do(t, http.MethodPost, "/auth/organization/create", jsonOf(t, map[string]string{"name": "Acme", "slug": "acme"}), http.StatusOK), &org)
	var claim struct {
		ID          string   `json:"id"`
		Slug        string   `json:"slug"`
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(verify()["org"], &claim); err != nil {
		t.Fatal(err)
	}
	if claim.ID != org.ID || claim.Slug != "acme" || claim.Role != string(organization.RoleOwner) || len(claim.Permissions) == 0 {
		t.Fatalf("org claim = %+v", claim)
	}
	if !slices.IsSorted(claim.Permissions) || !slices.Contains(claim.Permissions, "organization:delete") {
		t.Fatalf("owner permissions = %v", claim.Permissions)
	}
}

// TestTemplates_PublicMetadataClaim: the profile template carries the
// user's public metadata document, "{}" for a user who has none yet.
func TestTemplates_PublicMetadataClaim(t *testing.T) {
	b := newTestApp(t)
	signUp(t, b)
	var set jwt.JWKS
	decode(t, b.do(t, http.MethodGet, "/auth/jwt/jwks", nil, http.StatusOK), &set)
	got, err := jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: profileAudience}.Verify(tokenFor(t, b, TemplateProfile))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Extra[publicMetadataClaim]) != "{}" {
		t.Fatalf("public_metadata = %s", got.Extra[publicMetadataClaim])
	}
}

// TestTemplates_Refusals: an anonymous caller is refused, an unknown
// template answers the coded 404, and a client cannot add claims by sending
// them.
func TestTemplates_Refusals(t *testing.T) {
	b := newTestApp(t)
	b.do(t, http.MethodPost, "/auth/jwt/template", jsonOf(t, map[string]string{"template": TemplateSupabase}), http.StatusUnauthorized)
	signUp(t, b)
	res := b.do(t, http.MethodPost, "/auth/jwt/template", jsonOf(t, map[string]string{"template": "admin"}), http.StatusNotFound)
	var body bytes.Buffer
	_, _ = body.ReadFrom(res.Body)
	if !strings.Contains(body.String(), jwt.ErrUnknownTemplate.Code) {
		t.Fatalf("unknown template body = %s", body.String())
	}
	// Extra fields are refused or ignored; the token never carries them.
	res = b.do(t, http.MethodPost, "/auth/jwt/template", []byte(`{"template":"supabase","claims":{"role":"service_role"},"role":"service_role"}`), 0)
	if res.StatusCode == http.StatusOK {
		var out jwt.TokenResult
		decode(t, res, &out)
		payload, err := jwt.VerifyHS256(out.Token, []byte(testSecret))
		if err != nil || strings.Contains(string(payload), "service_role") {
			t.Fatalf("a client shaped a claim: %s %v", payload, err)
		}
	}
}

// tokenFor asks for a template's token over HTTP.
func tokenFor(t *testing.T, b *browser, name string) string {
	t.Helper()
	var out jwt.TokenResult
	decode(t, b.do(t, http.MethodPost, "/auth/jwt/template", jsonOf(t, jwt.TemplateRequest{Template: name}), http.StatusOK), &out)
	return out.Token
}

// headerOf decodes a token's JWS header.
func headerOf(t *testing.T, tok string) map[string]any {
	t.Helper()
	var h map[string]any
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if err != nil || json.Unmarshal(raw, &h) != nil {
		t.Fatalf("header of %q", tok)
	}
	return h
}

// newTestApp builds and migrates the app on a fresh SQLite file.
func newTestApp(t *testing.T) *browser {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	k, err := newKeys(func(string) string { return testSecret })
	if err != nil {
		t.Fatal(err)
	}
	org, meta := organization.New(), metadata.New()
	jw, err := newJWT(k, org, meta)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(db, org, meta, jw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return newBrowser(t, newHandler(a))
}

// TestNewKeys_RefusesAShortSecret: a Supabase secret shorter than
// jwt.MinHMACSecret is refused at start.
func TestNewKeys_RefusesAShortSecret(t *testing.T) {
	if _, err := newKeys(func(string) string { return "short" }); err == nil {
		t.Fatal("a short secret was accepted")
	}
	if k, err := newKeys(func(string) string { return "" }); err != nil || len(k.supabase) < jwt.MinHMACSecret {
		t.Fatalf("generated secret: %v", err)
	}
}

// signUp creates Alice's account; the browser keeps the session cookie.
func signUp(t *testing.T, b *browser) {
	t.Helper()
	b.do(t, http.MethodPost, "/auth/password/sign-up", jsonOf(t, map[string]string{"identifier": testEmail, "password": testPassword}), http.StatusOK)
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the app's Origin, because the session cookie is __Host- and Secure.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// newBrowser serves h over TLS to a client with a cookie jar.
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client}
}

// do sends body (nil sends none), checks the status unless it is 0 and
// returns the response with its body buffered.
func (b *browser) do(t *testing.T, method, path string, body []byte, status int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, b.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if status != 0 && res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, status, buf.String())
	}
	res.Body = readCloser{bytes.NewReader(buf.Bytes())}
	return res
}

// jsonOf encodes v as a JSON request body.
func jsonOf[T any](t *testing.T, v T) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// readCloser lets do hand back a body it already read.
type readCloser struct{ *bytes.Reader }

// Close does nothing: the body is in memory.
func (readCloser) Close() error { return nil }

// decode reads res's JSON body into out.
func decode[T any](t *testing.T, res *http.Response, out *T) {
	t.Helper()
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}
