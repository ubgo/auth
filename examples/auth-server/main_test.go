package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/jwt"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
)

// TestAuthServer_SignInThenCallTheAPIWithAJWT: Alice signs up on the pages,
// a client of the product mints a JWT from her session, and the API service
// accepts it on the strength of the published keys alone; without a token,
// with a tampered one, or with one for another audience it refuses.
func TestAuthServer_SignInThenCallTheAPIWithAJWT(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	if p := b.get(t, homePath); p.status != http.StatusSeeOther || p.location != authui.PathLogin {
		t.Fatalf("home signed out: %+v", p)
	}
	if p := b.post(t, authui.PathSignup, url.Values{"name": {testName}, "identifier": {testEmail}, "password": {testPassword}}); p.status != http.StatusSeeOther || p.location != homePath {
		t.Fatalf("sign-up: %+v", p)
	}
	if p := b.get(t, homePath); p.status != http.StatusOK || !strings.Contains(p.body, "Hello, "+testName) || !strings.Contains(p.body, authPrefix+"/jwt/token") {
		t.Fatalf("home: %d %s", p.status, p.body)
	}
	if p := b.get(t, authPrefix+"/ok"); p.status != http.StatusOK || !strings.Contains(p.body, `"ok":true`) {
		t.Fatalf("health: %+v", p)
	}
	if p := b.get(t, authPrefix+"/openapi.json"); p.status != http.StatusOK || !strings.Contains(p.body, `"/auth/jwt/token"`) {
		t.Fatalf("openapi: %d", p.status)
	}

	// The client mints a token from the session cookie.
	var minted jwt.TokenResult
	if p := b.postJSON(t, authPrefix+"/jwt/token", &minted); p.status != http.StatusOK || minted.Token == "" {
		t.Fatalf("token: %+v", p)
	}

	// The API service verifies with the key set it fetched, nothing else.
	set, err := fetchJWKS(b.client, b.srv.URL+jwksPath)
	if err != nil {
		t.Fatal(err)
	}
	api := newAPIService(jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: jwtAudience})
	if res := callAPI(api, minted.Token); res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"name":"Alice"`) {
		t.Fatalf("api with a valid token: %d %s", res.Code, res.Body.String())
	}
	if res := callAPI(api, ""); res.Code != http.StatusUnauthorized {
		t.Fatalf("api without a token: %d", res.Code)
	}
	// Two final characters the token does not already end with, so the
	// signature always changes.
	tampered := minted.Token[:len(minted.Token)-2] + "xx"
	if strings.HasSuffix(minted.Token, "xx") {
		tampered = minted.Token[:len(minted.Token)-2] + "yy"
	}
	if res := callAPI(api, tampered); res.Code != http.StatusUnauthorized {
		t.Fatalf("api with a tampered token: %d", res.Code)
	}
	other := newAPIService(jwt.Verifier{Keys: jwt.KeysFromJWKS(set), Issuer: baseURL, Audience: "someone-else"})
	if res := callAPI(other, minted.Token); res.Code != http.StatusUnauthorized {
		t.Fatalf("api of another audience: %d", res.Code)
	}
	// A key set fetched from the wrong place is an error, not an empty set.
	if _, err := fetchJWKS(b.client, b.srv.URL+"/nowhere"); err == nil {
		t.Fatal("fetchJWKS accepted a 404")
	}
}

// TestSigningKey: a seed in the environment is used, a malformed one is
// refused, and none means a fresh key.
func TestSigningKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	env := func(string) string { return base64.RawURLEncoding.EncodeToString(seed) }
	key, err := signingKey(env)
	if err != nil || !bytes.Equal(key.Seed(), seed) {
		t.Fatalf("key from env: %v", err)
	}
	if _, err := signingKey(func(string) string { return "short" }); err == nil {
		t.Fatal("a malformed seed was accepted")
	}
	if _, err := signingKey(func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
}

func callAPI(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// newTestAuth builds the auth server's Auth on a fresh SQLite file with a
// mailbox that records mail instead of printing it.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key, err := signingKey(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(db, &mailbox{}, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// browser is an HTTPS test server and a client with a cookie jar that posts
// forms with the Origin a page of the app would send, and does not follow
// redirects, so each step is checked.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
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
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{srv: srv, client: client, origin: baseURL}
}

// pageAnswer is one response as a test inspects it.
type pageAnswer struct {
	status   int
	body     string
	location string
}

// get fetches a page.
func (b *browser) get(t *testing.T, path string) pageAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b.do(t, req)
}

// post submits a form with the browser's Origin.
func (b *browser) post(t *testing.T, path string, form url.Values) pageAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.origin)
	return b.do(t, req)
}

// postJSON calls a JSON route with the browser's cookies and Origin, as a
// page script would, and decodes the answer into out.
func (b *browser) postJSON(t *testing.T, path string, out any) pageAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	p := b.do(t, req)
	if p.status == http.StatusOK {
		if err := json.Unmarshal([]byte(p.body), out); err != nil {
			t.Fatalf("decode %q: %v", p.body, err)
		}
	}
	return p
}

func (b *browser) do(t *testing.T, req *http.Request) pageAnswer {
	t.Helper()
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	return pageAnswer{status: res.StatusCode, body: buf.String(), location: res.Header.Get("Location")}
}
