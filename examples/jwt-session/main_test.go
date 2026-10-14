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
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/jwt"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// jwtSegments is how many dot-separated parts a compact JWS has.
	jwtSegments = 3
)

// TestSessionReadHandsOutAToken: every session read carries a fresh token in
// Set-Auth-JWT, readable cross-origin, which the report service accepts for
// the same user and session. A signed-out read carries none.
func TestSessionReadHandsOutAToken(t *testing.T) {
	b, _ := newTestApp(t)
	res := b.do(t, http.MethodGet, "/auth/session", nil, "", http.StatusUnauthorized)
	if res.Header.Get(jwt.SetJWTHeader) != "" {
		t.Fatal("a signed-out session read carried a token")
	}

	signUp(t, b)
	res = b.do(t, http.MethodGet, "/auth/session", nil, "", http.StatusOK)
	tok := res.Header.Get(jwt.SetJWTHeader)
	if strings.Count(tok, ".") != jwtSegments-1 {
		t.Fatalf("Set-Auth-JWT = %q", tok)
	}
	if !strings.Contains(res.Header.Get("Access-Control-Expose-Headers"), jwt.SetJWTHeader) {
		t.Fatalf("the header is not exposed to another origin: %q", res.Header.Get("Access-Control-Expose-Headers"))
	}
	var session auth.SessionResult
	decode(t, res, &session)
	var list auth.SessionsResult
	decode(t, b.do(t, http.MethodGet, "/auth/sessions", nil, "", http.StatusOK), &list)
	if len(list.Sessions) != 1 {
		t.Fatalf("sessions = %+v", list.Sessions)
	}

	var got reportResult
	decode(t, b.do(t, http.MethodGet, "/reports", nil, tok, http.StatusOK), &got)
	if got.User != session.User.ID || got.Session != list.Sessions[0].ID {
		t.Fatalf("/reports = %+v, want user %s session %s", got, session.User.ID, list.Sessions[0].ID)
	}
	b.do(t, http.MethodGet, "/reports", nil, "", http.StatusUnauthorized)
}

// TestSessionCacheIsASignedJWT: after the first lookup the client holds a
// snapshot that is a JWT of the cache's own type, the session is read from
// it rather than from the database, the report service refuses it as an
// access token, and sign-out clears it.
func TestSessionCacheIsASignedJWT(t *testing.T) {
	b, db := newTestApp(t)
	signUp(t, b)
	b.do(t, http.MethodGet, "/me", nil, "", http.StatusOK)

	snap := b.cookie(authhttp.CacheCookieName)
	parts := strings.Split(snap, ".")
	if len(parts) != jwtSegments {
		t.Fatalf("cache cookie = %q, not a JWT", snap)
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !strings.Contains(string(header), `"typ":"`+jwt.SessionCacheType+`"`) {
		t.Fatalf("snapshot header = %s %v", header, err)
	}
	b.do(t, http.MethodGet, "/reports", nil, snap, http.StatusUnauthorized)

	// The session row is gone, yet the snapshot still answers: the request
	// never reached the database. This is also why a revocation takes up to
	// cacheTTL to reach a client holding a snapshot.
	if _, err := db.Exec("DELETE FROM " + auth.TableNameSession); err != nil {
		t.Fatal(err)
	}
	b.do(t, http.MethodGet, "/me", nil, "", http.StatusOK)

	b.do(t, http.MethodPost, "/auth/sign-out", jsonOf(t, none{}), "", http.StatusOK)
	if b.cookie(authhttp.CacheCookieName) != "" {
		t.Fatal("the snapshot survived sign-out")
	}
	b.do(t, http.MethodGet, "/me", nil, "", http.StatusUnauthorized)
}

// TestSigningKeyFromEnvironment: a fixed seed gives the same key on every
// start; a malformed one is refused.
func TestSigningKeyFromEnvironment(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	env := func(string) string { return base64.RawURLEncoding.EncodeToString(seed) }
	k1, err := signingKey(env)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := signingKey(env)
	if !k1.Equal(k2) {
		t.Fatal("the same seed gave two keys")
	}
	if _, err := signingKey(func(string) string { return "short" }); err == nil {
		t.Fatal("a malformed seed was accepted")
	}
}

// newTestApp builds and migrates the app on a fresh SQLite file and serves
// it to a browser.
func newTestApp(t *testing.T) (*browser, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jw := newJWT(key)
	a, err := newAuth(db, jw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return newBrowser(t, newHandler(a, jw)), db
}

// signUp creates Alice's account; the browser keeps the session cookie.
func signUp(t *testing.T, b *browser) {
	t.Helper()
	b.do(t, http.MethodPost, "/auth/password/sign-up", jsonOf(t, fields{"identifier": testEmail, "password": testPassword}), "", http.StatusOK)
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the body of a route that takes no input.
type none struct{}

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

// do sends body (nil sends none) with bearer as the Authorization
// token when set, checks the status and returns the response with its body
// buffered.
func (b *browser) do(t *testing.T, method, path string, body []byte, bearer string, status int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, b.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	if bearer != "" {
		req.Header.Set("Authorization", bearerPrefix+bearer)
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
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

// cookie returns the value of the jar's cookie called name, or "".
func (b *browser) cookie(name string) string {
	u, _ := url.Parse(b.srv.URL)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}
