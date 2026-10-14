package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
)

// TestMobile_BearerSignInEndToEnd is the app's whole life: it asks for a
// bearer token at sign-up, receives it in a header and never as a cookie,
// uses it on /me, gets a sealed session copy to send back, and signs out
// without an Origin header, which a native app never has.
func TestMobile_BearerSignInEndToEnd(t *testing.T) {
	a := newTestAuth(t)
	srv := httptest.NewServer(newHandler(a))
	defer srv.Close()

	res := send(t, srv, http.MethodPost, "/auth/password/sign-up", map[string]string{"identifier": testEmail, "password": testPassword}, map[string]string{authhttp.TokenModeHeader: authhttp.TokenModeBearer})
	tok := res.Header.Get(authhttp.SetTokenHeader)
	if res.StatusCode != http.StatusOK || tok == "" || len(res.Cookies()) != 0 {
		t.Fatalf("bearer sign-up: %d token=%q cookies=%v", res.StatusCode, tok, res.Cookies())
	}
	if strings.Contains(body(t, res), tok) {
		t.Fatal("the token reached the JSON body")
	}
	expires, err := time.Parse(time.RFC3339, res.Header.Get(authhttp.SetTokenExpiresHeader))
	if err != nil || expires.Before(time.Now().Add(appLifetime.Idle-time.Minute)) {
		t.Fatalf("%s = %q, want about %v ahead", authhttp.SetTokenExpiresHeader, res.Header.Get(authhttp.SetTokenExpiresHeader), appLifetime.Idle)
	}

	// The first request looks the session up and hands back a sealed copy.
	bearer := map[string]string{"Authorization": "Bearer " + tok}
	res = send(t, srv, http.MethodGet, "/me", nil, bearer)
	var me meResponse
	decode(t, res, http.StatusOK, &me)
	snapshot := res.Header.Get(authhttp.SetSessionCacheHeader)
	if me.Credential != auth.CredentialBearer || snapshot == "" || len(res.Cookies()) != 0 {
		t.Fatalf("/me = %+v, %s=%q, cookies=%v", me, authhttp.SetSessionCacheHeader, snapshot, res.Cookies())
	}
	// Sent back, the copy answers without a new one being issued.
	res = send(t, srv, http.MethodGet, "/me", nil, map[string]string{"Authorization": "Bearer " + tok, authhttp.SessionCacheHeader: snapshot})
	decode(t, res, http.StatusOK, &me)
	if res.Header.Get(authhttp.SetSessionCacheHeader) != "" {
		t.Fatal("a valid copy was replaced")
	}
	// A copy made for another token is worthless with this one.
	res = send(t, srv, http.MethodGet, "/me", nil, map[string]string{"Authorization": "Bearer not-the-token", authhttp.SessionCacheHeader: snapshot})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me with a stolen copy and the wrong token: %d", res.StatusCode)
	}

	// Sign out needs no Origin in bearer mode, and the token dies.
	if res := send(t, srv, http.MethodPost, "/auth/sign-out", nil, bearer); res.StatusCode != http.StatusOK {
		t.Fatalf("bearer sign-out: %d %s", res.StatusCode, body(t, res))
	}
	if res := send(t, srv, http.MethodGet, "/me", nil, bearer); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/me after sign-out: %d", res.StatusCode)
	}
}

// TestMobile_BrowserGetsTheShorterLifetime: the same sign-in from a browser
// is a cookie that ends after the web lifetime, not the app's.
func TestMobile_BrowserGetsTheShorterLifetime(t *testing.T) {
	a := newTestAuth(t)
	srv := httptest.NewTLSServer(newHandler(a)) // the cookie is Secure, and a jar keeps it only over https
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar

	raw, _ := json.Marshal(map[string]string{"identifier": testEmail, "password": testPassword})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth/password/sign-up", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == authhttp.CookieName {
			cookie = c
		}
	}
	if res.StatusCode != http.StatusOK || cookie == nil || res.Header.Get(authhttp.SetTokenHeader) != "" {
		t.Fatalf("browser sign-up: %d cookie=%v header=%q", res.StatusCode, cookie, res.Header.Get(authhttp.SetTokenHeader))
	}
	if cookie.Expires.After(time.Now().Add(webLifetime.Idle + time.Minute)) {
		t.Fatalf("cookie expires %v, want within the web idle lifetime %v", cookie.Expires, webLifetime.Idle)
	}
	res, err = client.Get(srv.URL + "/me")
	if err != nil {
		t.Fatal(err)
	}
	var me meResponse
	decode(t, res, http.StatusOK, &me)
	if me.Credential != auth.CredentialCookie {
		t.Fatalf("/me = %+v, want the cookie credential", me)
	}
}

// TestSessionKey_RefusesAMalformedKey: a wrong AUTH_SESSION_KEY fails the
// start, rather than sealing with a key nobody meant.
func TestSessionKey_RefusesAMalformedKey(t *testing.T) {
	if _, err := sessionKey("not-hex"); err != errBadKey {
		t.Fatalf("sessionKey(not-hex) = %v", err)
	}
	if _, err := sessionKey("abcd"); err != errBadKey {
		t.Fatalf("sessionKey(too short) = %v", err)
	}
	if key, err := sessionKey(strings.Repeat("ab", auth.SealKeySize)); err != nil || len(key) != auth.SealKeySize {
		t.Fatalf("sessionKey(valid) = %v %v", key, err)
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailer that
// drops mail; the flows here never need a link.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key, err := sessionKey(strings.Repeat("ab", auth.SealKeySize))
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// send is a request the way a native app makes it: JSON in, headers set by
// hand, no cookie jar and no Origin.
func send(t *testing.T, srv *httptest.Server, method, path string, in map[string]string, headers map[string]string) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if in != nil {
		raw, _ := json.Marshal(in)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func body(t *testing.T, res *http.Response) string {
	t.Helper()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return buf.String()
}

func decode(t *testing.T, res *http.Response, status int, out any) {
	t.Helper()
	b := body(t, res)
	if res.StatusCode != status {
		t.Fatalf("status %d, want %d: %s", res.StatusCode, status, b)
	}
	if err := json.Unmarshal([]byte(b), out); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
}
