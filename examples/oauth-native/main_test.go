package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/oauth"
)

// TestIDToken_NativeAppSignsInWithoutABrowser: the "phone" gets an ID token
// from the provider's SDK (the issuer's /mint stands in for it) and posts it
// to the app in bearer mode; the app verifies it against the issuer's keys
// and answers a session token. A wrong nonce, a forged token and a token for
// another audience are refused with one code.
func TestIDToken_NativeAppSignsInWithoutABrowser(t *testing.T) {
	idp, a, _ := newTestApp(t)
	phone := newBrowser(t, newHandler(a))
	phone.bearer = true

	tok := idp.mint(t, issuerNativeClientID, "nonce-1")
	res, headers := phone.postRaw(t, "/auth/oauth/corp/id-token", fields{"idToken": tok, "nonce": "nonce-1"}, http.StatusOK)
	var out oauth.CallbackResult
	if err := json.Unmarshal(res, &out); err != nil || !out.Created || out.User.Name != issuerName {
		t.Fatalf("id-token sign-in = %s %v", res, err)
	}
	session := headers.Get(authhttp.SetTokenHeader)
	if session == "" {
		t.Fatal("no session token was handed to the native app")
	}
	// The session token works like any other.
	req, _ := http.NewRequest(http.MethodGet, phone.srv.URL+"/me", nil)
	req.Header.Set("Authorization", "Bearer "+session)
	resp, err := phone.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("/me with the native session: %v %v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// Signing in again is the same user, not a second account.
	again := post[oauth.CallbackResult](t, phone, "/auth/oauth/corp/id-token", fields{"idToken": idp.mint(t, issuerNativeClientID, "n2"), "nonce": "n2"}, http.StatusOK)
	if again.Created || again.User.ID != out.User.ID {
		t.Fatalf("second sign-in = %+v", again)
	}

	for name, body := range map[string]fields{
		"wrong nonce":    {"idToken": idp.mint(t, issuerNativeClientID, "n3"), "nonce": "other"},
		"forged":         {"idToken": tok[:len(tok)-4] + "AAAA", "nonce": "nonce-1"},
		"other audience": {"idToken": idp.mint(t, "someone-else", ""), "nonce": ""},
		"empty":          {"idToken": ""},
	} {
		if e := post[errorAnswer](t, phone, "/auth/oauth/corp/id-token", body, http.StatusUnauthorized); e.Error.Code != oauth.ErrIDTokenInvalid.Code {
			t.Errorf("%s: %+v", name, e.Error)
		}
	}
}

// TestCallback_ErrorsRedirectToTheSignInPage: a provider that refuses, and a
// callback opened in a browser that never started the flow, both land on
// the sign-in page with the error code in the query instead of a JSON body.
func TestCallback_ErrorsRedirectToTheSignInPage(t *testing.T) {
	_, a, _ := newTestApp(t)
	alice := newBrowser(t, newHandler(a))
	if loc := alice.redirect(t, "/auth/oauth/corp/callback?error=access_denied&state=x"); loc != signInPage+"?error="+oauth.ErrProviderDenied.Code {
		t.Fatalf("a refused callback redirected to %q", loc)
	}
	if loc := alice.redirect(t, "/auth/oauth/corp/callback?code=the-code&state=stale"); loc != signInPage+"?error="+oauth.ErrStateInvalid.Code {
		t.Fatalf("a callback without a flow redirected to %q", loc)
	}
	// The sign-in page shows the code.
	resp, err := alice.client.Get(alice.srv.URL + signInPage + "?error=" + oauth.ErrProviderDenied.Code)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), oauth.ErrProviderDenied.Code) {
		t.Fatalf("sign-in page = %s", buf.String())
	}
}

// TestFlow_DataReachesTheHookAndLogoutEndsBothSessions: the referral code on
// the start link is logged by the After hook when the user is created, and
// the provider logout clears the cookie, then sends the browser to the
// issuer with the stored ID token as id_token_hint.
func TestFlow_DataReachesTheHookAndLogoutEndsBothSessions(t *testing.T) {
	idp, a, logs := newTestApp(t)
	alice := newBrowser(t, newHandler(a))
	cb := alice.throughProvider(t, idp, "/auth/oauth/corp/start?returnTo=/me&data=ref%3Dfriend-42")
	if loc := alice.redirect(t, cb); loc != "/me" {
		t.Fatalf("callback redirected to %q", loc)
	}
	me := get[meResponse](t, alice, "/me", http.StatusOK)
	if !strings.Contains(logs.String(), fmt.Sprintf("user %s (created: true) arrived with data %q", me.ID, "ref=friend-42")) {
		t.Fatalf("log = %q", logs.String())
	}

	loc := alice.redirectPost(t, "/auth/oauth/corp/logout")
	end, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, idp.url+"/logout?") {
		t.Fatalf("logout sent the browser to %q", loc)
	}
	q := end.Query()
	if q.Get("id_token_hint") == "" || q.Get("client_id") != issuerClientID || q.Get("post_logout_redirect_uri") != baseURL {
		t.Fatalf("end-session parameters = %v", q)
	}
	get[errorAnswer](t, alice, "/me", http.StatusUnauthorized)
	// The issuer ends its session and sends the browser home.
	if back := alice.redirect(t, loc); back != baseURL {
		t.Fatalf("issuer sent the browser to %q", back)
	}
	if params, ok := idp.lastLogout(); !ok || params.Get("id_token_hint") != q.Get("id_token_hint") {
		t.Fatal("the issuer did not see the end-session request")
	}
}

// TestTokenKey_FromTheEnvironment: a set key is used as given; a malformed
// one is refused.
func TestTokenKey_FromTheEnvironment(t *testing.T) {
	want := bytes.Repeat([]byte{7}, auth.SealKeySize)
	got, err := tokenKey(func(string) string { return "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc" })
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("key from the environment = %x, %v", got, err)
	}
	if _, err := tokenKey(func(string) string { return "too-short" }); err == nil {
		t.Fatal("a malformed key must be refused")
	}
	if key, err := tokenKey(func(string) string { return "" }); err != nil || len(key) != auth.SealKeySize {
		t.Fatalf("generated key = %d bytes, %v", len(key), err)
	}
}

// logBuffer collects the app's log lines for assertions.
type logBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *logBuffer) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, format+"\n", args...)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// newTestApp runs the development issuer on httptest, builds the app around
// it and migrates a fresh SQLite file.
func newTestApp(t *testing.T) (*issuer, *auth.Auth, *logBuffer) {
	t.Helper()
	var idp *issuer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { idp.handler().ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	idp, err := newIssuer(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logs := &logBuffer{}
	a, err := newAuth(db, logMailer{}, newOAuth(srv.URL, bytes.Repeat([]byte{1}, auth.SealKeySize)), logs.printf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return idp, a, logs
}

// mint asks the issuer for an ID token the way a native SDK would.
func (i *issuer) mint(t *testing.T, aud, nonce string) string {
	t.Helper()
	tok, err := i.idToken(aud, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, and does not follow redirects, so each
// step is checked. With bearer set it asks for tokens in headers instead of
// cookies, as a native app does.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	bearer bool
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
	return &browser{srv: srv, client: client}
}

// throughProvider starts a flow and follows the issuer's consent redirect,
// returning the app's callback path and query.
func (b *browser) throughProvider(t *testing.T, idp *issuer, start string) string {
	t.Helper()
	consent := b.redirect(t, start)
	if !strings.HasPrefix(consent, idp.url+"/authorize?") {
		t.Fatalf("start sent the browser to %s, not the issuer", consent)
	}
	back, err := url.Parse(b.redirect(t, consent))
	if err != nil {
		t.Fatal(err)
	}
	return back.RequestURI()
}

// redirect GETs path (on the app, or an absolute URL) and returns the
// Location it answers; anything but a 302 fails the test.
func (b *browser) redirect(t *testing.T, path string) string {
	t.Helper()
	u := path
	if strings.HasPrefix(path, "/") {
		u = b.srv.URL + path
	}
	resp, err := b.client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("GET %s = %d %s, want 302", path, resp.StatusCode, buf.String())
	}
	return resp.Header.Get("Location")
}

// redirectPost POSTs an empty body to path with the app's Origin and returns
// the Location it answers.
func (b *browser) redirectPost(t *testing.T, path string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.srv.URL+path, nil)
	req.Header.Set("Origin", baseURL)
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("POST %s = %d %s, want 302", path, resp.StatusCode, buf.String())
	}
	return resp.Header.Get("Location")
}

type fields map[string]string

// none is the answer type when the body does not matter.
type none struct{}

// errorAnswer is the library's error JSON.
type errorAnswer struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (b *browser) postRaw(t *testing.T, path string, body fields, want int) ([]byte, http.Header) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	if b.bearer {
		req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("POST %s = %d %s, want %d", path, resp.StatusCode, buf.String(), want)
	}
	return buf.Bytes(), resp.Header
}

func post[T any](t *testing.T, b *browser, path string, body fields, want int) T {
	t.Helper()
	raw, _ := b.postRaw(t, path, body, want)
	var out T
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("POST %s answered %s: %v", path, raw, err)
		}
	}
	return out
}

func get[T any](t *testing.T, b *browser, path string, want int) T {
	t.Helper()
	resp, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("GET %s = %d %s, want %d", path, resp.StatusCode, buf.String(), want)
	}
	var out T
	if buf.Len() > 0 {
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatalf("GET %s answered %s: %v", path, buf.String(), err)
		}
	}
	return out
}
