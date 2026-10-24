package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
)

// TestBearer_RotationAndReuse walks the whole story in bearer mode: a slide
// hands out a new token in Set-Auth-Token, the old one keeps working inside
// the grace window, and presenting it after the window ends the session for
// the new token too and raises the alarm.
func TestBearer_RotationAndReuse(t *testing.T) {
	app := newTestApp(t, true)
	first := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	if first == "" {
		t.Fatal("sign-up returned no token")
	}
	// Not due yet: no new token.
	if got := app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK).Header.Get(authhttp.SetTokenHeader); got != "" {
		t.Fatal("a request before RefreshAfter rotated the token")
	}

	app.advance(refreshAfter + time.Second)
	second := app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	if second == "" || second == first {
		t.Fatalf("the slide did not rotate the token: %q", second)
	}
	// Within the grace window both tokens work: a parallel request that
	// left with the old one is not signed out.
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusOK)
	app.call(t, http.MethodGet, "/me", second, nil, http.StatusOK)
	if n := app.events(); n != 0 {
		t.Fatalf("%d security events inside the grace window", n)
	}

	app.advance(rotationGrace + time.Second)
	app.call(t, http.MethodGet, "/me", first, nil, http.StatusUnauthorized)
	// The session is gone for the holder of the new token too.
	app.call(t, http.MethodGet, "/me", second, nil, http.StatusUnauthorized)
	app.waitEvents(t, 1)
	e := app.event(0)
	if e.Kind != auth.SecuritySessionTokenReuse || e.Severity != auth.SeverityAlert || e.Attrs[auth.AttrSessionID] == "" || e.UserID == "" {
		t.Fatalf("event = %+v", e)
	}
}

// TestCookie_RotationKeepsTheBrowserSignedIn: in cookie mode the new token
// arrives as a new session cookie, and a browser that keeps its cookie jar
// never notices the rotation.
func TestCookie_RotationKeepsTheBrowserSignedIn(t *testing.T) {
	app := newTestApp(t, true)
	jar := &cookieJar{}
	app.browser(t, jar, http.MethodPost, "/auth/password/sign-up", credentials(), http.StatusOK)
	before := jar.session()
	for range 3 {
		app.advance(refreshAfter + time.Second)
		app.browser(t, jar, http.MethodGet, "/me", nil, http.StatusOK)
	}
	if jar.session() == before {
		t.Fatal("the cookie never changed across three slides")
	}
	if n := app.events(); n != 0 {
		t.Fatalf("%d security events for an honest browser", n)
	}
	// A copy of the first cookie, taken before the rotations, is the thief.
	stolen := &cookieJar{value: before}
	app.browser(t, stolen, http.MethodGet, "/me", nil, http.StatusUnauthorized)
}

// TestWithoutRotation_NothingChanges: the same app without
// WithTokenRotation slides the expiry under the same token, and that token
// keeps working however long after the slide it is presented.
func TestWithoutRotation_NothingChanges(t *testing.T) {
	app := newTestApp(t, false)
	tok := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	app.advance(refreshAfter + time.Second)
	if got := app.call(t, http.MethodGet, "/me", tok, nil, http.StatusOK).Header.Get(authhttp.SetTokenHeader); got != tok {
		t.Fatalf("the slide reissued %q, want the same token", got)
	}
	app.advance(rotationGrace + time.Hour)
	app.call(t, http.MethodGet, "/me", tok, nil, http.StatusOK)
	if n := app.events(); n != 0 {
		t.Fatalf("%d security events without rotation", n)
	}
}

// TestMultiSession_RotationIsNotASecondAccount: under WithMultiSession the
// browser keeps a cookie per signed-in account. A rotated token replaces the
// active account's cookie; it must not be kept as another account, or the
// device list would present the replaced token after its grace and revoke
// the user's own session.
func TestMultiSession_RotationIsNotASecondAccount(t *testing.T) {
	app := newTestApp(t, true, auth.WithMultiSession(3))
	jar := fullJar{}
	app.browserAll(t, jar, http.MethodPost, "/auth/password/sign-up", credentials(), http.StatusOK)
	first := jar[authhttp.CookieName]
	app.advance(refreshAfter + time.Second)
	app.browserAll(t, jar, http.MethodGet, "/me", nil, http.StatusOK)
	if jar[authhttp.CookieName] == first {
		t.Fatal("no rotation happened")
	}
	if n := jar.accounts(); n != 0 {
		t.Fatalf("the replaced token is kept as %d other account(s)", n)
	}
	app.advance(rotationGrace + time.Second)
	app.browserAll(t, jar, http.MethodGet, "/auth/device-sessions", nil, http.StatusOK)
	app.browserAll(t, jar, http.MethodGet, "/me", nil, http.StatusOK)
	if n := app.events(); n != 0 {
		t.Fatalf("%d security events for one honest browser", n)
	}
}

// fullJar keeps every cookie by name, as a browser does for one site.
type fullJar map[string]string

// accounts counts the multi-session account cookies.
func (j fullJar) accounts() int {
	n := 0
	for name := range j {
		if strings.Contains(name, "_account_") {
			n++
		}
	}
	return n
}

// browserAll is browser with every cookie sent and kept.
func (app *testApp) browserAll(t *testing.T, jar fullJar, method, path string, body []byte, status int) {
	t.Helper()
	req, err := http.NewRequest(method, app.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	for name, value := range jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	res := app.do(t, req, status)
	for _, c := range res.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(jar, c.Name)
			continue
		}
		jar[c.Name] = c.Value
	}
}

// testApp is the app on httptest with a clock the test moves and the
// security events it heard.
type testApp struct {
	srv  *httptest.Server
	db   *sql.DB
	auth *auth.Auth

	mu   sync.Mutex
	now  time.Time
	seen []auth.SecurityEvent
}

// newTestApp builds and migrates the app on a fresh SQLite file, with
// rotation on, or with the same refresh interval and sink and no rotation.
func newTestApp(t *testing.T, rotate bool, more ...auth.Option) *testApp {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &testApp{now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	sink := auth.SecuritySinkFunc(func(_ context.Context, batch []auth.SecurityEvent) error {
		app.mu.Lock()
		defer app.mu.Unlock()
		app.seen = append(app.seen, batch...)
		return nil
	})
	opts := rotationOptions(sink)
	if !rotate {
		opts = []auth.Option{auth.WithSession(auth.SessionConfig{RefreshAfter: refreshAfter}), auth.WithSecuritySink(sink, auth.SecurityQueue{})}
	}
	a, err := newAuth(db, opts, append(more, auth.WithClock(app.clock))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	app.db, app.auth = db, a
	app.srv = httptest.NewServer(newHandler(a))
	t.Cleanup(app.srv.Close)
	return app
}

func (app *testApp) clock() time.Time {
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.now
}

func (app *testApp) advance(d time.Duration) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.now = app.now.Add(d)
}

func (app *testApp) events() int {
	app.mu.Lock()
	defer app.mu.Unlock()
	return len(app.seen)
}

func (app *testApp) event(i int) auth.SecurityEvent {
	app.mu.Lock()
	defer app.mu.Unlock()
	return app.seen[i]
}

// waitEvents waits for the sink, which runs on its own goroutine.
func (app *testApp) waitEvents(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for app.events() < n {
		if time.Now().After(deadline) {
			t.Fatalf("heard %d security events, want %d", app.events(), n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// credentials is Alice's sign-up body.
func credentials() []byte {
	raw, _ := json.Marshal(map[string]string{"identifier": testEmail, "password": testPassword}) // a map of strings always encodes
	return raw
}

// call sends a bearer-mode request and checks the status.
func (app *testApp) call(t *testing.T, method, path, token string, body []byte, status int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, app.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return app.do(t, req, status)
}

// cookieJar holds the one session cookie, as a browser would.
type cookieJar struct{ value string }

func (j *cookieJar) session() string { return j.value }

// browser sends a cookie-mode request from the app's own origin, keeping
// whatever session cookie the response sets.
func (app *testApp) browser(t *testing.T, jar *cookieJar, method, path string, body []byte, status int) {
	t.Helper()
	req, err := http.NewRequest(method, app.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	if jar.value != "" {
		req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: jar.value})
	}
	res := app.do(t, req, status)
	for _, c := range res.Cookies() {
		if c.Name == authhttp.CookieName {
			jar.value = c.Value
		}
	}
}

// do sends req and checks the status.
func (app *testApp) do(t *testing.T, req *http.Request, status int) *http.Response {
	t.Helper()
	res, err := app.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, strings.TrimSpace(buf.String()))
	}
	return res
}
