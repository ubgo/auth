package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/sessiontest"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// expiryTolerance is how far an expiry may sit from the lifetime the
	// policy asked for, covering the time a test step takes.
	expiryTolerance = time.Minute
)

// stores is every store the test drives the same way. Redis is added when
// the address is set, and its absence is reported rather than hidden.
func stores(t *testing.T) []config {
	t.Helper()
	out := []config{
		{Store: storeDatabase},
		{Store: storeMemory},
		{Store: storeCustom},
		{Store: storeStateless, Key: newKey(t)},
	}
	if addr := os.Getenv(envRedisAddr); addr != "" {
		out = append(out, config{Store: storeRedis, RedisAddr: addr})
	} else {
		t.Logf("SKIP the redis store: set %s (127.0.0.1:7012 locally)", envRedisAddr)
	}
	return out
}

// TestStores signs up, reads the protected page, signs out and is refused,
// on every store: what a store must do is the same whichever it is.
func TestStores(t *testing.T) {
	for _, cfg := range stores(t) {
		t.Run(string(cfg.Store), func(t *testing.T) {
			a, _ := newTestAuth(t, cfg)
			b := newBrowser(t, newHandler(a))
			signUp(t, b)
			if got := get[meResponse](t, b, "/me", http.StatusOK); got.Credential != auth.CredentialCookie {
				t.Fatalf("/me = %+v", got)
			}
			post[auth.Done](t, b, "/auth/sign-out", none{}, http.StatusOK)
			get[errorAnswer](t, b, "/me", http.StatusUnauthorized)
		})
	}
}

// TestStateless: the token is the session, so no row exists; listing and
// revoking other sessions is refused with a stable code; sign-out-all still
// ends every session, through the per-user cutoff.
func TestStateless(t *testing.T) {
	a, db := newTestAuth(t, config{Store: storeStateless, Key: newKey(t)})
	laptop, phone := newBrowser(t, newHandler(a)), newBrowser(t, newHandler(a))
	signUp(t, laptop)
	signIn(t, phone)

	var rows int
	if err := db.QueryRow("SELECT count(*) FROM " + auth.TableNameSession).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("auth_session holds %d rows in stateless mode", rows)
	}
	if !laptop.hasCookie(authhttp.CookieName) {
		t.Fatal("no session cookie")
	}

	list := get[auth.SessionsResult](t, laptop, "/auth/sessions", http.StatusOK)
	if len(list.Sessions) != 1 || !list.Sessions[0].Current {
		t.Fatalf("stateless sessions list = %+v, want only the current one", list.Sessions)
	}
	other := post[errorAnswer](t, laptop, "/auth/sessions/revoke", fields{"id": "ses_other"}, http.StatusConflict)
	if other.Error.Code != auth.ErrSessionsUnavailable.Code {
		t.Fatalf("revoke another session = %+v", other.Error)
	}

	// Sign out everywhere from the phone: the laptop's token was issued
	// before the cutoff, so it stops opening a session.
	post[auth.Done](t, phone, "/auth/sign-out-all", none{}, http.StatusOK)
	get[errorAnswer](t, laptop, "/me", http.StatusUnauthorized)
	get[errorAnswer](t, phone, "/me", http.StatusUnauthorized)
	signIn(t, laptop)
	get[meResponse](t, laptop, "/me", http.StatusOK)
}

// TestSnapshotCache: after the first lookup the client holds a sealed copy,
// and the next requests reach no store at all. Sign-out clears the copy.
func TestSnapshotCache(t *testing.T) {
	counting := newLoggingStore(auth.NewMemorySessionStore(), nil)
	a, _ := newTestAuth(t, config{Store: storeCustom, CustomStore: counting, Cache: cacheSnapshot, Key: newKey(t)})
	b := newBrowser(t, newHandler(a))
	signUp(t, b)

	get[meResponse](t, b, "/me", http.StatusOK)
	if n := counting.Finds(); n != 1 {
		t.Fatalf("finds after the first request = %d, want 1", n)
	}
	if !b.hasCookie(authhttp.CacheCookieName) {
		t.Fatal("the first request handed out no snapshot cookie")
	}
	get[meResponse](t, b, "/me", http.StatusOK)
	get[meResponse](t, b, "/me", http.StatusOK)
	if n := counting.Finds(); n != 1 {
		t.Fatalf("finds after three requests = %d, want 1: the snapshot must answer the rest", n)
	}

	post[auth.Done](t, b, "/auth/sign-out", none{}, http.StatusOK)
	if b.hasCookie(authhttp.CacheCookieName) {
		t.Fatal("sign-out left the snapshot cookie")
	}
	get[errorAnswer](t, b, "/me", http.StatusUnauthorized)
}

// TestMemoryCache: the same promise from a cache in the process, with
// nothing handed to the client.
func TestMemoryCache(t *testing.T) {
	counting := newLoggingStore(auth.NewMemorySessionStore(), nil)
	a, _ := newTestAuth(t, config{Store: storeCustom, CustomStore: counting, Cache: cacheMemory})
	b := newBrowser(t, newHandler(a))
	signUp(t, b)
	for range 3 {
		get[meResponse](t, b, "/me", http.StatusOK)
	}
	if n := counting.Finds(); n != 1 {
		t.Fatalf("finds after three requests = %d, want 1", n)
	}
	if b.hasCookie(authhttp.CacheCookieName) {
		t.Fatal("a server-side cache must hand the client nothing")
	}
	post[auth.Done](t, b, "/auth/sign-out", none{}, http.StatusOK)
	get[errorAnswer](t, b, "/me", http.StatusUnauthorized)
}

// TestLifetimesByClient: a browser session ends after the web idle time, a
// bearer session after the app's, chosen when each was created.
func TestLifetimesByClient(t *testing.T) {
	a, _ := newTestAuth(t, config{Store: storeDatabase, Lifetimes: lifetimesByClient})
	b := newBrowser(t, newHandler(a))
	signUp(t, b)
	web := get[meResponse](t, b, "/me", http.StatusOK)
	assertExpiry(t, "browser", web.ExpiresAt, webLifetime.Idle)

	app := get[meResponse](t, b.bearer(t, signInBearer(t, b)), "/me", http.StatusOK)
	if app.Credential != auth.CredentialBearer {
		t.Fatalf("bearer /me = %+v", app)
	}
	assertExpiry(t, "app", app.ExpiresAt, appLifetime.Idle)
}

// TestCustomStore runs the app's own store through the library's contract
// suite, which is what any custom store does before it ships.
//
//ds:def id=testcustomstore-sa7nqfq3
func TestCustomStore(t *testing.T) {
	sessiontest.Run(t, func(*testing.T) auth.SessionStore {
		return newLoggingStore(auth.NewMemorySessionStore(), nil)
	})
}

// TestRedis drives the Redis store and cache together when Redis is there.
func TestRedis(t *testing.T) {
	addr := os.Getenv(envRedisAddr)
	if addr == "" {
		t.Skipf("set %s to run against Redis (127.0.0.1:7012 locally)", envRedisAddr)
	}
	a, _ := newTestAuth(t, config{Store: storeRedis, Cache: cacheRedis, RedisAddr: addr})
	b := newBrowser(t, newHandler(a))
	signUp(t, b)
	get[meResponse](t, b, "/me", http.StatusOK)
	get[meResponse](t, b, "/me", http.StatusOK)
	post[auth.Done](t, b, "/auth/sign-out", none{}, http.StatusOK)
	get[errorAnswer](t, b, "/me", http.StatusUnauthorized)
}

// TestParseFlags pins the refusals: an unknown choice, Redis without an
// address, a malformed key.
func TestParseFlags(t *testing.T) {
	env := func(map[string]string) func(string) string {
		return func(k string) string { return "" }
	}
	if _, err := parseFlags([]string{"-store", "files"}, env(nil)); err == nil {
		t.Fatal("an unknown store was accepted")
	}
	if _, err := parseFlags([]string{"-store", "stateless"}, func(string) string { return "abc" }); err == nil {
		t.Fatal("a malformed key was accepted")
	}
	cfg, err := parseFlags([]string{"-store", "redis"}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessionOptions(cfg); err == nil {
		t.Fatal("the redis store started without an address")
	}
}

// assertExpiry checks that an expiry sits idle after now, within tolerance.
func assertExpiry(t *testing.T, what string, expiresAt time.Time, idle time.Duration) {
	t.Helper()
	want := time.Now().Add(idle)
	if d := expiresAt.Sub(want); d < -expiryTolerance || d > expiryTolerance {
		t.Fatalf("%s session expires at %s, want about %s (idle %s)", what, expiresAt, want, idle)
	}
}

// newKey makes a sealing key for one test.
func newKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, auth.SealKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// signUp creates the test account in b and leaves it signed in.
func signUp(t *testing.T, b *browser) {
	t.Helper()
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
}

// signIn signs b in to the test account with a cookie.
func signIn(t *testing.T, b *browser) {
	t.Helper()
	post[none](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
}

// signInBearer signs in as an app would and returns the token from the
// Set-Auth-Token header; no cookie is set.
func signInBearer(t *testing.T, b *browser) string {
	t.Helper()
	raw, err := json.Marshal(fields{"identifier": testEmail, "password": testPassword})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+"/auth/password/sign-in", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	res, err := b.appClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	tok := res.Header.Get(authhttp.SetTokenHeader)
	if res.StatusCode != http.StatusOK || tok == "" || len(res.Cookies()) != 0 {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(res.Body)
		t.Fatalf("bearer sign-in: %d token=%v cookies=%v %s", res.StatusCode, tok != "", res.Cookies(), buf.String())
	}
	return tok
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// that drops mail, and returns the database for the test's own reads.
func newTestAuth(t *testing.T, cfg config) (*auth.Auth, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, discard{}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, db
}

// discard drops mail: these tests never open a link.
type discard struct{}

// Send drops m.
func (discard) Send(context.Context, email.Mail) error { return nil }

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app. With
// token set it is an app instead: no cookies, a bearer header.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
	token  string
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
	return &browser{srv: srv, client: client, origin: baseURL}
}

// bearer returns an app client on the same server that presents token.
func (b *browser) bearer(t *testing.T, token string) *browser {
	t.Helper()
	return &browser{srv: b.srv, client: b.appClient(), origin: b.origin, token: token}
}

// appClient is a client with no cookie jar, the way an app talks to the API.
// httptest hands out one shared client, and the browser's jar is on it.
func (b *browser) appClient() *http.Client {
	return &http.Client{Transport: b.srv.Client().Transport}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, checks the status and decodes the answer as Out.
func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
	var out Out
	if b.token != "" {
		req.Header.Set("Authorization", "Bearer "+b.token)
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
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}

// hasCookie reports whether the jar holds a cookie called name for the server.
func (b *browser) hasCookie(name string) bool {
	u, _ := url.Parse(b.srv.URL)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
