package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// tick is a step smaller than any window under test, to land just past
	// a boundary.
	tick = time.Minute
	// loopbackIP is the address httptest clients connect from.
	loopbackIP = "127.0.0.1"
	// kvSessionPrefix and kvRatePrefix are the key prefixes the library's
	// storage-backed stores write under (storage.go), so the test can tell a
	// session from a rate counter in the store.
	kvSessionPrefix = "auth:session:"
	kvRatePrefix    = "auth:rate:"
)

// TestSlidingLifetime: a session used within the idle timeout slides forward,
// one left idle past it ends, and none outlives MaxLifetime however active.
func TestSlidingLifetime(t *testing.T) {
	env := newEnv(t, tuning{})
	signUp(t, env.b)

	env.clk.advance(sessionConfig.RefreshAfter + tick)
	s := get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)
	if want := env.clk.now().Add(sessionConfig.IdleTimeout); !s.ExpiresAt.Equal(want) {
		t.Fatalf("after use, expires %s, want %s (slid by IdleTimeout)", s.ExpiresAt, want)
	}

	env.clk.advance(sessionConfig.IdleTimeout + tick)
	get[errorAnswer](t, env.b, "/auth/session", http.StatusUnauthorized)

	signIn(t, env.b)
	start := env.clk.now()
	for env.clk.now().Before(start.Add(sessionConfig.MaxLifetime - sessionConfig.IdleTimeout/2)) {
		env.clk.advance(sessionConfig.IdleTimeout / 2)
		get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)
	}
	env.clk.advance(sessionConfig.IdleTimeout / 2)
	get[errorAnswer](t, env.b, "/auth/session", http.StatusUnauthorized)
}

// TestExtras: GET /auth/session and the device list carry the app's data.
func TestExtras(t *testing.T) {
	env := newEnv(t, tuning{})
	signUp(t, env.b)

	s := get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)
	if s.Extras == nil || s.Extras.Plan != planFree || !s.Extras.SignedInAt.Equal(env.clk.now()) {
		t.Fatalf("session extras = %+v, want plan %q signed in at %s", s.Extras, planFree, env.clk.now())
	}
	list := get[deviceAnswer](t, env.b, "/auth/device-sessions", http.StatusOK)
	if len(list.Sessions) != 1 || list.Sessions[0].Extras == nil || list.Sessions[0].Extras.Plan != planFree {
		t.Fatalf("device sessions = %+v, want one carrying extras", list.Sessions)
	}
}

// TestIPTracking: by default a session keeps the client's address; under
// WithoutIPTracking it keeps none, in the store and the list. The user agent
// is kept in both.
func TestIPTracking(t *testing.T) {
	for _, tc := range []struct {
		name string
		tu   tuning
		ip   string
	}{{"default", tuning{}, loopbackIP}, {"no-ip", tuning{NoIP: true}, ""}} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t, tc.tu)
			id := signUp(t, env.b)
			stored, err := env.a.Sessions(context.Background(), id)
			if err != nil || len(stored) != 1 {
				t.Fatalf("Sessions = %+v, %v", stored, err)
			}
			listed := get[auth.SessionsResult](t, env.b, "/auth/sessions", http.StatusOK).Sessions
			if stored[0].IP != tc.ip || len(listed) != 1 || listed[0].IP != tc.ip {
				t.Fatalf("stored IP %q, listed %+v, want %q", stored[0].IP, listed, tc.ip)
			}
			// The option is about addresses only: the user agent is kept
			// either way, so the list can still say "Chrome on a Mac".
			if stored[0].UserAgent == "" {
				t.Fatal("no user agent stored")
			}
		})
	}
}

// TestSecondaryStorage: sessions and rate counters land in the key-value
// store, the session table stays empty, and sign-out removes the session key.
func TestSecondaryStorage(t *testing.T) {
	var env *testEnv
	kv := newMemoryKV(func() time.Time { return env.clk.now() })
	env = newEnv(t, tuning{KV: kv})
	signUp(t, env.b)

	if n := kv.count(kvSessionPrefix); n != 1 {
		t.Fatalf("%d session keys in the store, want 1", n)
	}
	if n := kv.count(kvRatePrefix); n == 0 {
		t.Fatal("no rate counter in the store")
	}
	var rows int
	if err := env.db.QueryRow("SELECT count(*) FROM " + auth.TableNameSession).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("auth_session rows = %d, %v; want none", rows, err)
	}
	post[auth.Done](t, env.b, "/auth/sign-out", none{}, http.StatusOK)
	if n := kv.count(kvSessionPrefix); n != 0 {
		t.Fatalf("%d session keys after sign-out, want 0", n)
	}
}

// TestDeferredRefresh: a read reports needsRefresh and leaves the expiry
// alone; POST /auth/session/refresh slides it.
func TestDeferredRefresh(t *testing.T) {
	env := newEnv(t, tuning{Deferred: true})
	signUp(t, env.b)
	before := get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)

	env.clk.advance(sessionConfig.RefreshAfter + tick)
	read := get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)
	if !read.NeedsRefresh || !read.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("read = %+v, want needsRefresh and expiry still %s", read, before.ExpiresAt)
	}
	slid := post[sessionAnswer](t, env.b, "/auth/session/refresh", none{}, http.StatusOK)
	if want := env.clk.now().Add(sessionConfig.IdleTimeout); !slid.ExpiresAt.Equal(want) {
		t.Fatalf("refreshed expiry %s, want %s", slid.ExpiresAt, want)
	}
	if again := get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK); again.NeedsRefresh {
		t.Fatal("needsRefresh still set right after a refresh")
	}
}

// TestStatelessVersion: no session row exists, and redeploying with a higher
// version signs out a token sealed under the lower one; a fresh sign-in works.
func TestStatelessVersion(t *testing.T) {
	key := newKey(t)
	env := newEnv(t, tuning{Stateless: true, Key: key})
	signUp(t, env.b)
	get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)

	env.deploy(t, tuning{Stateless: true, Key: key, Version: 1})
	get[errorAnswer](t, env.b, "/auth/session", http.StatusUnauthorized)
	signIn(t, env.b)
	get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)
}

// TestStatelessReadEvery: with WithStatelessRefreshWithoutRead a "sign out
// everywhere" reaches a token only at its next full read, one interval after
// the last; without it the token is refused at once.
func TestStatelessReadEvery(t *testing.T) {
	const interval = 2 * time.Minute
	for _, tc := range []struct {
		name      string
		readEvery time.Duration
		status    int
	}{{"every-request", 0, http.StatusUnauthorized}, {"read-every", interval, http.StatusOK}} {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t, tuning{Stateless: true, Key: newKey(t), ReadEvery: tc.readEvery})
			id := signUp(t, env.b)
			// The sign-in token carries no copy of the user: the first request
			// reads it and reseals the token with the copy.
			get[sessionAnswer](t, env.b, "/auth/session", http.StatusOK)
			env.clk.advance(time.Second) // the cutoff must fall after the token was issued
			if err := env.a.DeleteUserSessions(context.Background(), id, ""); err != nil {
				t.Fatal(err)
			}
			if tc.status == http.StatusOK {
				get[sessionAnswer](t, env.b, "/auth/session", tc.status)
				env.clk.advance(interval)
			}
			get[errorAnswer](t, env.b, "/auth/session", http.StatusUnauthorized)
		})
	}
}

// TestParseFlags: the switches land in the tuning, a stateless run takes its
// key from the environment, and a malformed key fails before the server
// starts.
func TestParseFlags(t *testing.T) {
	hexKey := strings.Repeat("ab", auth.SealKeySize)
	env := map[string]string{envSessionKey: hexKey}
	tu, err := parseFlags([]string{"-no-ip", "-kv", "-deferred", "-stateless", "-version", "2", "-read-every", "2m"}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !tu.NoIP || tu.KV == nil || !tu.Deferred || !tu.Stateless || tu.Version != 2 || tu.ReadEvery != 2*time.Minute || len(tu.Key) != auth.SealKeySize {
		t.Fatalf("tuning = %+v", tu)
	}
	env[envSessionKey] = "short"
	if _, err := parseFlags([]string{"-stateless"}, func(k string) string { return env[k] }); !errors.Is(err, errBadKey) {
		t.Fatalf("bad key: err = %v, want errBadKey", err)
	}
}

// sessionAnswer is GET /auth/session with the extras decoded as the app's own
// shape rather than the library's encode-only field.
type sessionAnswer struct {
	ExpiresAt    time.Time    `json:"expiresAt"`
	Extras       *sessionInfo `json:"extras"`
	NeedsRefresh bool         `json:"needsRefresh"`
}

// deviceAnswer is GET /auth/device-sessions with the extras decoded.
type deviceAnswer struct {
	Sessions []struct {
		Extras *sessionInfo `json:"extras"`
	} `json:"sessions"`
}

// signUp creates the test account in b, leaves it signed in, and returns its
// user id.
func signUp(t *testing.T, b *browser) string {
	t.Helper()
	return post[signInAnswer](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK).User.ID
}

// signIn signs b in to the test account.
func signIn(t *testing.T, b *browser) {
	t.Helper()
	post[signInAnswer](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
}

// signInAnswer is the part of a sign-up or sign-in answer the test reads.
type signInAnswer struct {
	User struct {
		ID string `json:"id"`
	} `json:"user"`
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

// count returns how many live keys start with prefix.
func (m *memoryKV) count(prefix string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k := range m.data {
		if _, ok := m.live(k); ok && strings.HasPrefix(k, prefix) {
			n++
		}
	}
	return n
}

// testClock is a clock the test moves by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

// now is the clock's current time; it is the auth.WithClock function.
func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// advance moves the clock forward by d.
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testEnv is one app under test: its database, clock, Auth and a browser on
// a server whose handler deploy can replace, as a redeploy does.
type testEnv struct {
	db      *sql.DB
	clk     *testClock
	a       *auth.Auth
	b       *browser
	handler atomic.Pointer[http.Handler]
}

// newEnv builds the app with tu on a fresh SQLite file and a test clock.
func newEnv(t *testing.T, tu tuning) *testEnv {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The clock starts at the real time, whole seconds: the cookie jar drops
	// a cookie whose expiry is past by the real clock, and stored times keep
	// whole seconds.
	env := &testEnv{db: db, clk: &testClock{t: time.Now().UTC().Truncate(time.Second)}}
	env.deploy(t, tu)
	env.b = newBrowser(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*env.handler.Load()).ServeHTTP(w, r)
	}))
	return env
}

// deploy builds an Auth with tu over the same database and clock and makes
// the server answer with it from the next request on.
func (env *testEnv) deploy(t *testing.T, tu tuning) {
	t.Helper()
	tu.Clock = env.clk.now
	a, err := newAuth(env.db, discard{}, tu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	h := newHandler(a)
	env.a = a
	env.handler.Store(&h)
}

// discard drops mail: these tests never open a link.
type discard struct{}

// Send drops m.
func (discard) Send(context.Context, email.Mail) error { return nil }

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
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
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the request body of a route that takes no input.
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
