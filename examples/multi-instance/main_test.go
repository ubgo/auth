package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
	// wrongTries is how many wrong passwords the password plugin allows per
	// account in its window; the next attempt is refused.
	wrongTries = 5
)

// TestMultiInstance_LimitsAndSessionsAreShared runs two instances on one
// database with the counters in the database. A session issued by A works on
// B, and five wrong passwords alternating between A and B lock the account on
// both: with per-process counters each instance would have seen only two or
// three.
func TestMultiInstance_LimitsAndSessionsAreShared(t *testing.T) {
	db := openTestDB(t)
	shared(t, db, auth.WithDBRateStore())
}

// TestMultiInstance_Redis is the same proof with the counters in Redis. It
// needs a Redis server, so it runs only when AUTH_REDIS_ADDR names one.
func TestMultiInstance_Redis(t *testing.T) {
	addr := os.Getenv(envRedisAddr)
	if addr == "" {
		t.Skipf("set %s to run against Redis", envRedisAddr)
	}
	rates, err := rateStore(addr)
	if err != nil {
		t.Fatal(err)
	}
	shared(t, openTestDB(t), rates)
}

// TestMultiInstance_PerProcessCountersAreNotShared is the counter-proof: with
// the default in-memory store, the same five wrong passwords spread across
// two instances are all still answered as wrong passwords, not refused.
func TestMultiInstance_PerProcessCountersAreNotShared(t *testing.T) {
	db := openTestDB(t)
	a, b := startPair(t, db, auth.WithRateStore(auth.NewMemoryRateStore(time.Now)), auth.WithRateStore(auth.NewMemoryRateStore(time.Now)))
	br := newBrowser(t)
	post[none](t, br, a.URL, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	for i := range wrongTries + 1 {
		res := post[errorAnswer](t, br, pick(i, a, b).URL, "/auth/password/sign-in", fields{"identifier": testEmail, "password": "wrong password!"}, http.StatusUnauthorized)
		if res.Error.Code != password.ErrInvalidCredentials.Code {
			t.Fatalf("attempt %d: %+v", i+1, res.Error)
		}
	}
}

// shared is the proof both stores must pass.
func shared(t *testing.T, db *sql.DB, rates auth.Option) {
	t.Helper()
	a, b := startPair(t, db, rates, rates)
	br := newBrowser(t)
	// A unique address, so a Redis that outlives the test cannot carry
	// counts from an earlier run into this one.
	who := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + testEmail

	post[none](t, br, a.URL, "/auth/password/sign-up", fields{"identifier": who, "password": testPassword, "name": testName}, http.StatusOK)
	if got := get[meResponse](t, br, b.URL, "/me", http.StatusOK); got.Hello != testName {
		t.Fatalf("instance B does not know A's session: %+v", got)
	}

	for i := range wrongTries {
		post[none](t, br, pick(i, a, b).URL, "/auth/password/sign-in", fields{"identifier": who, "password": "wrong password!"}, http.StatusUnauthorized)
	}
	// The right password, on the instance that saw fewer of the attempts.
	res := post[errorAnswer](t, br, b.URL, "/auth/password/sign-in", fields{"identifier": who, "password": testPassword}, http.StatusTooManyRequests)
	if res.Error.Code != auth.ErrRateLimited.Code {
		t.Fatalf("after %d wrong passwords across two instances: %+v", wrongTries, res.Error)
	}
}

// startPair serves two instances on db, the first migrating it, and returns
// their test servers.
func startPair(t *testing.T, db *sql.DB, ratesA, ratesB auth.Option) (a, b *httptest.Server) {
	t.Helper()
	servers := make([]*httptest.Server, 0, len(instances))
	for i, rates := range []auth.Option{ratesA, ratesB} {
		au, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }), rates)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = au.Close() })
		if i == 0 {
			if _, err := au.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		srv := httptest.NewTLSServer(newHandler(au, instances[i].name))
		t.Cleanup(srv.Close)
		servers = append(servers, srv)
	}
	return servers[0], servers[1]
}

// pick alternates between the two instances, like a round-robin balancer.
func pick(i int, a, b *httptest.Server) *httptest.Server {
	if i%2 == 0 {
		return a
	}
	return b
}

// openTestDB opens a fresh SQLite file with the app's pragmas.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// browser is a client with a cookie jar that sends the Origin a page of the
// app would. Both test servers are on 127.0.0.1, and a cookie is scoped to
// the host, not the port, so one jar reaches both instances as one browser
// behind a load balancer would.
type browser struct {
	client *http.Client
	origin string
}

// newBrowser returns a browser that trusts the test servers' certificate:
// the session cookie is __Host- and Secure, and a jar keeps such a cookie
// only for an https URL.
func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	tls := httptest.NewTLSServer(http.NotFoundHandler()) // only for its client's trust settings
	t.Cleanup(tls.Close)
	client := tls.Client()
	client.Jar = jar
	return &browser{client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON to base+path with the browser's Origin, checks the
// status and decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, base, path string, in In, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	return do[Out](t, b, req, status)
}

// get fetches base+path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, base, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

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
