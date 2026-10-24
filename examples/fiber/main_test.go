package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
)

// TestFiber signs up, reads the protected page, verifies the address
// from the mailed link, signs out, is refused a wrong password, and signs in
// again: the quick start flow through the fiber app main serves.
func TestFiber(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	up := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword, "name": testName}, http.StatusOK)
	if up.User.ID == "" || up.User.Name != testName {
		t.Fatalf("sign-up user = %+v", up.User)
	}
	if !b.hasCookie(authhttp.CookieName) {
		t.Fatal("sign-up set no session cookie")
	}

	if got := get[meResponse](t, b, "/me", http.StatusOK); got.ID != up.User.ID || got.Hello != testName {
		t.Fatalf("/me = %+v", got)
	}

	tok := box.lastToken(t, a, testEmail)
	if v := post[email.VerifyResult](t, b, "/auth/email/verify", fields{"token": tok}, http.StatusOK); v.Email != testEmail {
		t.Fatalf("verify = %+v", v)
	}

	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	get[none](t, b, "/me", http.StatusUnauthorized)

	bad := post[errorAnswer](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": "wrong password!"}, http.StatusUnauthorized)
	if bad.Error.Code != password.ErrInvalidCredentials.Code {
		t.Fatalf("wrong password error = %+v", bad.Error)
	}

	post[none](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	get[none](t, b, "/me", http.StatusOK)
}

// TestFiber_CrossSitePostIsRefused shows the origin check: a signed-in
// browser tricked into posting from another site is refused before anything
// runs.
func TestFiber_CrossSitePostIsRefused(t *testing.T) {
	a, _ := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)

	b.origin = "https://evil.example"
	post[none](t, b, "/auth/sign-out", none{}, http.StatusForbidden)
	get[none](t, b, "/me", http.StatusOK) // still signed in
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// that records mail instead of printing it.
func newTestAuth(t *testing.T) (*auth.Auth, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, err := newAuth(db, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box
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

// lastToken returns the token of the newest link mailed to addr. Mail goes
// out after the transaction commits, so it waits for deliveries first.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if u, err := url.Parse(field); err == nil && u.Query().Get("token") != "" {
				return u.Query().Get("token")
			}
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
}

// testURL is the address the test client uses. Nothing listens on it: the
// transport hands every request straight to the fiber app. It is https
// because the session cookie is __Host- and Secure, and a cookie jar keeps
// such a cookie only for an https URL.
const testURL = "https://fiber.test"

// fiberTimeout is how long one request may take inside app.Test. Its default
// of one second is too tight for argon2id at the production cost on a busy
// machine.
const fiberTimeout = 10 * time.Second

// browser is a client with a cookie jar that sends the Origin a page of the
// app would, like a real browser on the app.
type browser struct {
	url    string
	client *http.Client
	origin string
}

// fiberTransport serves each request with app.Test, fiber's in-memory
// round trip, so the test drives the real fiber app with a real cookie jar
// and no listening socket.
type fiberTransport struct{ app *fiber.App }

// RoundTrip runs req through the fiber app.
func (f fiberTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.app.Test(req, fiber.TestConfig{Timeout: fiberTimeout, FailOnTimeout: true})
}

// newBrowser returns a browser on app.
func newBrowser(t *testing.T, app *fiber.App) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{url: testURL, client: &http.Client{Transport: fiberTransport{app: app}, Jar: jar}, origin: baseURL}
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
	req, err := http.NewRequest(http.MethodPost, b.url+path, bytes.NewReader(raw))
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
	req, err := http.NewRequest(http.MethodGet, b.url+path, nil)
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

// hasCookie reports whether the jar holds a cookie called name for the server.
func (b *browser) hasCookie(name string) bool {
	u, _ := url.Parse(b.url)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
