package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
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
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/magiclink"
)

// testEmail is the address the links go to.
const testEmail = "alice@example.com"

// TestMagicLink_FirstLinkCreatesThenSignsIn: the first link creates the
// account, the link works once, and a later link signs in to the same account.
func TestMagicLink_FirstLinkCreatesThenSignsIn(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	post[auth.Done](t, b, "/auth/magiclink/send", fields{"identifier": testEmail}, http.StatusOK)
	link := box.lastLink(t, a, testEmail)
	if !strings.HasPrefix(link, baseURL+magiclink.DefaultPage+"?token=") {
		t.Fatalf("link = %q, want the app's %s page", link, magiclink.DefaultPage)
	}
	b.getPage(t, strings.TrimPrefix(link, baseURL))
	if b.hasCookie(authhttp.CookieName) {
		t.Fatal("opening the link page signed in; a mail scanner would have spent the link")
	}

	tok := tokenOf(t, link)
	first := post[magiclink.SignInResult](t, b, "/auth/magiclink/sign-in", fields{"token": tok}, http.StatusOK)
	if !first.Created || first.User.ID == "" {
		t.Fatalf("first sign-in = %+v, want a created user", first)
	}
	if got := get[meResponse](t, b, "/me", http.StatusOK); got.ID != first.User.ID {
		t.Fatalf("/me = %+v", got)
	}

	used := post[errorAnswer](t, b, "/auth/magiclink/sign-in", fields{"token": tok}, http.StatusBadRequest)
	if used.Error.Code != auth.ErrTokenInvalid.Code {
		t.Fatalf("a link used twice = %+v", used.Error)
	}

	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	post[auth.Done](t, b, "/auth/magiclink/send", fields{"identifier": testEmail}, http.StatusOK)
	again := post[magiclink.SignInResult](t, b, "/auth/magiclink/sign-in", fields{"token": tokenOf(t, box.lastLink(t, a, testEmail))}, http.StatusOK)
	if again.Created || again.User.ID != first.User.ID {
		t.Fatalf("second sign-in = %+v, want the same user %s", again, first.User.ID)
	}
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

// lastLink returns the newest link mailed to addr. Mail goes out after the
// transaction commits, so it waits for deliveries first.
func (m *mailbox) lastLink(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if strings.HasPrefix(field, baseURL) {
				return field
			}
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
}

// tokenOf returns the token in a mailed link.
func tokenOf(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

// getPage fetches an HTML page of the app and fails unless it answers 200.
func (b *browser) getPage(t *testing.T, path string) {
	t.Helper()
	res, err := b.client.Get(b.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", path, res.StatusCode)
	}
}

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
	u, _ := url.Parse(b.srv.URL)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
