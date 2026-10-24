package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	"github.com/ubgo/auth/plugin/password"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	testPassword = "correct horse battery staple"
	acme         = "Acme"
)

// TestSignup_UserAndWorkspaceCommitTogether: a sign-up creates the user,
// signs them in, creates their workspace and sends one verify mail.
func TestSignup_UserAndWorkspaceCommitTogether(t *testing.T) {
	a, pw, box := newTestApp(t)
	b := newBrowser(t, newHandler(a, pw))

	out := post[signupResponse](t, b, "/signup", fields{"email": aliceEmail, "password": testPassword, "name": "Alice", "workspace": acme}, http.StatusOK)
	if out.User.ID == "" || out.Workspace.Name != acme || !strings.HasPrefix(out.Workspace.ID, workspaceIDPrefix+"_") {
		t.Fatalf("sign-up = %+v", out)
	}
	if !b.hasCookie(authhttp.CookieName) {
		t.Fatal("sign-up set no session cookie")
	}
	list := get[workspacesResponse](t, b, "/workspaces", http.StatusOK)
	if len(list.Workspaces) != 1 || list.Workspaces[0] != out.Workspace {
		t.Fatalf("workspaces = %+v", list)
	}
	if n := box.count(a, aliceEmail); n != 1 {
		t.Fatalf("%d mails to alice, want 1 verify link", n)
	}
}

// TestSignup_FailedWorkspaceRollsBackTheUser: when the workspace insert fails,
// the user and identity the library wrote in the same transaction are rolled
// back, and the verify mail queued for after the commit is never sent.
func TestSignup_FailedWorkspaceRollsBackTheUser(t *testing.T) {
	a, pw, box := newTestApp(t)
	post[none](t, newBrowser(t, newHandler(a, pw)), "/signup", fields{"email": aliceEmail, "password": testPassword, "workspace": acme}, http.StatusOK)

	bob := newBrowser(t, newHandler(a, pw))
	taken := post[errorAnswer](t, bob, "/signup", fields{"email": bobEmail, "password": testPassword, "workspace": acme}, http.StatusConflict)
	if taken.Error.Code != errWorkspaceTaken.Code {
		t.Fatalf("second Acme = %+v", taken.Error)
	}
	if _, err := a.FindIdentity(context.Background(), email.KindEmail, bobEmail, false); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("bob's identity after the rollback: %v, want ErrIdentityNotFound", err)
	}
	if users := countRows(t, a, "SELECT COUNT(*) FROM auth_user"); users != 1 {
		t.Fatalf("%d users, want only alice", users)
	}
	if n := box.count(a, bobEmail); n != 0 {
		t.Fatalf("%d mails to bob for a rolled-back sign-up", n)
	}
	// The session the library issued inside the transaction was rolled back
	// with it, and its effect never reached the response: no cookie at all.
	if bob.hasCookie(authhttp.CookieName) {
		t.Fatal("a rolled-back sign-up set a session cookie")
	}
	get[errorAnswer](t, bob, "/workspaces", http.StatusUnauthorized)

	// Bob can sign up with another name: the failed attempt left nothing behind.
	post[none](t, bob, "/signup", fields{"email": bobEmail, "password": testPassword, "workspace": "Bobco"}, http.StatusOK)
}

// TestSignup_Refusals: the app's own sign-up answers in the library's error
// JSON, and refuses a cross-site form before doing anything.
func TestSignup_Refusals(t *testing.T) {
	a, pw, _ := newTestApp(t)
	b := newBrowser(t, newHandler(a, pw))
	if e := post[errorAnswer](t, b, "/signup", fields{"email": aliceEmail, "password": testPassword, "workspace": "  "}, http.StatusBadRequest); e.Error.Code != errWorkspaceName.Code {
		t.Fatalf("blank workspace = %+v", e.Error)
	}
	b.origin = "https://evil.example"
	if e := post[errorAnswer](t, b, "/signup", fields{"email": aliceEmail, "password": testPassword, "workspace": acme}, http.StatusForbidden); e.Error.Code != auth.ErrOriginNotTrusted.Code {
		t.Fatalf("cross-site sign-up = %+v", e.Error)
	}
	if users := countRows(t, a, "SELECT COUNT(*) FROM auth_user"); users != 0 {
		t.Fatalf("%d users after two refused sign-ups", users)
	}
}

// countRows runs a COUNT query.
func countRows(t *testing.T, a *auth.Auth, query string) int {
	t.Helper()
	var n int
	if err := a.DB().QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// newTestApp builds the app on a fresh SQLite file with a recording mailbox.
func newTestApp(t *testing.T) (*auth.Auth, *password.Plugin, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, pw, err := newAuth(db, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := migrate(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a, pw, box
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

// count returns how many mails went to addr, after every delivery in flight
// finished: mail goes out after the commit, in the background.
func (m *mailbox) count(a *auth.Auth, addr string) int {
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.sent {
		if x.To == addr {
			n++
		}
	}
	return n
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
