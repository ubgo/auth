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
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/terms"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	testPassword = "correct horse battery staple"
	// staleTerms is a version the app no longer shows.
	staleTerms = "2025-01"
)

// TestTerms_AcceptedAtSignUpThenOnBump: Alice's sign-up form sends the current
// version, so she reaches the dashboard at once; Bob's form showed an old
// version, so nothing is recorded and he is refused until he accepts the
// current one through the plugin's route.
func TestTerms_AcceptedAtSignUpThenOnBump(t *testing.T) {
	a, tm := newTestApp(t)
	h := newHandler(a, tm)
	ctx := context.Background()

	if v := get[termsResponse](t, newBrowser(t, h), "/terms", nil, http.StatusOK); v.Version != currentTerms || v.Header != terms.TermsHeader {
		t.Fatalf("GET /terms = %+v", v)
	}

	alice := newBrowser(t, h)
	aliceUp := post[signUpAnswer](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}, http.Header{terms.TermsHeader: {currentTerms}}, http.StatusOK)
	if ok, err := tm.Accepted(ctx, aliceUp.User.ID); err != nil || !ok {
		t.Fatalf("Accepted(alice) = %v %v after a sign-up that sent the current version", ok, err)
	}
	if d := get[dashboardResponse](t, alice, "/dashboard", nil, http.StatusOK); d.Hello != "Alice" {
		t.Fatalf("dashboard = %+v", d)
	}

	bob := newBrowser(t, h)
	bobUp := post[signUpAnswer](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword, "name": "Bob"}, http.Header{terms.TermsHeader: {staleTerms}}, http.StatusOK)
	if ok, err := tm.Accepted(ctx, bobUp.User.ID); err != nil || ok {
		t.Fatalf("Accepted(bob) = %v %v after a sign-up that sent a stale version", ok, err)
	}
	if e := get[errorAnswer](t, bob, "/dashboard", nil, http.StatusForbidden); e.Error.Code != terms.ErrNotAccepted.Code {
		t.Fatalf("bob on the dashboard: %+v", e.Error)
	}
	if e := post[errorAnswer](t, bob, "/auth/terms/accept", terms.AcceptRequest{Version: staleTerms}, nil, http.StatusConflict); e.Error.Code != terms.ErrStale.Code {
		t.Fatalf("accepting a stale version: %+v", e.Error)
	}
	post[auth.Done](t, bob, "/auth/terms/accept", terms.AcceptRequest{Version: currentTerms}, nil, http.StatusOK)
	if d := get[dashboardResponse](t, bob, "/dashboard", nil, http.StatusOK); d.Hello != "Bob" {
		t.Fatalf("dashboard after accepting = %+v", d)
	}

	// Signed out, the dashboard is 401 before the terms are even considered.
	get[errorAnswer](t, newBrowser(t, h), "/dashboard", nil, http.StatusUnauthorized)
}

// signUpAnswer is the part of the sign-up answer the test reads.
type signUpAnswer struct {
	User auth.UserView `json:"user"`
}

// newTestApp builds the app on a fresh SQLite file with a mailbox that
// records mail instead of printing it.
func newTestApp(t *testing.T) (*auth.Auth, *terms.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, tm, err := newAuth(db, &mailbox{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, tm
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

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin and extra headers, checks
// the status and decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, extra http.Header, status int) Out {
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
	return do[Out](t, b, req, extra, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, extra http.Header, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, extra, status)
}

// do sends req with extra headers, checks the status and decodes the answer.
func do[Out any](t *testing.T, b *browser, req *http.Request, extra http.Header, status int) Out {
	t.Helper()
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
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
