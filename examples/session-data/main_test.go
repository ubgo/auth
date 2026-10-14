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
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/sessiondata"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery"
	testAgent    = "example-test/1.0"
)

// TestSessionData_MeShowsBothKinds: after sign-up /me shows the default
// workspace (inline, from the hook) and the device (the plugin's row, from
// the sign-in); /workspace changes the inline value for every later request,
// and sign-out removes the plugin's row with the session.
func TestSessionData_MeShowsBothKinds(t *testing.T) {
	a, sd := newTestAuth(t)
	b := newBrowser(t, newHandler(a, sd))

	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	first := get[meResponse](t, b, "/me")
	if first.Workspace != defaultWorkspace || first.Device == nil || first.Device.UserAgent != testAgent || first.Device.SignedInAt.IsZero() {
		t.Fatalf("after sign-up /me = %+v", first)
	}

	post[auth.Done](t, b, "/workspace", fields{"workspace": "acme"}, http.StatusOK)
	second := get[meResponse](t, b, "/me")
	if second.Workspace != "acme" || second.Device == nil || !second.Device.SignedInAt.Equal(first.Device.SignedInAt) {
		t.Fatalf("after /workspace /me = %+v", second)
	}
	post[auth.Done](t, b, "/workspace", fields{}, http.StatusBadRequest)

	// The row belongs to the session: sign-out removes it, and a new sign-in
	// starts over with the defaults.
	post[auth.Done](t, b, "/auth/sign-out", fields{}, http.StatusOK)
	var n int
	if err := a.DB().QueryRow("SELECT COUNT(*) FROM " + a.TableName(sessiondata.TableData)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("plugin rows after sign-out = %d, %v; want 0", n, err)
	}
	post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	if third := get[meResponse](t, b, "/me"); third.Workspace != defaultWorkspace || third.Device == nil {
		t.Fatalf("after a new sign-in /me = %+v", third)
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file.
func newTestAuth(t *testing.T) (*auth.Auth, *sessiondata.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, sd, err := newAuth(db, discardMailer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, sd
}

// discardMailer drops every mail: this example never follows a link.
type discardMailer struct{}

func (discardMailer) Send(context.Context, email.Mail) error { return nil }

// browser is an HTTPS test server and a client with a cookie jar.
type browser struct {
	srv    *httptest.Server
	client *http.Client
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
	return &browser{srv: srv, client: client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// post sends in as JSON with the app's Origin and user agent, checks the
// status and decodes the answer as Out.
func post[Out any](t *testing.T, b *browser, path string, in fields, status int) Out {
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
	req.Header.Set("Origin", baseURL)
	return do[Out](t, b, req, status)
}

// get fetches path and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, http.StatusOK)
}

func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
	req.Header.Set("User-Agent", testAgent)
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
	var out Out
	if status == http.StatusOK {
		if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
		}
	}
	return out
}
