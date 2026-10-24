package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/lastlogin"
	"github.com/ubgo/auth/plugin/magiclink"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery"
)

// TestLastLogin_MeSaysHowTheUserSignedIn: after a password sign-up /me says
// "password"; after a magic link it says "magiclink", with a later time.
func TestLastLogin_MeSaysHowTheUserSignedIn(t *testing.T) {
	a, ll, box := newTestAuth(t)
	b := newBrowser(t, newHandler(a, ll))

	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	first := get[meResponse](t, b, "/me")
	if first.LastMethod != password.PluginName || first.LastAt == nil {
		t.Fatalf("after sign-up /me = %+v", first)
	}

	// A magic link goes only to a verified address: verify it first.
	post[email.VerifyResult](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, testEmail, email.DefaultVerifyPage)}, http.StatusOK)
	post[auth.Done](t, b, "/auth/magiclink/send", fields{"identifier": testEmail}, http.StatusOK)
	post[magiclink.SignInResult](t, b, "/auth/magiclink/sign-in", fields{"token": box.lastToken(t, a, testEmail, magiclink.DefaultPage)}, http.StatusOK)
	second := get[meResponse](t, b, "/me")
	if second.LastMethod != magiclink.PluginName || second.LastAt == nil || second.LastAt.Before(*first.LastAt) {
		t.Fatalf("after a magic link /me = %+v", second)
	}
	if got, err := ll.Of(context.Background(), second.ID); err != nil || got.LastLoginMethod != magiclink.PluginName {
		t.Fatalf("Of = %+v %v", got, err)
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox.
func newTestAuth(t *testing.T) (*auth.Auth, *lastlogin.Plugin, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, ll, err := newAuth(db, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, ll, box
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

// lastToken returns the token of the newest link to page mailed to addr.
// Mail goes out in the background, so a verify link may land after a magic
// link; matching the page picks the right one.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr, page string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if strings.HasPrefix(field, baseURL+page) {
				u, err := url.Parse(field)
				if err != nil {
					t.Fatal(err)
				}
				return u.Query().Get("token")
			}
		}
	}
	t.Fatalf("no %s link mailed to %s", page, addr)
	return ""
}

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

// post sends in as JSON with the app's Origin, checks the status and decodes
// the answer as Out.
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
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}
