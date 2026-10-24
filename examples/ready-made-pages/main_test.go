package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authui"
	"github.com/ubgo/auth/plugin/email"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	newPassword  = "brand new passphrase"
	testName     = "Alice"
)

// TestPages_SignUpVerifySignOutSignInReset drives the forms the way a browser
// does: each GET renders a form, each POST is sent with the app's Origin and
// answers with a redirect, which is checked rather than followed.
func TestPages_SignUpVerifySignOutSignInReset(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	if p := b.get(t, "/"); p.status != http.StatusSeeOther || p.location != dashboardPath {
		t.Fatalf("home: %+v", p)
	}
	if p := b.get(t, dashboardPath); p.status != http.StatusSeeOther || p.location != authui.PathLogin {
		t.Fatalf("dashboard signed out: %+v", p)
	}
	if p := b.get(t, authui.PathSignup); p.status != http.StatusOK || !strings.Contains(p.body, `name="password"`) || !strings.Contains(p.body, "Create account · "+appName) {
		t.Fatalf("sign-up page: %d %s", p.status, p.body)
	}

	if p := b.post(t, authui.PathSignup, url.Values{"name": {testName}, "identifier": {testEmail}, "password": {"short"}}); p.status != http.StatusBadRequest || !strings.Contains(p.body, `value="alice@example.com"`) {
		t.Fatalf("a too-short password must re-render the form with the address kept: %d %s", p.status, p.body)
	}
	if p := b.post(t, authui.PathSignup, url.Values{"name": {testName}, "identifier": {testEmail}, "password": {testPassword}}); p.status != http.StatusSeeOther || p.location != dashboardPath {
		t.Fatalf("sign-up: %+v", p)
	}
	if p := b.get(t, dashboardPath); p.status != http.StatusOK || !strings.Contains(p.body, "Hello, "+testName) {
		t.Fatalf("dashboard: %d %s", p.status, p.body)
	}
	if p := b.get(t, authui.PathSettings); p.status != http.StatusOK || !strings.Contains(p.body, "(this one)") {
		t.Fatalf("settings: %d %s", p.status, p.body)
	}

	// The mailed link opens a page; only its POST spends the token, so a mail
	// scanner that follows links cannot verify an address by itself.
	tok := box.lastToken(t, a, testEmail)
	if p := b.get(t, authui.PathVerify+"?token="+url.QueryEscape(tok)); p.status != http.StatusOK || !strings.Contains(p.body, `name="token"`) {
		t.Fatalf("verify page: %d %s", p.status, p.body)
	}
	if p := b.post(t, authui.PathVerify, url.Values{"token": {tok}}); p.status != http.StatusSeeOther || !strings.Contains(p.location, "verified") {
		t.Fatalf("verify: %+v", p)
	}

	if p := b.post(t, authui.PathLogout, nil); p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, authui.PathLogin) {
		t.Fatalf("sign-out: %+v", p)
	}
	if p := b.post(t, authui.PathLogin, url.Values{"identifier": {testEmail}, "password": {"wrong password!"}}); p.status != http.StatusUnauthorized || !strings.Contains(p.body, "The sign-in details are not right.") {
		t.Fatalf("wrong password: %d %s", p.status, p.body)
	}

	if p := b.post(t, authui.PathForgot, url.Values{"identifier": {testEmail}}); p.status != http.StatusSeeOther {
		t.Fatalf("forgot: %+v", p)
	}
	reset := box.lastToken(t, a, testEmail)
	if p := b.post(t, authui.PathReset, url.Values{"token": {reset}, "password": {newPassword}}); p.status != http.StatusSeeOther {
		t.Fatalf("reset: %+v", p)
	}
	if p := b.post(t, authui.PathLogin, url.Values{"identifier": {testEmail}, "password": {newPassword}}); p.status != http.StatusSeeOther || p.location != dashboardPath {
		t.Fatalf("sign-in with the new password: %+v", p)
	}
}

// TestPages_CrossSiteFormIsRefused: a hostile page that posts the sign-in
// form with the attacker's credentials (login CSRF) is refused, though no
// session cookie exists yet for the pipeline's own check to look at.
func TestPages_CrossSiteFormIsRefused(t *testing.T) {
	a, _ := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	b.post(t, authui.PathSignup, url.Values{"identifier": {testEmail}, "password": {testPassword}})

	evil := newBrowser(t, newHandler(a))
	evil.origin = "https://evil.example"
	if p := evil.post(t, authui.PathLogin, url.Values{"identifier": {testEmail}, "password": {testPassword}}); p.status != http.StatusForbidden || len(p.cookies) != 0 {
		t.Fatalf("cross-site sign-in: %+v", p)
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

// browser is an HTTPS test server and a client with a cookie jar that posts
// forms with the Origin a page of the app would send, and does not follow
// redirects, so each step is checked.
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
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{srv: srv, client: client, origin: baseURL}
}

// pageAnswer is one response as a test inspects it.
type pageAnswer struct {
	status   int
	body     string
	location string
	cookies  []*http.Cookie
}

// get fetches a page.
func (b *browser) get(t *testing.T, path string) pageAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b.do(t, req)
}

// post submits a form with the browser's Origin.
func (b *browser) post(t *testing.T, path string, form url.Values) pageAnswer {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.origin)
	return b.do(t, req)
}

func (b *browser) do(t *testing.T, req *http.Request) pageAnswer {
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
	return pageAnswer{status: res.StatusCode, body: buf.String(), location: res.Header.Get("Location"), cookies: res.Cookies()}
}
