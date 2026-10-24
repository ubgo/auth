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
	"regexp"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
)

const (
	// typedAddress is the address as a person types it; address is how the
	// library stores it and mails it.
	typedAddress = " Alice@Example.com"
	address      = "alice@example.com"
	// wrongCode is never a code the plugin sends: codes are six digits.
	wrongCode = "12345"
)

// TestEmailCodes_CodeCreatesThenFindsTheAccount: the first code creates the
// account with a verified address and a welcome mail; the next code signs in
// to the same account, and no second welcome is sent.
func TestEmailCodes_CodeCreatesThenFindsTheAccount(t *testing.T) {
	a, mail := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	post[auth.Done](t, b, "/auth/email/send-code", fields{"email": typedAddress}, http.StatusOK)
	first := post[email.CodeSignInResult](t, b, "/auth/email/sign-in-code", fields{"email": typedAddress, "code": mail.lastCode(t, a, address)}, http.StatusOK)
	if !first.Created || first.User.ID == "" {
		t.Fatalf("first sign-in = %+v, want a created user", first)
	}
	if !b.hasCookie(authhttp.CookieName) {
		t.Fatal("sign-in set no session cookie")
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.ID != first.User.ID || me.Email != address {
		t.Fatalf("/me = %+v", me)
	}
	if n := mail.subjects(a, address, "Welcome"); n != 1 {
		t.Fatalf("%d welcome mails after the first sign-in, want 1", n)
	}

	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	post[auth.Done](t, b, "/auth/email/send-code", fields{"email": address}, http.StatusOK)
	again := post[email.CodeSignInResult](t, b, "/auth/email/sign-in-code", fields{"email": address, "code": mail.lastCode(t, a, address)}, http.StatusOK)
	if again.Created || again.User.ID != first.User.ID {
		t.Fatalf("second sign-in = %+v, want the same user %s", again, first.User.ID)
	}
	if n := mail.subjects(a, address, "Welcome"); n != 1 {
		t.Fatalf("%d welcome mails after the second sign-in, want still 1", n)
	}
}

// TestEmailCodes_Refusals: a wrong code is refused, a code works once, and
// a value that is not an address gets the same OK as any other without a mail.
func TestEmailCodes_Refusals(t *testing.T) {
	a, mail := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	post[auth.Done](t, b, "/auth/email/send-code", fields{"email": address}, http.StatusOK)
	code := mail.lastCode(t, a, address)
	if e := post[errorAnswer](t, b, "/auth/email/sign-in-code", fields{"email": address, "code": wrongCode}, http.StatusBadRequest); e.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("wrong code = %+v", e.Error)
	}
	post[email.CodeSignInResult](t, b, "/auth/email/sign-in-code", fields{"email": address, "code": code}, http.StatusOK)
	if e := post[errorAnswer](t, b, "/auth/email/sign-in-code", fields{"email": address, "code": code}, http.StatusBadRequest); e.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("reused code = %+v", e.Error)
	}

	before := mail.count(a)
	post[auth.Done](t, b, "/auth/email/send-code", fields{"email": "not an address"}, http.StatusOK)
	if n := mail.count(a); n != before {
		t.Fatalf("a non-address got %d mails", n-before)
	}
}

// TestEmailCodes_WithoutCodesNobodyCanSignIn: the same plugin without a code
// option signs nobody in, and auth.New refuses the configuration at start-up.
func TestEmailCodes_WithoutCodesNobodyCanSignIn(t *testing.T) {
	_, err := auth.New(
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(&mailbox{}))),
	)
	if !errors.Is(err, auth.ErrNoSignInMethod) {
		t.Fatalf("auth.New = %v, want %v", err, auth.ErrNoSignInMethod)
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

// Send records the mail.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// codeInText finds the six-digit code in a mail.
var codeInText = regexp.MustCompile(`\b\d{6}\b`)

// lastCode returns the code in the newest mail to addr. Mail goes out after
// the transaction commits, so it waits for deliveries first.
func (m *mailbox) lastCode(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == addr {
			if code := codeInText.FindString(m.sent[i].Text); code != "" {
				return code
			}
		}
	}
	t.Fatalf("no code mailed to %s", addr)
	return ""
}

// subjects counts the mails to addr with the given subject.
func (m *mailbox) subjects(a *auth.Auth, addr, subject string) int {
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.sent {
		if x.To == addr && x.Subject == subject {
			n++
		}
	}
	return n
}

// count returns how many mails were sent, after deliveries finished.
func (m *mailbox) count(a *auth.Auth) int {
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
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
