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
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
)

const (
	address    = "alice@example.com"
	newAddress = "alice@work.example"
	secret     = "correct horse battery staple"
	// wrongCode is never a code the plugin mails: codes are six digits.
	wrongCode = "12345"
)

// TestEmailVerifyCode_SignUpVerifyChange walks the whole flow: sign-up mails a
// code and no link, a wrong code is refused, the right one verifies the
// address, and a change mails a code to the new address that the signed-in
// user confirms, while the old address gets an undo link.
func TestEmailVerifyCode_SignUpVerifyChange(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[auth.Done](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)

	mail := box.last(a, address)
	if strings.Contains(mail.Text, "http") {
		t.Fatalf("verify mail carries a link under VerifyByCode:\n%s", mail.Text)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Email != "" {
		t.Fatalf("/me before verify = %+v, want no verified address", me)
	}
	if e := post[errorAnswer](t, b, "/auth/email/verify-code", fields{"email": address, "code": wrongCode}, http.StatusBadRequest); e.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("wrong code = %+v", e.Error)
	}
	got := post[email.VerifyResult](t, b, "/auth/email/verify-code", fields{"email": address, "code": box.code(t, a, address)}, http.StatusOK)
	if got.Email != address {
		t.Fatalf("verify-code = %+v", got)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Email != address {
		t.Fatalf("/me after verify = %+v", me)
	}

	post[auth.Done](t, b, "/auth/email/change", fields{"email": newAddress}, http.StatusOK)
	code := box.code(t, a, newAddress)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Email != address {
		t.Fatalf("/me before the change is confirmed = %+v, want the old address", me)
	}
	post[email.VerifyResult](t, b, "/auth/email/confirm-change-code", fields{"email": newAddress, "code": code}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Email != newAddress {
		t.Fatalf("/me after the change = %+v", me)
	}
	if undo := box.last(a, address); !strings.Contains(undo.Text, baseURL+"/undo-email-change?token=") {
		t.Fatalf("the old address got no undo link:\n%s", undo.Text)
	}
}

// TestEmailVerifyCode_SignedOut: a code verifies the address as typed with no
// session (the person opened the mail on another device), and an unknown
// address answers exactly as a wrong code does.
func TestEmailVerifyCode_SignedOut(t *testing.T) {
	a, box := newTestAuth(t)
	post[auth.Done](t, newBrowser(t, newHandler(a)), "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)

	other := newBrowser(t, newHandler(a))
	if e := post[errorAnswer](t, other, "/auth/email/verify-code", fields{"email": "nobody@example.com", "code": box.code(t, a, address)}, http.StatusBadRequest); e.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("unknown address = %+v, want the wrong-code answer", e.Error)
	}
	post[email.VerifyResult](t, other, "/auth/email/verify-code", fields{"email": address, "code": box.code(t, a, address)}, http.StatusOK)
	in := newBrowser(t, newHandler(a))
	post[auth.Done](t, in, "/auth/password/sign-in", fields{"identifier": address, "password": secret}, http.StatusOK)
	if me := get[meResponse](t, in, "/me", http.StatusOK); me.Email != address {
		t.Fatalf("/me = %+v, want the address verified while signed out", me)
	}
}

// TestEmailVerifyCode_GuessesSpendTheCode: after maxAttempts wrong guesses the
// code is spent, and even the right one is refused.
func TestEmailVerifyCode_GuessesSpendTheCode(t *testing.T) {
	a, box := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[auth.Done](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)
	code := box.code(t, a, address)
	for range maxAttempts {
		post[errorAnswer](t, b, "/auth/email/verify-code", fields{"email": address, "code": wrongCode}, http.StatusBadRequest)
	}
	if e := post[errorAnswer](t, b, "/auth/email/verify-code", fields{"email": address, "code": code}, http.StatusBadRequest); e.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("the right code after %d wrong guesses = %+v, want refused", maxAttempts, e.Error)
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

// last returns the newest mail to address, after deliveries finished.
func (m *mailbox) last(a *auth.Auth, address string) email.Mail {
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == address {
			return m.sent[i]
		}
	}
	return email.Mail{}
}

// codeInMail finds the six-digit code in a mail.
var codeInMail = regexp.MustCompile(`\b\d{6}\b`)

// code returns the code in the newest mail to address.
func (m *mailbox) code(t *testing.T, a *auth.Auth, address string) string {
	t.Helper()
	code := codeInMail.FindString(m.last(a, address).Text)
	if code == "" {
		t.Fatalf("no code mailed to %s", address)
	}
	return code
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
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

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

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

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, fails the test on any other status, and decodes the answer.
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
