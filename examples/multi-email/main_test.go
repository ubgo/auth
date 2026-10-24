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
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	homeEmail    = "alice@example.com"
	workEmail    = "alice@work.example"
	bobEmail     = "bob@example.com"
	thiefEmail   = "mallory@evil.example"
	testPassword = "correct horse battery staple"
)

// TestMultiEmail walks the GitHub-style flow over HTTP: add a second address,
// fail to make it primary before it is verified, verify it, make it primary,
// remove the old one, and fail to remove the last one.
func TestMultiEmail(t *testing.T) {
	a, box := newTestAuth(t)
	alice := newBrowser(t, newHandler(a))

	up := post[password.SignInResult](t, alice, "/auth/password/sign-up", fields{"identifier": homeEmail, "password": testPassword}, http.StatusOK)
	post[email.VerifyResult](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, homeEmail)}, http.StatusOK)

	post[auth.Done](t, alice, "/auth/email/add", fields{"email": workEmail}, http.StatusOK)
	early := post[errorAnswer](t, alice, "/auth/email/make-primary", fields{"email": workEmail}, http.StatusConflict)
	if early.Error.Code != auth.ErrNotVerified.Code {
		t.Fatalf("make-primary before verify = %+v", early.Error)
	}

	if v := post[email.VerifyResult](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, workEmail)}, http.StatusOK); v.Email != workEmail {
		t.Fatalf("verify work = %+v", v)
	}
	post[auth.Done](t, alice, "/auth/email/make-primary", fields{"email": workEmail}, http.StatusOK)
	post[auth.Done](t, alice, "/auth/email/remove", fields{"email": homeEmail}, http.StatusOK)

	list := get[email.ListResult](t, alice, "/auth/email/list", http.StatusOK)
	want := []email.Address{{Email: workEmail, Verified: true, Primary: true}}
	if len(list.Addresses) != 1 || list.Addresses[0] != want[0] {
		t.Fatalf("list = %+v, want %+v", list.Addresses, want)
	}

	// auth_user keeps a copy of the primary address, for the app's queries.
	var cols email.EmailColumns
	if err := a.LoadUserColumns(context.Background(), up.User.ID, email.Bindings(&cols)...); err != nil {
		t.Fatal(err)
	}
	if cols.PrimaryEmail == nil || *cols.PrimaryEmail != workEmail || cols.EmailVerifiedAt == nil {
		t.Fatalf("auth_user primary = %v verified %v", cols.PrimaryEmail, cols.EmailVerifiedAt)
	}

	last := post[errorAnswer](t, alice, "/auth/email/remove", fields{"email": workEmail}, http.StatusConflict)
	if last.Error.Code != auth.ErrLastSignInMethod.Code {
		t.Fatalf("remove the last address = %+v", last.Error)
	}

	// The old address can sign in no more; the new one can.
	post[errorAnswer](t, newBrowser(t, newHandler(a)), "/auth/password/sign-in", fields{"identifier": homeEmail, "password": testPassword}, http.StatusUnauthorized)
	post[none](t, newBrowser(t, newHandler(a)), "/auth/password/sign-in", fields{"identifier": workEmail, "password": testPassword}, http.StatusOK)
}

// TestMultiEmail_AddressVerifiedElsewhereIsTaken: bob may add alice's
// verified address and is answered as for any other, but no verify link is
// mailed: alice's inbox gets the duplicate sign-up notice, and her own old
// link stays spent.
func TestMultiEmail_AddressVerifiedElsewhereIsTaken(t *testing.T) {
	a, box := newTestAuth(t)
	alice, bob := newBrowser(t, newHandler(a)), newBrowser(t, newHandler(a))
	post[none](t, alice, "/auth/password/sign-up", fields{"identifier": homeEmail, "password": testPassword}, http.StatusOK)
	link := box.lastToken(t, a, homeEmail)
	post[none](t, alice, "/auth/email/verify", fields{"token": link}, http.StatusOK)

	post[none](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword}, http.StatusOK)
	post[auth.Done](t, bob, "/auth/email/add", fields{"email": homeEmail}, http.StatusOK)
	if got := box.lastToken(t, a, homeEmail); got != link {
		t.Fatal("bob's add mailed alice a new verify link")
	}
	if last := box.last(homeEmail); !strings.HasPrefix(last.Subject, "Someone tried to sign up") {
		t.Fatalf("last mail to alice = %q, want the duplicate sign-up notice", last.Subject)
	}
}

// last returns the newest mail sent to addr, after deliveries finish.
func (m *mailbox) last(addr string) email.Mail {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == addr {
			return m.sent[i]
		}
	}
	return email.Mail{}
}

// TestMultiEmail_ChangeWithUndo is the stolen-account path: someone signed in
// as alice changes the address to one they own and confirms it from their
// inbox. alice's old address gets an undo link; following it makes her
// address primary again, deletes the thief's, and ends every session,
// including the thief's.
func TestMultiEmail_ChangeWithUndo(t *testing.T) {
	a, box := newTestAuth(t)
	alice, thief := newBrowser(t, newHandler(a)), newBrowser(t, newHandler(a))
	post[none](t, alice, "/auth/password/sign-up", fields{"identifier": homeEmail, "password": testPassword}, http.StatusOK)
	post[none](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, homeEmail)}, http.StatusOK)
	post[none](t, thief, "/auth/password/sign-in", fields{"identifier": homeEmail, "password": testPassword}, http.StatusOK)

	// Nothing changes until the link mailed to the new address is used.
	post[auth.Done](t, thief, "/auth/email/change", fields{"email": thiefEmail}, http.StatusOK)
	if got := get[email.ListResult](t, thief, "/auth/email/list", http.StatusOK); len(got.Addresses) != 1 {
		t.Fatalf("list before confirm = %+v", got.Addresses)
	}
	if c := post[email.VerifyResult](t, thief, "/auth/email/confirm-change", fields{"token": box.lastToken(t, a, thiefEmail)}, http.StatusOK); c.Email != thiefEmail {
		t.Fatalf("confirm-change = %+v", c)
	}
	changed := get[email.ListResult](t, thief, "/auth/email/list", http.StatusOK)
	wantChanged := []email.Address{{Email: homeEmail, Verified: true}, {Email: thiefEmail, Verified: true, Primary: true}}
	if !sameAddresses(changed.Addresses, wantChanged) {
		t.Fatalf("list after confirm = %+v, want %+v", changed.Addresses, wantChanged)
	}

	// The undo link went to the old address; opening it needs no session.
	post[auth.Done](t, newBrowser(t, newHandler(a)), "/auth/email/undo-change", fields{"token": box.lastToken(t, a, homeEmail)}, http.StatusOK)

	get[errorAnswer](t, thief, "/auth/session", http.StatusUnauthorized)
	get[errorAnswer](t, alice, "/auth/session", http.StatusUnauthorized)
	post[errorAnswer](t, newBrowser(t, newHandler(a)), "/auth/password/sign-in", fields{"identifier": thiefEmail, "password": testPassword}, http.StatusUnauthorized)

	post[none](t, alice, "/auth/password/sign-in", fields{"identifier": homeEmail, "password": testPassword}, http.StatusOK)
	restored := get[email.ListResult](t, alice, "/auth/email/list", http.StatusOK)
	if want := []email.Address{{Email: homeEmail, Verified: true, Primary: true}}; !sameAddresses(restored.Addresses, want) {
		t.Fatalf("list after undo = %+v, want %+v", restored.Addresses, want)
	}

	// An undo link works once.
	reused := post[errorAnswer](t, alice, "/auth/email/undo-change", fields{"token": box.lastToken(t, a, homeEmail)}, http.StatusBadRequest)
	if reused.Error.Code != auth.ErrTokenInvalid.Code {
		t.Fatalf("undo twice = %+v", reused.Error)
	}
}

// sameAddresses compares two address lists regardless of order.
func sameAddresses(got, want []email.Address) bool {
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			return false
		}
	}
	return true
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
