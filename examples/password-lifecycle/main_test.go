package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	// aliceEmail is the account the lifecycle runs on.
	aliceEmail = "alice@example.com"
	// bobEmail has a password nobody sprays.
	bobEmail = "bob@example.com"
	// testSecret is the deployment secret, exactly auth.MinSecretSize bytes.
	testSecret = "0123456789abcdef0123456789abcdef"
	// The passwords alice moves through, oldest first.
	firstPassword  = "first-long-password"
	secondPassword = "second-long-password"
	thirdPassword  = "third-long-password"
	fourthPassword = "fourth-long-password"
	// bobPassword is bob's own password.
	bobPassword = "bob-has-his-own-password"
	// sprayedPassword is the common password an attacker tries on many accounts.
	sprayedPassword = "Winter2026!"
	// wrongPassword is a password nobody has.
	wrongPassword = "not-the-password"
	// clockStep moves the clock past maxPasswordAge.
	clockStep = time.Hour
	// minCodeLength is the shortest run of digits read as a mailed code.
	minCodeLength = 6
)

// TestPasswordLifecycle_HistoryResetAndExpiry walks one password through its
// life: a change back to a remembered password is refused, a reset by mailed
// code works without any link, an aged password is refused only to its owner
// and is changed through change-expired, which refuses the same password
// again and signs in with a new one.
func TestPasswordLifecycle_HistoryResetAndExpiry(t *testing.T) {
	// The clock starts at the real time: the cookie jar drops a session
	// cookie whose expiry is in the real past.
	clock := &fakeClock{now: time.Now()}
	a, box := newTestAuth(t, clock)
	srv := newServer(t, newHandler(a))
	alice := newBrowser(t, srv)

	post[password.SignInResult](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": firstPassword}, http.StatusOK)
	post[email.VerifyResult](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)

	post[none](t, alice, "/auth/password/change", fields{"current": firstPassword, "new": secondPassword}, http.StatusOK)
	back := post[errorAnswer](t, alice, "/auth/password/change", fields{"current": secondPassword, "new": firstPassword}, http.StatusBadRequest)
	if back.Error.Code != password.ErrReused.Code {
		t.Fatalf("change back to a remembered password = %+v, want %s", back.Error, password.ErrReused.Code)
	}

	post[password.ForgotResult](t, alice, "/auth/password/forgot", fields{"identifier": aliceEmail}, http.StatusOK)
	code := box.lastCode(t, a, aliceEmail)
	post[none](t, alice, "/auth/password/reset-code", fields{"identifier": aliceEmail, "code": code, "password": thirdPassword}, http.StatusOK)
	post[password.SignInResult](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": thirdPassword}, http.StatusOK)

	clock.advance(maxPasswordAge + clockStep)
	expired := post[errorAnswer](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": thirdPassword}, http.StatusForbidden)
	if expired.Error.Code != password.ErrExpired.Code {
		t.Fatalf("sign-in with an aged password = %+v, want %s", expired.Error, password.ErrExpired.Code)
	}
	wrong := post[errorAnswer](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": wrongPassword}, http.StatusUnauthorized)
	if wrong.Error.Code != password.ErrInvalidCredentials.Code {
		t.Fatalf("a wrong password on an expired account = %+v: only the right password may learn it expired", wrong.Error)
	}
	same := post[errorAnswer](t, alice, "/auth/password/change-expired", fields{"identifier": aliceEmail, "current": thirdPassword, "new": thirdPassword}, http.StatusBadRequest)
	if same.Error.Code != password.ErrReused.Code {
		t.Fatalf("change-expired to the same password = %+v", same.Error)
	}
	in := post[password.SignInResult](t, alice, "/auth/password/change-expired", fields{"identifier": aliceEmail, "current": thirdPassword, "new": fourthPassword}, http.StatusOK)
	if got := get[meResponse](t, alice, "/me", http.StatusOK); got.ID != in.User.ID {
		t.Fatalf("/me after change-expired = %+v, want %s", got, in.User.ID)
	}
}

// TestPasswordLifecycle_SprayedPasswordIsRefused: one password that failed on
// sprayFailures different accounts is refused for every account, before it is
// checked, while other passwords keep working.
func TestPasswordLifecycle_SprayedPasswordIsRefused(t *testing.T) {
	a, _ := newTestAuth(t, &fakeClock{now: time.Now()})
	srv := newServer(t, newHandler(a))
	bob, attacker := newBrowser(t, srv), newBrowser(t, srv)
	post[password.SignInResult](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": bobPassword}, http.StatusOK)

	for i := range sprayFailures {
		victim := fmt.Sprintf("user%d@example.com", i)
		post[errorAnswer](t, attacker, "/auth/password/sign-in", fields{"identifier": victim, "password": sprayedPassword}, http.StatusUnauthorized)
	}
	refused := post[errorAnswer](t, attacker, "/auth/password/sign-in", fields{"identifier": bobEmail, "password": sprayedPassword}, http.StatusTooManyRequests)
	if refused.Error.Code != auth.ErrRateLimited.Code {
		t.Fatalf("the sprayed password after %d failures = %+v, want %s", sprayFailures, refused.Error, auth.ErrRateLimited.Code)
	}
	post[password.SignInResult](t, bob, "/auth/password/sign-in", fields{"identifier": bobEmail, "password": bobPassword}, http.StatusOK)
}

// fakeClock is a settable clock for auth.WithClock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the clock's time.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves the clock forward by d.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// that records mail instead of printing it, on clock.
func newTestAuth(t *testing.T, clock *fakeClock) (*auth.Auth, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, err := newAuth(db, []byte(testSecret), box, clock.Now)
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

// lastWord returns the first word of the newest mail to addr that match
// accepts. Mail goes out after the transaction commits, so it waits for
// deliveries first.
func (m *mailbox) lastWord(t *testing.T, a *auth.Auth, addr string, match func(string) bool) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, w := range strings.Fields(m.sent[i].Text) {
			if match(w) {
				return w
			}
		}
	}
	t.Fatalf("no matching mail to %s", addr)
	return ""
}

// lastToken returns the token of the newest link mailed to addr.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	link := m.lastWord(t, a, addr, func(w string) bool { return strings.HasPrefix(w, baseURL) })
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("token")
}

// lastCode returns the newest code mailed to addr: a run of digits.
func (m *mailbox) lastCode(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	return strings.TrimSuffix(m.lastWord(t, a, addr, func(w string) bool { return isCode(strings.TrimSuffix(w, ".")) }), ".")
}

// isCode reports whether w is a run of at least minCodeLength digits.
func isCode(w string) bool {
	if len(w) < minCodeLength {
		return false
	}
	for _, r := range w {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// newServer serves h over TLS, because the session and poll cookies are
// __Host- and Secure, and a cookie jar keeps such a cookie only for an https
// URL.
func newServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// browser is a client with its own cookie jar that sends the Origin a page of
// the app would; two browsers on one server are two devices.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser is a fresh device on srv.
func newBrowser(t *testing.T, srv *httptest.Server) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: srv.Client().Transport, Jar: jar}
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// none is the request body of a route that takes no input.
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
