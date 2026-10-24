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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	// aliceEmail to erinEmail are the test accounts; after one is revoked,
	// alice, carol and dave fill maxDeviceAccounts and erin is one too many.
	aliceEmail = "alice@example.com"
	bobEmail   = "bob@example.com"
	carolEmail = "carol@example.com"
	daveEmail  = "dave@example.com"
	erinEmail  = "erin@example.com"
	// testPassword is every test account's password.
	testPassword = "correct horse battery staple"
	// newTimezone is the value the profile update writes.
	newTimezone = "Asia/Kolkata"
	// paidPlan is the plan the app sets from its own code.
	paidPlan = "pro"
	// clockStart is where the test clock starts; any fixed time works.
	clockStart = "2026-10-09T10:00:00Z"
	// staleBy is how far past freshWindow the clock is moved so the sign-in
	// is no longer recent enough to delete.
	staleBy = time.Minute
)

// TestProfile_UpdatesListedFieldAndRefusesOthers: the user writes their own
// time zone, and neither the app-only plan column nor an undeclared name can
// be set; a refused update writes nothing at all.
func TestProfile_UpdatesListedFieldAndRefusesOthers(t *testing.T) {
	a, _, _ := newTestAuth(t, deleteAtOnce)
	b := newBrowser(t, newHandler(a))
	signUp(t, b, aliceEmail)

	fresh := get[meResponse](t, b, mePath, http.StatusOK)
	if fresh.Timezone != defaultTimezone || fresh.Plan != defaultPlan {
		t.Fatalf("new account = %+v, want the column defaults", fresh)
	}
	post[auth.UserView](t, b, "/auth/profile", profile{Name: "Alice", Fields: map[string]string{colTimezone: newTimezone}}, http.StatusOK)
	if got := get[meResponse](t, b, mePath, http.StatusOK); got.Timezone != newTimezone || got.Name != "Alice" {
		t.Fatalf("after update = %+v, want timezone %q", got, newTimezone)
	}

	for _, col := range []string{colPlan, "role"} {
		bad := post[errorAnswer](t, b, "/auth/profile", profile{Name: "Mallory", Fields: map[string]string{col: paidPlan}}, http.StatusBadRequest)
		if bad.Error.Code != auth.ErrFieldInvalid.Code {
			t.Fatalf("setting %q = %+v, want %s", col, bad.Error, auth.ErrFieldInvalid.Code)
		}
	}
	if got := get[meResponse](t, b, mePath, http.StatusOK); got.Plan != defaultPlan || got.Name != "Alice" {
		t.Fatalf("after refused updates = %+v, want nothing written", got)
	}

	// The app, not the user, writes the plan: from its own billing code.
	if err := auth.SetUserColumn(context.Background(), a, auth.AppName, fresh.ID, Plan, paidPlan); err != nil {
		t.Fatal(err)
	}
	if got := get[meResponse](t, b, mePath, http.StatusOK); got.Plan != paidPlan {
		t.Fatalf("after the app set the plan = %+v, want %q", got, paidPlan)
	}
}

// TestDeviceSessions_SwitchRevokeAndCap: two accounts on one browser are
// listed with the active one first, switching changes who /me is, revoking
// the other leaves one, and a sign-in past maxDeviceAccounts is refused.
func TestDeviceSessions_SwitchRevokeAndCap(t *testing.T) {
	a, _, _ := newTestAuth(t, deleteAtOnce)
	b := newBrowser(t, newHandler(a))
	alice := signUp(t, b, aliceEmail)
	bob := signUp(t, b, bobEmail)
	if got := b.cookiesWithPrefix(authhttp.AccountCookiePrefix); got != 1 {
		t.Fatalf("account cookies = %d, want 1 holding alice while bob is active", got)
	}

	list := get[auth.DeviceSessionsResult](t, b, "/auth/device-sessions", http.StatusOK)
	if len(list.Sessions) != 2 || !list.Sessions[0].Active || list.Sessions[0].User.ID != bob || list.Sessions[1].User.ID != alice {
		t.Fatalf("device sessions = %+v, want bob active then alice", list.Sessions)
	}
	aliceSession := list.Sessions[1].ID

	post[auth.Done](t, b, "/auth/device-sessions/switch", fields{"id": aliceSession}, http.StatusOK)
	if got := get[meResponse](t, b, mePath, http.StatusOK); got.ID != alice {
		t.Fatalf("after switch /me = %s, want alice %s", got.ID, alice)
	}
	list = get[auth.DeviceSessionsResult](t, b, "/auth/device-sessions", http.StatusOK)
	bobSession := list.Sessions[1].ID
	post[auth.Done](t, b, "/auth/device-sessions/revoke", fields{"id": bobSession}, http.StatusOK)
	if list = get[auth.DeviceSessionsResult](t, b, "/auth/device-sessions", http.StatusOK); len(list.Sessions) != 1 {
		t.Fatalf("after revoking bob = %+v, want alice alone", list.Sessions)
	}
	gone := post[errorAnswer](t, b, "/auth/device-sessions/switch", fields{"id": bobSession}, http.StatusNotFound)
	if gone.Error.Code != auth.ErrDeviceSessionNotFound.Code {
		t.Fatalf("switching to a revoked account = %+v", gone.Error)
	}

	signUp(t, b, carolEmail)
	signUp(t, b, daveEmail)
	capped := post[errorAnswer](t, b, "/auth/password/sign-up", fields{"identifier": erinEmail, "password": testPassword}, http.StatusConflict)
	if capped.Error.Code != auth.ErrTooManyDeviceSessions.Code {
		t.Fatalf("sign-up past the cap = %+v, want %s", capped.Error, auth.ErrTooManyDeviceSessions.Code)
	}
	if list = get[auth.DeviceSessionsResult](t, b, "/auth/device-sessions", http.StatusOK); len(list.Sessions) != maxDeviceAccounts {
		t.Fatalf("after the refused sign-up the device holds %d accounts, want %d", len(list.Sessions), maxDeviceAccounts)
	}
}

// TestSessions_RevokeOtherIsArchived: from one browser Alice ends her
// session on another; that browser is signed out, and the ended session is
// read back from the archive with the time it ended.
func TestSessions_RevokeOtherIsArchived(t *testing.T) {
	a, _, clk := newTestAuth(t, deleteAtOnce)
	h := newHandler(a)
	laptop, phone := newBrowser(t, h), newBrowser(t, h)
	signUp(t, laptop, aliceEmail)
	signIn(t, phone, aliceEmail)

	list := get[auth.SessionsResult](t, laptop, "/auth/sessions", http.StatusOK)
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions = %+v, want laptop and phone", list.Sessions)
	}
	var other string
	for _, s := range list.Sessions {
		if !s.Current {
			other = s.ID
		}
	}
	clk.advance(time.Minute)
	post[auth.Done](t, laptop, "/auth/sessions/revoke", fields{"id": other}, http.StatusOK)
	get[none](t, phone, mePath, http.StatusUnauthorized)

	ended := get[signedOutResponse](t, laptop, signedOutPath, http.StatusOK)
	if len(ended.Sessions) != 1 || ended.Sessions[0].ID != other || !ended.Sessions[0].RevokedAt.Equal(clk.now()) {
		t.Fatalf("signed-out history = %+v, want %s revoked at %s", ended.Sessions, other, clk.now())
	}
}

// TestDeleteAccount_NeedsFreshSignIn: once the sign-in is older than
// freshWindow, deleting is refused; signing in again allows it, and the
// account is gone.
func TestDeleteAccount_NeedsFreshSignIn(t *testing.T) {
	a, _, clk := newTestAuth(t, deleteAtOnce)
	b := newBrowser(t, newHandler(a))
	signUp(t, b, aliceEmail)

	clk.advance(freshWindow + staleBy)
	stale := post[errorAnswer](t, b, "/auth/account/delete", none{}, http.StatusForbidden)
	if stale.Error.Code != auth.ErrFreshSessionRequired.Code {
		t.Fatalf("deleting with an old sign-in = %+v, want %s", stale.Error, auth.ErrFreshSessionRequired.Code)
	}
	get[meResponse](t, b, mePath, http.StatusOK) // still signed in: only deleting needs a fresh sign-in

	signIn(t, b, aliceEmail)
	if res := post[auth.DeleteAccountResult](t, b, "/auth/account/delete", none{}, http.StatusOK); !res.Deleted {
		t.Fatalf("delete = %+v, want deleted", res)
	}
	get[none](t, b, mePath, http.StatusUnauthorized)
	post[none](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusUnauthorized)
}

// reauthPath is the password plugin's re-authentication route: the password
// again, on the session the browser already holds.
const reauthPath = "/auth/password/reauthenticate"

// TestDeleteAccount_ReauthenticatesTheSameSession: past freshWindow the
// browser types the password again at reauthPath instead of signing in
// again; the same session becomes fresh (no new cookie, still one session in
// the list) and the delete goes through.
func TestDeleteAccount_ReauthenticatesTheSameSession(t *testing.T) {
	a, _, clk := newTestAuth(t, deleteAtOnce)
	b := newBrowser(t, newHandler(a))
	signUp(t, b, aliceEmail)
	clk.advance(freshWindow + staleBy)
	post[errorAnswer](t, b, "/auth/account/delete", none{}, http.StatusForbidden)

	wrong := post[errorAnswer](t, b, reauthPath, fields{"password": "not it"}, http.StatusUnauthorized)
	if wrong.Error.Code != password.ErrInvalidCredentials.Code {
		t.Fatalf("wrong password = %+v", wrong.Error)
	}
	res := post[auth.Reauthentication](t, b, reauthPath, fields{"password": testPassword}, http.StatusOK)
	if !res.Fresh || res.SecondFactorRequired {
		t.Fatalf("re-authentication = %+v, want fresh", res)
	}
	sessions := get[auth.SessionsResult](t, b, "/auth/sessions", http.StatusOK)
	if len(sessions.Sessions) != 1 {
		t.Fatalf("sessions after re-authentication = %d, want the one the browser holds", len(sessions.Sessions))
	}
	if del := post[auth.DeleteAccountResult](t, b, "/auth/account/delete", none{}, http.StatusOK); !del.Deleted {
		t.Fatalf("delete after re-authentication = %+v", del)
	}
}

// TestDeleteAccount_ByMailedLink: with ConfirmByLink the call only mails a
// link; opening the link's page deletes nothing, and posting its token from
// a browser with no session deletes the account once.
func TestDeleteAccount_ByMailedLink(t *testing.T) {
	a, box, _ := newTestAuth(t, deleteByLink)
	h := newHandler(a)
	b := newBrowser(t, h)
	signUp(t, b, aliceEmail)
	unverified := post[errorAnswer](t, b, "/auth/account/delete", none{}, http.StatusConflict)
	if unverified.Error.Code != auth.ErrNoRecoveryChannel.Code {
		t.Fatalf("deleting before the address is verified = %+v, want %s", unverified.Error, auth.ErrNoRecoveryChannel.Code)
	}
	post[none](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)

	if res := post[auth.DeleteAccountResult](t, b, "/auth/account/delete", none{}, http.StatusOK); !res.ConfirmationSent || res.Deleted {
		t.Fatalf("delete = %+v, want a confirmation sent", res)
	}
	get[meResponse](t, b, mePath, http.StatusOK) // the account stays until the link is spent

	link := box.lastLink(t, a, aliceEmail)
	if !strings.HasPrefix(link, baseURL+auth.DefaultDeleteAccountPage+"?token=") {
		t.Fatalf("link = %q, want the app's %s page", link, auth.DefaultDeleteAccountPage)
	}
	other := newBrowser(t, h) // the mail was read on another device
	other.getPage(t, strings.TrimPrefix(link, baseURL))
	get[meResponse](t, b, mePath, http.StatusOK) // opening the page deleted nothing

	tok := tokenOf(t, link)
	post[auth.Done](t, other, "/auth/account/delete/confirm", fields{"token": tok}, http.StatusOK)
	get[none](t, b, mePath, http.StatusUnauthorized)
	spent := post[errorAnswer](t, other, "/auth/account/delete/confirm", fields{"token": tok}, http.StatusBadRequest)
	if spent.Error.Code != auth.ErrTokenInvalid.Code {
		t.Fatalf("a spent link = %+v", spent.Error)
	}
}

// profile is the body of POST /auth/profile as a client writes it.
type profile struct {
	Name   string            `json:"name"`
	Fields map[string]string `json:"fields"`
}

// signUp creates an account for addr in b and returns its user id.
func signUp(t *testing.T, b *browser, addr string) string {
	t.Helper()
	return post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword}, http.StatusOK).User.ID
}

// signIn signs addr in again in b, which starts a fresh session.
func signIn(t *testing.T, b *browser, addr string) {
	t.Helper()
	post[none](t, b, "/auth/password/sign-in", fields{"identifier": addr, "password": testPassword}, http.StatusOK)
}

// testClock is a clock the test moves by hand, to age a sign-in past
// freshWindow without waiting.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

// now is the clock's current time; it is the auth.WithClock function.
func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// advance moves the clock forward by d.
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestAuth builds the app's Auth with deletion on a fresh SQLite file,
// with a mailbox that records mail and a clock the test moves.
func newTestAuth(t *testing.T, deletion auth.AccountDeletion) (*auth.Auth, *mailbox, *testClock) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	start, err := time.Parse(time.RFC3339, clockStart)
	if err != nil {
		t.Fatal(err)
	}
	clk := &testClock{t: start}
	box := &mailbox{}
	a, err := newAuth(db, box, deletion, auth.WithClock(clk.now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box, clk
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

// lastToken returns the token in the newest link mailed to addr.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	return tokenOf(t, m.lastLink(t, a, addr))
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

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL. Each
// browser has its own jar, so two of them are two devices.
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

// do sends req, checks the status and decodes the JSON answer as Out.
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

// cookiesWithPrefix counts the jar's cookies for the server whose name
// starts with prefix: authhttp keeps each inactive account of the device in
// its own cookie.
func (b *browser) cookiesWithPrefix(prefix string) int {
	u, err := url.Parse(b.srv.URL)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range b.client.Jar.Cookies(u) {
		if strings.HasPrefix(c.Name, prefix) && c.Value != "" {
			n++
		}
	}
	return n
}
