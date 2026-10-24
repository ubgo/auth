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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/examples/plugin-delivery/chat"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testHandle   = "@Alice_Dev"
	// storedHandle is testHandle as the normalizer stores it.
	storedHandle = "alice_dev"
)

// TestChat_AddVerifyRecover is the whole flow over HTTP: add a handle, get a
// code through the bot, be refused with a wrong code, verify, then have a
// password reset link and an app message delivered to the chat.
func TestChat_AddVerifyRecover(t *testing.T) {
	a, bot, _ := newTestAuth(t, newClock())
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)

	post[auth.Done](t, b, "/auth/chat/add", fields{"handle": testHandle}, http.StatusOK)
	code := bot.lastCode(t, a, storedHandle)

	wrong := post[errorAnswer](t, b, "/auth/chat/verify", fields{"handle": testHandle, "code": "000000"}, http.StatusBadRequest)
	if wrong.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("wrong code = %+v", wrong.Error)
	}
	post[auth.Done](t, b, "/auth/chat/verify", fields{"handle": testHandle, "code": code}, http.StatusOK)

	idn := identityOf(t, a, testEmail, chat.KindChat)
	if !idn.Verified() || !idn.IsPrimary || idn.Value != storedHandle {
		t.Fatalf("chat identity = %+v", idn)
	}

	// Forgot password: the email plugin cannot recover here, so the reset
	// link goes to the chat.
	post[password.ForgotResult](t, b, "/auth/password/forgot", fields{"identifier": testEmail}, http.StatusOK)
	reset := bot.last(t, a, storedHandle)
	if !strings.Contains(reset, baseURL+password.DefaultResetPage+"?token=") {
		t.Fatalf("reset message = %q, want a link to %s", reset, password.DefaultResetPage)
	}

	// The app's own purpose: the plugin's template falls back to DefaultText.
	post[none](t, b, "/nudge", none{}, http.StatusAccepted)
	if got := bot.last(t, a, storedHandle); got != nudgeText {
		t.Fatalf("nudge = %q, want %q", got, nudgeText)
	}
}

// TestChat_CodeExpires moves the clock past the code's lifetime: the code is
// refused, and the handle stays unverified.
//
//ds:def id=testchat-codeexpires-sjmqyfy9
func TestChat_CodeExpires(t *testing.T) {
	clock := newClock()
	a, bot, _ := newTestAuth(t, clock)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	post[auth.Done](t, b, "/auth/chat/add", fields{"handle": testHandle}, http.StatusOK)
	code := bot.lastCode(t, a, storedHandle)

	clock.Advance(chat.DefaultCodeTTL + time.Second)
	late := post[errorAnswer](t, b, "/auth/chat/verify", fields{"handle": testHandle, "code": code}, http.StatusBadRequest)
	if late.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("expired code = %+v", late.Error)
	}
	if idn := identityOf(t, a, testEmail, chat.KindChat); idn.Verified() {
		t.Fatal("an expired code verified the handle")
	}
}

// TestChat_Refusals pins the plugin's own errors and the kind's validation.
func TestChat_Refusals(t *testing.T) {
	a, _, _ := newTestAuth(t, newClock())
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)

	bad := post[errorAnswer](t, b, "/auth/chat/add", fields{"handle": "a!"}, http.StatusBadRequest)
	if bad.Error.Code != auth.ErrIdentifierInvalid.Code {
		t.Fatalf("malformed handle = %+v", bad.Error)
	}
	post[auth.Done](t, b, "/auth/chat/add", fields{"handle": testHandle}, http.StatusOK)
	second := post[errorAnswer](t, b, "/auth/chat/add", fields{"handle": "@other"}, http.StatusConflict)
	if second.Error.Code != chat.ErrHasHandle.Code {
		t.Fatalf("second handle = %+v", second.Error)
	}
}

// TestChat_NewRefusesAPluginWithoutASender: the plugin's Validate runs inside
// auth.New, so the broken wiring fails at start-up with the plugin named.
//
//ds:def id=testchat-newrefusesapluginwithoutasender-6feusx2u
func TestChat_NewRefusesAPluginWithoutASender(t *testing.T) {
	db := openDB(t)
	_, err := auth.New(
		auth.WithDB(db, dialect),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.WithMailer(discard{})), password.New(), chat.New(nil, chat.Recover())),
	)
	if !errors.Is(err, chat.ErrNoSender) {
		t.Fatalf("auth.New = %v, want %v", err, chat.ErrNoSender)
	}
}

// TestChat_AddSurfacesEveryDatabaseFailure runs Add once per database call
// it makes, each time with a different call failing, and requires an error
// every time: a swallowed failure would report success for a handle that was
// never stored or a code that was never issued.
//
//ds:def id=testchat-addsurfaceseverydatabasefailure-nrsqf3wx
func TestChat_AddSurfacesEveryDatabaseFailure(t *testing.T) {
	sweepFaults(t, func(t *testing.T, db *sql.DB) func(context.Context) error {
		bot := &botbox{}
		a, err := newAuth(db, discard{}, bot, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = a.Close() })
		if _, err := a.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		pw, err := auth.PluginOf[*password.Plugin](a)
		if err != nil {
			t.Fatal(err)
		}
		ch, err := auth.PluginOf[*chat.Plugin](a)
		if err != nil {
			t.Fatal(err)
		}
		up, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: testEmail, Password: testPassword})
		if err != nil {
			t.Fatal(err)
		}
		return func(context.Context) error { return ch.Add(signedIn(a, up.Token), testHandle) }
	})
}

// identityOf returns the user's identity of kind, found through their email.
func identityOf(t *testing.T, a *auth.Auth, addr string, kind auth.IdentifierKindName) auth.Identity {
	t.Helper()
	ctx := context.Background()
	owner, err := a.FindIdentity(ctx, email.KindEmail, addr, false)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := a.Identities(ctx, owner.UserID)
	if err != nil {
		t.Fatal(err)
	}
	for _, idn := range ids {
		if idn.Kind == kind {
			return idn
		}
	}
	t.Fatalf("%s has no %s identity", addr, kind)
	return auth.Identity{}
}

// signedIn is a Go-API context carrying a session token, as a request from
// the user's device would.
func signedIn(a *auth.Auth, tok auth.Token) context.Context {
	return a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportGo, Credential: auth.CredentialBearer, Token: tok})
}

// anon is a Go-API context with no session.
func anon(a *auth.Auth) context.Context {
	return a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportGo})
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// and a bot that record instead of printing, on the given clock.
//
//ds:def id=newtestauth-aysyu5qt
func newTestAuth(t *testing.T, clock *clock) (*auth.Auth, *botbox, *mailbox) {
	t.Helper()
	db := openDB(t)
	box, bot := &mailbox{}, &botbox{}
	a, err := newAuth(db, box, bot, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, bot, box
}

// openDB opens a fresh SQLite file for one test.
//
//ds:def id=opendb-pcxjbzur
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// clock is a settable clock. Postgres and MySQL store microseconds, so it
// rounds to them, and a value read back equals the value written.
//
//ds:def id=clock-32ewvc3p
type clock struct {
	mu sync.Mutex
	t  time.Time
}

// newClock starts at the real time: the session cookie's expiry is judged by
// the HTTP client against the real clock, so a clock in the past would make
// the jar drop every cookie as expired.
//
//ds:def id=newclock-edpvz5ty
func newClock() *clock { return &clock{t: time.Now().UTC().Truncate(time.Microsecond)} }

// Now is what the library reads as the current time.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
//
//ds:def id=clock-advance-hu7nzsv3
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d).Truncate(time.Microsecond)
	c.mu.Unlock()
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

// discard drops mail, for a test that reads none.
type discard struct{}

// Send drops m.
func (discard) Send(context.Context, email.Mail) error { return nil }

// botbox records every chat message, by handle.
//
//ds:def id=botbox-tt9mpjx6
type botbox struct {
	mu   sync.Mutex
	sent map[string][]string
}

// Send records text for handle.
func (b *botbox) Send(_ context.Context, handle, text string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sent == nil {
		b.sent = map[string][]string{}
	}
	b.sent[handle] = append(b.sent[handle], text)
	return nil
}

// last returns the newest message sent to handle. Messages go out after the
// transaction commits, in the background, so it waits for deliveries first.
//
//ds:def id=botbox-last-e7m6hgct
func (b *botbox) last(t *testing.T, a *auth.Auth, handle string) string {
	t.Helper()
	a.WaitDeliveries()
	b.mu.Lock()
	defer b.mu.Unlock()
	list := b.sent[handle]
	if len(list) == 0 {
		t.Fatalf("no chat message sent to @%s", handle)
	}
	return list[len(list)-1]
}

// codeInText finds the six-digit code in a message.
var codeInText = regexp.MustCompile(`\b(\d{6})\b`)

// lastCode returns the code in the newest message sent to handle.
func (b *botbox) lastCode(t *testing.T, a *auth.Auth, handle string) string {
	t.Helper()
	text := b.last(t, a, handle)
	m := codeInText.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("no code in %q", text)
	}
	return m[1]
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

// do sends req, checks the status and decodes the answer as Out; an empty
// body decodes to the zero Out.
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
	if buf.Len() == 0 {
		return out
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}
