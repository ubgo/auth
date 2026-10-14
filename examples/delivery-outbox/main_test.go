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
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/verificationtest"
)

const (
	// testEmail is the address that signs up.
	testEmail = "alice@example.com"
	// testPassword is a password the default policy accepts.
	testPassword = "correct horse battery staple"
	// testSecret is a 32-byte AUTH_SECRET for the test only.
	testSecret = "test-secret-0123456789abcdefghij"
	// testWorkers and testQueue size the pool in the end-to-end tests.
	testWorkers, testQueue = 2, 8
)

// TestOutbox_FailedMailIsRetriedOnce: the first send fails, the message
// waits in the outbox sealed, SendOutbox leaves it alone until its backoff
// passes, then sends it exactly once, and the link in it verifies the address.
func TestOutbox_FailedMailIsRetriedOnce(t *testing.T) {
	app := newTestApp(t, demoFailures)
	b := newBrowser(t, newHandler(app.a))

	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	app.a.WaitDeliveries()
	if n := app.box.count(); n != 0 {
		t.Fatalf("%d mails sent while the mailer was down", n)
	}
	payloads := app.outboxPayloads(t)
	if len(payloads) != 1 {
		t.Fatalf("outbox rows after a failed send = %d, want 1", len(payloads))
	}
	if strings.Contains(payloads[0], testEmail) || strings.Contains(payloads[0], baseURL) {
		t.Fatalf("outbox payload is not sealed: %q", payloads[0])
	}

	if res := sendOutbox(t, app.a); res != (auth.OutboxResult{}) {
		t.Fatalf("SendOutbox before the backoff = %+v, want nothing sent", res)
	}
	app.clock.advance(auth.DeliveryRetryBase)
	if res := sendOutbox(t, app.a); res != (auth.OutboxResult{Sent: 1}) {
		t.Fatalf("SendOutbox after the backoff = %+v, want one sent", res)
	}
	if res := sendOutbox(t, app.a); res != (auth.OutboxResult{}) {
		t.Fatalf("SendOutbox again = %+v, want nothing: the row is gone", res)
	}
	if n := len(app.outboxPayloads(t)); n != 0 {
		t.Fatalf("outbox rows after the retry = %d, want 0", n)
	}
	if n := app.box.count(); n != 1 {
		t.Fatalf("mails sent = %d, want exactly 1", n)
	}

	if app.store.Len() != 1 {
		t.Fatalf("custom store holds %d tokens, want the one verify-email token", app.store.Len())
	}
	tok := app.box.lastToken(t)
	if v := post[email.VerifyResult](t, b, "/auth/email/verify", fields{"token": tok}, http.StatusOK); v.Email != testEmail {
		t.Fatalf("verify = %+v", v)
	}
	if app.store.Len() != 0 {
		t.Fatal("the spent token is still in the custom store")
	}
	if app.pool.ran.Load() == 0 {
		t.Fatal("the post-commit send did not run on the app's pool")
	}
}

// TestBackground_DeliveriesRunOnThePool: with a working mailer the
// post-commit send runs on the app's pool, delivers once, and leaves no
// outbox row behind.
func TestBackground_DeliveriesRunOnThePool(t *testing.T) {
	app := newTestApp(t, 0)
	b := newBrowser(t, newHandler(app.a))

	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	app.a.WaitDeliveries()
	if got := app.pool.ran.Load(); got != 1 {
		t.Fatalf("pool ran %d tasks, want the one delivery", got)
	}
	if app.pool.overflow.Load() != 0 {
		t.Fatal("a delivery overflowed an empty queue")
	}
	if n := app.box.count(); n != 1 {
		t.Fatalf("mails sent = %d, want 1", n)
	}
	if n := len(app.outboxPayloads(t)); n != 0 {
		t.Fatalf("outbox rows after a successful send = %d, want 0", n)
	}
}

// TestWorkerPool_FullQueueNeverDrops: a task that finds every worker busy
// and the queue full still runs, on its own goroutine, because a dropped
// task would make WaitDeliveries wait forever.
func TestWorkerPool_FullQueueNeverDrops(t *testing.T) {
	p := newWorkerPool(1, 1)
	release := make(chan struct{})
	busy := make(chan struct{})
	p.Run(context.Background(), func(context.Context) { close(busy); <-release })
	<-busy                                                // the only worker is now held
	p.Run(context.Background(), func(context.Context) {}) // fills the queue
	ran := make(chan struct{})
	p.Run(context.Background(), func(context.Context) { close(ran) })
	<-ran
	close(release)
	p.Close()
	if got := p.overflow.Load(); got != 1 {
		t.Fatalf("overflow = %d, want 1", got)
	}
	if got := p.ran.Load(); got != 2 {
		t.Fatalf("pool ran %d tasks, want 2", got)
	}
}

// TestMapVerificationStore_Contract proves the custom store keeps the
// contract every verification store must: single use under concurrency,
// purpose isolation, expiry, ConsumeAll and DeleteIdentifiers.
func TestMapVerificationStore_Contract(t *testing.T) {
	verificationtest.Run(t, func(*testing.T) auth.VerificationStore { return newMapVerificationStore() })
}

// testApp is the app's Auth with every seam the test inspects.
type testApp struct {
	a     *auth.Auth
	db    *sql.DB
	box   *mailbox
	pool  *workerPool
	store *mapVerificationStore
	clock *testClock
}

// newTestApp builds the app's Auth on a fresh SQLite file, with a mailer
// that fails failures sends before it records mail, and a clock the test
// moves forward instead of waiting out the backoff.
func newTestApp(t *testing.T, failures int) *testApp {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app := &testApp{db: db, box: &mailbox{}, pool: newWorkerPool(testWorkers, testQueue), store: newMapVerificationStore(), clock: &testClock{now: time.Now()}}
	t.Cleanup(app.pool.Close) // runs after a.Close, cleanups being last in, first out
	a, err := newAuth(db, []byte(testSecret), newFlakyMailer(app.box, failures), app.pool.Run, app.store, auth.WithClock(app.clock.Now))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	app.a = a
	return app
}

// outboxPayloads returns the payload column of every outbox row, as stored.
func (app *testApp) outboxPayloads(t *testing.T) []string {
	t.Helper()
	rows, err := app.db.Query("SELECT payload FROM " + app.a.TableName(auth.TableDeliveryOutbox))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// sendOutbox runs one SendOutbox pass and fails the test on an error.
func sendOutbox(t *testing.T, a *auth.Auth) auth.OutboxResult {
	t.Helper()
	res, err := a.SendOutbox(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// testClock is the clock the Auth reads, moved by the test.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the clock's time.
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// advance moves the clock forward by d.
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
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

// count reports how many mails were sent.
func (m *mailbox) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// lastToken returns the token of the newest link mailed.
func (m *mailbox) lastToken(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		for _, field := range strings.Fields(m.sent[i].Text) {
			if !strings.HasPrefix(field, baseURL) {
				continue
			}
			u, err := url.Parse(field)
			if err != nil {
				t.Fatal(err)
			}
			return u.Query().Get("token")
		}
	}
	t.Fatal("no link mailed")
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

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
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
	req.Header.Set("Origin", b.origin)
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
		t.Fatalf("POST %s: status %d, want %d: %s", path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("POST %s: decode %q: %v", path, buf.String(), err)
	}
	return out
}
