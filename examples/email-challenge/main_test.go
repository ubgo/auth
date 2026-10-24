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

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/emailchallenge"
)

const (
	// testEmail is the address the challenges go to.
	testEmail = "ada@example.com"
	// codeMarker precedes the code in the default mail text.
	codeMarker = "asked:"
	// wrongCode is a code no challenge was sent.
	wrongCode = "000000"
)

// TestEmailChallenge_LinkOnPhoneSignsInLaptop: the laptop starts, the link is
// opened on a phone, opening it approves nothing, the phone's Confirm approves,
// and the laptop's next poll signs the laptop in. The phone never gets a
// session.
func TestEmailChallenge_LinkOnPhoneSignsInLaptop(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	laptop, phone := newBrowser(t, srv), newBrowser(t, srv)

	started := post[emailchallenge.Result](t, laptop, "/auth/emailchallenge/start", fields{"identifier": testEmail}, http.StatusOK)
	if started.ExpiresAt == nil {
		t.Fatalf("start = %+v, want an expiry", started)
	}
	link, _ := box.last(t, a, testEmail)
	token := tokenOf(t, link)

	phone.getPage(t, strings.TrimPrefix(link, baseURL))
	ctx := get[emailchallenge.ContextResult](t, phone, "/auth/emailchallenge/context?token="+url.QueryEscape(token), http.StatusOK)
	if ctx.State != emailchallenge.StateNeedsConfirmation || ctx.Identifier != testEmail {
		t.Fatalf("context on the phone = %+v, want needs-confirmation for %s", ctx, testEmail)
	}
	if got := post[emailchallenge.Result](t, laptop, "/auth/emailchallenge/poll", none{}, http.StatusOK); got.State != emailchallenge.StatePending {
		t.Fatalf("poll before the confirm = %+v, want pending: opening the link must approve nothing", got)
	}

	approved := post[emailchallenge.Result](t, phone, "/auth/emailchallenge/approve", fields{"token": token}, http.StatusOK)
	if approved.State != emailchallenge.StateApproved {
		t.Fatalf("approve = %+v", approved)
	}
	if phone.hasCookie(authhttp.CookieName) {
		t.Fatal("the phone got a session; approval must sign nobody in")
	}

	done := post[emailchallenge.Result](t, laptop, "/auth/emailchallenge/poll", none{}, http.StatusOK)
	if done.State != emailchallenge.StateCompleted || done.User == nil || !done.Created {
		t.Fatalf("poll after the confirm = %+v, want completed with a created user", done)
	}
	if got := get[meResponse](t, laptop, "/me", http.StatusOK); got.ID != done.User.ID {
		t.Fatalf("/me on the laptop = %+v, want %s", got, done.User.ID)
	}
	if got := post[emailchallenge.Result](t, laptop, "/auth/emailchallenge/poll", none{}, http.StatusOK); got.State != emailchallenge.StateExpired {
		t.Fatalf("poll after completion = %+v, want expired: one approval signs in once", got)
	}
}

// TestEmailChallenge_CodeSignsInAndWrongCodesSpendIt: the code from the mail
// signs the asking browser in at once; another challenge's wrong codes spend
// it after the attempt cap, so the right code no longer works.
func TestEmailChallenge_CodeSignsInAndWrongCodesSpendIt(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	laptop := newBrowser(t, srv)

	post[emailchallenge.Result](t, laptop, "/auth/emailchallenge/start", fields{"identifier": testEmail}, http.StatusOK)
	_, code := box.last(t, a, testEmail)
	in := post[emailchallenge.Result](t, laptop, "/auth/emailchallenge/verify-otp", fields{"otp": code}, http.StatusOK)
	if in.State != emailchallenge.StateCompleted || in.User == nil {
		t.Fatalf("verify-otp = %+v, want completed", in)
	}

	other := newBrowser(t, srv)
	post[emailchallenge.Result](t, other, "/auth/emailchallenge/start", fields{"identifier": testEmail}, http.StatusOK)
	_, code = box.last(t, a, testEmail)
	for range emailchallenge.DefaultMaxAttempts {
		got := post[errorAnswer](t, other, "/auth/emailchallenge/verify-otp", fields{"otp": wrongCode}, http.StatusBadRequest)
		if got.Error.Code != auth.ErrCodeInvalid.Code {
			t.Fatalf("a wrong code = %+v", got.Error)
		}
	}
	if got := post[errorAnswer](t, other, "/auth/emailchallenge/verify-otp", fields{"otp": code}, http.StatusBadRequest); got.Error.Code != auth.ErrCodeInvalid.Code {
		t.Fatalf("the right code after %d wrong ones = %+v, want it spent", emailchallenge.DefaultMaxAttempts, got.Error)
	}
}

// TestEmailChallenge_CodeNeedsThePollToken: a code typed in a browser that did
// not start the challenge is refused, so a code read from a mailbox cannot
// sign a stranger's browser in.
func TestEmailChallenge_CodeNeedsThePollToken(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	laptop, stranger := newBrowser(t, srv), newBrowser(t, srv)

	post[emailchallenge.Result](t, laptop, "/auth/emailchallenge/start", fields{"identifier": testEmail}, http.StatusOK)
	_, code := box.last(t, a, testEmail)
	got := post[errorAnswer](t, stranger, "/auth/emailchallenge/verify-otp", fields{"otp": code}, http.StatusBadRequest)
	if got.Error.Code != emailchallenge.ErrInvalid.Code {
		t.Fatalf("a code without the poll token = %+v, want %s", got.Error, emailchallenge.ErrInvalid.Code)
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

// last returns the link and the code of the newest mail to addr. Mail goes out
// after the transaction commits, so it waits for deliveries first.
func (m *mailbox) last(t *testing.T, a *auth.Auth, addr string) (link, code string) {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		words := strings.Fields(m.sent[i].Text)
		for j, w := range words {
			switch {
			case strings.HasPrefix(w, baseURL):
				link = w
			case w == codeMarker && j+1 < len(words):
				code = words[j+1]
			}
		}
		if link == "" || code == "" {
			t.Fatalf("mail to %s has no link or code: %q", addr, m.sent[i].Text)
		}
		return link, code
	}
	t.Fatalf("no mail to %s", addr)
	return "", ""
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

// hasCookie reports whether the jar holds a cookie called name for the server.
func (b *browser) hasCookie(name string) bool {
	u, _ := url.Parse(b.srv.URL) // httptest always gives a well-formed URL
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}
