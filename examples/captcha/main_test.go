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
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/captcha"
	"github.com/ubgo/auth/plugin/email"
)

const (
	aliceEmail   = "alice@example.com"
	testPassword = "correct horse battery staple"
	testSecret   = "test-secret"
	// humanToken and botToken are what the fake provider accepts and
	// rejects; a real token is opaque and single-use.
	humanToken = "token-from-a-solved-widget"
	botToken   = "token-a-bot-made-up"
)

// TestCaptcha_GuardsSignUpAndSignIn: without a token sign-up is refused before
// it runs, with a token the provider rejects it is refused too, with an
// accepted token Alice is in; the dashboard then needs no captcha, and the
// provider saw the secret and the client address.
func TestCaptcha_GuardsSignUpAndSignIn(t *testing.T) {
	provider := newFakeTurnstile(t)
	a := newTestApp(t, provider.URL)
	h := newHandler(a)
	alice := newBrowser(t, h)
	form := fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}

	if e := post[errorAnswer](t, alice, "/auth/password/sign-up", form, nil, http.StatusBadRequest); e.Error.Code != captcha.ErrMissing.Code {
		t.Fatalf("sign-up without a token: %+v", e.Error)
	}
	if provider.calls != 0 {
		t.Fatal("a missing token must not cost a provider call")
	}
	if e := post[errorAnswer](t, alice, "/auth/password/sign-up", form, token(botToken), http.StatusForbidden); e.Error.Code != captcha.ErrFailed.Code {
		t.Fatalf("sign-up with a rejected token: %+v", e.Error)
	}
	up := post[signUpAnswer](t, alice, "/auth/password/sign-up", form, token(humanToken), http.StatusOK)
	if up.User.Name != "Alice" {
		t.Fatalf("sign-up = %+v", up)
	}
	if provider.lastForm.Get("secret") != testSecret || provider.lastForm.Get("response") != humanToken || provider.lastForm.Get("remoteip") == "" {
		t.Fatalf("provider saw %v", provider.lastForm)
	}
	if d := get[dashboardResponse](t, alice, "/dashboard", nil, http.StatusOK); d.Hello != "Alice" {
		t.Fatalf("dashboard = %+v", d)
	}

	// Sign-in is guarded the same way; a token minted for another widget
	// (another action) is refused even though the provider says success.
	bob := newBrowser(t, h)
	creds := fields{"identifier": aliceEmail, "password": testPassword}
	if e := post[errorAnswer](t, bob, "/auth/password/sign-in", creds, nil, http.StatusBadRequest); e.Error.Code != captcha.ErrMissing.Code {
		t.Fatalf("sign-in without a token: %+v", e.Error)
	}
	provider.action = "newsletter"
	if e := post[errorAnswer](t, bob, "/auth/password/sign-in", creds, token(humanToken), http.StatusForbidden); e.Error.Code != captcha.ErrFailed.Code {
		t.Fatalf("sign-in with a token for another action: %+v", e.Error)
	}
	provider.action = expectedAction
	post[signUpAnswer](t, bob, "/auth/password/sign-in", creds, token(humanToken), http.StatusOK)

	// A provider outage fails closed.
	provider.down = true
	if e := post[errorAnswer](t, newBrowser(t, h), "/auth/password/sign-in", creds, token(humanToken), http.StatusServiceUnavailable); e.Error.Code != captcha.ErrUnavailable.Code {
		t.Fatalf("sign-in with the provider down: %+v", e.Error)
	}
}

// TestNewVerifier_RealEndpointByDefault: with no override the verifier is
// Turnstile's, and main refuses to start without the secret.
func TestNewVerifier_RealEndpointByDefault(t *testing.T) {
	if v := newVerifier(testSecret, ""); v.Provider() != "turnstile" {
		t.Fatalf("Provider = %q", v.Provider())
	}
	if _, err := newAuth(nil, &mailbox{}, captcha.Turnstile("")); err == nil {
		t.Fatal("auth.New accepted an empty secret")
	}
}

// fakeTurnstile answers like Cloudflare's siteverify: success for humanToken
// with the configured action, a rejection otherwise, and a 502 when down.
type fakeTurnstile struct {
	*httptest.Server
	mu       sync.Mutex
	calls    int
	lastForm url.Values
	action   string
	down     bool
}

func newFakeTurnstile(t *testing.T) *fakeTurnstile {
	t.Helper()
	f := &fakeTurnstile{action: expectedAction}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		f.calls++
		f.lastForm = r.PostForm
		if f.down {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		verdict := map[string]any{"success": r.PostForm.Get("response") == humanToken, "action": f.action, "hostname": "localhost"}
		if !verdict["success"].(bool) {
			verdict["error-codes"] = []string{"invalid-input-response"}
		}
		_ = json.NewEncoder(w).Encode(verdict)
	}))
	t.Cleanup(f.Close)
	return f
}

// token is the header a page sends after the widget is solved.
func token(v string) http.Header { return http.Header{captcha.TokenHeader: {v}} }

// signUpAnswer is the part of the sign-up answer the test reads.
type signUpAnswer struct {
	User auth.UserView `json:"user"`
}

// newTestApp builds the app on a fresh SQLite file against the fake provider.
func newTestApp(t *testing.T, siteVerifyURL string) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, &mailbox{}, newVerifier(testSecret, siteVerifyURL))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
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

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin and extra headers, checks
// the status and decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, extra http.Header, status int) Out {
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
	return do[Out](t, b, req, extra, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, extra http.Header, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, extra, status)
}

// do sends req with extra headers, checks the status and decodes the answer.
func do[Out any](t *testing.T, b *browser, req *http.Request, extra http.Header, status int) Out {
	t.Helper()
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
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
