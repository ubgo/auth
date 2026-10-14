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
	"github.com/ubgo/auth/plugin/phone"
)

const (
	// typedNumber is the number as a person types it; normalizedNumber is
	// how the library stores it and texts it.
	typedNumber      = "+1 (555) 010-0100"
	normalizedNumber = "+15550100100"
	// abroadNumber is outside allowedPrefixes.
	abroadNumber = "+49 30 1234567"
	// wrongCode is never a code the plugin sends: codes are six digits.
	wrongCode = "12345"
)

// TestPhoneOnly_CodeCreatesThenFindsTheAccount: the first code creates the
// account with a verified number; after signing out, the next code signs in
// to the same account instead of making another.
func TestPhoneOnly_CodeCreatesThenFindsTheAccount(t *testing.T) {
	a, sms := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	post[auth.Done](t, b, "/auth/phone/send-code", fields{"phone": typedNumber}, http.StatusOK)
	first := post[phone.SignInResult](t, b, "/auth/phone/sign-in", fields{"phone": typedNumber, "code": sms.lastCode(t, a, normalizedNumber)}, http.StatusOK)
	if !first.Created || first.User.ID == "" {
		t.Fatalf("first sign-in = %+v, want a created user", first)
	}
	if !b.hasCookie(authhttp.CookieName) {
		t.Fatal("sign-in set no session cookie")
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.ID != first.User.ID || me.Phone != normalizedNumber || !me.PhoneVerified {
		t.Fatalf("/me = %+v", me)
	}

	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	get[none](t, b, "/me", http.StatusUnauthorized)

	post[auth.Done](t, b, "/auth/phone/send-code", fields{"phone": normalizedNumber}, http.StatusOK)
	again := post[phone.SignInResult](t, b, "/auth/phone/sign-in", fields{"phone": normalizedNumber, "code": sms.lastCode(t, a, normalizedNumber)}, http.StatusOK)
	if again.Created || again.User.ID != first.User.ID {
		t.Fatalf("second sign-in = %+v, want the same user %s", again, first.User.ID)
	}
}

// TestPhoneOnly_Refusals: a wrong code and a number outside the allowed
// countries are both refused, and no text goes abroad.
func TestPhoneOnly_Refusals(t *testing.T) {
	a, sms := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	post[auth.Done](t, b, "/auth/phone/send-code", fields{"phone": typedNumber}, http.StatusOK)
	bad := post[errorAnswer](t, b, "/auth/phone/sign-in", fields{"phone": typedNumber, "code": wrongCode}, http.StatusBadRequest)
	if bad.Error.Code != phone.ErrCodeInvalid.Code {
		t.Fatalf("wrong code = %+v", bad.Error)
	}

	abroad := post[errorAnswer](t, b, "/auth/phone/send-code", fields{"phone": abroadNumber}, http.StatusBadRequest)
	if abroad.Error.Code != auth.ErrIdentifierInvalid.Code {
		t.Fatalf("number abroad = %+v", abroad.Error)
	}
	if n := sms.count(a); n != 1 {
		t.Fatalf("%d texts sent, want only the first", n)
	}
}

// TestPhoneOnly_WithoutCodesNobodyCanSignIn: the same plugin without
// SignInWithCode signs nobody in, and auth.New refuses the configuration at
// start-up instead of serving an app nobody can enter.
func TestPhoneOnly_WithoutCodesNobodyCanSignIn(t *testing.T) {
	_, err := auth.New(
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(phone.New(phone.Login(), phone.Recover(), phone.WithSMS(&smsbox{}))),
	)
	if !errors.Is(err, auth.ErrNoSignInMethod) {
		t.Fatalf("auth.New = %v, want %v", err, auth.ErrNoSignInMethod)
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file with an SMS box
// that records texts instead of printing them.
func newTestAuth(t *testing.T) (*auth.Auth, *smsbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &smsbox{}
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

// smsText is one recorded text.
type smsText struct{ to, text string }

// smsbox records every text sent.
type smsbox struct {
	mu   sync.Mutex
	sent []smsText
}

// Send records the text.
func (s *smsbox) Send(_ context.Context, to, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, smsText{to: to, text: text})
	return nil
}

// codeInText finds the six-digit code in a text.
var codeInText = regexp.MustCompile(`\b\d{6}\b`)

// lastCode returns the code in the newest text to number. Texts go out after
// the transaction commits, so it waits for deliveries first.
func (s *smsbox) lastCode(t *testing.T, a *auth.Auth, number string) string {
	t.Helper()
	a.WaitDeliveries()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].to == number {
			if code := codeInText.FindString(s.sent[i].text); code != "" {
				return code
			}
		}
	}
	t.Fatalf("no code texted to %s", number)
	return ""
}

// count returns how many texts were sent, after deliveries finished.
func (s *smsbox) count(a *auth.Auth) int {
	a.WaitDeliveries()
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
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
