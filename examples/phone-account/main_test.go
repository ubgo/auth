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
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
)

const (
	address = "alice@example.com"
	secret  = "correct horse battery staple"
	// typedNumber is the number as a person types it; normalizedNumber is
	// how the library stores it and texts it.
	typedNumber      = "+1 (555) 010-0100"
	normalizedNumber = "+15550100100"
	secondNumber     = "+15550100199"
	// wrongCode is never a code the plugin sends: codes are six digits.
	wrongCode = "12345"
)

// TestPhoneAccount_AddVerifyRemove walks the whole flow: the number is texted
// a code on add, is not primary until verified, a wrong code is refused, the
// right one makes it the user's verified number, and remove takes it away.
func TestPhoneAccount_AddVerifyRemove(t *testing.T) {
	a, sms := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)

	post[auth.Done](t, b, "/auth/phone/add", fields{"phone": typedNumber}, http.StatusOK)
	code := sms.lastCode(t, a, normalizedNumber)
	if text := sms.last(a, normalizedNumber); !strings.HasSuffix(text, "It expires in 5 minutes.") {
		t.Fatalf("text %q does not state the configured TTL", text)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != "" {
		t.Fatalf("/me before verify = %+v, want no number: an unverified one is not primary", me)
	}
	if e := post[errorAnswer](t, b, "/auth/phone/verify", fields{"phone": typedNumber, "code": wrongCode}, http.StatusBadRequest); e.Error.Code != phone.ErrCodeInvalid.Code {
		t.Fatalf("wrong code = %+v", e.Error)
	}
	post[auth.Done](t, b, "/auth/phone/verify", fields{"phone": typedNumber, "code": code}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != normalizedNumber || !me.PhoneVerified {
		t.Fatalf("/me after verify = %+v", me)
	}

	// Resend to a verified number sends nothing and is not an error.
	before := sms.count(a)
	post[auth.Done](t, b, "/auth/phone/resend", fields{"phone": normalizedNumber}, http.StatusOK)
	if n := sms.count(a); n != before {
		t.Fatalf("resend to a verified number sent %d texts", n-before)
	}

	post[auth.Done](t, b, "/auth/phone/remove", fields{"phone": normalizedNumber}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != "" {
		t.Fatalf("/me after remove = %+v", me)
	}
}

// TestPhoneAccount_Refusals: one number per account, a resend texts a new code
// to an unverified number, and a malformed number is refused.
func TestPhoneAccount_Refusals(t *testing.T) {
	a, sms := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)

	if e := post[errorAnswer](t, b, "/auth/phone/add", fields{"phone": "555 0100"}, http.StatusBadRequest); e.Error.Code != auth.ErrIdentifierInvalid.Code {
		t.Fatalf("number without a country code = %+v", e.Error)
	}
	post[auth.Done](t, b, "/auth/phone/add", fields{"phone": typedNumber}, http.StatusOK)
	first := sms.lastCode(t, a, normalizedNumber)
	if e := post[errorAnswer](t, b, "/auth/phone/add", fields{"phone": secondNumber}, http.StatusConflict); e.Error.Code != phone.ErrHasNumber.Code {
		t.Fatalf("second number = %+v", e.Error)
	}
	post[auth.Done](t, b, "/auth/phone/resend", fields{"phone": typedNumber}, http.StatusOK)
	if second := sms.lastCode(t, a, normalizedNumber); second == first || sms.count(a) != 2 {
		t.Fatalf("resend: codes %q then %q, %d texts", first, second, sms.count(a))
	}
	if e := post[errorAnswer](t, b, "/auth/phone/verify", fields{"phone": typedNumber, "code": first}, http.StatusBadRequest); e.Error.Code != phone.ErrCodeInvalid.Code {
		t.Fatalf("the replaced code = %+v, want refused", e.Error)
	}
}

// newTestAuth builds the app's Auth on a fresh SQLite file with an SMS box
// that records texts instead of printing them; mail is dropped.
func newTestAuth(t *testing.T) (*auth.Auth, *smsbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &smsbox{}
	a, err := newAuth(db, logMailer{}, box)
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

// last returns the newest text to number, after deliveries finished.
func (s *smsbox) last(a *auth.Auth, number string) string {
	a.WaitDeliveries()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.sent) - 1; i >= 0; i-- {
		if s.sent[i].to == number {
			return s.sent[i].text
		}
	}
	return ""
}

// lastCode returns the code in the newest text to number.
func (s *smsbox) lastCode(t *testing.T, a *auth.Auth, number string) string {
	t.Helper()
	code := codeInText.FindString(s.last(a, number))
	if code == "" {
		t.Fatalf("no code texted to %s", number)
	}
	return code
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

// fields is a JSON request body as a client writes it.
type fields map[string]string

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
