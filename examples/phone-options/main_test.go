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

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
)

const (
	secret = "correct horse battery staple"
	// first and second are two numbers, already in the form the library
	// stores them in.
	first  = "+14155550101"
	second = "+14155550102"
	// wrongCode is never a code: codes are six digits.
	wrongCode = "12345"
	// providerText starts every text of the fake verification service, so a
	// test can tell its codes from the plugin's.
	providerText = "Your verification code is "
)

// TestPhoneOptions_ChangeInOneStep: change texts the new number and changes
// nothing; confirm-change makes it the verified number and releases the old
// one in the same step, so another account can then take it.
func TestPhoneOptions_ChangeInOneStep(t *testing.T) {
	a, sms := newTestAuth(t, modeSingle)
	b := signUp(t, a, "alice@example.com")
	addAndVerify(t, a, sms, b, first)

	post[auth.Done](t, b, "/auth/phone/change", fields{"phone": second}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != first {
		t.Fatalf("/me before confirm = %+v, want the old number kept", me)
	}
	if e := post[errorAnswer](t, b, "/auth/phone/confirm-change", fields{"phone": second, "code": wrongCode}, http.StatusBadRequest); e.Error.Code != phone.ErrCodeInvalid.Code {
		t.Fatalf("wrong code = %+v", e.Error)
	}
	got := post[phone.ChangeResult](t, b, "/auth/phone/confirm-change", fields{"phone": second, "code": sms.lastCode(t, a, second)}, http.StatusOK)
	if got.Phone != second {
		t.Fatalf("confirm-change = %+v", got)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != second {
		t.Fatalf("/me after confirm = %+v", me)
	}

	// The old number was removed with the change: another account verifies it.
	bob := signUp(t, a, "bob@example.com")
	addAndVerify(t, a, sms, bob, first)
	if me := get[meResponse](t, bob, "/me", http.StatusOK); me.Phone != first {
		t.Fatalf("bob's /me = %+v, want the number alice gave up", me)
	}
}

// TestPhoneOptions_SeveralNumbers: under Multiple a second number is added
// beside the first, the first verified one stays primary, make-primary moves
// that to a verified number only, and removing the primary promotes the other.
func TestPhoneOptions_SeveralNumbers(t *testing.T) {
	a, sms := newTestAuth(t, modeMultiple)
	b := signUp(t, a, "alice@example.com")
	addAndVerify(t, a, sms, b, first)
	post[auth.Done](t, b, "/auth/phone/add", fields{"phone": second}, http.StatusOK)

	if e := post[errorAnswer](t, b, "/auth/phone/make-primary", fields{"phone": second}, http.StatusConflict); e.Error.Code != auth.ErrNotVerified.Code {
		t.Fatalf("make-primary on an unverified number = %+v", e.Error)
	}
	post[auth.Done](t, b, "/auth/phone/verify", fields{"phone": second, "code": sms.lastCode(t, a, second)}, http.StatusOK)
	want := []phone.Number{{Phone: first, Verified: true, Primary: true}, {Phone: second, Verified: true}}
	if got := get[phone.ListResult](t, b, "/auth/phone/list", http.StatusOK); !equalNumbers(got.Numbers, want) {
		t.Fatalf("list = %+v, want %+v: verifying a second number does not take primary", got.Numbers, want)
	}

	post[auth.Done](t, b, "/auth/phone/make-primary", fields{"phone": second}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != second {
		t.Fatalf("/me after make-primary = %+v", me)
	}
	post[auth.Done](t, b, "/auth/phone/remove", fields{"phone": second}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != first {
		t.Fatalf("/me after removing the primary = %+v, want the remaining number promoted", me)
	}
}

// TestPhoneOptions_ListOnlyUnderMultiple: without Multiple the list route
// does not exist.
func TestPhoneOptions_ListOnlyUnderMultiple(t *testing.T) {
	a, _ := newTestAuth(t, modeSingle)
	b := signUp(t, a, "alice@example.com")
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+"/auth/phone/list", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("list without Multiple = %d, want 404", res.StatusCode)
	}
}

// TestPhoneOptions_ProviderChecksCodes: with WithVerifier the provider's
// service texts the code and checks it, for verify and change alike, and its
// own attempt count applies.
func TestPhoneOptions_ProviderChecksCodes(t *testing.T) {
	a, sms := newTestAuth(t, modeProvider)
	b := signUp(t, a, "alice@example.com")

	post[auth.Done](t, b, "/auth/phone/add", fields{"phone": first}, http.StatusOK)
	if text := sms.last(a, first); !strings.HasPrefix(text, providerText) {
		t.Fatalf("text %q is not the provider's", text)
	}
	code := sms.lastCode(t, a, first)
	for range verifyMaxChecks {
		post[errorAnswer](t, b, "/auth/phone/verify", fields{"phone": first, "code": wrongCode}, http.StatusBadRequest)
	}
	if e := post[errorAnswer](t, b, "/auth/phone/verify", fields{"phone": first, "code": code}, http.StatusBadRequest); e.Error.Code != phone.ErrCodeInvalid.Code {
		t.Fatalf("the right code after the provider's %d wrong checks = %+v, want refused", verifyMaxChecks, e.Error)
	}
	post[auth.Done](t, b, "/auth/phone/resend", fields{"phone": first}, http.StatusOK)
	post[auth.Done](t, b, "/auth/phone/verify", fields{"phone": first, "code": sms.lastCode(t, a, first)}, http.StatusOK)

	post[auth.Done](t, b, "/auth/phone/change", fields{"phone": second}, http.StatusOK)
	if text := sms.last(a, second); !strings.HasPrefix(text, providerText) {
		t.Fatalf("change text %q is not the provider's", text)
	}
	post[phone.ChangeResult](t, b, "/auth/phone/confirm-change", fields{"phone": second, "code": sms.lastCode(t, a, second)}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.Phone != second {
		t.Fatalf("/me after a provider-checked change = %+v", me)
	}
}

// TestPhoneOptions_Refusals: an unknown mode is refused, and so is
// GenerateCode beside WithVerifier, whose provider makes the code.
func TestPhoneOptions_Refusals(t *testing.T) {
	if _, err := phoneOptions("multi", &smsbox{}); !errors.Is(err, errUnknownMode) {
		t.Fatalf("phoneOptions(typo) = %v", err)
	}
	opts, err := phoneOptions(modeProvider, &smsbox{})
	if err != nil {
		t.Fatal(err)
	}
	gen := phone.GenerateCode(func(context.Context, phone.CodeFor) (string, error) { return "123456", nil })
	if _, err := newAuth(openDB(t), logMailer{}, &smsbox{}, append(opts, gen)...); !errors.Is(err, phone.ErrGenerateWithVerifier) {
		t.Fatalf("GenerateCode with WithVerifier = %v", err)
	}
}

// equalNumbers compares two lists of numbers in order.
func equalNumbers(got, want []phone.Number) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// signUp creates an account with a password and returns its signed-in browser.
func signUp(t *testing.T, a *auth.Auth, address string) *browser {
	t.Helper()
	b := newBrowser(t, newHandler(a))
	post[auth.Done](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK)
	return b
}

// addAndVerify adds number to the browser's account and verifies it.
func addAndVerify(t *testing.T, a *auth.Auth, sms *smsbox, b *browser, number string) {
	t.Helper()
	post[auth.Done](t, b, "/auth/phone/add", fields{"phone": number}, http.StatusOK)
	post[auth.Done](t, b, "/auth/phone/verify", fields{"phone": number, "code": sms.lastCode(t, a, number)}, http.StatusOK)
}

// openDB opens a fresh SQLite file in the test's temp dir.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newTestAuth builds the app in mode on a fresh SQLite file with an SMS box
// that records texts; mail is printed.
func newTestAuth(t *testing.T, m mode) (*auth.Auth, *smsbox) {
	t.Helper()
	box := &smsbox{}
	opts, err := phoneOptions(m, box)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(openDB(t), logMailer{}, box, opts...)
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
