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

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

const (
	// aliceEmail is the user with a delivered-code factor.
	aliceEmail = "alice@example.com"
	// testPassword is alice's password.
	testPassword = "correct horse battery staple"
	// testSecret is the deployment secret, exactly auth.MinSecretSize bytes.
	testSecret = "0123456789abcdef0123456789abcdef"
	// wrongCode is never a delivered code: the core's codes are random
	// digits, and the test retries in the one-in-a-million case it is.
	wrongCode = "000000"
	// minCodeLength is the shortest run of digits read as a mailed code.
	minCodeLength = 6
)

// TestTwoFactorOptions_DeliveredCodeAndTrustedDevice: a user enrols a mailed
// code as their factor, a password sign-in is pending until the mailed code,
// "remember this device" skips the factor on the next sign-in from that
// browser only, and the device is listed.
func TestTwoFactorOptions_DeliveredCodeAndTrustedDevice(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	laptop := newBrowser(t, srv)
	enrolDelivered(t, a, box, laptop)

	post[none](t, laptop, "/auth/sign-out", none{}, http.StatusOK)
	in := post[password.SignInResult](t, laptop, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	if !in.SecondFactorRequired {
		t.Fatal("a password sign-in of a user with a factor was not pending")
	}
	get[errorAnswer](t, laptop, "/me", http.StatusUnauthorized)
	post[none](t, laptop, "/auth/twofactor/send", none{}, http.StatusOK)
	post[none](t, laptop, "/auth/twofactor/verify", verifyBody{Code: box.lastCode(t, a, aliceEmail), TrustDevice: true}, http.StatusOK)
	get[meResponse](t, laptop, "/me", http.StatusOK)

	post[none](t, laptop, "/auth/sign-out", none{}, http.StatusOK)
	again := post[password.SignInResult](t, laptop, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	if again.SecondFactorRequired {
		t.Fatal("a trusted device was asked for the factor again")
	}
	devices := get[twofactor.DevicesResult](t, laptop, "/auth/twofactor/devices", http.StatusOK)
	if len(devices.Devices) != 1 || !devices.Devices[0].Current {
		t.Fatalf("devices = %+v, want this one", devices.Devices)
	}

	phone := newBrowser(t, srv)
	other := post[password.SignInResult](t, phone, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	if !other.SecondFactorRequired {
		t.Fatal("another device skipped the factor: trust must belong to one device")
	}
}

// TestTwoFactorOptions_PolicyAsksAfterAMailedCode: with signInPolicy, a
// sign-in by mailed code asks for the factor too; the default policy would
// let it through.
func TestTwoFactorOptions_PolicyAsksAfterAMailedCode(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	enrolDelivered(t, a, box, newBrowser(t, srv))

	b := newBrowser(t, srv)
	post[none](t, b, "/auth/email/send-code", fields{"email": aliceEmail}, http.StatusOK)
	in := post[email.CodeSignInResult](t, b, "/auth/email/sign-in-code", fields{"email": aliceEmail, "code": box.lastCode(t, a, aliceEmail)}, http.StatusOK)
	if !in.SecondFactorRequired {
		t.Fatal("a sign-in by mailed code skipped the factor under signInPolicy")
	}
	ask, err := twofactor.DefaultPolicy(context.Background(), twofactor.PolicyRequest{SignInAttempt: auth.SignInAttempt{Operation: email.EndpointSignInCode, Method: email.PluginName}})
	if err != nil || ask {
		t.Fatalf("DefaultPolicy after a mailed code = %v, %v; want false, which is why the app replaces it", ask, err)
	}
	ask, err = twofactor.DefaultPolicy(context.Background(), twofactor.PolicyRequest{SignInAttempt: auth.SignInAttempt{Operation: "passkey.login-finish", Method: "passkey", SingleFactor: true}})
	if err != nil || !ask {
		t.Fatalf("DefaultPolicy after a passkey that did not verify the user = %v, %v; want true", ask, err)
	}
}

// TestTwoFactorOptions_LockoutRefusesEvenTheRightCode: maxWrongCodes wrong
// codes in a row lock the factor, and while it is locked the right code is
// refused too, so guessing gains nothing.
func TestTwoFactorOptions_LockoutRefusesEvenTheRightCode(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	enrolDelivered(t, a, box, newBrowser(t, srv))

	b := newBrowser(t, srv)
	post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[none](t, b, "/auth/twofactor/send", none{}, http.StatusOK)
	code := box.lastCode(t, a, aliceEmail)
	if code == wrongCode {
		t.Skip("the mailed code is the wrong code; run again")
	}
	for range maxWrongCodes {
		bad := post[errorAnswer](t, b, "/auth/twofactor/verify", fields{"code": wrongCode}, http.StatusBadRequest)
		if bad.Error.Code != twofactor.ErrCodeInvalid.Code {
			t.Fatalf("a wrong code = %+v", bad.Error)
		}
	}
	right := post[errorAnswer](t, b, "/auth/twofactor/verify", fields{"code": code}, http.StatusTooManyRequests)
	if right.Error.Code != twofactor.ErrLocked.Code {
		t.Fatalf("the right code after %d wrong ones = %+v, want %s", maxWrongCodes, right.Error, twofactor.ErrLocked.Code)
	}
}

// TestTwoFactorOptions_StepUpCheck: a signed-in user proves the factor again
// before a sensitive action; the check changes no session.
func TestTwoFactorOptions_StepUpCheck(t *testing.T) {
	a, box := newTestAuth(t)
	srv := newServer(t, newHandler(a))
	b := newBrowser(t, srv)
	enrolDelivered(t, a, box, b)

	post[none](t, b, "/auth/twofactor/send", none{}, http.StatusOK)
	code := box.lastCode(t, a, aliceEmail)
	if code != wrongCode {
		bad := post[errorAnswer](t, b, "/auth/twofactor/check", fields{"code": wrongCode}, http.StatusBadRequest)
		if bad.Error.Code != twofactor.ErrCodeInvalid.Code {
			t.Fatalf("step-up with a wrong code = %+v", bad.Error)
		}
	}
	post[none](t, b, "/auth/twofactor/check", fields{"code": code}, http.StatusOK)
	get[meResponse](t, b, "/me", http.StatusOK)
}

// enrolDelivered signs alice up on b, verifies her address (a delivered code
// needs a verified channel) and turns on the mailed-code factor with its first
// code. b stays signed in.
func enrolDelivered(t *testing.T, a *auth.Auth, box *mailbox, b *browser) {
	t.Helper()
	post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[email.VerifyResult](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)
	enr := post[twofactor.EnrollResult](t, b, "/auth/twofactor/enroll", fields{"method": string(twofactor.MethodDelivered)}, http.StatusOK)
	if enr.Method != twofactor.MethodDelivered || enr.URL != "" {
		t.Fatalf("enroll = %+v, want a delivered factor with no QR code", enr)
	}
	codes := post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/confirm", fields{"code": box.lastCode(t, a, aliceEmail)}, http.StatusOK)
	if len(codes.Codes) == 0 {
		t.Fatal("confirm returned no recovery codes")
	}
}

// verifyBody is the verify request with "remember this device", the one body
// here with a field that is not a string.
type verifyBody struct {
	Code        string `json:"code"`
	TrustDevice bool   `json:"trustDevice"`
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
	a, err := newAuth(db, []byte(testSecret), box)
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
