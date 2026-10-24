package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // RFC 6238 TOTP is HMAC-SHA1, the algorithm every authenticator app uses
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

const (
	aliceEmail = "alice@example.com"
	staffEmail = "support@example.com"
	secret     = "correct horse battery staple"
	// hotpModulus keeps six digits of the truncated HMAC (RFC 4226).
	hotpModulus = 1_000_000
	// unknownUser is a user id nobody has.
	unknownUser = "usr_nobody"
)

// testSecret is a fixed app secret, long enough for auth.WithSecret.
var testSecret = bytes.Repeat([]byte{7}, 32)

// TestTwoFactorManage_ShowAgain: the otpauth URI is read back with the
// password and matches the one enrolled, and the recovery codes are shown
// again as they were handed out, in the same order, minus one that was used.
func TestTwoFactorManage_ShowAgain(t *testing.T) {
	a, _ := newTestAuth(t)
	staff := staffList{}
	b := newBrowser(t, newHandler(a, nil, staff))
	signUp(t, b, aliceEmail)
	enr, codes := enrol(t, b)

	if e := post[errorAnswer](t, b, "/auth/twofactor/totp-uri", fields{"password": "not the password"}, http.StatusUnauthorized); e.Error.Code != password.ErrInvalidCredentials.Code {
		t.Fatalf("totp-uri with a wrong password = %+v", e.Error)
	}
	if got := post[twofactor.TOTPURIResult](t, b, "/auth/twofactor/totp-uri", fields{"password": secret}, http.StatusOK); got.URL != enr.URL {
		t.Fatalf("totp-uri = %q, want the enrolled %q", got.URL, enr.URL)
	}
	if got := post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/recovery-codes/view", fields{}, http.StatusOK); !slices.Equal(got.Codes, codes.Codes) {
		t.Fatalf("view = %v, want %v", got.Codes, codes.Codes)
	}

	// A recovery code spent at sign-in drops out of the view.
	post[auth.Done](t, b, "/auth/sign-out", fields{}, http.StatusOK)
	post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": secret}, http.StatusOK)
	post[auth.Done](t, b, "/auth/twofactor/verify", fields{"code": codes.Codes[0]}, http.StatusOK)
	if got := post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/recovery-codes/view", fields{}, http.StatusOK); !slices.Equal(got.Codes, codes.Codes[1:]) {
		t.Fatalf("view after one was used = %v, want %v", got.Codes, codes.Codes[1:])
	}
}

// TestTwoFactorManage_Disable: turning the factor off needs a code the user
// could pass with, after which sign-in is a full session again.
func TestTwoFactorManage_Disable(t *testing.T) {
	a, _ := newTestAuth(t)
	b := newBrowser(t, newHandler(a, nil, staffList{}))
	signUp(t, b, aliceEmail)
	enr, _ := enrol(t, b)

	if e := post[errorAnswer](t, b, "/auth/twofactor/disable", fields{"code": wrong(t, enr.Secret)}, http.StatusBadRequest); e.Error.Code != twofactor.ErrCodeInvalid.Code {
		t.Fatalf("disable with a wrong code = %+v", e.Error)
	}
	// The code that confirmed was spent; the next step's code is accepted.
	post[auth.Done](t, b, "/auth/twofactor/disable", fields{"code": totp(t, enr.Secret, time.Now().Add(twofactor.Step))}, http.StatusOK)
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.TwoFactorEnabled {
		t.Fatalf("/me after disable = %+v", me)
	}
	if e := post[errorAnswer](t, b, "/auth/twofactor/disable", fields{"code": "000000"}, http.StatusConflict); e.Error.Code != twofactor.ErrNotEnrolled.Code {
		t.Fatalf("disable twice = %+v", e.Error)
	}
	post[auth.Done](t, b, "/auth/sign-out", fields{}, http.StatusOK)
	if in := post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": secret}, http.StatusOK); in.SecondFactorRequired {
		t.Fatalf("sign-in after disable = %+v, want a full session", in)
	}
}

// TestTwoFactorManage_Support: a lockout refuses even the right code until
// staff unlock it; reset turns the factor off for a user who lost everything;
// only staff may call either, and a mistyped id is not_enrolled.
func TestTwoFactorManage_Support(t *testing.T) {
	a, tf := newTestAuth(t)
	staff := staffList{}
	h := newHandler(a, tf, staff)

	alice := newBrowser(t, h)
	aliceID := signUp(t, alice, aliceEmail)
	enr, _ := enrol(t, alice)
	desk := newBrowser(t, h)
	staff[signUp(t, desk, staffEmail)] = true

	// Alice locks herself out at sign-in.
	post[auth.Done](t, alice, "/auth/sign-out", fields{}, http.StatusOK)
	post[password.SignInResult](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": secret}, http.StatusOK)
	for range maxWrongCodes {
		post[errorAnswer](t, alice, "/auth/twofactor/verify", fields{"code": wrong(t, enr.Secret)}, http.StatusBadRequest)
	}
	next := totp(t, enr.Secret, time.Now().Add(twofactor.Step))
	if e := post[errorAnswer](t, alice, "/auth/twofactor/verify", fields{"code": next}, http.StatusTooManyRequests); e.Error.Code != twofactor.ErrLocked.Code {
		t.Fatalf("the right code while locked = %+v", e.Error)
	}

	// Only staff may call support, and a mistyped id shows up.
	if e := post[errorAnswer](t, newSignedIn(t, h, "mallory@example.com"), "/support/two-factor/unlock", fields{"userId": aliceID}, http.StatusForbidden); e.Error.Code != errNotStaff.Code {
		t.Fatalf("unlock by a non-staff user = %+v", e.Error)
	}
	if e := post[errorAnswer](t, desk, "/support/two-factor/reset", fields{"userId": unknownUser}, http.StatusConflict); e.Error.Code != twofactor.ErrNotEnrolled.Code {
		t.Fatalf("reset of an unknown id = %+v", e.Error)
	}

	post[auth.Done](t, desk, "/support/two-factor/unlock", fields{"userId": aliceID}, http.StatusOK)
	post[auth.Done](t, alice, "/auth/twofactor/verify", fields{"code": next}, http.StatusOK)
	if me := get[meResponse](t, alice, "/me", http.StatusOK); !me.TwoFactorEnabled {
		t.Fatalf("/me after unlock = %+v, want the factor untouched", me)
	}

	post[auth.Done](t, desk, "/support/two-factor/reset", fields{"userId": aliceID}, http.StatusOK)
	post[auth.Done](t, alice, "/auth/sign-out", fields{}, http.StatusOK)
	if in := post[password.SignInResult](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": secret}, http.StatusOK); in.SecondFactorRequired {
		t.Fatalf("sign-in after reset = %+v, want the first factor only", in)
	}
}

// TestTwoFactorManage_AdminRoutes: an admin sees alice's factor, pauses it
// (she signs in with her password alone), switches it back on (her sessions
// end and her recovery codes work again) and resets it; alice herself is
// refused, and an admin's own factor cannot be paused or reset over HTTP.
func TestTwoFactorManage_AdminRoutes(t *testing.T) {
	a, _ := newTestAuth(t)
	h := newHandler(a, nil, staffList{})
	alice := newBrowser(t, h)
	aliceID := signUp(t, alice, aliceEmail)
	_, codes := enrol(t, alice)
	desk := newBrowser(t, h)
	deskID := signUp(t, desk, staffEmail)
	ad, err := auth.PluginOf[*admin.Plugin](a)
	if err != nil {
		t.Fatal(err)
	}
	if err := ad.Grant(context.Background(), deskID); err != nil { // main uses STAFF_USER_IDS instead
		t.Fatal(err)
	}
	state := "/auth/admin/two-factor?userId=" + aliceID
	body := fields{"userId": aliceID}

	if e := get[errorAnswer](t, alice, state, http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("alice reading her own factor through admin = %+v", e.Error)
	}
	if got := get[admin.TwoFactorResult](t, desk, state, http.StatusOK); got != (admin.TwoFactorResult{Enrolled: true, Enabled: true, Method: string(twofactor.MethodTOTP)}) {
		t.Fatalf("two-factor = %+v", got)
	}

	post[auth.Done](t, desk, "/auth/admin/disable-two-factor", body, http.StatusOK)
	if got := get[admin.TwoFactorResult](t, desk, state, http.StatusOK); got.Enabled || !got.Enrolled {
		t.Fatalf("after disable = %+v, want paused", got)
	}
	post[auth.Done](t, alice, "/auth/sign-out", fields{}, http.StatusOK)
	if in := post[password.SignInResult](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": secret}, http.StatusOK); in.SecondFactorRequired {
		t.Fatalf("sign-in while paused = %+v, want a full session", in)
	}

	post[auth.Done](t, desk, "/auth/admin/enable-two-factor", body, http.StatusOK)
	get[errorAnswer](t, alice, "/me", http.StatusUnauthorized)
	if in := post[password.SignInResult](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": secret}, http.StatusOK); !in.SecondFactorRequired {
		t.Fatalf("sign-in after enable = %+v, want the factor asked for", in)
	}
	post[auth.Done](t, alice, "/auth/twofactor/verify", fields{"code": codes.Codes[1]}, http.StatusOK)

	if e := post[errorAnswer](t, desk, "/auth/admin/reset-two-factor", fields{"userId": deskID}, http.StatusConflict); e.Error.Code != admin.ErrAdminTarget.Code {
		t.Fatalf("resetting an admin = %+v", e.Error)
	}
	post[auth.Done](t, desk, "/auth/admin/reset-two-factor", body, http.StatusOK)
	if got := get[admin.TwoFactorResult](t, desk, state, http.StatusOK); got != (admin.TwoFactorResult{}) {
		t.Fatalf("after reset = %+v, want no factor", got)
	}
}

// TestTwoFactorManage_NeedsSecret: sealed recovery codes need auth.WithSecret,
// so a missing AUTH_SECRET stops auth.New instead of starting an app whose
// codes nothing can open.
func TestTwoFactorManage_NeedsSecret(t *testing.T) {
	if _, _, err := newAuth(openDB(t), nil, logMailer{}); err == nil {
		t.Fatal("newAuth started without a secret")
	}
}

// enrol turns on the authenticator-app factor for the browser's user.
func enrol(t *testing.T, b *browser) (twofactor.EnrollResult, twofactor.RecoveryCodes) {
	t.Helper()
	enr := post[twofactor.EnrollResult](t, b, "/auth/twofactor/enroll", fields{}, http.StatusOK)
	codes := post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/confirm", fields{"code": totp(t, enr.Secret, time.Now())}, http.StatusOK)
	return enr, codes
}

// signUp creates an account with a password in b and returns its user id.
func signUp(t *testing.T, b *browser, address string) string {
	t.Helper()
	return post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": address, "password": secret}, http.StatusOK).User.ID
}

// newSignedIn returns a browser signed in to a new account.
func newSignedIn(t *testing.T, h http.Handler, address string) *browser {
	t.Helper()
	b := newBrowser(t, h)
	signUp(t, b, address)
	return b
}

// wrong returns a six-digit code that is none of the codes accepted now
// (the previous, current and next step).
func wrong(t *testing.T, secretB32 string) string {
	t.Helper()
	now := time.Now()
	valid := []string{totp(t, secretB32, now.Add(-twofactor.Step)), totp(t, secretB32, now), totp(t, secretB32, now.Add(twofactor.Step))}
	for i := range 10 {
		c := fmt.Sprintf("%06d", i*111111)
		if !slices.Contains(valid, c) {
			return c
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

// totp is an independent RFC 6238 implementation (HMAC-SHA1, 30-second
// steps, six digits): what an authenticator app computes from the secret.
func totp(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/int64(twofactor.Step/time.Second)))
	m := hmac.New(sha1.New, key)
	m.Write(counter[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%0*d", twofactor.Digits, (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%hotpModulus)
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

// newTestAuth builds the app's Auth on a fresh SQLite file, mail discarded.
func newTestAuth(t *testing.T) (*auth.Auth, *twofactor.Plugin) {
	t.Helper()
	a, tf, err := newAuth(openDB(t), testSecret, email.MailerFunc(func(context.Context, email.Mail) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, tf
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

// fields is a JSON request body as a client writes it. The library's request
// types are not used to send: their secrets encode as "[redacted]" on purpose.
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
