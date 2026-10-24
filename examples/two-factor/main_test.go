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
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	// hotpModulus keeps six digits of the truncated HMAC (RFC 4226).
	hotpModulus = 1_000_000
	// wrongCode and otherWrongCode are two codes; at most one of them is the
	// current code.
	wrongCode      = "000000"
	otherWrongCode = "111111"
)

// testKey is a fixed sealing key; production reads envKey.
var testKey = bytes.Repeat([]byte{7}, auth.SealKeySize)

// TestTwoFactor_EnrolSignInRecover walks the whole life of a factor over
// HTTP: enrol, confirm with the first code, a password sign-in that is only
// pending until the code, and a recovery code that works exactly once.
func TestTwoFactor_EnrolSignInRecover(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))

	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)

	enr := post[twofactor.EnrollResult](t, b, "/auth/twofactor/enroll", none{}, http.StatusOK)
	if !strings.HasPrefix(enr.URL, "otpauth://totp/"+appName+":"+testEmail+"?") {
		t.Fatalf("otpauth URL = %s, want issuer %s and the email as the account", enr.URL, appName)
	}
	wrong := wrongCode
	if totp(t, enr.Secret, time.Now()) == wrong {
		wrong = otherWrongCode
	}
	bad := post[errorAnswer](t, b, "/auth/twofactor/confirm", fields{"code": wrong}, http.StatusBadRequest)
	if bad.Error.Code != twofactor.ErrCodeInvalid.Code {
		t.Fatalf("confirm with a wrong code = %+v", bad.Error)
	}
	codes := post[twofactor.RecoveryCodes](t, b, "/auth/twofactor/confirm", fields{"code": totp(t, enr.Secret, time.Now())}, http.StatusOK)
	if len(codes.Codes) != twofactor.DefaultRecoveryCodes {
		t.Fatalf("recovery codes = %v", codes.Codes)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); !me.TwoFactorEnabled {
		t.Fatalf("/me = %+v, want two-factor on", me)
	}
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)

	// The password alone yields a pending session, which signs nobody in.
	in := post[password.SignInResult](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	if !in.SecondFactorRequired {
		t.Fatalf("sign-in = %+v, want the second factor required", in)
	}
	get[none](t, b, "/me", http.StatusUnauthorized)
	// The code that confirmed was spent: the next step's code is accepted
	// (one step of clock skew is allowed), a replay of the same step is not.
	post[none](t, b, "/auth/twofactor/verify", fields{"code": totp(t, enr.Secret, time.Now().Add(twofactor.Step))}, http.StatusOK)
	get[none](t, b, "/me", http.StatusOK)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)

	// A lost phone: a recovery code instead, dashes and case optional.
	post[none](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	recovery := codes.Codes[0]
	post[none](t, b, "/auth/twofactor/verify", fields{"code": strings.ToLower(strings.ReplaceAll(recovery, "-", ""))}, http.StatusOK)
	get[none](t, b, "/me", http.StatusOK)
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)

	post[none](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	reused := post[errorAnswer](t, b, "/auth/twofactor/verify", fields{"code": recovery}, http.StatusBadRequest)
	if reused.Error.Code != twofactor.ErrCodeInvalid.Code {
		t.Fatalf("a recovery code used twice = %+v", reused.Error)
	}
	get[none](t, b, "/me", http.StatusUnauthorized)
}

// TestSealKey pins the key rules main applies to the environment.
func TestSealKey(t *testing.T) {
	random, err := sealKey("")
	if err != nil || len(random) != auth.SealKeySize {
		t.Fatalf("unset key = %d bytes, %v", len(random), err)
	}
	hexKey := strings.Repeat("ab", auth.SealKeySize)
	if key, err := sealKey(hexKey); err != nil || len(key) != auth.SealKeySize || key[0] != 0xab {
		t.Fatalf("hex key = %x, %v", key, err)
	}
	for _, bad := range []string{"not hex", hexKey[:10]} {
		if _, err := sealKey(bad); err == nil {
			t.Fatalf("sealKey(%q) accepted a malformed key", bad)
		}
	}
}

// totp is an independent RFC 6238 implementation (HMAC-SHA1, 30-second
// steps, six digits), so the test does not check the plugin against itself.
// It is what an authenticator app computes from the enrolled secret.
func totp(t *testing.T, secretB32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secretB32)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(at.Unix()/int64(twofactor.Step/time.Second)))
	m := hmac.New(sha1.New, secret)
	m.Write(counter[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%0*d", twofactor.Digits, (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%hotpModulus)
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mail sink.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }), testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
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
