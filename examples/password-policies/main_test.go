package main

import (
	"bytes"
	"context"
	"crypto/sha1" // the range API is keyed by SHA-1; it is an index, not a password hash
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/password/hibp"
)

const (
	testEmail = "alice@example.com"
	// testBreached is the one password the fake range API knows.
	testBreached = "Tr0ub4dor&3xyz"
	testGood     = "Correct Horse Battery 42"
)

// TestPolicies_RefuseInOrder: length first, then the class rule, then the
// company rule with its own code, then the breach check, and a password that
// passes them all creates the account.
func TestPolicies_RefuseInOrder(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	for _, tc := range []struct {
		pw   string
		code string
	}{
		{"Short1!", password.ErrTooShort.Code},
		{"alllowercaseletters", password.ErrWeak.Code},
		{"Acme Rocks 2026 Forever", ErrCompanyName.Code},
		{testBreached, password.ErrBreached.Code},
	} {
		got := post[errorAnswer](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": tc.pw}, http.StatusBadRequest)
		if got.Error.Code != tc.code {
			t.Fatalf("sign-up with %q: %s, want %s", tc.pw, got.Error.Code, tc.code)
		}
	}
	up := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testGood}, http.StatusOK)
	if up.User.ID == "" {
		t.Fatalf("sign-up = %+v", up)
	}
	if me := get[meResponse](t, b, "/me", http.StatusOK); me.ID != up.User.ID || !me.HasPassword {
		t.Fatalf("/me = %+v, want hasPassword", me)
	}
}

// TestPolicies_ApplyToChange: the same rules refuse a weak new password at
// change, and the current one still works afterwards.
func TestPolicies_ApplyToChange(t *testing.T) {
	a := newTestAuth(t)
	b := newBrowser(t, newHandler(a))
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": testEmail, "password": testGood}, http.StatusOK)
	got := post[errorAnswer](t, b, "/auth/password/change", fields{"current": testGood, "new": testBreached}, http.StatusBadRequest)
	if got.Error.Code != password.ErrBreached.Code {
		t.Fatalf("change to a breached password: %s", got.Error.Code)
	}
	post[none](t, b, "/auth/sign-out", none{}, http.StatusOK)
	post[none](t, b, "/auth/password/sign-in", fields{"identifier": testEmail, "password": testGood}, http.StatusOK)
}

// newTestAuth builds the app's Auth on a fresh SQLite file, with mail recorded
// and a fake range API that knows one breached password.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := httptest.NewServer(http.HandlerFunc(rangeAPI))
	t.Cleanup(srv.Close)
	checker := hibp.New(hibp.WithBaseURL(srv.URL+"/range/"), hibp.WithHTTPClient(srv.Client()))
	a, err := newAuth(db, &mailbox{}, checker)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// rangeAPI answers like api.pwnedpasswords.com/range/<prefix>: one line per
// known suffix with its count. It knows testBreached and nothing else, and
// checks that only the five-character prefix was sent.
func rangeAPI(w http.ResponseWriter, r *http.Request) {
	sum := sha1.Sum([]byte(testBreached))
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix := strings.TrimPrefix(r.URL.Path, "/range/")
	if len(prefix) != 5 {
		http.Error(w, "the range API takes a 5-character prefix", http.StatusBadRequest)
		return
	}
	if prefix == full[:5] {
		_, _ = w.Write([]byte(full[5:] + ":1234\r\n"))
	}
}

// mailbox records every mail sent; this example reads none of it.
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
