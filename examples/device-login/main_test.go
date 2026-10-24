package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/deviceauth"
	"github.com/ubgo/auth/plugin/email"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery"
)

// userCodeIn finds the user code in what the CLI printed.
var userCodeIn = regexp.MustCompile(`enter the code (\S+)`)

// TestDeviceLogin_ApproveSignsTheCLIIn: the CLI asks for a code and prints
// it; a signed-in browser looks the code up (which claims it) and approves;
// the CLI's poll then gets a session of that browser's user, and /me answers
// it as a bearer credential.
func TestDeviceLogin_ApproveSignsTheCLIIn(t *testing.T) {
	srv, web := newTestServer(t)
	var out bytes.Buffer
	c := newClient(srv.Client(), srv.URL)
	// The CLI's wait before its first poll is where the person approves: the
	// test's browser does it there, so the first poll finds the approval.
	c.Sleep = func(context.Context, time.Duration) error {
		code := printedCode(t, out.String())
		lookup := do[deviceauth.VerifyResult](t, web, http.MethodGet, authPrefix+"/device/verify?user_code="+url.QueryEscape(code), nil, http.StatusOK)
		if !lookup.Owned || lookup.ClientID != clientID || lookup.Status != deviceauth.StatusPending {
			t.Errorf("lookup = %+v, want a pending code of %s owned by the browser", lookup, clientID)
		}
		do[deviceauth.DecisionResult](t, web, http.MethodPost, authPrefix+"/device/approve", fields{"userCode": code}, http.StatusOK)
		return nil
	}
	if err := login(context.Background(), &out, c); err != nil {
		t.Fatalf("login: %v\n%s", err, out.String())
	}
	got := out.String()
	if !strings.Contains(got, "open "+baseURL+"/device and enter the code ") || !strings.Contains(got, `/me answered with credential "bearer"`) || !strings.Contains(got, "(Alice)") {
		t.Fatalf("the CLI printed:\n%s", got)
	}
}

// TestDeviceLogin_DenyEndsTheCLI: a denial ends the poll with the RFC's
// access_denied, and the code cannot be approved afterwards.
func TestDeviceLogin_DenyEndsTheCLI(t *testing.T) {
	srv, web := newTestServer(t)
	var out bytes.Buffer
	var code string
	c := newClient(srv.Client(), srv.URL)
	c.Sleep = func(context.Context, time.Duration) error {
		code = printedCode(t, out.String())
		do[deviceauth.VerifyResult](t, web, http.MethodGet, authPrefix+"/device/verify?user_code="+url.QueryEscape(code), nil, http.StatusOK)
		do[deviceauth.DecisionResult](t, web, http.MethodPost, authPrefix+"/device/deny", fields{"userCode": code}, http.StatusOK)
		return nil
	}
	err := login(context.Background(), &out, c)
	var ce *deviceauth.ClientError
	if !errors.As(err, &ce) || ce.ErrorName != deviceauth.RFCAccessDenied {
		t.Fatalf("login after a denial: %v, want access_denied", err)
	}
	if strings.Contains(out.String(), "signed in as") {
		t.Fatalf("a denied CLI signed in:\n%s", out.String())
	}
}

// TestDeviceLogin_UnknownClientIsRefused: the web app accepts only clientID,
// so another client gets invalid_client and no code.
func TestDeviceLogin_UnknownClientIsRefused(t *testing.T) {
	srv, _ := newTestServer(t)
	c := newClient(srv.Client(), srv.URL)
	c.ClientID = "someone-else"
	_, err := c.RequestCode(context.Background(), "")
	var ce *deviceauth.ClientError
	if !errors.As(err, &ce) || ce.ErrorName != deviceauth.RFCInvalidClient {
		t.Fatalf("an unknown client: %v, want invalid_client", err)
	}
}

// TestDeviceLogin_MeNeedsASession: /me refuses a request with no session,
// and a bad bearer token is refused before any decoding.
func TestDeviceLogin_MeNeedsASession(t *testing.T) {
	srv, _ := newTestServer(t)
	var who meResponse
	if err := call(context.Background(), srv.Client(), srv.URL+"/me", "not-a-session", &who); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("/me with a bad token: %v, want 401", err)
	}
}

func TestSQLiteDSN_EscapesThePath(t *testing.T) {
	if got := sqliteDSN("a#b?c.db"); !strings.HasPrefix(got, "file:a%23b%3Fc.db?") {
		t.Fatalf("sqliteDSN = %s", got)
	}
}

func TestLogMailer_Sends(t *testing.T) {
	if err := (logMailer{}).Send(context.Background(), email.Mail{To: testEmail, Subject: "s", Text: "t"}); err != nil {
		t.Fatal(err)
	}
}

// printedCode is the user code the CLI printed so far.
func printedCode(t *testing.T, printed string) string {
	t.Helper()
	m := userCodeIn.FindStringSubmatch(printed)
	if m == nil {
		t.Fatalf("no code in the CLI's output:\n%s", printed)
	}
	return m[1]
}

// newTestServer runs the web app on a TLS test server (the session cookie is
// __Host- and Secure) and returns it with a browser that has signed up.
func newTestServer(t *testing.T) (*httptest.Server, *browser) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, dp, err := newAuth(db, logMailer{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(newHandler(a, dp))
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// srv.Client() is shared; copy it so the jar belongs to the browser and
	// the CLI's client stays cookie-less, as a real CLI is.
	client := *srv.Client()
	client.Jar = jar
	web := &browser{srv: srv, client: &client}
	do[json.RawMessage](t, web, http.MethodPost, authPrefix+"/password/sign-up", fields{"identifier": testEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	return srv, web
}

// browser is a client with a cookie jar against the test server.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// do sends a request with the app's Origin, checks the status and decodes
// the answer as Out.
func do[Out any](t *testing.T, b *browser, method, path string, in fields, status int) Out {
	t.Helper()
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, b.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != status {
		t.Fatalf("%s %s: %d %s, want %d", method, path, res.StatusCode, raw, status)
	}
	var out Out
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", method, path, raw, err)
	}
	return out
}
