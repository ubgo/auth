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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/plugin/email"
)

// generatedDir is where the committed client lives, relative to this package.
const generatedDir = "web/src/auth"

func discard(context.Context, email.Mail) error { return nil }

// newTestApp builds the app exactly as main does, on a fresh SQLite file.
func newTestApp(t *testing.T) http.Handler {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, email.MailerFunc(discard))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return newHandler(a)
}

// call sends one JSON request the way the generated client does (a GET with
// no body, a POST with a JSON body and the page's Origin) and decodes the
// answer, failing unless the status is want.
func call(t *testing.T, c *http.Client, srv, method, path, body string, want int) map[string]any {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if res.StatusCode != want {
		t.Fatalf("%s %s = %d %v, want %d", method, path, res.StatusCode, out, want)
	}
	return out
}

// TestNickname_TheClientsCallsWork walks what web/src/nickname-form.ts does
// over HTTP: set, the plugin's own error code, read back, and the session
// requirement.
func TestNickname_TheClientsCallsWork(t *testing.T) {
	ts := httptest.NewServer(newTestApp(t))
	defer ts.Close()
	inner, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The cookie is __Host- and Secure; loopbackJar keeps it for
	// http://127.0.0.1 the way a browser does.
	c := &http.Client{Jar: loopbackJar{inner}}

	call(t, c, ts.URL, http.MethodGet, "/auth/nickname/get", "", http.StatusUnauthorized)
	call(t, c, ts.URL, http.MethodPost, "/auth/password/sign-up", `{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}`, http.StatusOK)
	if got := call(t, c, ts.URL, http.MethodGet, "/auth/nickname/get", "", http.StatusOK); got["nickname"] != nil {
		t.Fatalf("a new user's nickname = %v, want null", got)
	}
	if got := call(t, c, ts.URL, http.MethodPost, "/auth/nickname/set", `{"nickname":"  Ada  "}`, http.StatusOK); got["nickname"] != "Ada" {
		t.Fatalf("set = %v, want the trimmed nickname", got)
	}
	tooLong := call(t, c, ts.URL, http.MethodPost, "/auth/nickname/set", `{"nickname":"`+strings.Repeat("x", 33)+`"}`, http.StatusBadRequest)
	if detail, _ := tooLong["error"].(map[string]any); detail["code"] != "nickname.too_long" {
		t.Fatalf("too long = %v, want nickname.too_long", tooLong)
	}
	if got := call(t, c, ts.URL, http.MethodGet, "/auth/nickname/get", "", http.StatusOK); got["nickname"] != "Ada" {
		t.Fatalf("get = %v, want the nickname that was kept", got)
	}
	call(t, c, ts.URL, http.MethodPost, "/auth/nickname/set", `{"nickname":""}`, http.StatusOK)
	if got := call(t, c, ts.URL, http.MethodGet, "/auth/nickname/get", "", http.StatusOK); got["nickname"] != nil {
		t.Fatalf("after clearing = %v, want null", got)
	}
}

// TestClient_GeneratedCopyIsCurrent runs `auth client ts` through the app's
// own command line into a temporary directory and compares every file with
// the copy committed in web/src/auth. It fails when the Go side changed (a
// field, an operation, an error code) and nobody ran go generate, which is
// the check an app keeps in CI so the frontend never compiles against a
// stale client.
//
//ds:def id=tsclientcustom-fresh-5hm2qw8z
func TestClient_GeneratedCopyIsCurrent(t *testing.T) {
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "unused.db")))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, err := newAuth(db, email.MailerFunc(discard))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	out := t.TempDir()
	var stdout, stderr bytes.Buffer
	code, handled := command(context.Background(), a, []string{authCommand, authcli.CmdClient, authcli.CmdClientTS, "--out", out}, &stdout, &stderr)
	if !handled || code != authcli.ExitOK {
		t.Fatalf("auth client ts = %d (handled %v): %s", code, handled, stderr.String())
	}
	written, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 5 {
		t.Fatalf("auth client ts wrote %d files, want 5", len(written))
	}
	for _, f := range written {
		want, err := os.ReadFile(filepath.Join(out, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		have, err := os.ReadFile(filepath.Join(generatedDir, f.Name()))
		if err != nil {
			t.Fatalf("%v; run: go generate ./ts-client-custom", err)
		}
		if !bytes.Equal(have, want) {
			t.Fatalf("%s/%s is stale; run: go generate ./ts-client-custom", generatedDir, f.Name())
		}
	}
	client, err := os.ReadFile(filepath.Join(generatedDir, "client.ts"))
	if err != nil || !bytes.Contains(client, []byte("export function nickname(): Plugin<\"nickname\", NicknameOps>")) {
		t.Fatalf("the committed client has no nickname() factory (%v)", err)
	}
	if _, handled := command(context.Background(), a, []string{"serve"}, &stdout, &stderr); handled {
		t.Fatal("a command line that is not `auth …` was taken by authcli")
	}
}

// loopbackJar is a cookie jar that treats http://127.0.0.1 as the secure
// origin a browser does, so a Secure __Host- cookie is kept and sent back on
// every Go version; only Go's newer jars do this themselves, and the
// examples declare an older minimum.
type loopbackJar struct{ *cookiejar.Jar }

func secure(u *url.URL) *url.URL { s := *u; s.Scheme = "https"; return &s }

func (j loopbackJar) SetCookies(u *url.URL, c []*http.Cookie) { j.Jar.SetCookies(secure(u), c) }
func (j loopbackJar) Cookies(u *url.URL) []*http.Cookie       { return j.Jar.Cookies(secure(u)) }
