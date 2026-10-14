package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/email"
)

// nodeMinMajor and nodeMinMinor are the first Node version that runs a .ts
// file without a flag (type stripping on by default in 22.18 and 23.6).
const (
	nodeMinMajor = 22
	nodeMinMinor = 18
)

// nodeTimeout bounds each Node program; each takes well under a second.
const nodeTimeout = 60 * time.Second

// tokenFile is the CLI's default token file, in the directory it runs in.
const tokenFile = ".auth-token"

// tokenFileMode is the mode cli.ts writes the token with (TOKEN_FILE_MODE).
const tokenFileMode fs.FileMode = 0o600

// testPassword is the password the test signs up with.
const testPassword = "correct horse battery staple"

// sessionCookie is authhttp's session cookie, which a browser sends to the
// Node server and the Node server forwards.
const sessionCookie = "__Host-auth_session"

// nodeVersion matches `node --version`, such as v26.4.0.
var nodeVersion = regexp.MustCompile(`^v(\d+)\.(\d+)\.`)

// tsSources are the TypeScript files node runs: this example's and the
// client's it imports.
var tsSources = []string{"web/*.ts", "../../clients/ts/src/*.ts"}

// trackSources reads every file node will run. go test caches a passing
// result by the files the test process itself opened, and node opens these
// in another process, so without this read an edit to a .ts file would be
// answered from the cache with the old "ok".
func trackSources(t *testing.T) {
	t.Helper()
	for _, pattern := range tsSources {
		files, err := filepath.Glob(pattern)
		if err != nil || len(files) == 0 {
			t.Fatalf("no TypeScript sources match %s (%v)", pattern, err)
		}
		for _, f := range files {
			if _, err := os.ReadFile(f); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// requireNode fails the test, never skips it, when node is missing or too
// old: a skipped run would leave the TypeScript programs unchecked while the
// suite stays green.
func requireNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs web/*.ts and needs Node %d.%d or later", nodeMinMajor, nodeMinMinor)
	}
	out, err := exec.Command(node, "--version").Output()
	if err != nil {
		t.Fatalf("node --version: %v", err)
	}
	m := nodeVersion.FindSubmatch(out)
	if m == nil {
		t.Fatalf("node --version printed %q", out)
	}
	major, _ := strconv.Atoi(string(m[1])) // the pattern matched digits
	minor, _ := strconv.Atoi(string(m[2]))
	if major < nodeMinMajor || (major == nodeMinMajor && minor < nodeMinMinor) {
		t.Fatalf("node %s is too old: Node %d.%d or later runs .ts files without a flag", bytes.TrimSpace(out), nodeMinMajor, nodeMinMinor)
	}
	return node
}

// startAPI starts the server exactly as main wires it, on a fresh SQLite
// file and a random port.
func startAPI(t *testing.T) *httptest.Server {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, email.MailerFunc(func(context.Context, email.Mail) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(a))
	t.Cleanup(srv.Close)
	return srv
}

// webFile is the absolute path of a program in web/, so a command can run
// in another directory.
func webFile(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("web", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCLI_TheTokenSurvivesARestart runs web/cli.ts once per command, each a
// new process in the same directory, and checks every printed line and exit
// code, and the token file between them.
func TestCLI_TheTokenSurvivesARestart(t *testing.T) {
	node := requireNode(t)
	trackSources(t)
	api := startAPI(t)
	cli := webFile(t, "cli.ts")
	dir := t.TempDir()

	steps := []struct {
		args      []string
		want      string
		exit      int
		tokenFile bool
	}{
		{[]string{"whoami"}, "not signed in (auth.signed_out)\n", 1, false},
		{[]string{"sign-up", "ada@example.com", testPassword, "Ada"}, "signed up and signed in as Ada; token saved\n", 0, true},
		{[]string{"whoami"}, "Ada (token read from .auth-token)\n", 0, true},
		{[]string{"sign-out"}, "signed out; token file removed\n", 0, false},
		{[]string{"whoami"}, "not signed in (auth.signed_out)\n", 1, false},
		{[]string{"sign-in", "ada@example.com", "not the password"}, "The sign-in details are not right. (password.invalid_credentials)\n", 1, false},
		{[]string{"sign-in", "ada@example.com", testPassword}, "signed in as Ada; token saved\n", 0, true},
		{[]string{"whoami"}, "Ada (token read from .auth-token)\n", 0, true},
	}
	for _, s := range steps {
		ctx, cancel := context.WithTimeout(context.Background(), nodeTimeout)
		cmd := exec.CommandContext(ctx, node, append([]string{cli}, s.args...)...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "AUTH_URL="+api.URL)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		cancel()
		exit := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exit = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("cli.ts %s: %v", s.args[0], err)
		}
		if stdout.String() != s.want || exit != s.exit {
			t.Fatalf("cli.ts %s = exit %d %q (stderr %q), want exit %d %q", s.args[0], exit, stdout.String(), stderr.String(), s.exit, s.want)
		}
		info, err := os.Stat(filepath.Join(dir, tokenFile))
		switch {
		case s.tokenFile && err != nil:
			t.Fatalf("after %s: the token file is missing: %v", s.args[0], err)
		case s.tokenFile && info.Mode().Perm() != tokenFileMode:
			t.Fatalf("after %s: token file mode %v, want %v", s.args[0], info.Mode().Perm(), tokenFileMode)
		case !s.tokenFile && !errors.Is(err, fs.ErrNotExist):
			t.Fatalf("after %s: the token file exists (%v), want it removed", s.args[0], err)
		}
	}
}

// TestServer_ForwardsTheBrowsersCookie signs in the way a browser does
// (cookie mode, the page's Origin), then asks web/server.ts for its page
// with that browser's Cookie header, without one, and with the cookie after
// sign-out.
func TestServer_ForwardsTheBrowsersCookie(t *testing.T) {
	node := requireNode(t)
	trackSources(t)
	api := startAPI(t)

	// The browser: a cookie jar (Go's keeps the Secure __Host- cookie for
	// http://127.0.0.1) and the app's Origin on every POST.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	browser := &http.Client{Jar: jar}
	post := func(path, body string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, api.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", baseURL)
		req.Header.Set("Content-Type", "application/json")
		res, err := browser.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("POST %s = %d", path, res.StatusCode)
		}
	}
	post("/auth/password/sign-up", `{"identifier":"ada@example.com","password":"`+testPassword+`","name":"Ada"}`)
	apiURL, err := url.Parse(api.URL)
	if err != nil {
		t.Fatal(err)
	}
	var cookie string
	for _, c := range jar.Cookies(apiURL) {
		if c.Name == sessionCookie {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("sign-up set no session cookie")
	}

	// The Node server on a free port; its first line names it.
	ctx, cancel := context.WithTimeout(context.Background(), nodeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, webFile(t, "server.ts"))
	cmd.Env = append(os.Environ(), "AUTH_URL="+api.URL, "PORT=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	first, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("server.ts printed no address: %v (stderr %q)", err, stderr.String())
	}
	page, ok := strings.CutPrefix(strings.TrimSpace(first), "listening on ")
	if !ok {
		t.Fatalf("server.ts printed %q, want its address", first)
	}

	get := func(cookie string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, page+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, string(body)
	}
	if code, body := get(cookie); code != http.StatusOK || body != "hello Ada\n" {
		t.Fatalf("with the cookie = %d %q, want 200 hello Ada", code, body)
	}
	if code, body := get(""); code != http.StatusUnauthorized || body != "signed out\n" {
		t.Fatalf("without a cookie = %d %q, want 401 signed out", code, body)
	}
	post("/auth/sign-out", `{}`)
	if code, body := get(cookie); code != http.StatusUnauthorized || body != "signed out\n" {
		t.Fatalf("with the cookie after sign-out = %d %q, want 401 signed out", code, body)
	}
	if stderr.Len() != 0 {
		t.Fatalf("server.ts logged: %s", stderr.String())
	}
}
