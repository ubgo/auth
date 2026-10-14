package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// nodeMinMajor and nodeMinMinor are the first Node version that runs a .ts
// file without a flag (type stripping on by default in 22.18 and 23.6).
const (
	nodeMinMajor = 22
	nodeMinMinor = 18
)

// nodeTimeout bounds the script; it takes well under a second.
const nodeTimeout = 60 * time.Second

// wantFlows is everything web/flows.ts prints when every flow answers as it
// should. The README's transcript is this text.
const wantFlows = `email verification
  ok   password.signUp: signed in as Ada
       mail: "Verify your email address"
  ok   email.verify: address verified
  err  email.verify (same link again): auth.token_invalid
password reset
  ok   password.forgot: check_your_inbox
       mail: "Reset your password"
  ok   password.reset
  err  password.signIn (old password): password.invalid_credentials
  ok   password.signIn (new password): signed in as Ada
magic link
  ok   magiclink.send
       mail: "Your sign-in link"
  ok   magiclink.signIn: signed in as Ada
  err  magiclink.signIn (same link again): auth.token_invalid
sign out everywhere
  ok   session (laptop): Ada
  ok   session (phone): Ada
  ok   signOutAll (from the phone)
  err  session (laptop): auth.signed_out
  err  session (phone): auth.signed_out
second factor by mailed code
  ok   password.signIn: secondFactorRequired=false
  ok   twofactor.enroll: method=delivered enabled=false
       mail: "Your sign-in code"
  ok   twofactor.confirm: 10 recovery codes
  ok   signOut
  ok   password.signIn: secondFactorRequired=true
  err  session (pending): auth.signed_out
  ok   twofactor.send
       mail: "Your sign-in code"
  err  twofactor.verify (wrong code): twofactor.code_invalid
  ok   twofactor.verify
  ok   session: Ada
re-authentication on the current session
  err  password.reauthenticate (wrong password): password.invalid_credentials
  ok   password.reauthenticate: fresh=false secondFactorRequired=true
  ok   twofactor.send
       mail: "Your sign-in code"
  ok   twofactor.reauthenticate: fresh=true
  ok   sessions (the same one, now fresh): same id: true
organizations
  ok   organization.create: Acme
  ok   organization.invite
       mail: "You are invited to join an organization"
  ok   organization.list: Acme (owner)
  ok   organization.setActive: active: Acme
flows: every step answered as expected
`

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
// old: a skipped run would leave the TypeScript flows unchecked while the
// suite stays green.
func requireNode(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node is not on PATH: this test runs web/flows.ts and needs Node %d.%d or later", nodeMinMajor, nodeMinMinor)
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

// TestFlows_TheScriptRunsEveryFlow starts the server exactly as main wires
// it, on a fresh SQLite file and a random port, runs web/flows.ts against it
// with Node and compares the whole output.
func TestFlows_TheScriptRunsEveryFlow(t *testing.T) {
	node := requireNode(t)
	trackSources(t)
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), "test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	key := bytes.Repeat([]byte{7}, auth.SealKeySize)
	box := &devMailbox{}
	a, err := newAuth(db, box, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(a, box))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), nodeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, filepath.Join("web", "flows.ts"))
	cmd.Env = append(os.Environ(), "AUTH_URL="+srv.URL)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("node web/flows.ts: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if got := stdout.String(); got != wantFlows {
		t.Fatalf("web/flows.ts printed:\n%s\nwant:\n%s", got, wantFlows)
	}
}
