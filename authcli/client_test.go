package authcli_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authcli"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/sqlb"
)

// keywordPlugin is named after a TypeScript keyword and serves one
// operation, so the generator has a namespace it must refuse.
type keywordPlugin struct{ op auth.Operation }

func (keywordPlugin) Name() string                   { return "delete" }
func (keywordPlugin) SignsIn() bool                  { return true }
func (p keywordPlugin) Operations() []auth.Operation { return []auth.Operation{p.op} }

// `auth client ts --out dir` writes exactly the files TypeScriptClient
// generates into a directory it creates, lists them, and refuses a missing
// language, a missing --out, an extra argument and a bad flag.
func TestMain_ClientTS(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "web", "auth")
	code, out, errOut := run(t, a, "client", "ts", "--out", dir)
	if code != authcli.ExitOK {
		t.Fatalf("client ts: %d %s", code, errOut)
	}
	want, err := authhttp.TypeScriptClient(a)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range want {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("%s: %v, equal %v", name, err, bytes.Equal(got, body))
		}
		if !strings.Contains(out, filepath.Join(dir, name)) {
			t.Errorf("stdout does not list %s: %q", name, out)
		}
	}
	for _, args := range [][]string{
		{"client"}, {"client", "go"}, {"client", "ts"}, {"client", "ts", "--out", dir, "extra"}, {"client", "ts", "--bogus"},
	} {
		if code, _, _ := run(t, a, args...); code != authcli.ExitUsage {
			t.Errorf("%v: %d, want ExitUsage", args, code)
		}
	}
	if code, _, _ := run(t, a, "client", "ts", "-h"); code != authcli.ExitOK {
		t.Errorf("client ts -h: %d", code)
	}
}

// A directory that cannot be created and a plugin the generator refuses
// both fail with ExitFailed and the reason on stderr.
func TestMain_ClientTSFails(t *testing.T) {
	a, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(signIn{}))
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, a, "client", "ts", "--out", filepath.Join(file, "sub")); code != authcli.ExitFailed || !strings.Contains(errOut, "auth client ts:") {
		t.Fatalf("out under a file: %d %q", code, errOut)
	}
	blocked := t.TempDir()
	if err := os.Mkdir(filepath.Join(blocked, authhttp.TSFileClient), 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, a, "client", "ts", "--out", blocked); code != authcli.ExitFailed || !strings.Contains(errOut, "auth client ts:") {
		t.Fatalf("a directory where client.ts goes: %d %q", code, errOut)
	}
	op := auth.Define(auth.OpInfo{ID: "delete.ping", Kind: auth.Query, Require: auth.Public, Path: "/ping"},
		func(context.Context, *auth.Call, struct{}) (auth.Done, error) { return auth.Done{OK: true}, nil })
	bad, err := auth.New(auth.WithDialect(sqlb.PostgresDialect{}), auth.WithPlugins(keywordPlugin{op: op}))
	if err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, bad, "client", "ts", "--out", t.TempDir()); code != authcli.ExitFailed || !strings.Contains(errOut, "keyword") {
		t.Fatalf("keyword plugin: %d %q", code, errOut)
	}
}
