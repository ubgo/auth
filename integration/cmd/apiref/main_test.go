package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
)

// TestGenerate_ListsEveryPluginAndIsStable: the table names the core and
// every built-in plugin, holds the routes the README promises, the OpenAPI
// document describes the same routes, and two runs render byte for byte the
// same, so a check against the committed files cannot flap.
func TestGenerate_ListsEveryPluginAndIsStable(t *testing.T) {
	first, _, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	for name := range first {
		if !bytes.Equal(first[name], second[name]) {
			t.Fatalf("two runs rendered a different %s", name)
		}
	}
	doc := string(first[fileHTTPAPI])
	for _, want := range []string{
		"| `POST` | `/auth/password/sign-in` | `public` | `password.sign-in` | [password](../plugins/password.md) |",
		"| `GET` | `/auth/session` | `signed_in` | `core.session` | [core](../concepts/sessions.md) |",
		"| `POST` | `/auth/sign-out` | `signed_in` |",
		"[email](../plugins/email.md)", "[phone](../plugins/phone.md)", "[username](../plugins/username.md)",
		"[oauth](../plugins/oauth.md)", "[twofactor](../plugins/twofactor.md)", "[passkey](../plugins/passkey.md)",
		"[magiclink](../plugins/magiclink.md)", "[admin](../plugins/admin.md)", "[apikey](../plugins/apikey.md)",
		"[jwt](../plugins/jwt.md)", "[terms](../plugins/terms.md)", "[organization](../plugins/organization.md)",
		"/auth/oauth/google/start", "/auth/oauth/github/start",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("table lacks %q", want)
		}
	}
	routes := 0
	for i, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "| `") {
			routes++
			if strings.Count(line, "|") != 6 {
				t.Errorf("line %d has the wrong number of columns: %s", i+1, line)
			}
		}
	}
	var openapi struct {
		Info    map[string]string         `json:"info"`
		Paths   map[string]map[string]any `json:"paths"`
		Servers []map[string]string       `json:"servers"`
	}
	if err := json.Unmarshal(first[fileOpenAPI], &openapi); err != nil {
		t.Fatal(err)
	}
	ops := 0
	for _, methods := range openapi.Paths {
		ops += len(methods)
	}
	if ops != routes {
		t.Fatalf("openapi has %d operations, the table %d routes", ops, routes)
	}
	if openapi.Info["title"] != openAPITitle || openapi.Servers[0]["url"] != baseURL || openapi.Paths["/auth/password/sign-in"]["post"] == nil {
		t.Fatalf("openapi header = %v %v", openapi.Info, openapi.Servers)
	}
	if !bytes.HasSuffix(first[fileOpenAPI], []byte("\n")) {
		t.Fatal("openapi.json lacks a final newline")
	}
	// The client reference has one row per route, the core's section first,
	// and a union type's bar escaped so the table keeps its columns.
	ref := string(first[fileTSClient])
	for _, want := range []string{
		"## Core (on the client's root)",
		"| `password()` | [`client.password`](#password) | ",
		"| `password.signIn` | `POST /auth/password/sign-in` | `public` | `PasswordSignInRequest` | `PasswordSignInResult` |",
		"| `session` | `GET /auth/session` | `signed_in` | `EmptyInput` | `AuthSessionResult` |",
		"## device\n\nEnable with `device()`; call as `client.device.<method>`. Plugin guide: [device](../plugins/deviceauth.md).",
	} {
		if !strings.Contains(ref, want) {
			t.Errorf("ts-client.md lacks %q", want)
		}
	}
	if strings.Index(ref, "## Core") > strings.Index(ref, "## admin") {
		t.Error("ts-client.md lists a plugin before the core")
	}
	methods := 0
	for i, line := range strings.Split(ref, "\n") {
		if strings.HasPrefix(line, "| `") && strings.Contains(line, prefix+"/") {
			methods++
			if strings.Count(line, "|")-strings.Count(line, "\\|") != 6 {
				t.Errorf("ts-client.md line %d has the wrong number of columns: %s", i+1, line)
			}
		}
	}
	if methods != routes {
		t.Fatalf("ts-client.md has %d methods, the table %d routes", methods, routes)
	}
}

// TestRun_CheckFailsOnAStaleFile: -check accepts the files the generator
// wrote, refuses one that differs by a byte, and refuses a missing one.
func TestRun_CheckFailsOnAStaleFile(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir, "", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := run("", dir, "", "", nil); err != nil {
		t.Fatalf("check of fresh files: %v", err)
	}
	path := filepath.Join(dir, fileOpenAPI)
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(doc, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run("", dir, "", "", nil); !errors.Is(err, ErrStale) {
		t.Fatalf("check of a stale file = %v, want ErrStale", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := run("", dir, "", "", nil); !errors.Is(err, ErrStale) {
		t.Fatalf("check with a missing file = %v, want ErrStale", err)
	}
	if err := run(filepath.Join(dir, "missing", "dir"), "", "", "", nil); err == nil {
		t.Fatal("writing into a missing directory succeeded")
	}
}

// TestRun_ClientFilesAreWrittenAndChecked: -client writes the TypeScript
// client beside the docs, -check with -client refuses a stale client file
// even when every doc is fresh, and writing into a missing client directory
// fails.
func TestRun_ClientFilesAreWrittenAndChecked(t *testing.T) {
	docs, client := t.TempDir(), t.TempDir()
	if err := run(docs, "", client, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := run("", docs, client, "", nil); err != nil {
		t.Fatalf("check of fresh files: %v", err)
	}
	path := filepath.Join(client, authhttp.TSFileClient)
	ts, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(ts, []byte("export function password(): Plugin<\"password\", PasswordOps>")) {
		t.Fatalf("client.ts lacks the password factory:\n%.400s", ts)
	}
	if err := os.WriteFile(path, append(ts, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run("", docs, client, "", nil); !errors.Is(err, ErrStale) {
		t.Fatalf("check of a stale client = %v, want ErrStale", err)
	}
	if err := run("", docs, "", "", nil); err != nil {
		t.Fatalf("check without -client looked at the client: %v", err)
	}
	if err := run(docs, "", filepath.Join(client, "missing"), "", nil); err == nil {
		t.Fatal("writing the client into a missing directory succeeded")
	}
}

// TestRun_ConceptsPageMustListEveryCode: the repository's errors page has a
// row for every declared code (the real file, so a new code without its
// "when" fails here and in task check), and a page missing one fails run.
func TestRun_ConceptsPageMustListEveryCode(t *testing.T) {
	// The test runs in the package directory, three levels below the root.
	if err := run("", "", "", filepath.Join("..", "..", defaultConceptsPage), io.Discard); err != nil {
		t.Fatal(err)
	}
	page := filepath.Join(t.TempDir(), "errors.md")
	if err := os.WriteFile(page, []byte("| `auth.signed_out` | 401 | m | w |\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run("", "", "", page, io.Discard); !errors.Is(err, errUndocumented) {
		t.Fatalf("run with an incomplete page = %v", err)
	}
}

// TestRun_PrintsWithoutFlags: no flags means the table goes to stdout.
func TestRun_PrintsWithoutFlags(t *testing.T) {
	var out bytes.Buffer
	if err := run("", "", "", "", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "# HTTP API reference") {
		t.Fatalf("stdout = %q", out.String()[:40])
	}
}

// TestGenerate_EveryGuideLinkResolves: each plugin cell links to a guide that
// exists, including a plugin whose name is not its page's (deviceauth
// registers as "device").
func TestGenerate_EveryGuideLinkResolves(t *testing.T) {
	docs, _, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	links := regexp.MustCompile(`\]\((\.\./[^)#]+\.md)\)`).FindAllStringSubmatch(string(docs["http-api.md"]), -1)
	if len(links) == 0 {
		t.Fatal("no guide links in http-api.md")
	}
	for _, m := range links {
		if _, err := os.Stat(filepath.Join("..", "..", "..", "docs", "reference", m[1])); err != nil {
			t.Errorf("http-api.md links to %s: %v", m[1], err)
		}
	}
}

// TestGenerate_ClientCoversTheOpenAPIDocument: every operation of the OpenAPI
// document, with its method and path, is a method of the generated
// TypeScript client, and the client has no operation the document lacks, so
// the two outputs of one operation list cannot disagree. Health is a route
// of authhttp, not an operation, and is not in the client.
func TestGenerate_ClientCoversTheOpenAPIDocument(t *testing.T) {
	docs, client, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	var openapi struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(docs[fileOpenAPI], &openapi); err != nil {
		t.Fatal(err)
	}
	ts := string(client[authhttp.TSFileClient])
	ops := 0
	for path, methods := range openapi.Paths {
		for method, op := range methods {
			ops++
			want := `id: "` + op.OperationID + `", method: "` + strings.ToUpper(method) + `", path: "` + strings.TrimPrefix(path, prefix) + `"`
			if !strings.Contains(ts, want) {
				t.Errorf("client.ts lacks %s", want)
			}
		}
	}
	if n := strings.Count(ts, `{ id: "`); n != ops || ops == 0 {
		t.Fatalf("client.ts has %d operations, openapi.json %d", n, ops)
	}
}
