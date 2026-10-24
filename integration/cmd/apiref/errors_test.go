package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth/authhttp"
)

// TestErrorCodes_ListsEveryPluginAndRenders: the registry holds the core's
// codes and every wired plugin's, sorted; the three renderings agree on the
// codes; the TypeScript is a const object keyed by code.
//
//ds:def id=testerrorcodes-listseverypluginandrenders-rg5ftw6v
func TestErrorCodes_ListsEveryPluginAndRenders(t *testing.T) {
	if _, err := plugins(); err != nil { // imports every plugin, so their declarations ran
		t.Fatal(err)
	}
	codes := errorCodes()
	byCode := map[string]errorCode{}
	for i, c := range codes {
		byCode[c.Code] = c
		if i > 0 && codes[i-1].Code >= c.Code {
			t.Fatalf("not sorted at %s", c.Code)
		}
	}
	for code, plugin := range map[string]string{"auth.internal": "core", "auth.signed_out": "core", "auth.rate_limited": "core", "password.invalid_credentials": "password", "captcha.failed": "captcha", "oauth.bad_return_to": "oauth"} {
		if byCode[code].Plugin != plugin {
			t.Errorf("%s owner = %q, want %q", code, byCode[code].Plugin, plugin)
		}
	}
	md := string(renderErrorCodesMD(codes))
	if !strings.Contains(md, "| `auth.signed_out` | 401 | Sign in to continue. | core |") {
		t.Fatalf("markdown lacks the signed-out row:\n%s", md[:400])
	}
	raw, err := renderErrorCodesJSON(codes)
	if err != nil {
		t.Fatal(err)
	}
	var back []errorCode
	if err := json.Unmarshal(raw, &back); err != nil || len(back) != len(codes) {
		t.Fatalf("json: %v, %d codes", err, len(back))
	}
	ts := string(authhttp.TypeScriptErrorCodes())
	for _, want := range []string{
		"export const AUTH_ERROR_CODES = {",
		`  "auth.signed_out": { status: 401, message: "Sign in to continue.", plugin: "core" },`,
		"export type AuthErrorCode = keyof typeof AUTH_ERROR_CODES;",
		"export function isAuthErrorCode(code: string): code is AuthErrorCode {",
	} {
		if !strings.Contains(ts, want) {
			t.Errorf("typescript lacks %q", want)
		}
	}
	if strings.Count(ts, "{ status:") != len(codes) {
		t.Fatalf("typescript has %d entries for %d codes", strings.Count(ts, "{ status:"), len(codes))
	}
}

// TestCheckDocumented: every declared code must have a row on the concepts
// page, and the page may not list a code nothing declares.
func TestCheckDocumented(t *testing.T) {
	codes := []errorCode{{Code: "auth.signed_out", Status: 401}, {Code: "x.y", Status: 400}}
	page := filepath.Join(t.TempDir(), "errors.md")
	write := func(body string) {
		if err := os.WriteFile(page, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("| `auth.signed_out` | 401 | m | w |\n| `x.y` | 400 | m | w |\n")
	if err := checkDocumented(page, codes); err != nil {
		t.Fatal(err)
	}
	write("| `auth.signed_out` | 401 | m | w |\n")
	if err := checkDocumented(page, codes); err == nil || !strings.Contains(err.Error(), "x.y") {
		t.Fatalf("undocumented code: %v", err)
	}
	write("| `auth.signed_out` | 401 | m | w |\n| `x.y` | 400 | m | w |\n| `gone.code` | 400 | m | w |\n")
	if err := checkDocumented(page, codes); err == nil || !strings.Contains(err.Error(), "gone.code") {
		t.Fatalf("stale documented code: %v", err)
	}
	if err := checkDocumented(filepath.Join(t.TempDir(), "missing.md"), codes); err == nil {
		t.Fatal("a missing page passed")
	}
}
