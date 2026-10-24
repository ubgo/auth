package auth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// corePrefix starts every error code the core package declares; a plugin's
// codes start with the plugin's name instead.
const corePrefix = "auth."

// TestGuard_CoreErrorCodesArePrefixed: every NewError call in the core
// package passes a literal code starting with "auth.", so a client can tell
// the core's codes from a plugin's by the prefix alone ("internal",
// "rate_limited" and "origin_not_trusted" lacked it until 2026-10-09). It
// reads the syntax tree, because Errors() at run time also lists the codes of
// every plugin the test binary links.
func TestGuard_CoreErrorCodesArePrefixed(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "NewError" || len(call.Args) == 0 {
				return true
			}
			found++
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok {
				t.Errorf("%s: NewError's code must be a string literal", fset.Position(call.Pos()))
				return true
			}
			if code, _ := strconv.Unquote(lit.Value); !strings.HasPrefix(code, corePrefix) {
				t.Errorf("%s: core error code %q lacks the %q prefix", fset.Position(call.Pos()), code, corePrefix)
			}
			return true
		})
	}
	if found < 20 {
		t.Fatalf("found %d NewError calls in the core; the walk is broken", found)
	}
	for _, e := range []*auth.Error{auth.ErrInternal, auth.ErrRateLimited, auth.ErrOriginNotTrusted} {
		if !strings.HasPrefix(e.Code, corePrefix) {
			t.Errorf("%q lacks the %q prefix", e.Code, corePrefix)
		}
	}
}
