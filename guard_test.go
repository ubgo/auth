package auth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests read the source, not the behaviour. Each one pins a rule that
// a reviewer would otherwise have to remember, and each works on the syntax
// tree, not on lines: a line-based matcher is blind to an expression split
// over lines, and its "found nothing" then passes no matter what the code
// does.

// sourceFiles parses every non-test .go file under the given directories of
// this module. It fails when it parses nothing, so a moved directory cannot
// turn the guards into vacuous passes.
func sourceFiles(t *testing.T, dirs ...string) map[string]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && path != dir && (d.Name() == "contrib" || d.Name() == "integration" || d.Name() == "examples" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			out[path] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no source parsed under %v", dirs)
	}
	return out
}

// secretName matches identifiers that hold a secret or a digest of one.
var secretName = regexp.MustCompile(`(?i)(token|hash|secret|verifier|password|code|state|flow|reveal)$`)

func nameOf(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.CallExpr:
		return nameOf(v.Fun)
	}
	return ""
}

// notSecret are names the pattern catches that hold no secret: a driver's
// SQLSTATE error code.
var notSecret = map[string]bool{"SQLState": true}

// harmless is an operand a secret may be compared with in the open: the
// empty value, and a length.
func harmless(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return v.Name == "nil"
	case *ast.CallExpr:
		return nameOf(v.Fun) == "len"
	}
	return false
}

// TestGuard_SecretsAreComparedInConstantTime: a token, hash, code or secret
// is never compared with == or != (or bytes.Equal) against another value,
// because those return at the first differing byte and the time taken tells
// an attacker how much of a guess was right. subtle.ConstantTimeCompare is
// the only allowed comparison. A comparison with "" or nil is fine: it reveals
// only whether a value is present.
func TestGuard_SecretsAreComparedInConstantTime(t *testing.T) {
	for path, f := range sourceFiles(t, ".") {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BinaryExpr:
				if v.Op != token.EQL && v.Op != token.NEQ {
					return true
				}
				for _, pair := range [][2]ast.Expr{{v.X, v.Y}, {v.Y, v.X}} {
					name := nameOf(pair[0])
					if secretName.MatchString(name) && !notSecret[name] && !harmless(pair[1]) && !isKindConstant(pair[1]) {
						t.Errorf("%s: %s compared with %s; use subtle.ConstantTimeCompare", path, nameOf(pair[0]), v.Op)
					}
				}
			case *ast.CallExpr:
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Equal" && nameOf(sel.X) == "bytes" {
					t.Errorf("%s: bytes.Equal on bytes; use subtle.ConstantTimeCompare", path)
				}
			}
			return true
		})
	}
}

// isKindConstant allows comparing a status such as res.StatusCode with a named
// constant (http.StatusOK): neither side is secret.
func isKindConstant(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && (strings.HasPrefix(sel.Sel.Name, "Status") || strings.HasPrefix(sel.Sel.Name, "Code"))
}

// coreTables are the tables only the core writes.
var coreTables = map[string]bool{"TableUser": true, "TableIdentity": true, "TableSession": true, "TableVerification": true}

var rawCoreWrite = regexp.MustCompile(`(?i)(insert\s+into|update|delete\s+from)\s+"?auth_(user|identity|session|verification)\b`)

// TestGuard_PluginsNeverWriteCoreTables: reads are open, writes are closed.
// A plugin changes a core row only through the core's API (CreateIdentity,
// SetUserColumn …), where the invariants and the data hooks live. This scans
// every plugin for a builder aimed at a core table and for raw SQL that
// writes one.
func TestGuard_PluginsNeverWriteCoreTables(t *testing.T) {
	for path, f := range sourceFiles(t, "plugin") {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CallExpr:
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if !ok || len(v.Args) != 1 || (sel.Sel.Name != "Into" && sel.Sel.Name != "Table" && sel.Sel.Name != "From") {
					return true
				}
				arg, ok := v.Args[0].(*ast.SelectorExpr)
				if !ok || nameOf(arg.X) != "auth" || !coreTables[arg.Sel.Name] {
					return true
				}
				if sel.Sel.Name == "From" && !isWriteChain(sel.X) {
					return true // a SELECT … FROM a core table is a read
				}
				t.Errorf("%s: %s(auth.%s) writes a core table; use the core API", path, sel.Sel.Name, arg.Sel.Name)
			case *ast.BasicLit:
				if v.Kind == token.STRING && rawCoreWrite.MatchString(v.Value) {
					t.Errorf("%s: raw SQL writes a core table: %s", path, v.Value)
				}
			}
			return true
		})
	}
}

// isWriteChain reports whether a method chain starts at sqlb.NewDelete.
func isWriteChain(e ast.Expr) bool {
	for {
		switch v := e.(type) {
		case *ast.CallExpr:
			if nameOf(v.Fun) == "NewDelete" {
				return true
			}
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
				e = sel.X
				continue
			}
			return false
		default:
			return false
		}
	}
}

// TestGuard_PasswordSignInAlwaysHashesOnce: the argon2 check must run on
// every path through sign-in, known account or not, or the answer's timing
// tells an attacker which identifiers have accounts. Structurally, doSignIn:
//
//   - calls checkPassword exactly once, as a statement of the function body
//     itself and not inside a branch, and
//   - returns nothing before that call except an infrastructure error (a
//     variable named err or lerr) or the refusal of an over-long password,
//     which depends on the input alone and not on any account.
//
// TestPassword_UnknownAccountCostsAHash in the integration module checks the
// same rule by timing.
//
//ds:def id=testguard-passwordsigninalwayshashesonce-6msnvqty
func TestGuard_PasswordSignInAlwaysHashesOnce(t *testing.T) {
	var body *ast.BlockStmt
	for _, f := range sourceFiles(t, "plugin/password") {
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "doSignIn" {
				body = fn.Body
			}
		}
	}
	if body == nil {
		t.Fatal("doSignIn not found; the guard would pass vacuously")
	}
	isCheck := func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		return ok && nameOf(c.Fun) == "checkPassword"
	}
	calls := 0
	ast.Inspect(body, func(n ast.Node) bool {
		if isCheck(n) {
			calls++
		}
		return true
	})
	checkAt := -1
	for i, st := range body.List {
		ast.Inspect(st, func(n ast.Node) bool {
			if _, ok := n.(*ast.BlockStmt); ok {
				return false // nested block: not top level
			}
			if isCheck(n) {
				checkAt = i
			}
			return true
		})
	}
	if calls != 1 || checkAt < 0 {
		t.Fatalf("doSignIn calls checkPassword %d times, top level at statement %d; want exactly 1, unconditionally", calls, checkAt)
	}
	for i, st := range body.List[:checkAt] {
		lengthGuard := false
		if ifs, ok := st.(*ast.IfStmt); ok {
			ast.Inspect(ifs.Cond, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "maxLen" {
					lengthGuard = true
				}
				return true
			})
		}
		ast.Inspect(st, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok || lengthGuard || len(ret.Results) == 0 {
				return true
			}
			last := nameOf(ret.Results[len(ret.Results)-1])
			if last != "err" && last != "lerr" {
				t.Errorf("statement %d of doSignIn returns %s before the hash check; an unknown account would answer faster", i, last)
			}
			return true
		})
	}
}
