package auth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The nil-option guard: every exported option constructor in this
// repository, in every module (core, plugins, contrib, authgate, authtest),
// that takes a func or an interface must refuse nil through
// auth.OptionErrors, and the package must pin it in its options_nil_test.go,
// so an option added tomorrow cannot skip the rule. It reads the source
// rather than running the options because the plugin and contrib modules are
// separate modules this one cannot import; each package's
// options_nil_test.go is the runtime half.

// optionModulePath is the import path of the repository root.
const optionModulePath = "github.com/ubgo/auth"

// optionNilTestFile is the per-package test that pins each option at run
// time; the guard requires every option's qualified name as a string literal
// in it.
const optionNilTestFile = "options_nil_test.go"

// Kinds the guard sorts a parameter type into.
const (
	kindFunc      = "func"
	kindInterface = "interface"
	kindOther     = "other"
)

// externalTypeKinds are the types from outside this repository that option
// parameters use, by import path and name. The guard cannot parse another
// module, so an option whose parameter has an external type not listed here
// fails the guard until someone adds it, rather than being skipped.
var externalTypeKinds = map[string]string{
	"github.com/ubgo/sqlb.Dialect":                                      kindInterface,
	"github.com/ubgo/sqlb.Table":                                        kindOther,
	"github.com/go-webauthn/webauthn/protocol.AuthenticationExtensions": kindOther,
	"github.com/go-webauthn/webauthn/metadata.Provider":                 kindInterface,
	"time.Duration":    kindOther,
	"time.Time":        kindOther,
	"io/fs.FS":         kindInterface,
	"crypto.Signer":    kindInterface,
	"crypto.PublicKey": kindInterface,
}

// nilKeepsDefault are the options that take a func or an interface and
// deliberately keep (or restore) their default when given nil instead of
// refusing it,
// each with the reason. Each still needs its entry in the package's
// options_nil_test.go, which proves nil is safe.
var nilKeepsDefault = map[string]string{
	"apikey.WithPermissions": "nil is documented: it turns permissions off again, as inside a Configuration that should not inherit them; every read checks for nil",
	"authhttp.APIKeyFrom":    "authhttp has no error path (Handler builds an http.Handler, RequestOf runs per request); every read checks for nil",
	"authhttp.ClientIPFunc":  "authhttp has no error path; requestOf falls back to the headers when the func is nil",
	"authhttp.EncodeErrors":  "authhttp has no error path; a nil encoder is the built-in JSON body",
	"authhttp.LocaleFunc":    "authhttp has no error path; a nil func reads Accept-Language",
	"authui.HTTPOptions":     "passed to authhttp, whose newConfig skips a nil Option",
	"authui.Templates":       "authui.Handler has no error path; nil is DefaultTemplates()",
	"authui.Texts":           "authui.Handler has no error path; nil is the built-in English texts",
	"oauthpopup.HTTPOptions": "passed to authhttp, whose newConfig skips a nil Option",
}

// optionPkg is one parsed package: its name, its files, and every type it
// declares with the imports of the file that declares it.
type optionPkg struct {
	name  string
	dir   string
	files []*ast.File
	types map[string]optionTypeDecl
}

// optionTypeDecl is a type declaration and the imports its expression is
// read with.
type optionTypeDecl struct {
	expr    ast.Expr
	imports map[string]string
}

// optionNilParam is one option parameter the guard requires to refuse nil.
type optionNilParam struct {
	name     string // qualified option name, "email.WithMailer"
	param    string
	variadic bool
	pkg      *optionPkg
	fn       *ast.FuncDecl
}

// TestGuard_OptionsRefuseNil walks every option that takes a func or an
// interface and fails unless (1) the closure it returns starts with
// `if x.RefuseNil("<pkg>.<Name>", param) { return }` (RefuseNilEach for a
// variadic one), so nothing reads the value first, and (2) the qualified
// name appears in the package's options_nil_test.go, whose test proves at run
// time that New or OptionErr reports it. Options in nilKeepsDefault skip (1)
// and still need (2).
func TestGuard_OptionsRefuseNil(t *testing.T) {
	pkgs := parseOptionPackages(t, ".")
	var found []optionNilParam
	for _, p := range pkgs {
		found = append(found, optionNilParams(t, pkgs, p)...)
	}
	if len(found) < 150 {
		t.Fatalf("found %d options taking a func or an interface; the walk is broken (there were 160 on 2026-10-09)", len(found))
	}
	pinned := map[string]string{}
	seen := map[string]bool{}
	for _, o := range found {
		seen[o.name] = true
		if _, ok := nilKeepsDefault[o.name]; !ok {
			if !refusesNilFirst(o) {
				t.Errorf("%s: the closure it returns must start with `if x.RefuseNil(%q, %s) { return }` (auth.RefuseNilEach for a variadic parameter)", o.name, o.name, o.param)
			}
		}
		src, ok := pinned[o.pkg.dir]
		if !ok {
			b, _ := os.ReadFile(filepath.Join(o.pkg.dir, optionNilTestFile))
			src = string(b)
			pinned[o.pkg.dir] = src
		}
		if !strings.Contains(src, strconv.Quote(o.name)) {
			t.Errorf("%s: missing from %s, which must prove at run time that nil is refused (or kept as the default)", o.name, filepath.Join(o.pkg.dir, optionNilTestFile))
		}
	}
	for name := range nilKeepsDefault {
		if !seen[name] {
			t.Errorf("nilKeepsDefault names %s, which no longer takes a func or an interface; remove the entry", name)
		}
	}
}

// parseOptionPackages parses every non-test .go file under root, keyed by
// import path. It skips the modules that are not library code (examples,
// integration), generated code, test data and private docs.
func parseOptionPackages(t *testing.T, root string) map[string]*optionPkg {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string]*optionPkg{}
	skip := map[string]bool{"examples": true, "integration": true, "testdata": true, "node_modules": true, "example": true}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (skip[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		dir := filepath.Dir(path)
		ip := optionModulePath
		if dir != "." {
			ip += "/" + filepath.ToSlash(dir)
		}
		p := pkgs[ip]
		if p == nil {
			p = &optionPkg{name: f.Name.Name, dir: dir, types: map[string]optionTypeDecl{}}
			pkgs[ip] = p
		}
		p.files = append(p.files, f)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		for _, f := range p.files {
			imports := fileImports(pkgs, f)
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, s := range gd.Specs {
					ts := s.(*ast.TypeSpec)
					p.types[ts.Name.Name] = optionTypeDecl{expr: ts.Type, imports: imports}
				}
			}
		}
	}
	return pkgs
}

// fileImports maps each name a file refers to an import by to its path.
func fileImports(pkgs map[string]*optionPkg, f *ast.File) map[string]string {
	out := map[string]string{}
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := path[strings.LastIndex(path, "/")+1:]
		if p := pkgs[path]; p != nil {
			name = p.name
		}
		if im.Name != nil {
			name = im.Name.Name
		}
		out[name] = path
	}
	return out
}

// optionNilParams lists p's exported option constructors (a function whose
// one result is a func type named *Option) and their func and interface
// parameters.
func optionNilParams(t *testing.T, pkgs map[string]*optionPkg, p *optionPkg) []optionNilParam {
	t.Helper()
	ip := ""
	for path, q := range pkgs {
		if q == p {
			ip = path
		}
	}
	var out []optionNilParam
	for _, f := range p.files {
		imports := fileImports(pkgs, f)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !fd.Name.IsExported() || fd.Type.Results == nil || len(fd.Type.Results.List) != 1 {
				continue
			}
			res := fd.Type.Results.List[0].Type
			if !strings.HasSuffix(typeName(res), "Option") || typeKind(t, pkgs, ip, imports, res) != kindFunc {
				continue
			}
			for _, prm := range fd.Type.Params.List {
				pt, variadic := prm.Type, false
				if e, ok := pt.(*ast.Ellipsis); ok {
					pt, variadic = e.Elt, true
				}
				if k := typeKind(t, pkgs, ip, imports, pt); k != kindFunc && k != kindInterface {
					continue
				}
				for _, n := range prm.Names {
					out = append(out, optionNilParam{name: p.name + "." + fd.Name.Name, param: n.Name, variadic: variadic, pkg: p, fn: fd})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// typeName is the last identifier of a type expression, "Option" for
// "authhttp.Option".
func typeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// typeKind sorts a type expression read in package ip with the given imports
// into func, interface or other, following named types and aliases through
// this repository and externalTypeKinds beyond it. An external type missing
// from that table fails the test.
func typeKind(t *testing.T, pkgs map[string]*optionPkg, ip string, imports map[string]string, e ast.Expr) string {
	t.Helper()
	switch x := e.(type) {
	case *ast.FuncType:
		return kindFunc
	case *ast.InterfaceType:
		return kindInterface
	case *ast.Ident:
		if x.Name == "any" || x.Name == "error" {
			return kindInterface
		}
		if d, ok := pkgs[ip].types[x.Name]; ok {
			return typeKind(t, pkgs, ip, d.imports, d.expr)
		}
		return kindOther
	case *ast.SelectorExpr:
		path := imports[x.X.(*ast.Ident).Name]
		if q := pkgs[path]; q != nil {
			if d, ok := q.types[x.Sel.Name]; ok {
				return typeKind(t, pkgs, path, d.imports, d.expr)
			}
		}
		if k, ok := externalTypeKinds[path+"."+x.Sel.Name]; ok {
			return k
		}
		t.Errorf("option parameter type %s.%s is outside this repository; add it to externalTypeKinds", path, x.Sel.Name)
		return kindOther
	case *ast.IndexExpr:
		return typeKind(t, pkgs, ip, imports, x.X)
	case *ast.ParenExpr:
		return typeKind(t, pkgs, ip, imports, x.X)
	}
	return kindOther
}

// refusesNilFirst reports whether o's function returns a closure whose first
// statement is `if <recv>.RefuseNil("<name>", <param>) { return }` or
// `if auth.RefuseNilEach(&<recv>.optErrs, "<name>", <param>) { return }`.
func refusesNilFirst(o optionNilParam) bool {
	body := o.fn.Body.List
	if len(body) == 0 {
		return false
	}
	ret, ok := body[len(body)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	lit, ok := ret.Results[0].(*ast.FuncLit)
	if !ok || len(lit.Body.List) == 0 {
		return false
	}
	is, ok := lit.Body.List[0].(*ast.IfStmt)
	if !ok || is.Init != nil || len(is.Body.List) != 1 {
		return false
	}
	if r, ok := is.Body.List[0].(*ast.ReturnStmt); !ok || len(r.Results) != 0 {
		return false
	}
	call, ok := is.Cond.(*ast.CallExpr)
	if !ok {
		return false
	}
	want, args := "RefuseNil", call.Args
	if o.variadic {
		want = "RefuseNilEach"
		if len(args) != 3 {
			return false
		}
		args = args[1:]
	}
	if typeName(call.Fun) != want || len(args) != 2 {
		return false
	}
	lit0, ok := args[0].(*ast.BasicLit)
	if !ok || lit0.Value != strconv.Quote(o.name) {
		return false
	}
	id, ok := args[1].(*ast.Ident)
	return ok && id.Name == o.param
}
