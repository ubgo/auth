package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Discovery for the config edge test: every exported option constructor in
// the repository, read from the source the way the root module's
// TestGuard_OptionsRefuseNil reads it. Go cannot list a package's functions
// at run time, so the source is the only complete list; the runtime half
// (configedge_test.go) holds a registry of the function values and fails
// when the source names an option the registry lacks, so an option added
// tomorrow is covered by a one-line registry entry the failure prints.

// edgeRepoRoot is the repository root, seen from this module.
const edgeRepoRoot = ".."

// edgeModulePath is the import path of the repository root.
const edgeModulePath = "github.com/ubgo/auth"

// edgeOption is one discovered option constructor.
type edgeOption struct {
	// name is "<package name>.<Func>", the key of the registry.
	name string
	// importPath is the package's import path.
	importPath string
	// result is the name of the option type it returns.
	result string
}

// edgeSkipDirs are directories that hold no library code: examples, this
// module, test data, generated example code and private docs.
var edgeSkipDirs = map[string]bool{"examples": true, "integration": true, "testdata": true, "node_modules": true, "example": true}

// discoverOptions parses every non-test .go file of the repository and
// returns its exported option constructors: a function with no receiver
// whose one result is a named type ending in "Option" that its package
// declares as a func type.
func discoverOptions(t *testing.T) []edgeOption {
	t.Helper()
	fset := token.NewFileSet()
	type pkg struct {
		name  string
		files []*ast.File
		funcs map[string]bool
	}
	pkgs := map[string]*pkg{}
	err := filepath.WalkDir(edgeRepoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != edgeRepoRoot && (edgeSkipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
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
		rel, err := filepath.Rel(edgeRepoRoot, filepath.Dir(path))
		if err != nil {
			return err
		}
		ip := edgeModulePath
		if rel != "." {
			ip += "/" + filepath.ToSlash(rel)
		}
		p := pkgs[ip]
		if p == nil {
			p = &pkg{name: f.Name.Name, funcs: map[string]bool{}}
			pkgs[ip] = p
		}
		p.files = append(p.files, f)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, s := range gd.Specs {
				ts := s.(*ast.TypeSpec)
				if _, ok := ts.Type.(*ast.FuncType); ok {
					p.funcs[ts.Name.Name] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []edgeOption
	for ip, p := range pkgs {
		for _, f := range p.files {
			imports := map[string]string{}
			for _, im := range f.Imports {
				path, _ := strconv.Unquote(im.Path.Value)
				name := path[strings.LastIndex(path, "/")+1:]
				if q := pkgs[path]; q != nil {
					name = q.name
				}
				if im.Name != nil {
					name = im.Name.Name
				}
				imports[name] = path
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Recv != nil || !fd.Name.IsExported() || fd.Type.Results == nil || len(fd.Type.Results.List) != 1 || fd.Type.TypeParams != nil {
					continue
				}
				owner, typ := ip, ""
				switch r := fd.Type.Results.List[0].Type.(type) {
				case *ast.Ident:
					typ = r.Name
				case *ast.SelectorExpr:
					x, ok := r.X.(*ast.Ident)
					if !ok {
						continue
					}
					owner, typ = imports[x.Name], r.Sel.Name
				default:
					continue
				}
				q := pkgs[owner]
				if q == nil || !strings.HasSuffix(typ, "Option") || !q.funcs[typ] {
					continue
				}
				out = append(out, edgeOption{name: p.name + "." + fd.Name.Name, importPath: ip, result: q.name + "." + typ})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}
