package auth_test

import (
	"go/ast"
	"go/token"
	"regexp"
	"testing"
)

// tableLabelName matches the exported constants that hold a table's label:
// TableNameUser, TableNameAccount, auth.TableNameIdentity.
var tableLabelName = regexp.MustCompile(`^TableName[A-Z]`)

// sqlAssemblers are the calls that turn their arguments into statement text.
// A table label passed to one of them is on its way into SQL.
var sqlAssemblers = map[string]bool{"WriteString": true, "Sprintf": true, "Sprint": true, "Fprintf": true, "Join": true, "Concat": true}

// TestGuard_TableNamesNeverConcatenated enforces the rule behind RenameTable
// and WithTablePrefix: a TableName constant is a label, and only the Auth
// knows the table's real name. The core and every plugin therefore name a
// table in SQL through the Auth (TableName, ReferencesUser) or through a
// sqlb.Table value the dialect renders, never by writing the constant into
// statement text. The guard refuses a TableName identifier as an operand of
// "+" or as an argument to a string assembler anywhere in the library's
// source, which is the shape every DDL generator had before this rule.
//
// Proven by breaking: a "+ TableNamePassword" put back into the password
// plugin's migration fails this test naming the file.
func TestGuard_TableNamesNeverConcatenated(t *testing.T) {
	for path, f := range sourceFiles(t, ".") {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BinaryExpr:
				if v.Op == token.ADD {
					for _, side := range []ast.Expr{v.X, v.Y} {
						if isTableLabel(side) {
							t.Errorf("%s: table label %s concatenated into a string; name the table through the Auth (TableName) instead", path, nameOf(side))
						}
					}
				}
			case *ast.CallExpr:
				if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sqlAssemblers[sel.Sel.Name] {
					for _, arg := range v.Args {
						if isTableLabel(arg) {
							t.Errorf("%s: table label %s passed to %s; name the table through the Auth (TableName) instead", path, nameOf(arg), sel.Sel.Name)
						}
					}
				}
			}
			return true
		})
	}
}

// isTableLabel reports whether e is a TableName constant, bare or qualified
// (nameOf returns the selector's last name).
func isTableLabel(e ast.Expr) bool {
	_, ident := e.(*ast.Ident)
	_, sel := e.(*ast.SelectorExpr)
	return (ident || sel) && tableLabelName.MatchString(nameOf(e))
}
