package auth_test

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestGuard_BuiltInPluginsTakeTheirTypes: no built-in source calls
// auth.TypesFor or declares the untyped Migrations(engine) method. Each one
// writes DDL through TypedMigrations and the SQLTypes it is handed, because
// New refuses auth.WithSQLTypes while any registered plugin writes DDL
// without them, so one untyped built-in would make the override unusable
// for every app that registers it.
//
// Proven by breaking: the apikey plugin put back on Migrations(engine) with
// auth.TypesFor fails this test naming the file twice.
func TestGuard_BuiltInPluginsTakeTheirTypes(t *testing.T) {
	for path, f := range sourceFiles(t, "plugin", "authgate", "authhttp", "authcli", "authui") {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				if x, ok := v.X.(*ast.Ident); ok && x.Name == "auth" && v.Sel.Name == "TypesFor" {
					t.Errorf("%s: auth.TypesFor ignores the app's WithSQLTypes; implement auth.TypedMigrator and use the types it is handed", path)
				}
			case *ast.FuncDecl:
				if v.Recv != nil && v.Name.Name == "Migrations" {
					t.Errorf("%s: a Migrations method keeps the built-in types; implement auth.TypedMigrator (TypedMigrations) instead", path)
				}
			}
			return true
		})
	}
}

// idColumnName matches the column constants that hold a generated id or
// refer to one: user, organization, team, session and the other row ids.
var idColumnName = regexp.MustCompile(`^Col\w*(UserID|OrgID|OrganizationID|TeamID|SessionID|IdentityID|InviteID|AgentID|HostID|RoleID|GroupID|SCIMUserID|AccountID|RecoveryID|DeviceID|HistoryID|FamilyID|Referrer|Referred|StepReferral|InvitedBy|GrantedBy|DeniedBy|UseUser|UseInvite|RecoveryUser|DeviceUser|Impersonator)$`)

// emptyIDColumns are the id columns that store "" for "none" without a
// DEFAULT ” the guard could see, by file and constant, each with its reason.
var emptyIDColumns = map[string]map[string]string{
	"plugin/audit/audit.go": {
		// An event of an anonymous call has no session; the log stores "".
		"ColSessionID": "audit events store an empty session id",
	},
}

// TestGuard_IDColumnsAreTypedID: no DDL in the core or a built-in plugin
// types an id column with SQLTypes.Key. An id column typed Key keeps TEXT
// while the app's WithSQLTypes ID makes user ids UUID, and on Postgres the
// first join or comparison between the two fails. The one exception is a
// column that stores "" for "none" (DEFAULT ” in the DDL, or listed in
// emptyIDColumns), which a native id type cannot hold, such as the audit
// log's session and organization.
//
// Proven by breaking: the oauth plugin's user_id put back on t.Key fails
// this test naming the file and the column.
func TestGuard_IDColumnsAreTypedID(t *testing.T) {
	for path, f := range sourceFiles(t, ".") {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.BinaryExpr:
				if v.Op != token.ADD {
					return true
				}
				ops := flattenAdd(v)
				for i := 0; i+2 < len(ops); i++ {
					col, ok := ops[i].(*ast.Ident)
					if !ok || !idColumnName.MatchString(col.Name) || !isSpaceLit(ops[i+1]) || !isTypesField(ops[i+2], "Key") {
						continue
					}
					if i+3 < len(ops) && strings.Contains(litValue(ops[i+3]), "DEFAULT ''") {
						continue
					}
					if _, ok := emptyIDColumns[filepath.ToSlash(path)][col.Name]; ok {
						continue
					}
					t.Errorf("%s: %s is typed t.Key; an id column takes t.ID", path, col.Name)
				}
				return false
			case *ast.CallExpr:
				// alter(ColX, t.Key+" NULL") and the like.
				if len(v.Args) == 2 {
					if col, ok := v.Args[0].(*ast.Ident); ok && idColumnName.MatchString(col.Name) {
						if ops := flattenAdd(v.Args[1]); len(ops) > 0 && isTypesField(ops[0], "Key") {
							t.Errorf("%s: %s is typed t.Key; an id column takes t.ID", path, col.Name)
						}
					}
				}
			}
			return true
		})
	}
}

// flattenAdd lists the operands of a chain of + in order; any other
// expression is a one-element list.
func flattenAdd(e ast.Expr) []ast.Expr {
	if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.ADD {
		return append(flattenAdd(b.X), flattenAdd(b.Y)...)
	}
	if p, ok := e.(*ast.ParenExpr); ok {
		return flattenAdd(p.X)
	}
	return []ast.Expr{e}
}

// isSpaceLit reports whether e is the string literal " ".
func isSpaceLit(e ast.Expr) bool { return litValue(e) == " " }

// litValue is a string literal's value, "" for anything else.
func litValue(e ast.Expr) string {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING || len(l.Value) < 2 {
		return ""
	}
	return l.Value[1 : len(l.Value)-1]
}

// isTypesField reports whether e selects field from a value, as t.Key does.
func isTypesField(e ast.Expr, field string) bool {
	s, ok := e.(*ast.SelectorExpr)
	return ok && s.Sel.Name == field
}
