package auth_test

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"testing"
)

// foreignKeyWords are the DDL words ADR-0002 bans from every statement the
// library writes: a constraint tying a table to another, and the cascade that
// made deletion a database matter. "REFERENCES" alone is enough to catch a
// column-level foreign key written without the FOREIGN KEY prefix.
var foreignKeyWords = regexp.MustCompile(`(?i)\bFOREIGN\s+KEY\b|\bREFERENCES\b|\bON\s+DELETE\s+CASCADE\b`)

// TestGuard_NoForeignKeys enforces ADR-0002 on the library's source: no
// string literal in the core or any plugin spells a foreign key or a cascade,
// so no migration can create one on any engine. Tables are plain storage and
// DeleteUser removes a user's rows in Go (UserTables).
//
// Proven by breaking: a "REFERENCES auth_user (id)" put back into a plugin's
// CREATE TABLE fails this test naming the file.
//
//ds:def id=testguard-noforeignkeys-2v4neb3f
func TestGuard_NoForeignKeys(t *testing.T) {
	for path, f := range sourceFiles(t, ".") {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if foreignKeyWords.MatchString(s) {
				t.Errorf("%s: statement text %q spells a foreign key or cascade; the library creates none (ADR-0002), list the table in UserTables instead", path, s)
			}
			return true
		})
	}
}
