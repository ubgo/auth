package admin

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// render builds SELECT ... WHERE pred for d and returns the SQL and args.
func render(t *testing.T, d sqlb.Dialect, pred sqlb.Predicate) sqlb.Query {
	t.Helper()
	q, err := sqlb.NewSelect(d).Exprs(auth.UserID).From(auth.TableUser).Where(pred).Build()
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// TestEscapeGlob: every GLOB metacharacter becomes a one-character class and
// nothing else changes, multi-byte text included.
func TestEscapeGlob(t *testing.T) {
	for in, want := range map[string]string{
		"":          "",
		"plain é":   "plain é",
		"a*b?c[d]e": "a[*]b[?]c[[]d]e",
		"%_!":       "%_!",
	} {
		if got := escapeGlob(in); got != want {
			t.Errorf("escapeGlob(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExactCaseMatch_GlobOnSQLiteLikeElsewhere: SQLite gets GLOB with the
// wildcards around the escaped value; the other engines get the escaped LIKE.
// An unknown operator is refused on both paths.
func TestExactCaseMatch_GlobOnSQLiteLikeElsewhere(t *testing.T) {
	for op, want := range map[SearchOperator]string{SearchContains: "*a[*]*", SearchStartsWith: "a[*]*", SearchEndsWith: "*a[*]"} {
		pred, err := exactCaseMatch(auth.EngineSQLite, auth.UserName, op, "a*")
		if err != nil {
			t.Fatal(err)
		}
		q := render(t, sqlb.SQLiteDialect{}, pred)
		if !strings.Contains(q.SQL, " GLOB ") || strings.Contains(q.SQL, "LIKE") || len(q.Args) != 1 || q.Args[0] != want {
			t.Errorf("%s: %s %v", op, q.SQL, q.Args)
		}
	}
	for _, engine := range []string{auth.EnginePostgres, auth.EngineMySQL} {
		pred, err := exactCaseMatch(engine, auth.UserName, SearchStartsWith, "50%")
		if err != nil {
			t.Fatal(err)
		}
		q := render(t, sqlb.PostgresDialect{}, pred)
		if !strings.Contains(q.SQL, " LIKE ") || !strings.Contains(q.SQL, "ESCAPE '!'") || q.Args[0] != "50!%%" {
			t.Errorf("%s: %s %v", engine, q.SQL, q.Args)
		}
		if _, err := exactCaseMatch(engine, auth.UserName, "like", "x"); !errors.Is(err, ErrBadSearchOperator) {
			t.Errorf("%s bad operator: %v", engine, err)
		}
	}
	if _, err := exactCaseMatch(auth.EngineSQLite, auth.UserName, "like", "x"); !errors.Is(err, ErrBadSearchOperator) {
		t.Errorf("sqlite bad operator: %v", err)
	}
}

// TestLikeMatch_Patterns: each operator puts the wildcards where it says and
// escapes the value's own pattern characters.
func TestLikeMatch_Patterns(t *testing.T) {
	for op, want := range map[SearchOperator]string{SearchContains: "%a!_b%", SearchStartsWith: "a!_b%", SearchEndsWith: "%a!_b"} {
		pred, err := likeMatch(auth.IdentityValue, op, "a_b")
		if err != nil {
			t.Fatal(err)
		}
		if q := render(t, sqlb.MySQLDialect{}, pred); q.Args[0] != want {
			t.Errorf("%s: %v", op, q.Args)
		}
	}
	if _, err := likeMatch(auth.IdentityValue, "", "x"); !errors.Is(err, ErrBadSearchOperator) {
		t.Errorf("empty operator reaching likeMatch: %v", err)
	}
}

// TestFoldEmail_MatchesTheEmailKind: a fragment is folded exactly as the
// email kind folds a stored address, or an email search would miss rows.
func TestFoldEmail_MatchesTheEmailKind(t *testing.T) {
	for _, s := range []string{" Bob@Example.COM ", "ÉMILE@zola.fr", "plain"} {
		want, err := email.Normalize(s)
		if err != nil || foldEmail(s) != want {
			t.Errorf("foldEmail(%q) = %q, email.Normalize = %q %v", s, foldEmail(s), want, err)
		}
	}
}

// TestOptions_SearchRateAndImpersonatingAdmins: the defaults are the named
// constants and refuse admin targets; the options replace them.
func TestOptions_SearchRateAndImpersonatingAdmins(t *testing.T) {
	p := New()
	if p.searchLimit != DefaultSearchLimit || p.searchWindow != DefaultSearchWindow || p.impersonateAdmins {
		t.Fatalf("defaults = %d %v %v", p.searchLimit, p.searchWindow, p.impersonateAdmins)
	}
	p = New(SearchRate(5, 2*DefaultSearchWindow), AllowImpersonatingAdmins())
	if p.searchLimit != 5 || p.searchWindow != 2*DefaultSearchWindow || !p.impersonateAdmins {
		t.Fatalf("options = %d %v %v", p.searchLimit, p.searchWindow, p.impersonateAdmins)
	}
}
