package organization

import (
	"net/http"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// MemberSort is what the members list is ordered by. A closed set rather
// than a column name, so a request can never order by, and so probe, a
// column it should not read.
type MemberSort string

// Member sort keys.
const (
	// SortJoinedAt orders by when the member joined; the default.
	SortJoinedAt MemberSort = "joinedAt"
	// SortCreatedAt is better-auth's name for the same order.
	SortCreatedAt MemberSort = "createdAt"
	SortName      MemberSort = "name"
	SortRole      MemberSort = "role"
	SortUserID    MemberSort = "userId"
)

// MemberSortValues is the canonical list of sort keys.
var MemberSortValues = []MemberSort{SortJoinedAt, SortCreatedAt, SortName, SortRole, SortUserID}

// Direction is a sort direction.
type Direction string

// Directions.
const (
	Asc  Direction = "asc"
	Desc Direction = "desc"
)

// MemberField is what a members filter compares.
type MemberField string

// Member filter fields. JoinedAt and CreatedAt are the same column, when the
// member joined, under our name and better-auth's.
const (
	FieldRole      MemberField = "role"
	FieldUserID    MemberField = "userId"
	FieldName      MemberField = "name"
	FieldJoinedAt  MemberField = "joinedAt"
	FieldCreatedAt MemberField = "createdAt"
)

// MemberFieldValues is the canonical list of filter fields.
var MemberFieldValues = []MemberField{FieldRole, FieldUserID, FieldName, FieldJoinedAt, FieldCreatedAt}

// FilterOperator is how a members filter compares.
type FilterOperator string

// Filter operators, better-auth's names. A text field (role, userId, name)
// takes eq, ne, in, not_in, contains, starts_with and ends_with, all
// case-sensitive on every engine (memberTextMatch); the time field takes eq,
// ne, lt, lte, gt and gte. The order operators are refused on text, because
// "less than" between two names depends on the engine's collation, so the
// same request would answer differently on Postgres and SQLite.
const (
	OpEq         FilterOperator = "eq"
	OpNe         FilterOperator = "ne"
	OpIn         FilterOperator = "in"
	OpNotIn      FilterOperator = "not_in"
	OpContains   FilterOperator = "contains"
	OpStartsWith FilterOperator = "starts_with"
	OpEndsWith   FilterOperator = "ends_with"
	OpLt         FilterOperator = "lt"
	OpLte        FilterOperator = "lte"
	OpGt         FilterOperator = "gt"
	OpGte        FilterOperator = "gte"
)

// FilterOperatorValues is the canonical list of filter operators.
var FilterOperatorValues = []FilterOperator{OpEq, OpNe, OpIn, OpNotIn, OpContains, OpStartsWith, OpEndsWith, OpLt, OpLte, OpGt, OpGte}

// ErrBadQuery is a sort key, direction, filter field or operator the
// members list does not support.
var ErrBadQuery = auth.NewError("organization.bad_query", http.StatusBadRequest, "This sort or filter is not supported.")

// memberRoleText is the role column as text, for the fragment operators.
var memberRoleText = sqlb.Col[string](TableMember, ColMemberRole)

// memberOrder is the ORDER BY of the members list: the key, then the user id,
// so pages never overlap when the key ties.
func memberOrder(by MemberSort, dir Direction) ([]sqlb.OrderTerm, error) {
	d := sqlb.SortAsc
	switch dir {
	case "", Asc:
	case Desc:
		d = sqlb.SortDesc
	default:
		return nil, ErrBadQuery
	}
	var first sqlb.OrderTerm
	switch by {
	case "", SortJoinedAt, SortCreatedAt:
		first = sqlb.OrderBy(MemberJoinedAt, d)
	case SortName:
		first = sqlb.OrderBy(auth.UserName, d)
	case SortRole:
		first = sqlb.OrderBy(MemberRole, d)
	case SortUserID:
		return []sqlb.OrderTerm{sqlb.OrderBy(MemberUserID, d)}, nil
	default:
		return nil, ErrBadQuery
	}
	return []sqlb.OrderTerm{first, sqlb.OrderBy(MemberUserID, sqlb.SortAsc)}, nil
}

// memberFilter is the WHERE term of a members filter on engine. In and
// not_in split value at commas, the URL form of a list; a time value is
// RFC 3339 ("2026-10-08T10:00:00Z").
func memberFilter(engine string, field MemberField, op FilterOperator, value string) (sqlb.Predicate, error) {
	var col sqlb.Expr[string]
	switch field {
	case FieldRole:
		col = memberRoleText
	case FieldUserID:
		col = MemberUserID
	case FieldName:
		col = auth.UserName
	case FieldJoinedAt, FieldCreatedAt:
		return memberTimeFilter(op, value)
	default:
		return nil, ErrBadQuery
	}
	switch op {
	case "", OpEq:
		return sqlb.Eq(col, value), nil
	case OpNe:
		return sqlb.NotEq(col, value), nil
	case OpIn, OpNotIn:
		var vals []string
		for _, v := range strings.Split(value, ",") {
			if v = strings.TrimSpace(v); v != "" {
				vals = append(vals, v)
			}
		}
		if len(vals) == 0 {
			return nil, ErrBadQuery
		}
		if op == OpNotIn {
			return sqlb.NotIn(col, vals...), nil
		}
		return sqlb.In(col, vals...), nil
	case OpContains, OpStartsWith, OpEndsWith:
		return memberTextMatch(engine, col, op, value), nil
	}
	return nil, ErrBadQuery
}

// memberTimeFilter compares when a member joined with an RFC 3339 instant.
// The value is parsed in Go, so a malformed one is ErrBadQuery rather than
// whatever each engine makes of the text.
func memberTimeFilter(op FilterOperator, value string) (sqlb.Predicate, error) {
	at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		return nil, ErrBadQuery
	}
	at = at.UTC()
	switch op {
	case "", OpEq:
		return sqlb.Eq(MemberJoinedAt, at), nil
	case OpNe:
		return sqlb.NotEq(MemberJoinedAt, at), nil
	case OpLt:
		return sqlb.Less(MemberJoinedAt, at), nil
	case OpLte:
		return sqlb.LessEq(MemberJoinedAt, at), nil
	case OpGt:
		return sqlb.Greater(MemberJoinedAt, at), nil
	case OpGte:
		return sqlb.GreaterEq(MemberJoinedAt, at), nil
	}
	return nil, ErrBadQuery
}

// sqliteGlob is SQLite's case-sensitive pattern operator.
const sqliteGlob = "GLOB"

// memberTextMatch is a fragment match with case on every engine: Postgres
// LIKE and MySQL LIKE on the utf8mb4_bin tables are case-sensitive already;
// SQLite's LIKE ignores ASCII case, so there it is GLOB, its case-sensitive
// twin, with the value's glob syntax escaped. Values are compared exactly,
// as everywhere in the library, never folded in SQL.
func memberTextMatch(engine string, col sqlb.Expr[string], op FilterOperator, value string) sqlb.Predicate {
	if engine != auth.EngineSQLite {
		switch op {
		case OpStartsWith:
			return sqlb.StartsWith(col, value)
		case OpEndsWith:
			return sqlb.EndsWith(col, value)
		}
		return sqlb.Contains(col, value)
	}
	v := escapeGlob(value)
	pattern := "*" + v + "*"
	switch op {
	case OpStartsWith:
		pattern = v + "*"
	case OpEndsWith:
		pattern = "*" + v
	}
	return sqlb.Compare(col, sqliteGlob, sqlb.Param(pattern))
}

// escapeGlob makes every GLOB metacharacter literal by putting it in a
// one-character class: * ? and [ become [*] [?] [[]. A ] outside a class is
// already literal, and GLOB has no escape character.
func escapeGlob(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '*' || r == '?' || r == '[' {
			b.WriteByte('[')
			b.WriteRune(r)
			b.WriteByte(']')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
