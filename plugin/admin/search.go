package admin

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// SearchField is what search-users matches the value against. A closed set
// rather than a column name, for the reason UserSort is one: an admin search
// can never read a column the admin should not see.
type SearchField string

// Search fields.
const (
	// SearchEmail matches the user's email addresses (auth_identity rows of
	// kind email), verified or not. It ignores case: addresses are stored
	// folded, and the value is folded the same way before it is compared.
	// The default when Field is empty.
	SearchEmail SearchField = "email"
	// SearchName matches the display name as stored, case included. Names
	// have no normalized form, and the library folds case in Go only, never
	// with lower() in SQL, so "ada" does not find "Ada".
	SearchName SearchField = "name"
)

// SearchFieldValues is the canonical list of search fields.
var SearchFieldValues = []SearchField{SearchEmail, SearchName}

// SearchOperator is where the value must appear in the field.
type SearchOperator string

// Search operators.
const (
	// SearchContains matches the value anywhere; the default when Operator
	// is empty.
	SearchContains   SearchOperator = "contains"
	SearchStartsWith SearchOperator = "starts_with"
	SearchEndsWith   SearchOperator = "ends_with"
)

// SearchOperatorValues is the canonical list of search operators.
var SearchOperatorValues = []SearchOperator{SearchContains, SearchStartsWith, SearchEndsWith}

// SearchUsersRequest is the input of search-users: a fragment of an address
// or a name, and the same paging, sort and filters as UsersRequest. Every
// character of Value is text: %, _ and the escape character match
// themselves, never "anything".
type SearchUsersRequest struct {
	Value    string         `json:"value"`
	Field    SearchField    `json:"field,omitempty"`
	Operator SearchOperator `json:"operator,omitempty"`
	// Page, Limit, Offset, the sort and the filters are UsersRequest's.
	Page           int            `json:"page,omitempty,string"`
	Limit          int            `json:"limit,omitempty,string"`
	Offset         int            `json:"offset,omitempty,string"`
	Sort           UserSort       `json:"sort,omitempty"`
	SortBy         SortField      `json:"sortBy,omitempty"`
	SortDirection  SortDirection  `json:"sortDirection,omitempty"`
	Admin          Flag           `json:"admin,omitempty"`
	Banned         Flag           `json:"banned,omitempty"`
	FilterField    FilterField    `json:"filterField,omitempty"`
	FilterOperator FilterOperator `json:"filterOperator,omitempty"`
	FilterValue    *string        `json:"filterValue,omitempty"`
}

// SearchUsers pages through users whose address or name holds a fragment, as
// the signed-in admin. It has its own rate rule (SearchRate), because a
// fragment search is the one admin read that can walk the user table.
func (p *Plugin) SearchUsers(ctx context.Context, in SearchUsersRequest) (UsersResult, error) {
	return p.searchUsers.Call(ctx, in)
}

// doSearchUsers checks the caller before the input, like every admin
// operation, so a non-admin learns nothing from which inputs are refused.
func (p *Plugin) doSearchUsers(ctx context.Context, c *auth.Call, in SearchUsersRequest) (UsersResult, error) {
	if err := p.require(ctx, c, ResourceUser, ActionList); err != nil {
		return UsersResult{}, err
	}
	value := strings.TrimSpace(in.Value)
	if value == "" || utf8.RuneCountInString(value) > MaxSearchLength {
		return UsersResult{}, ErrSearchValue
	}
	op := in.Operator
	if op == "" {
		op = SearchContains
	}
	var pred sqlb.Predicate
	switch in.Field {
	case "", SearchEmail:
		if p.emails == nil {
			return UsersResult{}, ErrNoEmailPlugin
		}
		match, err := likeMatch(auth.IdentityValue, op, foldEmail(value))
		if err != nil {
			return UsersResult{}, err
		}
		ids := c.Auth.Select().Exprs(auth.IdentityUserID).From(auth.TableIdentity).Where(sqlb.Eq(auth.IdentityKind, email.KindEmail), match)
		pred = sqlb.InSubquery(auth.UserID, ids)
	case SearchName:
		var err error
		if pred, err = exactCaseMatch(c.Auth.Engine(), auth.UserName, op, value); err != nil {
			return UsersResult{}, err
		}
	default:
		return UsersResult{}, ErrBadSearchField
	}
	list := UsersRequest{Page: in.Page, Limit: in.Limit, Offset: in.Offset, Sort: in.Sort, SortBy: in.SortBy, SortDirection: in.SortDirection,
		Admin: in.Admin, Banned: in.Banned, FilterField: in.FilterField, FilterOperator: in.FilterOperator, FilterValue: in.FilterValue}
	return p.list(ctx, c, list, []sqlb.Predicate{pred})
}

// foldEmail folds a fragment of an address the way email.Normalize folds a
// whole one (trimmed, lowercased), so it compares exactly against the stored
// values. A custom email.WithNormalizer is not applied: it may reshape a whole
// address (drop dots or a +tag), which means nothing for a piece of one.
func foldEmail(fragment string) string { return strings.ToLower(strings.TrimSpace(fragment)) }

// likeMatch is the escaped LIKE predicate for op: sqlb escapes %, _ and its
// escape character and writes the ESCAPE clause, so the value is text on
// every engine. Case follows the column's comparison, which is why the email
// search folds its value first.
func likeMatch(col sqlb.Expr[string], op SearchOperator, value string) (sqlb.Predicate, error) {
	switch op {
	case SearchContains:
		return sqlb.Contains(col, value), nil
	case SearchStartsWith:
		return sqlb.StartsWith(col, value), nil
	case SearchEndsWith:
		return sqlb.EndsWith(col, value), nil
	}
	return nil, ErrBadSearchOperator
}

// sqliteGlob is SQLite's case-sensitive pattern operator.
const sqliteGlob = "GLOB"

// exactCaseMatch matches value in col with case, identically on every engine.
// Postgres LIKE and MySQL LIKE on the utf8mb4_bin tables are case-sensitive
// already; SQLite's LIKE ignores ASCII case, so there it is GLOB, its
// case-sensitive twin, with the value's glob syntax escaped.
func exactCaseMatch(engine string, col sqlb.Expr[string], op SearchOperator, value string) (sqlb.Predicate, error) {
	if engine != auth.EngineSQLite {
		return likeMatch(col, op, value)
	}
	v := escapeGlob(value)
	var pattern string
	switch op {
	case SearchContains:
		pattern = "*" + v + "*"
	case SearchStartsWith:
		pattern = v + "*"
	case SearchEndsWith:
		pattern = "*" + v
	default:
		return nil, ErrBadSearchOperator
	}
	return sqlb.Compare(col, sqliteGlob, sqlb.Param(pattern)), nil
}

// escapeGlob makes every GLOB metacharacter literal by putting it in a
// one-character class: * ? and [ become [*] [?] [[]. A ] outside a class is
// already literal, and GLOB has no escape character to escape.
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
