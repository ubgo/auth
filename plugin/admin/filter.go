package admin

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// FilterField is the user field a list filter compares (filterField). A
// closed set rather than a column name, for the reason
// UserSort is one: an admin filter can never read a column the admin should
// not see, and each field has the operators that mean something for its type
// (FilterOperatorsOf).
type FilterField string

// Filter fields, named as the user's JSON fields.
const (
	// FilterEmail compares the user's email addresses (auth_identity rows of
	// kind email), verified or not. The value is folded as addresses are
	// stored, so the comparison ignores case. The default when FilterField is
	// empty.
	FilterEmail FilterField = "email"
	// FilterEmailVerified is true for a user holding at least one verified
	// address.
	FilterEmailVerified FilterField = "emailVerified"
	// FilterID compares the user id exactly.
	FilterID FilterField = "id"
	// FilterName compares the display name as stored, case included, as
	// SearchName does.
	FilterName FilterField = "name"
	// FilterRole compares the roles a user holds (RolesOf): a stored role, the
	// first of AdminRoles for a user the flag or AdminIDs makes an admin, and
	// DefaultRole for a user with neither. eq means "holds this role".
	FilterRole FilterField = "role"
	// FilterBanned is true for a user whose ban is in force, the banned=
	// flag's meaning.
	FilterBanned FilterField = "banned"
	// FilterBanReason compares the stored ban reason, case included.
	FilterBanReason FilterField = "banReason"
	// FilterBanExpires compares the end of a ban; a user with no ban end
	// (none, or a permanent one) never matches.
	FilterBanExpires FilterField = "banExpires"
	// FilterCreatedAt and FilterUpdatedAt compare the user row's times.
	FilterCreatedAt FilterField = "createdAt"
	FilterUpdatedAt FilterField = "updatedAt"
)

// FilterFieldValues is the canonical list of filter fields.
var FilterFieldValues = []FilterField{FilterEmail, FilterEmailVerified, FilterID, FilterName, FilterRole, FilterBanned, FilterBanReason, FilterBanExpires, FilterCreatedAt, FilterUpdatedAt}

// FilterOperator is how a list filter compares (filterOperator).
type FilterOperator string

// Filter operators. The text operators contains, starts_with and ends_with
// treat every character of the value as text, as search-users does.
const (
	// FilterEq is the default when FilterOperator is empty.
	FilterEq         FilterOperator = "eq"
	FilterNe         FilterOperator = "ne"
	FilterLt         FilterOperator = "lt"
	FilterLte        FilterOperator = "lte"
	FilterGt         FilterOperator = "gt"
	FilterGte        FilterOperator = "gte"
	FilterIn         FilterOperator = "in"
	FilterNotIn      FilterOperator = "not_in"
	FilterContains   FilterOperator = "contains"
	FilterStartsWith FilterOperator = "starts_with"
	FilterEndsWith   FilterOperator = "ends_with"
)

// FilterOperatorValues is the canonical list of filter operators.
var FilterOperatorValues = []FilterOperator{FilterEq, FilterNe, FilterLt, FilterLte, FilterGt, FilterGte, FilterIn, FilterNotIn, FilterContains, FilterStartsWith, FilterEndsWith}

// Operator sets per field type. An operator outside a field's set is
// ErrBadFilterOperator rather than a guess: lt on an address or contains on
// a time has no answer worth giving.
var (
	textOperators = []FilterOperator{FilterEq, FilterNe, FilterIn, FilterNotIn, FilterContains, FilterStartsWith, FilterEndsWith}
	idOperators   = []FilterOperator{FilterEq, FilterNe, FilterIn, FilterNotIn}
	boolOperators = []FilterOperator{FilterEq, FilterNe}
	timeOperators = []FilterOperator{FilterEq, FilterNe, FilterLt, FilterLte, FilterGt, FilterGte}
)

// FilterOperatorsOf is the operators field accepts, nil for an unknown
// field.
func FilterOperatorsOf(field FilterField) []FilterOperator {
	switch field {
	case FilterEmail, FilterName, FilterBanReason:
		return textOperators
	case FilterID, FilterRole:
		return idOperators
	case FilterEmailVerified, FilterBanned:
		return boolOperators
	case FilterCreatedAt, FilterUpdatedAt, FilterBanExpires:
		return timeOperators
	}
	return nil
}

// FilterListSeparator splits the value of in and not_in: "a,b" is the two
// values a and b. A query string carries one value per parameter, so the
// list is one comma-joined value.
const FilterListSeparator = ","

// MaxFilterValues bounds the values of one in or not_in filter: a page of
// MaxPageSize ids is the largest list an admin screen has a reason to send,
// and the bound keeps one request from becoming a statement with thousands
// of parameters.
const MaxFilterValues = MaxPageSize

// Errors of the list filter.
var (
	// ErrBadFilterField refuses a filter field outside FilterFieldValues.
	ErrBadFilterField = auth.NewError("admin.bad_filter_field", http.StatusBadRequest, "This filter field does not exist.")
	// ErrBadFilterOperator refuses an operator outside the field's
	// FilterOperatorsOf.
	ErrBadFilterOperator = auth.NewError("admin.bad_filter_operator", http.StatusBadRequest, "This filter operator does not apply to this field.")
	// ErrBadFilterValue refuses a value the field cannot hold: not true or
	// false for a flag, not an RFC 3339 time for a time, empty, longer than
	// MaxSearchLength, or more than MaxFilterValues values for in and not_in.
	ErrBadFilterValue = auth.NewError("admin.bad_filter_value", http.StatusBadRequest, "This filter value does not fit the field.")
)

// filterPredicate is the predicate of one filter (filterField,
// filterOperator, filterValue), or nil when value is empty and nothing is
// filtered. The field and the operator are checked first, so a wrong name is
// refused whatever the value.
func (p *Plugin) filterPredicate(engine string, now time.Time, field FilterField, op FilterOperator, value *string) (sqlb.Predicate, error) {
	if field == "" {
		field = FilterEmail
	}
	if op == "" {
		op = FilterEq
	}
	ops := FilterOperatorsOf(field)
	if ops == nil {
		return nil, ErrBadFilterField
	}
	if !slices.Contains(ops, op) {
		return nil, ErrBadFilterOperator
	}
	if value == nil {
		return nil, nil
	}
	values, err := filterValues(op, *value)
	if err != nil {
		return nil, err
	}
	switch field {
	case FilterEmail:
		if p.emails == nil {
			return nil, ErrNoEmailPlugin
		}
		for i := range values {
			values[i] = foldEmail(values[i])
		}
		return p.emailFilter(op, values), nil
	case FilterEmailVerified:
		b, err := filterBool(values[0])
		if err != nil {
			return nil, err
		}
		verified := p.core.Select().Exprs(auth.IdentityUserID).From(auth.TableIdentity).Where(sqlb.Eq(auth.IdentityKind, email.KindEmail), sqlb.IsNotNull(auth.IdentityVerifiedAt))
		if b == (op == FilterEq) {
			return sqlb.InSubquery(auth.UserID, verified), nil
		}
		return sqlb.NotInSubquery(auth.UserID, verified), nil
	case FilterID:
		return textFilter(engine, auth.UserID, op, values)
	case FilterName:
		return textFilter(engine, auth.UserName, op, values)
	case FilterBanReason:
		return textFilter(engine, BanReason, op, values)
	case FilterRole:
		return p.roleFilter(op, values), nil
	case FilterBanned:
		b, err := filterBool(values[0])
		if err != nil {
			return nil, err
		}
		if b == (op == FilterEq) {
			return banned(now), nil
		}
		return notBanned(now), nil
	case FilterCreatedAt:
		return timeFilter(auth.UserCreatedAt, op, values[0])
	case FilterUpdatedAt:
		return timeFilter(auth.UserUpdatedAt, op, values[0])
	}
	return banExpiresFilter(op, values[0])
}

// filterValues splits value for in and not_in and checks every part: none
// empty, none longer than MaxSearchLength, at most MaxFilterValues of them.
// Every other operator takes the value whole.
func filterValues(op FilterOperator, value string) ([]string, error) {
	values := []string{value}
	if op == FilterIn || op == FilterNotIn {
		values = strings.Split(value, FilterListSeparator)
	}
	if len(values) > MaxFilterValues {
		return nil, ErrBadFilterValue
	}
	for i, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || len([]rune(v)) > MaxSearchLength {
			return nil, ErrBadFilterValue
		}
		values[i] = v
	}
	return values, nil
}

// filterBool reads a flag filter's value.
func filterBool(v string) (bool, error) {
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, ErrBadFilterValue
	}
	return b, nil
}

// filterTime reads a time filter's value, RFC 3339 as every time the
// library answers with.
func filterTime(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return time.Time{}, ErrBadFilterValue
	}
	return t.UTC(), nil
}

// textFilter compares a text column with case on every engine: = and IN are
// exact everywhere (SQLite's default collation, Postgres, the utf8mb4_bin
// MySQL tables), and the fragment operators go through exactCaseMatch.
func textFilter(engine string, col sqlb.Expr[string], op FilterOperator, values []string) (sqlb.Predicate, error) {
	switch op {
	case FilterEq:
		return sqlb.Eq(col, values[0]), nil
	case FilterNe:
		return sqlb.NotEq(col, values[0]), nil
	case FilterIn:
		return sqlb.In(col, values...), nil
	case FilterNotIn:
		return sqlb.NotIn(col, values...), nil
	}
	return exactCaseMatch(engine, col, SearchOperator(op), values[0])
}

// emailFilter matches users through their email identities. A positive
// operator is "holds a matching address"; ne and not_in are its negation,
// "holds no such address", which includes users with no address at all, as
// a user without an email is not equal to the value.
func (p *Plugin) emailFilter(op FilterOperator, values []string) sqlb.Predicate {
	var match sqlb.Predicate
	switch op {
	case FilterEq, FilterNe:
		match = sqlb.Eq(auth.IdentityValue, values[0])
	case FilterIn, FilterNotIn:
		match = sqlb.In(auth.IdentityValue, values...)
	case FilterContains:
		match = sqlb.Contains(auth.IdentityValue, values[0])
	case FilterStartsWith:
		match = sqlb.StartsWith(auth.IdentityValue, values[0])
	default:
		// FilterEndsWith, the last of textOperators.
		match = sqlb.EndsWith(auth.IdentityValue, values[0])
	}
	ids := p.core.Select().Exprs(auth.IdentityUserID).From(auth.TableIdentity).Where(sqlb.Eq(auth.IdentityKind, email.KindEmail), match)
	if op == FilterNe || op == FilterNotIn {
		return sqlb.NotInSubquery(auth.UserID, ids)
	}
	return sqlb.InSubquery(auth.UserID, ids)
}

// roleFilter is "holds one of values" (eq, in) or its negation (ne,
// not_in), with RolesOf's meaning: the stored roles, the flag's admin role
// and DefaultRole for a user with neither.
func (p *Plugin) roleFilter(op FilterOperator, values []string) sqlb.Predicate {
	var held []sqlb.Predicate
	for _, v := range values {
		held = append(held, p.holdsRole(v))
	}
	pred := sqlb.Or(held...)
	if op == FilterNe || op == FilterNotIn {
		return sqlb.Not(pred)
	}
	return pred
}

// holdsRole is the SQL twin of slices.Contains(rolesOf(...), role). A stored
// value is the roles joined by roleSeparator with no spaces (writeRoles), so
// the role is the whole value, its first, its last or a middle element; the
// LIKE fragments are escaped, so a role name is text.
func (p *Plugin) holdsRole(role string) sqlb.Predicate {
	stored := p.storedRole(role)
	flagged := sqlb.IsNotNull(GrantedAt)
	if ids := p.fixedAdminIDs(); len(ids) > 0 {
		flagged = sqlb.Or(flagged, sqlb.In(auth.UserID, ids...))
	}
	terms := []sqlb.Predicate{stored}
	if role == p.adminRoles[0] {
		// rolesOf adds the first admin role to a flagged user who holds no
		// admin role; one who holds another admin role is not given it, which
		// is "flagged and none of the admin roles stored".
		var none []sqlb.Predicate
		for _, r := range p.adminRoles {
			none = append(none, sqlb.Not(p.storedRole(r)))
		}
		terms = append(terms, sqlb.And(append([]sqlb.Predicate{flagged}, none...)...))
	}
	if role == p.defaultRole {
		// DefaultRole is given only to a user with no stored role who is not
		// flagged.
		terms = append(terms, sqlb.And(sqlb.Eq(UserRole, ""), sqlb.Not(flagged)))
	}
	return sqlb.Or(terms...)
}

// storedRole is "the stored value holds role", the first term of holdsRole.
func (p *Plugin) storedRole(role string) sqlb.Predicate {
	return sqlb.Or(sqlb.Eq(UserRole, role), sqlb.StartsWith(UserRole, role+roleSeparator),
		sqlb.EndsWith(UserRole, roleSeparator+role), sqlb.Contains(UserRole, roleSeparator+role+roleSeparator))
}

// fixedAdminIDs is AdminIDs in a stable order, for an IN list.
func (p *Plugin) fixedAdminIDs() []string {
	ids := make([]string, 0, len(p.adminIDs))
	for id := range p.adminIDs {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// timeFilter compares a non-null time column.
func timeFilter(col sqlb.Expr[time.Time], op FilterOperator, value string) (sqlb.Predicate, error) {
	t, err := filterTime(value)
	if err != nil {
		return nil, err
	}
	switch op {
	case FilterEq:
		return sqlb.Eq(col, t), nil
	case FilterNe:
		return sqlb.NotEq(col, t), nil
	case FilterLt:
		return sqlb.Less(col, t), nil
	case FilterLte:
		return sqlb.LessEq(col, t), nil
	case FilterGt:
		return sqlb.Greater(col, t), nil
	}
	return sqlb.GreaterEq(col, t), nil
}

// banExpiresFilter compares the nullable ban end; a NULL never matches, ne
// included, so "banExpires ne X" lists bans that end at another time.
func banExpiresFilter(op FilterOperator, value string) (sqlb.Predicate, error) {
	t, err := filterTime(value)
	if err != nil {
		return nil, err
	}
	var cmp sqlb.Predicate
	switch op {
	case FilterEq:
		cmp = sqlb.Eq(BanExpiresAt, &t)
	case FilterNe:
		cmp = sqlb.NotEq(BanExpiresAt, &t)
	case FilterLt:
		cmp = sqlb.Less(BanExpiresAt, &t)
	case FilterLte:
		cmp = sqlb.LessEq(BanExpiresAt, &t)
	case FilterGt:
		cmp = sqlb.Greater(BanExpiresAt, &t)
	default:
		cmp = sqlb.GreaterEq(BanExpiresAt, &t)
	}
	return sqlb.And(sqlb.IsNotNull(BanExpiresAt), cmp), nil
}

// SortField is the user field the list is sorted by (sortBy):
// a closed set, as UserSort is.
type SortField string

// Sort fields. Email is not one: a user may hold several addresses, so
// "sorted by email" has no single value per row.
const (
	SortByCreatedAt SortField = "createdAt"
	SortByUpdatedAt SortField = "updatedAt"
	SortByName      SortField = "name"
	SortByID        SortField = "id"
)

// SortFieldValues is the canonical list of sort fields.
var SortFieldValues = []SortField{SortByCreatedAt, SortByUpdatedAt, SortByName, SortByID}

// SortDirection is the direction of a SortField sort (sortDirection).
type SortDirection string

// Sort directions; empty is SortAsc, the default.
const (
	SortAsc  SortDirection = "asc"
	SortDesc SortDirection = "desc"
)

// SortDirectionValues is the canonical list of sort directions.
var SortDirectionValues = []SortDirection{SortAsc, SortDesc}

// sortOrder is the ORDER BY of sortBy and sortDirection when sortBy is set,
// and of the older sort value otherwise. Naming both is refused
// (ErrBadSort): the two would disagree on which wins. The id is always the
// last term, so pages are stable when two rows share a value.
func sortOrder(legacy UserSort, by SortField, dir SortDirection) ([]sqlb.OrderTerm, error) {
	if by == "" {
		if dir != "" {
			return nil, ErrBadSort
		}
		return legacy.order()
	}
	if legacy != "" {
		return nil, ErrBadSort
	}
	d := sqlb.SortAsc
	switch dir {
	case "", SortAsc:
	case SortDesc:
		d = sqlb.SortDesc
	default:
		return nil, ErrBadSort
	}
	tie := sqlb.OrderBy(auth.UserID, sqlb.SortAsc)
	switch by {
	case SortByCreatedAt:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserCreatedAt, d), tie}, nil
	case SortByUpdatedAt:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserUpdatedAt, d), tie}, nil
	case SortByName:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserName, d), tie}, nil
	case SortByID:
		return []sqlb.OrderTerm{sqlb.OrderBy(auth.UserID, d)}, nil
	}
	return nil, ErrBadSort
}
