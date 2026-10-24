package admin

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

// TestFilterOperatorsOf: every field has its operator set, and an unknown
// field has none.
func TestFilterOperatorsOf(t *testing.T) {
	for _, f := range FilterFieldValues {
		if len(FilterOperatorsOf(f)) == 0 {
			t.Fatalf("%s has no operators", f)
		}
	}
	if FilterOperatorsOf("password") != nil {
		t.Fatal("an unknown field has operators")
	}
	if slices.Contains(FilterOperatorsOf(FilterEmail), FilterLt) || !slices.Contains(FilterOperatorsOf(FilterCreatedAt), FilterLt) {
		t.Fatal("lt belongs to times, not to addresses")
	}
	for _, op := range []FilterOperator{FilterContains, FilterStartsWith, FilterEndsWith} {
		if !slices.Contains(SearchOperatorValues, SearchOperator(op)) {
			t.Fatalf("%s is not a search operator, so textFilter cannot hand it to exactCaseMatch", op)
		}
	}
}

// TestFilterValues: in and not_in split and trim, every other operator takes
// the value whole, and an empty part, an over-long part or too many parts
// are refused.
func TestFilterValues(t *testing.T) {
	if got, err := filterValues(FilterIn, " a , b "); err != nil || !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("in = %v %v", got, err)
	}
	if got, err := filterValues(FilterEq, "a,b"); err != nil || !slices.Equal(got, []string{"a,b"}) {
		t.Fatalf("eq = %v %v", got, err)
	}
	for _, c := range []struct {
		op FilterOperator
		v  string
	}{
		{FilterEq, ""}, {FilterEq, "  "}, {FilterNotIn, "a,,b"},
		{FilterEq, strings.Repeat("x", MaxSearchLength+1)},
		{FilterIn, strings.Repeat("x,", MaxFilterValues) + "x"},
	} {
		if _, err := filterValues(c.op, c.v); !errors.Is(err, ErrBadFilterValue) {
			t.Fatalf("%s %q = %v", c.op, c.v, err)
		}
	}
	if _, err := filterValues(FilterIn, strings.TrimSuffix(strings.Repeat("x,", MaxFilterValues), ",")); err != nil {
		t.Fatalf("exactly MaxFilterValues: %v", err)
	}
}

// TestFilterBoolAndTime: flags read as strconv booleans, times as RFC 3339
// in UTC.
func TestFilterBoolAndTime(t *testing.T) {
	if b, err := filterBool("true"); err != nil || !b {
		t.Fatal(b, err)
	}
	if _, err := filterBool("yes"); !errors.Is(err, ErrBadFilterValue) {
		t.Fatal(err)
	}
	tm, err := filterTime("2026-10-08T12:00:00+05:30")
	if err != nil || tm.Location() != time.UTC || tm.Hour() != 6 || tm.Minute() != 30 {
		t.Fatal(tm, err)
	}
	if _, err := filterTime("2026-10-08"); !errors.Is(err, ErrBadFilterValue) {
		t.Fatal(err)
	}
	if _, err := timeFilter(auth.UserCreatedAt, FilterGt, "x"); !errors.Is(err, ErrBadFilterValue) {
		t.Fatal(err)
	}
	if _, err := banExpiresFilter(FilterGt, "x"); !errors.Is(err, ErrBadFilterValue) {
		t.Fatal(err)
	}
}

// TestFilterPredicate_RefusesBeforeTheValue: the field and the operator are
// checked even when there is no value, and a nil value filters nothing.
func TestFilterPredicate_RefusesBeforeTheValue(t *testing.T) {
	p := New()
	now := time.Now()
	if _, err := p.filterPredicate(auth.EngineSQLite, now, "password", "", nil); !errors.Is(err, ErrBadFilterField) {
		t.Fatal(err)
	}
	if _, err := p.filterPredicate(auth.EngineSQLite, now, FilterName, FilterGt, nil); !errors.Is(err, ErrBadFilterOperator) {
		t.Fatal(err)
	}
	if pred, err := p.filterPredicate(auth.EngineSQLite, now, "", "", nil); pred != nil || err != nil {
		t.Fatal(pred, err)
	}
	v := "a@b.c"
	if _, err := p.filterPredicate(auth.EngineSQLite, now, FilterEmail, FilterEq, &v); !errors.Is(err, ErrNoEmailPlugin) {
		t.Fatalf("email filter without the email plugin = %v", err)
	}
}

// TestSortOrder: sortBy with each direction, the older values, and the
// refusals for mixing them, a direction alone, and unknown names.
func TestSortOrder(t *testing.T) {
	for _, by := range SortFieldValues {
		for _, d := range append([]SortDirection{""}, SortDirectionValues...) {
			if terms, err := sortOrder("", by, d); err != nil || len(terms) == 0 {
				t.Fatalf("%s %s = %v %v", by, d, terms, err)
			}
		}
	}
	if terms, err := sortOrder(UserSortNameAsc, "", ""); err != nil || len(terms) != 2 {
		t.Fatal(terms, err)
	}
	for _, c := range []struct {
		legacy UserSort
		by     SortField
		dir    SortDirection
	}{
		{UserSortNameAsc, SortByName, ""}, {"", "", SortDesc}, {"", SortByName, "up"}, {"", "email", ""}, {"nope", "", ""},
	} {
		if _, err := sortOrder(c.legacy, c.by, c.dir); !errors.Is(err, ErrBadSort) {
			t.Fatalf("%+v = %v", c, err)
		}
	}
}

// TestPaging: defaults, the clamp, pages from one, and an offset that
// replaces the page.
func TestPaging(t *testing.T) {
	for _, c := range []struct{ page, limit, offset, wl, wp, wo int }{
		{0, 0, 0, DefaultPageSize, 1, 0},
		{3, 10, 0, 10, 3, 20},
		{1, MaxPageSize + 1, 0, MaxPageSize, 1, 0},
		{9, 10, 25, 10, 3, 25},
	} {
		if l, p, o := paging(auth.Config{}, c.page, c.limit, c.offset); l != c.wl || p != c.wp || o != c.wo {
			t.Fatalf("%+v = %d %d %d", c, l, p, o)
		}
	}
	// auth.WithDefaultPageSize replaces the default, never the cap or a
	// requested size.
	cfg := auth.Config{DefaultPageSize: 7}
	if l, _, _ := paging(cfg, 1, 0, 0); l != 7 {
		t.Fatalf("core default: %d, want 7", l)
	}
	if l, _, _ := paging(cfg, 1, 12, 0); l != 12 {
		t.Fatalf("requested: %d, want 12", l)
	}
	if l, _, _ := paging(auth.Config{DefaultPageSize: MaxPageSize + 5}, 1, 0, 0); l != MaxPageSize {
		t.Fatalf("core default above the cap: %d, want %d", l, MaxPageSize)
	}
}

// TestApplyData: the profile keys become the update, declared columns are
// prepared, and everything else is refused before any write.
func TestApplyData(t *testing.T) {
	plan := sqlb.Col[string](auth.TableUser, "plan")
	bad := errors.New("bad plan")
	p := New(EditableColumns(Editable(plan, func(v string) error {
		if v == "gold" {
			return bad
		}
		return nil
	}), EditableColumn{}))
	if len(p.editable) != 1 || p.editable["plan"].Name() != "plan" {
		t.Fatalf("editable = %v; the zero EditableColumn must be dropped", p.editable)
	}
	data := func(s string) UpdateUserRequest {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatal(err)
		}
		return UpdateUserRequest{UserID: "u", Data: m}
	}
	upd, writes, err := p.applyData(data(`{"name":"N","image":"https://x/i.png","plan":"pro"}`))
	if err != nil || *upd.Name != "N" || *upd.Image != "https://x/i.png" || len(writes) != 1 {
		t.Fatalf("= %+v %d %v", upd, len(writes), err)
	}
	name := "kept"
	if upd, writes, err := p.applyData(UpdateUserRequest{Name: &name}); err != nil || upd.Name != &name || writes != nil {
		t.Fatal(upd, writes, err)
	}
	for s, want := range map[string]error{
		`{}`:                   ErrNoUserData,
		`{"password":"x"}`:     ErrFieldNotEditable,
		`{"image":1}`:          ErrBadUserData,
		`{"plan":["pro"]}`:     ErrBadUserData,
		`{"plan":"pro" }`:      nil,
		`{"plan":"gold"}`:      bad,
		`{"plan":{"a":1}}`:     ErrBadUserData,
		`{"plan":"a","x":"y"}`: ErrFieldNotEditable,
	} {
		if _, _, err := p.applyData(data(s)); !errors.Is(err, want) {
			t.Errorf("%s = %v, want %v", s, err, want)
		}
	}
}

// TestFixedAdminIDs: AdminIDs come out sorted, so the role filter's IN list
// is the same statement on every call.
func TestFixedAdminIDs(t *testing.T) {
	if got := New(AdminIDs("c", "a", "b")).fixedAdminIDs(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatal(got)
	}
	if got := New().fixedAdminIDs(); len(got) != 0 {
		t.Fatal(got)
	}
}

// TestLivePredicates: a live session is unexpired, not pending and not
// revoked, the three conditions of the SQL store's own List.
func TestLivePredicates(t *testing.T) {
	if got := livePredicates(time.Now()); len(got) != 3 {
		t.Fatalf("= %d predicates", len(got))
	}
}
