package apikey

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/sqlb"
)

func TestValidate_NamesHintAndGenerator(t *testing.T) {
	wire := func(opts ...Option) error {
		_, err := auth.New(auth.WithPlugins(stubSignIn{}, New(append([]Option{Scopes("s")}, opts...)...)))
		return err
	}
	for name, opts := range map[string][]Option{
		"negative min":       {NameBounds(-1, 10)},
		"max below min":      {NameBounds(10, 5)},
		"min without max":    {NameBounds(3, 0)},
		"hint too long":      {HintLength(maxHintLength + 1)},
		"negative hint":      {HintLength(-1)},
		"hint over the name": {HintLength(9)},
	} {
		if err := wire(opts...); !errors.Is(err, ErrBadLimits) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, opts := range map[string][]Option{
		"bounds":        {NameBounds(1, 32)},
		"empty allowed": {NameBounds(0, 32)},
		"no hint":       {HintLength(0)},
		"longest hint":  {HintLength(maxHintLength)},
	} {
		if err := wire(opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	p := New(Scopes("s"))
	if p.hintLen != hintExtra || p.nameMin != 0 || p.nameMax != 0 || p.gen == nil || len(p.gen()) < minSecretLength {
		t.Fatalf("defaults = %+v", p)
	}
	// NameBounds refuses; NameLength cuts.
	bounded := New(Scopes("s"), NameBounds(2, 5))
	for _, n := range []string{"a", "sixsix"} {
		if _, err := bounded.checkName(n); !errors.Is(err, ErrBadName) {
			t.Errorf("%q: %v", n, err)
		}
	}
	if got, err := bounded.checkName("héllo"); err != nil || got != "héllo" {
		t.Fatalf("five runes: %q %v", got, err)
	}
	if got, _ := New(Scopes("s"), NameLength(3)).checkName("abcdef"); got != "abc" {
		t.Fatalf("cut = %q", got)
	}
}

func TestParseList(t *testing.T) {
	for name, in := range map[string]ListRequest{
		"negative limit":  {Limit: "-1"},
		"word limit":      {Limit: "ten"},
		"negative offset": {Offset: "-5"},
		"unknown sort":    {SortBy: "secret"},
		"unknown dir":     {Sort: "sideways"},
	} {
		if _, err := parseList(in); !errors.Is(err, ErrBadList) {
			t.Errorf("%s: %v", name, err)
		}
	}
	pg, err := parseList(ListRequest{})
	if err != nil || pg.limit != 0 || pg.offset != 0 || len(pg.order) != 2 {
		t.Fatalf("zero request = %+v %v", pg, err)
	}
	pg, err = parseList(ListRequest{Limit: "10", Offset: "20", SortBy: SortByName, Sort: SortDesc})
	if err != nil || pg.limit != 10 || pg.offset != 20 || len(pg.order) != 3 {
		t.Fatalf("full request = %+v %v", pg, err)
	}
	// Every sort field is accepted and ends with the stable tiebreak.
	for _, by := range SortByValues {
		pg, err := parseList(ListRequest{SortBy: by, Sort: SortAsc})
		if err != nil || len(pg.order) < 2 {
			t.Fatalf("%s: %+v %v", by, pg, err)
		}
	}
}

func TestLimits_WithDefaults(t *testing.T) {
	refill := Limits{RefillAmount: 5, RefillInterval: 3600e9}
	if got := refill.withDefaults(); got.Remaining == nil || *got.Remaining != 5 {
		t.Fatalf("refill without a count = %+v", got)
	}
	given := Limits{Remaining: intp(2), RefillAmount: 5, RefillInterval: 3600e9}
	if got := given.withDefaults(); *got.Remaining != 2 {
		t.Fatalf("a given count was replaced: %+v", got)
	}
	if got := (Limits{}).withDefaults(); got.Remaining != nil {
		t.Fatalf("no refill: %+v", got)
	}
}

func TestNormalizeScopes(t *testing.T) {
	if got := normalizeScopes(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil = %#v", got)
	}
	if got := normalizeScopes([]string{"b", "a", "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("dedup = %v", got)
	}
}

func TestOperations_IncludeGet(t *testing.T) {
	p := New(Scopes("s"))
	var found bool
	for _, op := range p.Operations() {
		if op.Info().ID == EndpointGet && op.Info().Path == "/get" && op.Info().Kind == auth.Query && op.Info().Require == auth.SignedIn {
			found = true
		}
	}
	if !found {
		t.Fatal("no get operation")
	}
	// The list input is a query of strings, so the HTTP decoder can fill it.
	_ = sqlb.Table{}
}
