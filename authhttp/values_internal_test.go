package authhttp

import (
	"net/url"
	"testing"
	"time"
)

// valuesBase is embedded to prove promoted fields are found.
type valuesBase struct {
	Offset uint `json:"offset"`
}

// valuesInput has a field of every kind decodeValues must shape.
type valuesInput struct {
	valuesBase
	Limit   int       `json:"limit"`
	Ratio   float64   `json:"ratio"`
	On      bool      `json:"on"`
	Opt     *int      `json:"opt"`
	Tagged  int       `json:"tagged,string"`
	Name    string    `json:"name"`
	At      time.Time `json:"at"`
	Skipped int       `json:"-"`
	Plain   int8      // no tag: matched by field name, case-insensitively
}

// valuesLoop embeds a pointer to itself, which the field walk must not
// follow forever.
type valuesLoop struct {
	*valuesLoop
	N int `json:"n"`
}

// TestDecodeValues_ScalarFields: query and form values reach number and bool
// fields as JSON numbers and bools, `,string` and text fields keep their
// string, and a value that is not the field's kind is refused, never zeroed.
func TestDecodeValues_ScalarFields(t *testing.T) {
	var in valuesInput
	q := url.Values{
		"limit": {"+007"}, "offset": {"18446744073709551615"}, "ratio": {"0.5"}, "on": {"1"},
		"opt": {"3"}, "tagged": {"4"}, "name": {"12"}, "at": {"2026-10-09T00:00:00Z"}, "plain": {"-2"},
	}
	if err := decodeValues(q, &in); err != nil {
		t.Fatal(err)
	}
	if in.Limit != 7 || in.Offset != 18446744073709551615 || in.Ratio != 0.5 || !in.On || in.Opt == nil || *in.Opt != 3 ||
		in.Tagged != 4 || in.Name != "12" || in.At.IsZero() || in.Plain != -2 {
		t.Fatalf("decoded %+v", in)
	}
	for _, bad := range []url.Values{{"limit": {"ten"}}, {"ratio": {"NaN"}}, {"on": {"maybe"}}, {"tagged": {"x"}}} {
		var out valuesInput
		if err := decodeValues(bad, &out); err == nil {
			t.Errorf("%v decoded into %+v", bad, out)
		}
	}
	var hidden valuesInput
	if err := decodeValues(url.Values{"Skipped": {"1"}}, &hidden); err != nil || hidden.Skipped != 0 {
		t.Errorf("json:\"-\" field: %+v %v", hidden, err)
	}
	var loop valuesLoop
	if err := decodeValues(url.Values{"n": {"5"}}, &loop); err != nil || loop.N != 5 {
		t.Errorf("self-embedding struct: %+v %v", loop, err)
	}
}
