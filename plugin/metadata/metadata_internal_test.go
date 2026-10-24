package metadata

import (
	"encoding/json"
	"errors"
	"testing"
)

// TestMergePatch_RFC7396 runs the examples of RFC 7396 appendix A whose
// target and patch are objects (the plugin refuses the others, see
// TestParseObject), plus nesting and number cases the appendix leaves out.
func TestMergePatch_RFC7396(t *testing.T) {
	for _, tc := range []struct{ target, patch, want string }{
		{`{"a":"b"}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"b"}`, `{"b":"c"}`, `{"a":"b","b":"c"}`},
		{`{"a":"b"}`, `{"a":null}`, `{}`},
		{`{"a":"b","b":"c"}`, `{"a":null}`, `{"b":"c"}`},
		{`{"a":["b"]}`, `{"a":"c"}`, `{"a":"c"}`},
		{`{"a":"c"}`, `{"a":["b"]}`, `{"a":["b"]}`},
		{`{"a":{"b":"c"}}`, `{"a":{"b":"d","c":null}}`, `{"a":{"b":"d"}}`},
		{`{"a":[{"b":"c"}]}`, `{"a":[1]}`, `{"a":[1]}`},
		{`{"e":null}`, `{"a":1}`, `{"a":1,"e":null}`},
		{`{}`, `{"a":{"bb":{"ccc":null}}}`, `{"a":{"bb":{}}}`},
		// Beyond the appendix: an object over a scalar, a missing key's null,
		// numbers that float64 would round, and markup kept as written.
		{`{"a":1}`, `{"a":{"b":2}}`, `{"a":{"b":2}}`},
		{`{"a":1}`, `{"zz":null}`, `{"a":1}`},
		{`{}`, `{"big":12345678901234567890,"f":0.1}`, `{"big":12345678901234567890,"f":0.1}`},
		{`{}`, `{"html":"<b>&</b>"}`, `{"html":"<b>&</b>"}`},
		{`{"u":"é"}`, `{"v":"日本"}`, `{"u":"é","v":"日本"}`},
		// A stored document that is not an object starts over.
		{`[1]`, `{"a":1}`, `{"a":1}`},
	} {
		doc := json.RawMessage(tc.target)
		if err := mergeInto(&doc, json.RawMessage(tc.patch)); err != nil {
			t.Errorf("%s + %s: %v", tc.target, tc.patch, err)
			continue
		}
		if string(doc) != tc.want {
			t.Errorf("%s + %s = %s, want %s", tc.target, tc.patch, doc, tc.want)
		}
	}
}

// TestParseObject: exactly one JSON object is accepted; every other value,
// trailing data and malformed input is ErrInvalid.
func TestParseObject(t *testing.T) {
	for _, ok := range []string{`{}`, `{"a":1}`, ` {"a":{"b":[1,null]}} `, `{"":""}`} {
		if _, err := parseObject(json.RawMessage(ok)); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{``, `null`, `[]`, `[1]`, `"x"`, `1`, `true`, `{`, `{"a":}`, `{} {}`, `{}x`, `{"a":1}]`} {
		if _, err := parseObject(json.RawMessage(bad)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: err = %v, want ErrInvalid", bad, err)
		}
	}
}

// TestMetadataDoc maps every kind to its field and refuses any other.
func TestMetadataDoc(t *testing.T) {
	m := Metadata{Public: json.RawMessage(`1`), Private: json.RawMessage(`2`), Unsafe: json.RawMessage(`3`)}
	for i, k := range KindValues {
		d, err := m.doc(k)
		if err != nil || string(*d) != string(rune('1'+i)) {
			t.Errorf("%s = %v, %v", k, d, err)
		}
	}
	if _, err := m.doc("secret"); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("unknown kind: %v", err)
	}
}

// TestBound: each kind is held to its own bound.
func TestBound(t *testing.T) {
	p := New(WithMaxSize(10), WithUnsafeMaxSize(5))
	small, five, eleven := json.RawMessage(`{}`), json.RawMessage(`{"a":1}`)[:5], json.RawMessage(`{"a":"1234"}`)
	if err := p.bound(Metadata{Public: small, Private: small, Unsafe: five}); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]Metadata{
		"public":  {Public: eleven, Private: small, Unsafe: small},
		"private": {Public: small, Private: eleven, Unsafe: small},
		"unsafe":  {Public: small, Private: small, Unsafe: json.RawMessage(`{"a":1}`)},
	} {
		if err := p.bound(m); !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s over its bound: %v", name, err)
		}
	}
}
