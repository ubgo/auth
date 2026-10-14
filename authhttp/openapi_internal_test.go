package authhttp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every shape the schema derivation must handle, in one type.
type kinds struct {
	Embedded
	Bool     bool            `json:"bool"`
	Int      int64           `json:"int"`
	Float    float64         `json:"float"`
	Str      string          `json:"str,omitempty"`
	When     time.Time       `json:"when"`
	Maybe    *string         `json:"maybe"`
	MaybeObj *Embedded       `json:"maybeObj"`
	List     []string        `json:"list"`
	Bytes    []byte          `json:"bytes"`
	Dict     map[string]int  `json:"dict"`
	Raw      json.RawMessage `json:"raw"`
	Any      any             `json:"any"`
	Nested   Embedded        `json:"nested"`
	Inline   struct{ X int } `json:"inline"`
	Self     *kinds          `json:"self"`
	Untagged int             `json:""`
	Dash     string          `json:"-"`
	hidden   string
	Array    [2]time.Duration  `json:"array"`
	Chan     map[string]func() `json:"chan"`
}

// Embedded is flattened into kinds, as encoding/json flattens it.
type Embedded struct {
	Inner string `json:"inner"`
}

// TestSchemaOf_EveryKind: the derivation mirrors what encoding/json writes.
func TestSchemaOf_EveryKind(t *testing.T) {
	b := &openAPIBuilder{schemas: map[string]any{}, building: map[string]bool{}}
	ref := b.schemaOf(reflect.TypeFor[kinds]())
	if ref["$ref"] != "#/components/schemas/authhttp.kinds" {
		t.Fatalf("ref = %v", ref)
	}
	s, _ := b.schemas["authhttp.kinds"].(openAPIDoc)
	props, _ := s["properties"].(openAPIDoc)
	want := map[string]string{
		"inner": `{"type":"string"}`, "bool": `{"type":"boolean"}`, "int": `{"type":"integer"}`, "float": `{"type":"number"}`,
		"str": `{"type":"string"}`, "when": `{"format":"date-time","type":"string"}`,
		"maybe":    `{"type":["string","null"]}`,
		"maybeObj": `{"oneOf":[{"$ref":"#/components/schemas/authhttp.Embedded"},{"type":"null"}]}`,
		"list":     `{"items":{"type":"string"},"type":"array"}`, "bytes": `{"contentEncoding":"base64","type":"string"}`,
		"dict": `{"additionalProperties":{"type":"integer"},"type":"object"}`,
		"raw":  `{}`, "any": `{}`, // RawMessage writes itself: any JSON
		"nested":   `{"$ref":"#/components/schemas/authhttp.Embedded"}`,
		"inline":   `{"properties":{"X":{"type":"integer"}},"required":["X"],"type":"object"}`,
		"self":     `{"oneOf":[{"$ref":"#/components/schemas/authhttp.kinds"},{"type":"null"}]}`,
		"Untagged": `{"type":"integer"}`,
		"array":    `{"items":{"type":"integer"},"type":"array"}`,
		"chan":     `{"additionalProperties":{},"type":"object"}`,
	}
	for name, w := range want {
		got, _ := json.Marshal(props[name])
		if string(got) != w {
			t.Errorf("%s = %s, want %s", name, got, w)
		}
	}
	if _, leaked := props["hidden"]; leaked || (kinds{}).hidden != "" {
		t.Error("an unexported field reached the schema")
	}
	if _, leaked := props["Dash"]; leaked {
		t.Error(`a json:"-" field reached the schema`)
	}
	req, _ := json.Marshal(s["required"])
	if string(req) != `["inner","bool","int","float","when","maybe","maybeObj","list","bytes","dict","raw","any","nested","inline","self","Untagged","array","chan"]` {
		t.Errorf("required = %s", req)
	}
	if len(b.building) != 0 {
		t.Fatal("a schema was left marked as building")
	}
	// Non-struct and nil inputs have no fields and an open schema.
	if got := jsonFields(reflect.TypeFor[int]()); got != nil {
		t.Fatalf("jsonFields(int) = %v", got)
	}
	if got := b.schemaOf(nil); got["type"] != "object" {
		t.Fatalf("schemaOf(nil) = %v", got)
	}
	if n := componentName(reflect.TypeFor[int]()); n != "int" {
		t.Fatalf("componentName(int) = %q", n)
	}
	// A query's parameters: one per field, strings, omitempty optional.
	params := b.queryParameters(reflect.TypeFor[struct {
		A string `json:"a"`
		B int    `json:"b,omitempty"`
	}]())
	got, _ := json.Marshal(params)
	if string(got) != `[{"in":"query","name":"a","required":true,"schema":{"type":"string"}},{"in":"query","name":"b","required":false,"schema":{"type":"string"}}]` {
		t.Fatalf("parameters = %s", got)
	}
}

// TestJSONFields_NilAndPointer: no type has no fields, and a pointer to a
// struct lists the struct's.
func TestJSONFields_NilAndPointer(t *testing.T) {
	if got := jsonFields(nil); got != nil {
		t.Fatalf("jsonFields(nil) = %v", got)
	}
	if got := jsonFields(reflect.TypeFor[*Embedded]()); len(got) != 1 || got[0].name != "inner" {
		t.Fatalf("jsonFields(*Embedded) = %v", got)
	}
}

// TestRequirementText_Unknown: a requirement the text does not know is
// written as its own name rather than hidden.
func TestRequirementText_Unknown(t *testing.T) {
	if got := requirementText("later"); got != "later" {
		t.Fatalf("requirementText = %q", got)
	}
}

// Shapes for encoding/json's field rules that kinds does not reach: a type
// embedded in itself, embedded non-structs, names shared at one depth and
// across depths, and `,string` on a pointer and on a kind it ignores.
type (
	jsonLoop struct {
		*jsonLoop
		Name string `json:"name"`
	}
	JSONWord     string
	jsonWordless string
	jsonQuiet    string
	jsonDeep     struct {
		Shadowed string `json:"shadowed"`
		Untagged string
	}
	jsonOther struct {
		Untagged string
		Winner   string `json:"Winner"`
	}
	jsonLoser struct {
		Winner string
	}
	jsonRules struct {
		jsonDeep
		jsonOther
		jsonLoser
		JSONWord
		jsonWordless `json:"-"`
		jsonQuiet
		*jsonLoop
		Shadowed string `json:"shadowed"`
		MaybeN   *int   `json:"maybeN,string"`
		Count    int    `json:"count,string"`
		List     []int  `json:"list,string"`
	}
)

// TestJSONFields_MatchTheEncoder: the fields the schema and the TypeScript
// type list are exactly the keys encoding/json writes for the same value,
// and a `,string` pointer is a nullable string while `,string` on a slice is
// ignored, as the encoder ignores it.
func TestJSONFields_MatchTheEncoder(t *testing.T) {
	n := 1
	v := jsonRules{jsonLoop: &jsonLoop{Name: "x"}, MaybeN: &n, List: []int{1}}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	fields := jsonFields(reflect.TypeFor[jsonRules]())
	got := map[string]bool{}
	for _, f := range fields {
		got[f.name] = true
	}
	for k := range keys {
		if !got[k] {
			t.Errorf("encoder writes %q, jsonFields lacks it", k)
		}
	}
	if len(got) != len(keys) {
		t.Fatalf("jsonFields = %v, encoder keys = %s", got, raw)
	}
	b := &openAPIBuilder{schemas: map[string]any{}, building: map[string]bool{}}
	b.schemaOf(reflect.TypeFor[jsonRules]())
	props, _ := b.schemas["authhttp.jsonRules"].(openAPIDoc)["properties"].(openAPIDoc)
	for name, want := range map[string]string{"maybeN": `{"type":["string","null"]}`, "count": `{"type":"string"}`, "list": `{"items":{"type":"integer"},"type":"array"}`} {
		if s, _ := json.Marshal(props[name]); string(s) != want {
			t.Errorf("%s = %s, want %s", name, s, want)
		}
	}
	tb := &tsBuilder{decls: map[string]string{}, owners: map[string]reflect.Type{}}
	tb.typeOf(reflect.TypeFor[jsonRules]())
	decl := tb.decls["AuthhttpJsonRules"]
	for _, want := range []string{"maybeN: string | null;", "list: number[] | null;", "Winner: string;", "JSONWord: string;", "shadowed: string;"} {
		if !strings.Contains(decl, want) {
			t.Errorf("TypeScript lacks %q:\n%s", want, decl)
		}
	}
}
