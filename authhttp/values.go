package authhttp

import (
	"encoding"
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// scalarKind is how a query or form value must be written in JSON for the
// field it lands in to decode it.
type scalarKind int

const (
	// scalarString is every field that decodes a JSON string: strings, and
	// numbers or bools tagged `,string`, and types with their own decoding.
	scalarString scalarKind = iota
	// scalarInt is a signed or unsigned integer field.
	scalarInt
	// scalarFloat is a float field.
	scalarFloat
	// scalarBool is a bool field.
	scalarBool
)

// Reflect types of the decoders that take over a field's decoding: a field
// whose type has one decides for itself, so its value stays a JSON string.
var (
	jsonUnmarshaler = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()
)

// scalarFields maps the JSON name of every number and bool field of t to its
// kind, following pointers and embedded structs as encoding/json does. A
// field tagged `,string` or `json:"-"`, and every other kind, is left out:
// it decodes a JSON string, which is what a value already is.
func scalarFields(t reflect.Type) map[string]scalarKind {
	out := map[string]scalarKind{}
	collectScalars(t, out, map[reflect.Type]bool{})
	return out
}

func collectScalars(t reflect.Type, out map[string]scalarKind, seen map[reflect.Type]bool) {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			collectScalars(f.Type, out, seen)
			continue
		}
		if name == "" {
			name = f.Name
		}
		if slices.Contains(strings.Split(opts, ","), "string") {
			continue
		}
		if k := kindOf(f.Type); k != scalarString {
			out[name] = k
		}
	}
}

// kindOf is the scalarKind of a field type, through one pointer.
func kindOf(t reflect.Type) scalarKind {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	pt := reflect.PointerTo(t)
	if pt.Implements(jsonUnmarshaler) || pt.Implements(textUnmarshaler) {
		return scalarString
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return scalarInt
	case reflect.Float32, reflect.Float64:
		return scalarFloat
	case reflect.Bool:
		return scalarBool
	}
	return scalarString
}

// fieldKind finds key's kind the way encoding/json matches keys: the exact
// name first, then a case-insensitive match.
func fieldKind(kinds map[string]scalarKind, key string) scalarKind {
	if k, ok := kinds[key]; ok {
		return k
	}
	for name, k := range kinds {
		if strings.EqualFold(name, key) {
			return k
		}
	}
	return scalarString
}

// valueJSON writes v as the JSON its field decodes. A value that does not
// parse as the field's kind stays a JSON string, so the decoder refuses it
// with the same bad-request error a malformed JSON body gets; it is never
// coerced into a zero.
func valueJSON(v string, k scalarKind) json.RawMessage {
	switch k {
	case scalarInt:
		// Re-formatted rather than copied, so "+5" and "007", which
		// strconv accepts and JSON does not, still decode.
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return json.RawMessage(strconv.FormatInt(n, 10))
		}
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return json.RawMessage(strconv.FormatUint(n, 10))
		}
	case scalarFloat:
		if f, err := strconv.ParseFloat(v, 64); err == nil && !math.IsInf(f, 0) && !math.IsNaN(f) {
			return json.RawMessage(strconv.FormatFloat(f, 'g', -1, 64))
		}
	case scalarBool:
		if b, err := strconv.ParseBool(v); err == nil {
			return json.RawMessage(strconv.FormatBool(b))
		}
	}
	// Marshalling a string cannot fail: encoding/json replaces invalid UTF-8.
	s, _ := json.Marshal(v)
	return s
}
