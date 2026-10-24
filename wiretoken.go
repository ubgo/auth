package auth

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// tokenType and jsonMarshaler are the reflect types checkOutputTokens looks
// for: a Token is the defect, and a type with its own MarshalJSON decides its
// encoding itself, so the walk does not look inside it.
var (
	tokenType     = reflect.TypeFor[Token]()
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
)

// checkOutputTokens refuses an output type that carries a Token in a field
// JSON encoding writes.
//
// Why: Token.MarshalJSON writes "[redacted]" so a logged struct never leaks a
// secret, which means a Token in an operation's output answers that constant
// instead of the token the caller was meant to receive. That shipped twice
// (invite's created token and emailchallenge's poll token) before this check
// existed. A response field meant for the caller is a WireToken; a value that
// travels through an effect is tagged `json:"-"`.
//
// It walks exported fields the way encoding/json does: through pointers,
// slices, arrays, map values and embedded structs, skipping `json:"-"` and any
// type with its own MarshalJSON. An interface field is not followed, since its
// dynamic type is unknown here.
func checkOutputTokens(t reflect.Type) error {
	if path := findToken(t, "", map[reflect.Type]bool{}); path != "" {
		return fmt.Errorf("output field %s is an auth.Token, which JSON-encodes as %q; use auth.WireToken to hand it to the caller, or tag it `json:\"-\"`", path, redacted)
	}
	return nil
}

// findToken returns the dotted path of the first Token reachable from t, or
// "" when there is none. seen stops a recursive type from looping.
func findToken(t reflect.Type, path string, seen map[reflect.Type]bool) string {
	if t == tokenType {
		if path == "" {
			return "(the output itself)"
		}
		return path
	}
	if seen[t] || t.Implements(jsonMarshaler) || reflect.PointerTo(t).Implements(jsonMarshaler) {
		return ""
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return findToken(t.Elem(), path, seen)
	case reflect.Struct:
		for i := range t.NumField() {
			f := t.Field(i)
			if !f.IsExported() && !f.Anonymous {
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, _, _ := strings.Cut(tag, ",")
			next := path
			switch {
			case name == "" && f.Anonymous:
				// encoding/json lifts an untagged embedded struct's
				// fields into the outer object, so the path stays.
			case name == "":
				name = f.Name
				fallthrough
			default:
				next = joinPath(path, name)
			}
			if p := findToken(f.Type, next, seen); p != "" {
				return p
			}
		}
	}
	return ""
}

// joinPath appends a field's JSON name to a dotted path.
func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
