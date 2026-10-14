package authhttp

import (
	"reflect"
	"testing"
)

// The naming and quoting helpers: what an id, a property name and a string
// become in TypeScript, for the inputs the golden plugin does not reach.
func TestTypeScript_Names(t *testing.T) {
	for in, want := range map[string]string{"sign-in": "signIn", "get_client": "getClient", "2fa": "_2fa", "--": "_", "a.b-c": "aBC"} {
		if got := tsCamel(in); got != want {
			t.Errorf("tsCamel(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		`plain`: `"plain"`, `say "hi"`: `"say \"hi\""`, `back\slash`: `"back\\slash"`,
		"line\nbreak": `"line\nbreak"`, "tab\there": `"tab\u0009here"`, "sep\u2028": `"sep\u2028"`,
	} {
		if got := tsString(in); got != want {
			t.Errorf("tsString(%q) = %s, want %s", in, got, want)
		}
	}
	if tsNullable("unknown") != "unknown" || tsNullable("string | null") != "string | null" || tsNullable("number") != "number | null" {
		t.Error("tsNullable adds null once, and never to unknown")
	}
}

// Kinds the golden plugin does not use: a byte array, a channel (which
// encoding/json cannot write), a nil type.
func TestTypeScript_TypeOfEdges(t *testing.T) {
	b := &tsBuilder{decls: map[string]string{}, owners: map[string]reflect.Type{}}
	for typ, want := range map[reflect.Type]string{
		reflect.TypeFor[[4]byte]():         "string",
		reflect.TypeFor[[]byte]():          "string | null",
		reflect.TypeFor[chan int]():        "unknown",
		reflect.TypeFor[*[]string]():       "string[] | null",
		reflect.TypeFor[map[string]bool](): "{ [key: string]: boolean } | null",
	} {
		if got := b.typeOf(typ); got != want {
			t.Errorf("typeOf(%v) = %q, want %q", typ, got, want)
		}
	}
	if got := b.typeOf(nil); got != tsEmpty {
		t.Errorf("typeOf(nil) = %q", got)
	}
}
