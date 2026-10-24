package username_test

import (
	"testing"

	"github.com/ubgo/auth/plugin/username"
)

// FuzzValidateNeverLooksLikeAnotherKind: a handle Validate accepts never
// contains "@" and never starts with "+", so one sign-in field can always
// tell a handle from an address or a number.
func FuzzValidateNeverLooksLikeAnotherKind(f *testing.F) {
	for _, s := range []string{"ada", "a@b", "+1555", "Ada_1", "ädа"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		v, _ := username.Normalize(raw)
		if username.Validate(v) != nil {
			return
		}
		for _, r := range v {
			if r == '@' || r == '+' {
				t.Fatalf("handle %q contains %q", v, r)
			}
		}
		if again, _ := username.Normalize(v); again != v {
			t.Fatalf("not idempotent: %q then %q", v, again)
		}
	})
}
