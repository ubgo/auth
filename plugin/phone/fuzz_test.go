package phone_test

import (
	"strings"
	"testing"

	"github.com/ubgo/auth/plugin/phone"
)

// FuzzNormalize: an accepted number is "+" and ASCII digits only, and
// normalizing it again changes nothing.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"+1 (555) 010-0100", "+44.20", "555", "+", "+١٢٣"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		v, err := phone.Normalize(raw)
		if err != nil {
			return
		}
		if !strings.HasPrefix(v, "+") || strings.Trim(v[1:], "0123456789") != "" {
			t.Fatalf("Normalize(%q) = %q, not + and digits", raw, v)
		}
		again, err := phone.Normalize(v)
		if err != nil || again != v {
			t.Fatalf("not idempotent: %q then %q (%v)", v, again, err)
		}
		_ = phone.Validate(v)
	})
}
