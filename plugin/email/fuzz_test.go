package email_test

import (
	"testing"
	"unicode/utf8"

	"github.com/ubgo/auth/plugin/email"
)

// FuzzNormalizeIsIdempotent: normalizing twice gives the same value, so a
// stored value always finds itself, and Validate never panics.
func FuzzNormalizeIsIdempotent(f *testing.F) {
	for _, s := range []string{"Alice@Example.COM", " a@b.co ", "ÉMILE@x.fr", "@", "", "a@b@c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		once, err := email.Normalize(raw)
		if err != nil {
			return
		}
		twice, err := email.Normalize(once)
		if err != nil || twice != once {
			t.Fatalf("Normalize(%q) = %q, then %q (%v)", raw, once, twice, err)
		}
		if utf8.ValidString(raw) && !utf8.ValidString(once) {
			t.Fatalf("valid input %q normalized to invalid UTF-8", raw)
		}
		_ = email.Validate(once)
	})
}
