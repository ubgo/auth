package password

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// TestNew_RefusesLengthsNoPasswordPasses: a MaxLength under 1 or under
// MinLength, or a negative MinLength, fails auth.New naming the setting,
// instead of answering password.too_long to every sign-up. Found by the
// config edge test (integration/configedge_test.go).
func TestNew_RefusesLengthsNoPasswordPasses(t *testing.T) {
	for _, opts := range [][]Option{
		{MaxLength(0)},
		{MaxLength(-1)},
		{MinLength(-1)},
		{MinLength(20), MaxLength(10)},
	} {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, New(append(opts, Argon2(fast))...)))
		if !errors.Is(err, ErrBadLengths) {
			t.Fatalf("auth.New = %v, want ErrBadLengths", err)
		}
	}
	if _, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, New(MinLength(0), MaxLength(1), Argon2(fast)))); err != nil {
		t.Fatalf("the smallest legal lengths: %v", err)
	}
}

// TestNew_RefusesArgon2ParamsArgon2PanicsOn: Argon2 with a Time or Threads
// of 0 fails auth.New with ErrBadArgon2; before, argon2.IDKey panicked
// inside Init's dummy hash, so auth.New itself panicked.
func TestNew_RefusesArgon2ParamsArgon2PanicsOn(t *testing.T) {
	for _, p := range []Argon2Params{{}, {Memory: 64, Time: 0, Threads: 1}, {Memory: 64, Time: 1, Threads: 0}} {
		_, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(loginKind{recover: true}, New(Argon2(p))))
		if !errors.Is(err, ErrBadArgon2) {
			t.Fatalf("Argon2(%+v): auth.New = %v, want ErrBadArgon2", p, err)
		}
	}
	if _, err := (Argon2id{Params: Argon2Params{}}).Hash("pw"); !errors.Is(err, ErrBadArgon2) {
		t.Fatalf("Argon2id.Hash with zero params = %v, want ErrBadArgon2", err)
	}
}
