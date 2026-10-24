package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

func TestStuffingGuard_ValidateRefusesNegativesAndNoSecret(t *testing.T) {
	withSecret := auth.Config{}
	for _, pol := range []StuffingPolicy{{PasswordFailures: -1}, {GlobalFailures: -1}, {Window: -1}} {
		g := &stuffingGuard{pol: pol}
		if err := g.validate(&withSecret); !errors.Is(err, auth.ErrBadOperation) {
			t.Fatalf("%+v: %v, want ErrBadOperation", pol, err)
		}
	}
	if err := (&stuffingGuard{}).validate(&withSecret); !errors.Is(err, auth.ErrNoSecret) {
		t.Fatalf("no secret: %v, want ErrNoSecret", err)
	}
}

func TestStuffingGuard_PasswordKeyIsKeyedAndHidesThePassword(t *testing.T) {
	a := &stuffingGuard{key: []byte(strings.Repeat("a", 32))}
	b := &stuffingGuard{key: []byte(strings.Repeat("b", 32))}
	k := a.passwordKey("Summer2026!")
	if strings.Contains(k, "Summer2026") || !strings.HasPrefix(k, stuffingPasswordKey) {
		t.Fatalf("key %q", k)
	}
	if k != a.passwordKey("Summer2026!") || k == a.passwordKey("Summer2026?") || k == b.passwordKey("Summer2026!") {
		t.Fatal("the key must depend on the password and the secret only")
	}
}
