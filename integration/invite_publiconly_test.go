package integration

import (
	"errors"
	"testing"

	"github.com/ubgo/auth/plugin/invite"
)

// TestInvite_PublicOnlyRefusesPrivateInvites: with invite.PublicOnly a
// create that names an address is refused with invite.ErrForbidden and
// stores nothing, while a public invite is created as before.
func TestInvite_PublicOnlyRefusesPrivateInvites(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw, iv := e.emailPlugin(), e.passwordPlugin(), invite.New(invite.PublicOnly())
		a := e.newAuth(t, nil, em, pw, iv)
		_, ctx := p3Inviter(t, a, "Ines")
		if _, err := iv.Create(ctx, invite.Request{Email: "guest@example.com"}); !errors.Is(err, invite.ErrForbidden) {
			t.Fatalf("private invite under PublicOnly: %v", err)
		}
		if n := p3Count(t, a, invite.TableInvite); n != 0 {
			t.Fatalf("a refused private invite left %d rows", n)
		}
		if cr := must[invite.Created](t)(iv.Create(ctx, invite.Request{MaxUses: 1})); cr.Token == "" {
			t.Fatalf("public invite = %+v", cr)
		}
	})
}
