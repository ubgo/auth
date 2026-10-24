package organization

import (
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
)

// TestValidate_InviteKindMustDeliver: a kind registered by a plugin that
// cannot deliver (username) is refused at auth.New with
// auth.ErrNoDeliverer, instead of the first invite failing; a delivering
// kind beside it still wires.
func TestValidate_InviteKindMustDeliver(t *testing.T) {
	base := auth.WithBaseURL("https://app.example.com")
	ph := func() auth.Plugin { return phone.New(phone.WithSMS(nopSMS{})) }
	_, err := auth.New(base, auth.WithPlugins(signInStub{}, ph(), username.New(), New(InviteBy(phone.KindPhone, username.KindUsername))))
	if !errors.Is(err, auth.ErrNoDeliverer) {
		t.Fatalf("invite by username: %v, want ErrNoDeliverer", err)
	}
	if _, err := auth.New(base, auth.WithPlugins(signInStub{}, ph(), username.New(), New(InviteBy(phone.KindPhone)))); err != nil {
		t.Fatalf("invite by phone beside username: %v", err)
	}
}
