package organization

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/phone"
)

type nopSMS struct{}

func (nopSMS) Send(context.Context, string, string) error { return nil }

// TestRequires_EmailOnlyWhenInvitingByEmail: the default requires the email
// plugin; InviteBy without email and WithoutInvitations require nothing.
func TestRequires_EmailOnlyWhenInvitingByEmail(t *testing.T) {
	if got := New().Requires(); !slices.Equal(got, []string{email.PluginName}) {
		t.Fatalf("default requires %v", got)
	}
	if got := New(InviteBy(phone.KindPhone, email.KindEmail)).Requires(); !slices.Equal(got, []string{email.PluginName}) {
		t.Fatalf("phone and email requires %v", got)
	}
	if got := New(InviteBy(phone.KindPhone)).Requires(); got != nil {
		t.Fatalf("phone only requires %v", got)
	}
	if got := New(WithoutInvitations()).Requires(); got != nil {
		t.Fatalf("without invitations requires %v", got)
	}
}

// TestValidate_InviteKinds: a kind no plugin registers and an empty InviteBy
// are refused at start-up; a phone-only app and an app without invitations
// (no BaseURL, no identifier plugin) wire.
func TestValidate_InviteKinds(t *testing.T) {
	ph := func() auth.Plugin { return phone.New(phone.WithSMS(nopSMS{})) }
	base := auth.WithBaseURL("https://app.example.com")
	if _, err := auth.New(base, auth.WithPlugins(signInStub{}, New(InviteBy(phone.KindPhone)))); err == nil || !strings.Contains(err.Error(), `"phone", which no plugin registers`) {
		t.Fatalf("unregistered kind: %v", err)
	}
	if _, err := auth.New(base, auth.WithPlugins(signInStub{}, ph(), New(InviteBy()))); err == nil || !strings.Contains(err.Error(), "at least one identifier kind") {
		t.Fatalf("no kinds: %v", err)
	}
	if _, err := auth.New(base, auth.WithPlugins(signInStub{}, ph(), New(InviteBy(phone.KindPhone)))); err != nil {
		t.Fatalf("phone-only: %v", err)
	}
	p := New(WithoutInvitations())
	a, err := auth.New(auth.WithPlugins(signInStub{}, p))
	if err != nil {
		t.Fatalf("without invitations: %v", err)
	}
	if _, ok := a.Operation(EndpointInvite); ok || len(p.RateLimits()) != 0 {
		t.Fatal("invite is mounted without invitations")
	}
	if len(New().Operations())-len(p.Operations()) != 7 {
		t.Fatalf("operations: %d vs %d", len(New().Operations()), len(p.Operations()))
	}
}

// TestAddressOf: Email is the email kind and cannot be combined with another
// address; an Identifier without a Kind is InviteBy's first kind, and is
// ambiguous with several.
func TestAddressOf(t *testing.T) {
	one := New(InviteBy(phone.KindPhone))
	two := New(InviteBy(email.KindEmail, phone.KindPhone))
	for _, c := range []struct {
		name       string
		p          *Plugin
		mail, raw  string
		kind, want auth.IdentifierKindName
		err        error
	}{
		{"email field", two, "a@x.com", "", "", email.KindEmail, nil},
		{"email field naming its kind", two, "a@x.com", "", email.KindEmail, email.KindEmail, nil},
		{"email and identifier", two, "a@x.com", "+1", "", "", ErrInviteAddress},
		{"email with another kind", two, "a@x.com", "", phone.KindPhone, "", ErrInviteAddress},
		{"identifier, one kind", one, "", "+1", "", phone.KindPhone, nil},
		{"identifier, several kinds", two, "", "+1", "", "", ErrInviteAddress},
		{"identifier with kind", two, "", "+1", phone.KindPhone, phone.KindPhone, nil},
		{"nothing", two, "", "", "", email.KindEmail, nil},
	} {
		kind, _, err := c.p.addressOf(c.mail, c.kind, c.raw)
		if !errors.Is(err, c.err) || (c.err == nil && kind != c.want) {
			t.Errorf("%s: kind %q err %v", c.name, kind, err)
		}
	}
	none := New(WithoutInvitations())
	if k, _, err := none.memberAddress(MemberRequest{Identifier: "a@x.com"}); err != nil || k != email.KindEmail {
		t.Fatalf("member address without invitations: %q %v", k, err)
	}
	if k, _, err := two.memberAddress(MemberRequest{Kind: phone.KindPhone, Identifier: "+1"}); err != nil || k != phone.KindPhone {
		t.Fatalf("member address by kind: %q %v", k, err)
	}
	if _, _, err := two.memberAddress(MemberRequest{Email: "a@x.com", Identifier: "+1"}); !errors.Is(err, ErrInviteAddress) {
		t.Fatalf("member named twice: %v", err)
	}
}
