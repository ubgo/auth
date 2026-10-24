package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/phone"
	"github.com/ubgo/auth/plugin/username"
)

// orgAddrUser creates a user holding one identity of kind, verified or not,
// and a signed-in request context for them.
func orgAddrUser(t *testing.T, a *auth.Auth, kind auth.IdentifierKindName, raw string, verified bool) (auth.User, context.Context) {
	t.Helper()
	ctx := context.Background()
	u := must[auth.User](t)(a.CreateUser(ctx, auth.NewUser{Name: raw}))
	if _, err := a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: kind, Raw: raw, Verified: verified, Primary: verified}); err != nil {
		t.Fatal(err)
	}
	_, tok, err := a.CreateSession(ctx, u.ID, auth.Client{})
	if err != nil {
		t.Fatal(err)
	}
	return u, request(a, tok)
}

// TestOrgAddress_PhoneOnlyAppInvitesByPhone: with InviteBy(phone) an app
// that has no email plugin wires the organization plugin, the invitation is
// texted through the phone plugin's Deliver, and only the user holding the
// VERIFIED phone identity sees and accepts it. An email address is refused.
func TestOrgAddress_PhoneOnlyAppInvitesByPhone(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		org := organization.New(organization.InviteBy(phone.KindPhone))
		a := e.newAuth(t, nil, e.phonePlugin(phone.Login(), phone.Multiple(), phone.SignInWithCode()), org)
		const number = "+14155550123"
		_, ownerCtx := orgAddrUser(t, a, phone.KindPhone, "+14155550100", true)
		o := must[organization.Org](t)(org.Create(ownerCtx, organization.CreateRequest{Name: "Acme", Slug: "acme-phone"}))

		// A user who holds the number unverified is not the invitee.
		_, squatterCtx := orgAddrUser(t, a, phone.KindPhone, number, false)
		before := e.sms.Count(a, number) // the squatter's verification code
		if err := org.Invite(ownerCtx, organization.InviteRequest{OrgID: o.ID, Identifier: number, Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		if n := e.sms.Count(a, number) - before; n != 1 {
			t.Fatalf("texts to the invitee: %d, want 1", n)
		}
		if list := must[[]organization.Invite](t)(org.Invites(squatterCtx)); len(list) != 0 {
			t.Fatalf("an unverified holder sees %+v", list)
		}

		invitee, inviteeCtx := orgAddrUser(t, a, phone.KindPhone, "+14155550199", true)
		if _, err := a.CreateIdentity(context.Background(), auth.NewIdentity{UserID: invitee.ID, Kind: phone.KindPhone, Raw: number, Verified: true}); err != nil {
			t.Fatal(err)
		}
		list := must[[]organization.Invite](t)(org.Invites(inviteeCtx))
		if len(list) != 1 || list[0].Kind != phone.KindPhone || list[0].Identifier != number || list[0].Email != "" {
			t.Fatalf("invitee sees %+v", list)
		}
		if _, err := org.Accept(inviteeCtx, list[0].ID); err != nil {
			t.Fatal(err)
		}
		if r := must[organization.Role](t)(org.RoleOf(context.Background(), o.ID, invitee.ID)); r != organization.RoleMember {
			t.Fatalf("role after accept: %q", r)
		}

		if err := org.Invite(ownerCtx, organization.InviteRequest{OrgID: o.ID, Email: "bob@example.com", Role: organization.RoleMember}); !errors.Is(err, organization.ErrInviteAddress) {
			t.Fatalf("email invite in a phone-only app: %v", err)
		}
		// Naming the person by an email and an identifier at once is
		// ambiguous, on invite and on remove-member alike.
		both := organization.InviteRequest{OrgID: o.ID, Email: "bob@example.com", Identifier: number, Role: organization.RoleMember}
		if err := org.Invite(ownerCtx, both); !errors.Is(err, organization.ErrInviteAddress) {
			t.Fatalf("invite naming an email and an identifier: %v", err)
		}
		if err := org.RemoveMember(ownerCtx, organization.MemberRequest{OrgID: o.ID, Email: "bob@example.com", Identifier: number}); !errors.Is(err, organization.ErrInviteAddress) {
			t.Fatalf("remove-member naming an email and an identifier: %v", err)
		}
		// remove-member names the member by the verified number too.
		if err := org.RemoveMember(ownerCtx, organization.MemberRequest{OrgID: o.ID, Kind: phone.KindPhone, Identifier: number}); err != nil {
			t.Fatal(err)
		}
		if _, err := org.RoleOf(context.Background(), o.ID, invitee.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("still a member: %v", err)
		}
	})
}

// TestOrgAddress_WithoutInvitations: a username-only app that adds members
// from the server registers the plugin with WithoutInvitations; no
// invitation route is mounted and AddMember works.
func TestOrgAddress_WithoutInvitations(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		org := organization.New(organization.WithoutInvitations())
		a := e.newAuth(t, nil, username.New(username.Login()), e.passwordPlugin(password.WithoutRecovery()), org)
		for _, id := range []auth.EndpointID{organization.EndpointInvite, organization.EndpointAccept, organization.EndpointInvites} {
			if _, ok := a.Operation(id); ok {
				t.Fatalf("%s is mounted without invitations", id)
			}
		}
		_, ownerCtx := orgAddrUser(t, a, username.KindUsername, "owner", true)
		o := must[organization.Org](t)(org.Create(ownerCtx, organization.CreateRequest{Name: "Acme", Slug: "acme-user"}))
		bob, _ := orgAddrUser(t, a, username.KindUsername, "bob", true)
		if err := org.AddMember(context.Background(), o.ID, bob.ID, organization.RoleMember); err != nil {
			t.Fatal(err)
		}
		if r := must[organization.Role](t)(org.RoleOf(context.Background(), o.ID, bob.ID)); r != organization.RoleMember {
			t.Fatalf("role: %q", r)
		}
	})
}
