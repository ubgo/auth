package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
)

// errOrgGate is what a failing CreateGate returns.
var errOrgGate = errors.New("integration: plan lookup failed")

// TestOrgSwitch_CreateGateAndMaxOwned: the gate refuses by user, its error
// surfaces, and the ownership cap counts owner memberships; CreateFor from Go
// bypasses both.
func TestOrgSwitch_CreateGateAndMaxOwned(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var gateErr error
		gate := func(_ context.Context, u auth.User) (bool, error) { return u.Name != "Eve", gateErr }
		w := orgSetup(t, e, organization.CreateGate(gate), organization.MaxOwned(1))
		eve := must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "eve@example.com", Password: secret, Name: "Eve"}))
		if _, err := w.org.Create(request(w.a, eve.Token), organization.CreateRequest{Name: "Evil", Slug: "evil"}); !errors.Is(err, organization.ErrCreateForbidden) {
			t.Fatalf("gated user creates: %v", err)
		}
		if _, err := w.org.Create(request(w.a, w.owner.Token), organization.CreateRequest{Name: "Beta", Slug: "beta"}); !errors.Is(err, organization.ErrLimitReached) {
			t.Fatalf("second organization with MaxOwned(1): %v", err)
		}
		gateErr = errOrgGate
		if _, err := w.org.Create(request(w.a, w.owner.Token), organization.CreateRequest{Name: "Beta", Slug: "beta"}); !errors.Is(err, errOrgGate) {
			t.Fatalf("gate error: %v", err)
		}
		gateErr = nil
		// Trusted code is not gated or capped.
		o := must[organization.Org](t)(w.org.CreateFor(context.Background(), w.owner.User.ID, organization.CreateRequest{Name: "Beta", Slug: "Beta"}))
		if role, err := w.orgRole(t, w.owner.User.ID); err != nil || role != organization.RoleOwner || o.Slug != "beta" {
			t.Fatalf("CreateFor = %+v %v", o, err)
		}
		if _, err := w.org.CreateFor(context.Background(), "usr_doesnotexist", organization.CreateRequest{Name: "X", Slug: "x-org"}); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("CreateFor an unknown user: %v", err)
		}
		if got := count(t, e, organization.TableNameOrg); got != 2 {
			t.Fatalf("organizations = %d, want acme and beta", got)
		}
	})
}

// TestOrgSwitch_MaxMembersAndAddMember: the cap applies to accepting and to
// AddMember; an existing member keeps their role; AddMember validates its
// inputs.
func TestOrgSwitch_MaxMembersAndAddMember(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e, organization.MaxMembers(2))
		bob := w.orgUser(t, e, "bob@example.com")
		carol := w.orgUser(t, e, "carol@example.com")
		w.orgJoin(t, bob, "bob@example.com", organization.RoleMember)
		if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "carol@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatalf("inviting into a full organization is allowed: %v", err)
		}
		list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, carol.Token)))
		if _, err := w.org.Accept(request(w.a, carol.Token), list[0].ID); !errors.Is(err, organization.ErrMembersLimit) {
			t.Fatalf("accepting into a full organization: %v", err)
		}
		ctx := context.Background()
		if err := w.org.AddMember(ctx, w.o.ID, carol.User.ID, organization.RoleMember); !errors.Is(err, organization.ErrMembersLimit) {
			t.Fatalf("AddMember into a full organization: %v", err)
		}
		if err := w.org.AddMember(ctx, w.o.ID, bob.User.ID, organization.RoleOwner); err != nil {
			t.Fatal(err)
		}
		if role, _ := w.orgRole(t, bob.User.ID); role != organization.RoleMember {
			t.Fatalf("AddMember changed an existing member's role to %q", role)
		}
		if err := w.org.AddMember(ctx, w.o.ID, carol.User.ID, "root"); !errors.Is(err, organization.ErrBadRole) {
			t.Fatalf("AddMember with a bad role: %v", err)
		}
		if err := w.org.AddMember(ctx, "org_doesnotexist", carol.User.ID, organization.RoleMember); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("AddMember to an unknown organization: %v", err)
		}
		if err := w.org.AddMember(ctx, w.o.ID, "usr_doesnotexist", organization.RoleMember); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("AddMember of an unknown user: %v", err)
		}
		// The invitation is still pending: carol joins once there is room.
		if err := w.org.RemoveMember(request(w.a, w.owner.Token), organization.MemberRequest{OrgID: w.o.ID, UserID: bob.User.ID}); err != nil {
			t.Fatal(err)
		}
		must[organization.Org](t)(w.org.Accept(request(w.a, carol.Token), list[0].ID))
	})
}

// TestOrgSwitch_CheckSlugRoleAndInvitation covers the three new reads.
func TestOrgSwitch_CheckSlugRoleAndInvitation(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e)
		ctx := request(w.a, w.owner.Token)
		for in, want := range map[string]organization.SlugResult{
			" Acme ": {Slug: "acme", Available: false},
			"Beta":   {Slug: "beta", Available: true},
			"-bad":   {Slug: "-bad", Available: false},
		} {
			if got := must[organization.SlugResult](t)(w.org.CheckSlug(ctx, in)); got != want {
				t.Fatalf("CheckSlug(%q) = %+v, want %+v", in, got, want)
			}
		}
		if role := must[organization.Role](t)(w.org.Role(ctx, w.o.ID)); role != organization.RoleOwner {
			t.Fatalf("Role = %q", role)
		}
		carol := w.orgUser(t, e, "carol@example.com")
		if _, err := w.org.Role(request(w.a, carol.Token), w.o.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("stranger's role: %v", err)
		}
		bob := w.orgUser(t, e, "bob@example.com")
		if err := w.org.Invite(ctx, organization.InviteRequest{OrgID: w.o.ID, Email: "bob@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, bob.Token)))
		if inv := must[organization.Invite](t)(w.org.Invitation(request(w.a, bob.Token), list[0].ID)); inv != list[0] {
			t.Fatalf("Invitation = %+v, want %+v", inv, list[0])
		}
		if _, err := w.org.Invitation(request(w.a, carol.Token), list[0].ID); !errors.Is(err, organization.ErrInviteInvalid) {
			t.Fatalf("another user's invitation: %v", err)
		}
	})
}

// TestOrgSwitch_InviteReplaceLimitAndMessage: re-inviting replaces pending
// invitations when asked, the rate rule is configurable, and the mail is
// worded by the app.
func TestOrgSwitch_InviteReplaceLimitAndMessage(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		words := func(m organization.InviteMail) (string, string) {
			return m.Inviter.Name + " invited you to " + m.Org.Name, "Join as " + string(m.Invite.Role) + ": " + m.Link
		}
		w := orgSetup(t, e, organization.ReplacePendingInvites(), organization.InviteLimit(3, time.Hour), organization.InviteMessage(words))
		ctx := func() context.Context { return request(w.a, w.owner.Token) }
		invite := func(addr string) error {
			return w.org.Invite(ctx(), organization.InviteRequest{OrgID: w.o.ID, Email: addr, Role: organization.RoleMember})
		}
		if err := invite("bob@example.com"); err != nil {
			t.Fatal(err)
		}
		if err := invite("Bob@Example.com"); err != nil {
			t.Fatal(err)
		}
		if got := count(t, e, organization.TableNameInvite); got != 1 {
			t.Fatalf("pending invitations after re-invite = %d, want 1", got)
		}
		mail := e.mail.To(w.a, "bob@example.com")
		if last := mail[len(mail)-1]; last.Subject != "Alice invited you to Acme" || !strings.HasPrefix(last.Text, "Join as member: ") {
			t.Fatalf("mail = %q / %q", last.Subject, last.Text)
		}
		if err := invite("carol@example.com"); err != nil {
			t.Fatal(err)
		}
		if err := invite("dave@example.com"); !errors.Is(err, auth.ErrRateLimited) {
			t.Fatalf("fourth invite with InviteLimit(3): %v", err)
		}
	})
}

// TestOrgSwitch_InviteDefaultKeepsPending: without ReplacePendingInvites,
// each invite is another pending row.
func TestOrgSwitch_InviteDefaultKeepsPending(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e)
		for range 2 {
			if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "bob@example.com", Role: organization.RoleMember}); err != nil {
				t.Fatal(err)
			}
		}
		if got := count(t, e, organization.TableNameInvite); got != 2 {
			t.Fatalf("pending invitations by default = %d, want 2", got)
		}
	})
}

// TestOrgSwitch_MembersPagingAndRemoveByEmail: the members list pages with a
// total and a clamped limit; a member is removed by verified address.
func TestOrgSwitch_MembersPagingAndRemoveByEmail(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e)
		bob := w.orgUser(t, e, "bob@example.com")
		carol := w.orgUser(t, e, "carol@example.com")
		e.clock.Advance(time.Second) // joined-at order: alice, bob, carol
		w.orgJoin(t, bob, "bob@example.com", organization.RoleMember)
		e.clock.Advance(time.Second)
		w.orgJoin(t, carol, "carol@example.com", organization.RoleMember)
		ctx := request(w.a, w.owner.Token)
		op, _ := w.a.Operation(organization.EndpointMembers)
		page := func(p, limit int) organization.MembersResult {
			out, err := op.Invoke(ctx, func(dst any) error {
				*dst.(*organization.OrgRequest) = organization.OrgRequest{OrgID: w.o.ID, Page: p, Limit: limit} // the transport's decoder shape
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			return out.(organization.MembersResult)
		}
		first, second := page(1, 2), page(2, 2)
		if len(first.Members) != 2 || first.Total != 3 || first.Page != 1 || first.Limit != 2 {
			t.Fatalf("page 1 = %+v", first)
		}
		if len(second.Members) != 1 || second.Members[0].User.ID != carol.User.ID {
			t.Fatalf("page 2 = %+v", second)
		}
		if all := page(0, organization.MaxMembersPage+1); all.Limit != organization.MaxMembersPage || len(all.Members) != 3 {
			t.Fatalf("clamped = %+v", all)
		}
		if all := must[[]organization.MemberView](t)(w.org.Members(ctx, w.o.ID)); len(all) != 3 {
			t.Fatalf("Members from Go = %d rows, want the default page of 3", len(all))
		}

		remove := func(addr string) error {
			return w.org.RemoveMember(ctx, organization.MemberRequest{OrgID: w.o.ID, Email: addr})
		}
		if err := remove("nobody@example.com"); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("unknown address: %v", err)
		}
		if err := remove("not an address"); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("invalid address: %v", err)
		}
		if err := remove("Bob@Example.com"); err != nil {
			t.Fatal(err)
		}
		if _, err := w.orgRole(t, bob.User.ID); !errors.Is(err, organization.ErrNotMember) {
			t.Fatalf("bob after removal by email: %v", err)
		}
	})
}

// TestOrgSwitch_FaultsSurface sweeps the new database calls.
func TestOrgSwitch_FaultsSurface(t *testing.T) {
	cases := map[string]struct {
		opts []organization.Option
		op   func(t *testing.T, w *orgFaultWorld) func(context.Context) error
	}{
		"create-gated-capped": {[]organization.Option{organization.CreateGate(func(context.Context, auth.User) (bool, error) { return true, nil }), organization.MaxOwned(5)}, func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.org.Create(request(w.a, w.owner.Token), organization.CreateRequest{Name: "Beta", Slug: "beta"})
				return err
			}
		}},
		"accept-capped": {[]organization.Option{organization.MaxMembers(10)}, func(t *testing.T, w *orgFaultWorld) func(context.Context) error {
			dave := w.orgUser(t, w.env, "dave@example.com")
			if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember}); err != nil {
				t.Fatal(err)
			}
			list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, dave.Token)))
			return func(context.Context) error { _, err := w.org.Accept(request(w.a, dave.Token), list[0].ID); return err }
		}},
		"invite-replacing": {[]organization.Option{organization.ReplacePendingInvites()}, func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				return w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember})
			}
		}},
		"members-page": {nil, func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.org.Members(request(w.a, w.owner.Token), w.o.ID); return err }
		}},
		"remove-by-email": {nil, func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				return w.org.RemoveMember(request(w.a, w.owner.Token), organization.MemberRequest{OrgID: w.o.ID, Email: "carol@example.com"})
			}
		}},
		"check-slug": {nil, func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.org.CheckSlug(request(w.a, w.owner.Token), "beta")
				return err
			}
		}},
		"role": {nil, func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.org.Role(request(w.a, w.owner.Token), w.o.ID); return err }
		}},
		"invitation": {nil, func(t *testing.T, w *orgFaultWorld) func(context.Context) error {
			dave := w.orgUser(t, w.env, "dave@example.com")
			if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember}); err != nil {
				t.Fatal(err)
			}
			list := must[[]organization.Invite](t)(w.org.Invites(request(w.a, dave.Token)))
			return func(context.Context) error {
				_, err := w.org.Invitation(request(w.a, dave.Token), list[0].ID)
				return err
			}
		}},
		"add-member": {[]organization.Option{organization.MaxMembers(10)}, func(t *testing.T, w *orgFaultWorld) func(context.Context) error {
			dave := w.orgUser(t, w.env, "dave@example.com")
			return func(ctx context.Context) error {
				return w.org.AddMember(ctx, w.o.ID, dave.User.ID, organization.RoleMember)
			}
		}},
		"create-for": {nil, func(_ *testing.T, w *orgFaultWorld) func(context.Context) error {
			return func(ctx context.Context) error {
				_, err := w.org.CreateFor(ctx, w.owner.User.ID, organization.CreateRequest{Name: "Beta", Slug: "beta"})
				return err
			}
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
				w := &orgFaultWorld{orgWorld: orgSetup(t, e.env, tc.opts...), env: e.env}
				w.bob = w.orgUser(t, e.env, "bob@example.com")
				w.carol = w.orgUser(t, e.env, "carol@example.com")
				w.orgJoin(t, w.bob, "bob@example.com", organization.RoleOwner)
				w.orgJoin(t, w.carol, "carol@example.com", organization.RoleMember)
				return tc.op(t, w)
			})
		})
	}
}

// TestAdminSwitch_ListedAdmin builds the listed admin on one database.
func TestAdminSwitch_ListedAdmin(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		em, pw := e.emailPlugin(), e.passwordPlugin()
		// First instance: sign up both users with a plain plugin.
		seed := e.newAuth(t, nil, em, pw, admin.New())
		boss := signUpVerified(t, e, seed, pw, em)
		bob := must[password.SignInResult](t)(pw.SignUp(anon(seed), password.SignUpRequest{Identifier: "bob@example.com", Password: secret, Name: "Bob"}))
		carol := must[password.SignInResult](t)(pw.SignUp(anon(seed), password.SignUpRequest{Identifier: "carol@example.com", Password: secret, Name: "Carol"}))
		// Second instance on the same database, with bob listed.
		em2, pw2 := e.emailPlugin(), e.passwordPlugin()
		ad := admin.New(admin.AdminIDs(bob.User.ID), admin.DefaultBanReason("policy"), admin.ImpersonationTTL(30*time.Minute), admin.DefaultBanDuration(2*time.Hour))
		a := e.newAuth(t, nil, em2, pw2, ad)
		bobCtx := request(a, bob.Token)
		page := must[admin.UsersResult](t)(ad.Users(bobCtx, admin.UsersRequest{Query: bob.User.ID}))
		if len(page.Users) != 1 || !page.Users[0].Admin {
			t.Fatalf("listed admin lists users = %+v", page)
		}
		if err := ad.Grant(context.Background(), boss.User.ID); err != nil {
			t.Fatal(err)
		}
		if err := ad.Ban(request(a, boss.Token), bob.User.ID, "x"); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("banning a listed admin: %v", err)
		}
		if err := ad.RemoveUser(request(a, boss.Token), bob.User.ID); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("removing a listed admin: %v", err)
		}
		// Defaults: reason, duration and impersonation length.
		if err := ad.Ban(bobCtx, carol.User.ID, ""); err != nil {
			t.Fatal(err)
		}
		d := must[admin.UserDetail](t)(ad.User(bobCtx, carol.User.ID))
		if d.BanReason != "policy" || !d.User.Banned {
			t.Fatalf("ban with defaults = %+v", d)
		}
		e.clock.Advance(2*time.Hour + time.Minute)
		if d := must[admin.UserDetail](t)(ad.User(bobCtx, carol.User.ID)); d.User.Banned {
			t.Fatalf("ban past DefaultBanDuration still shows: %+v", d)
		}
		// The clock moved, so bob signs in again for the fresh-sign-in routes.
		bobFresh := request(a, must[password.SignInResult](t)(pw2.SignIn(anon(a), password.SignInRequest{Identifier: "bob@example.com", Password: secret})).Token)
		if err := ad.Unban(bobFresh, carol.User.ID); err != nil {
			t.Fatal(err)
		}
		as := must[admin.ImpersonateResult](t)(ad.Impersonate(bobFresh, admin.ImpersonateRequest{UserID: carol.User.ID}))
		if got := as.ExpiresAt.Sub(e.clock.Now()); got != 30*time.Minute {
			t.Fatalf("impersonation without minutes lasts %v, want ImpersonationTTL", got)
		}
	})
}

// TestAdminSwitch_TemporaryBan: a ban with minutes refuses sessions until it
// passes, then stops on its own; filters and the summary agree.
func TestAdminSwitch_TemporaryBan(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgAdminSetup(t, e)
		op, _ := w.a.Operation(admin.EndpointBan)
		if _, err := op.Invoke(w.orgBossCtx(), func(dst any) error {
			*dst.(*admin.BanRequest) = admin.BanRequest{UserID: w.bob.User.ID, Reason: "cooling off", Minutes: 10}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := w.a.ResolveSession(context.Background(), w.bob.Token); !errors.Is(err, auth.ErrSignedOut) {
			t.Fatalf("banned user's session: %v", err)
		}
		// During the ban a sign-in with the right password is refused with
		// the ban's code (the session hook); no new session comes to exist.
		if _, err := w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}); !errors.Is(err, admin.ErrBanned) {
			t.Fatalf("sign-in during the ban: %v", err)
		}
		banned := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Banned: admin.FlagTrue}))
		if banned.Total != 1 || banned.Users[0].ID != w.bob.User.ID || !banned.Users[0].Banned {
			t.Fatalf("banned filter during the ban = %+v", banned)
		}
		if _, err := w.ad.Impersonate(w.orgBossCtx(), admin.ImpersonateRequest{UserID: w.bob.User.ID}); !errors.Is(err, admin.ErrBannedTarget) {
			t.Fatalf("impersonating during the ban: %v", err)
		}

		e.clock.Advance(11 * time.Minute)
		again := must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}))
		if _, _, _, err := w.a.ResolveSession(context.Background(), again.Token); err != nil {
			t.Fatalf("session after the ban lapsed: %v", err)
		}
		if banned := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Banned: admin.FlagTrue})); banned.Total != 0 {
			t.Fatalf("banned filter after the ban lapsed = %+v", banned)
		}
		if free := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Banned: admin.FlagFalse})); free.Total != 2 {
			t.Fatalf("not-banned filter after the ban lapsed = %+v", free)
		}
		if d := must[admin.UserDetail](t)(w.ad.User(w.orgBossCtx(), w.bob.User.ID)); d.User.Banned || d.BanReason != "cooling off" {
			t.Fatalf("detail after the ban lapsed = %+v", d)
		}
		// Unban clears the dates even after the ban lapsed. The clock moved, so
		// the admin signs in again for a fresh session.
		bossFresh := request(w.a, must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: alice, Password: secret})).Token)
		if err := w.ad.Unban(bossFresh, w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		if d := must[admin.UserDetail](t)(w.ad.User(w.orgBossCtx(), w.bob.User.ID)); d.BanReason != "" {
			t.Fatalf("detail after unban = %+v", d)
		}
	})
}

// TestAdminSwitch_SortFilterOffset: the list sorts by the closed set, filters
// admins, pages by offset, and refuses anything else.
func TestAdminSwitch_SortFilterOffset(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgAdminSetup(t, e)
		e.clock.Advance(time.Second) // carol is created strictly after alice and bob
		must[password.SignInResult](t)(w.pw.SignUp(anon(w.a), password.SignUpRequest{Identifier: "carol@example.com", Password: secret, Name: "Carol"}))
		names := func(in admin.UsersRequest) []string {
			out := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), in))
			var ns []string
			for _, u := range out.Users {
				ns = append(ns, u.Name)
			}
			return ns
		}
		if got := names(admin.UsersRequest{Sort: admin.UserSortNameAsc}); strings.Join(got, ",") != "Alice,Bob,Carol" {
			t.Fatalf("name asc = %v", got)
		}
		if got := names(admin.UsersRequest{Sort: admin.UserSortNameDesc}); strings.Join(got, ",") != "Carol,Bob,Alice" {
			t.Fatalf("name desc = %v", got)
		}
		if got := names(admin.UsersRequest{Sort: admin.UserSortOldest}); got[2] != "Carol" {
			t.Fatalf("oldest first = %v", got)
		}
		if got := names(admin.UsersRequest{}); got[0] != "Carol" {
			t.Fatalf("default newest first = %v", got)
		}
		if _, err := w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Sort: "email"}); !errors.Is(err, admin.ErrBadSort) {
			t.Fatalf("unknown sort: %v", err)
		}
		if _, err := w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Admin: "yes"}); !errors.Is(err, admin.ErrBadFilter) {
			t.Fatalf("bad filter: %v", err)
		}
		admins := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Admin: admin.FlagTrue}))
		if admins.Total != 1 || admins.Users[0].ID != w.boss.User.ID {
			t.Fatalf("admins = %+v", admins)
		}
		if others := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Admin: admin.FlagFalse})); others.Total != 2 {
			t.Fatalf("non-admins = %+v", others)
		}
		off := must[admin.UsersResult](t)(w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Sort: admin.UserSortNameAsc, Limit: 1, Offset: 1}))
		if len(off.Users) != 1 || off.Users[0].Name != "Bob" || off.Offset != 1 || off.Page != 2 {
			t.Fatalf("offset page = %+v", off)
		}
	})
}

// TestAdminSwitch_UpdateSessionsRevokeRemove covers the four new routes.
func TestAdminSwitch_UpdateSessionsRevokeRemove(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgAdminSetup(t, e)
		name := "Robert"
		if err := w.ad.UpdateUser(w.orgBossCtx(), admin.UpdateUserRequest{UserID: w.bob.User.ID, Name: &name}); err != nil {
			t.Fatal(err)
		}
		if d := must[admin.UserDetail](t)(w.ad.User(w.orgBossCtx(), w.bob.User.ID)); d.User.Name != "Robert" {
			t.Fatalf("after update = %+v", d.User)
		}
		long := strings.Repeat("x", auth.MaxNameLength+1)
		if err := w.ad.UpdateUser(w.orgBossCtx(), admin.UpdateUserRequest{UserID: w.bob.User.ID, Name: &long}); !errors.Is(err, auth.ErrProfileInvalid) {
			t.Fatalf("too long a name: %v", err)
		}
		if err := w.ad.UpdateUser(request(w.a, w.bob.Token), admin.UpdateUserRequest{UserID: w.boss.User.ID, Name: &name}); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin updates: %v", err)
		}

		second := must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret}))
		sessions := must[[]auth.SessionView](t)(w.ad.Sessions(w.orgBossCtx(), w.bob.User.ID))
		if len(sessions) != 2 || sessions[0].Current || sessions[1].Current {
			t.Fatalf("sessions = %+v", sessions)
		}
		if _, err := w.ad.Sessions(w.orgBossCtx(), "usr_doesnotexist"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("sessions of an unknown user: %v", err)
		}
		if _, err := w.ad.Sessions(request(w.a, w.bob.Token), w.boss.User.ID); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin lists sessions: %v", err)
		}
		if err := w.ad.RevokeSession(w.orgBossCtx(), w.bob.User.ID, sessions[0].ID); err != nil {
			t.Fatal(err)
		}
		left := must[[]auth.SessionView](t)(w.ad.Sessions(w.orgBossCtx(), w.bob.User.ID))
		if len(left) != 1 || left[0].ID == sessions[0].ID {
			t.Fatalf("after revoking one = %+v", left)
		}
		if err := w.ad.RevokeSession(w.orgBossCtx(), "usr_doesnotexist", left[0].ID); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("revoke for an unknown user: %v", err)
		}
		if err := w.ad.RemoveUser(w.orgBossCtx(), w.boss.User.ID); !errors.Is(err, admin.ErrAdminTarget) {
			t.Fatalf("removing an admin: %v", err)
		}
		if err := w.ad.RemoveUser(w.orgBossCtx(), "usr_doesnotexist"); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("removing an unknown user: %v", err)
		}
		bobCtx := request(w.a, must[password.SignInResult](t)(w.pw.SignIn(anon(w.a), password.SignInRequest{Identifier: "bob@example.com", Password: secret})).Token)
		if err := w.ad.RemoveUser(bobCtx, w.boss.User.ID); !errors.Is(err, admin.ErrForbidden) {
			t.Fatalf("non-admin removes: %v", err)
		}
		if err := w.ad.RemoveUser(w.orgBossCtx(), w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := w.ad.User(w.orgBossCtx(), w.bob.User.ID); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("removed user: %v", err)
		}
		if _, _, _, err := w.a.ResolveSession(context.Background(), second.Token); err == nil {
			t.Fatal("a removed user's session must not resolve")
		}
	})
}

// TestAdminSwitch_FaultsSurface sweeps the new admin database calls.
func TestAdminSwitch_FaultsSurface(t *testing.T) {
	cases := map[string]func(t *testing.T, w *orgAdminWorld) func(context.Context) error{
		"ban-with-minutes": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			op, _ := w.a.Operation(admin.EndpointBan)
			return func(context.Context) error {
				_, err := op.Invoke(w.orgBossCtx(), func(dst any) error {
					*dst.(*admin.BanRequest) = admin.BanRequest{UserID: w.bob.User.ID, Minutes: 5}
					return nil
				})
				return err
			}
		},
		"users-filtered": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error {
				_, err := w.ad.Users(w.orgBossCtx(), admin.UsersRequest{Admin: admin.FlagFalse, Banned: admin.FlagFalse, Sort: admin.UserSortNameAsc, Offset: 1})
				return err
			}
		},
		"update-user": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			name := "Robert"
			return func(context.Context) error {
				return w.ad.UpdateUser(w.orgBossCtx(), admin.UpdateUserRequest{UserID: w.bob.User.ID, Name: &name})
			}
		},
		"sessions": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error { _, err := w.ad.Sessions(w.orgBossCtx(), w.bob.User.ID); return err }
		},
		"revoke-session": func(t *testing.T, w *orgAdminWorld) func(context.Context) error {
			list := must[[]auth.SessionView](t)(w.ad.Sessions(w.orgBossCtx(), w.bob.User.ID))
			return func(context.Context) error { return w.ad.RevokeSession(w.orgBossCtx(), w.bob.User.ID, list[0].ID) }
		},
		"remove-user": func(_ *testing.T, w *orgAdminWorld) func(context.Context) error {
			return func(context.Context) error { return w.ad.RemoveUser(w.orgBossCtx(), w.bob.User.ID) }
		},
	}
	for name, op := range cases {
		t.Run(name, func(t *testing.T) {
			sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error { return op(t, orgAdminSetup(t, e.env)) })
		})
	}
}
