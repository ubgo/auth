package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/organization"
)

// p3OrgWant fails unless err is want.
func p3OrgWant(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

// TestP3Org_MembersFilterOperators: better-auth's filter operators on the
// members list. Text fragments keep case on every engine (SQLite included,
// where LIKE would not), LIKE syntax in a value is text, and the joined-at
// instant takes the order operators.
func TestP3Org_MembersFilterOperators(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		for id, name := range map[string]string{w.bob.User.ID: "Bob Stone", w.carol.User.ID: "carol 100%"} {
			if _, err := w.a.UpdateUser(context.Background(), id, auth.UserUpdate{Name: &name}); err != nil {
				t.Fatal(err)
			}
		}
		list := func(in organization.OrgRequest) organization.MembersResult {
			t.Helper()
			in.OrgID = w.o.ID
			return must[organization.MembersResult](t)(w.org.ListMembers(w.ownerCtx(), in))
		}
		text := func(op organization.FilterOperator, v string) int64 {
			t.Helper()
			return list(organization.OrgRequest{FilterField: organization.FieldName, FilterOperator: op, FilterValue: v}).Total
		}
		for _, c := range []struct {
			op   organization.FilterOperator
			v    string
			want int64
		}{
			{organization.OpContains, "Sto", 1}, {organization.OpContains, "sto", 0},
			{organization.OpStartsWith, "Ali", 1}, {organization.OpStartsWith, "ali", 0},
			{organization.OpEndsWith, "one", 1}, {organization.OpEndsWith, "ONE", 0},
			{organization.OpContains, "%", 1}, {organization.OpContains, "_", 0}, {organization.OpContains, "*", 0},
			{organization.OpNotIn, "Alice,Bob Stone", 1},
		} {
			if got := text(c.op, c.v); got != c.want {
				t.Errorf("name %s %q = %d, want %d", c.op, c.v, got, c.want)
			}
		}
		if got := list(organization.OrgRequest{FilterField: organization.FieldRole, FilterOperator: organization.OpNotIn, FilterValue: "owner,admin"}); got.Total != 1 || got.Members[0].User.ID != w.carol.User.ID {
			t.Fatalf("role not_in = %+v", got)
		}

		all := list(organization.OrgRequest{})
		var bobAt time.Time
		for _, m := range all.Members {
			if m.User.ID == w.bob.User.ID {
				bobAt = m.JoinedAt
			}
		}
		at := bobAt.UTC().Format(time.RFC3339Nano)
		for _, c := range []struct {
			f    organization.MemberField
			op   organization.FilterOperator
			want int64
		}{
			{organization.FieldJoinedAt, organization.OpEq, 1}, {organization.FieldCreatedAt, organization.OpNe, 2},
			{organization.FieldJoinedAt, organization.OpLt, 1}, {organization.FieldJoinedAt, organization.OpLte, 2},
			{organization.FieldCreatedAt, organization.OpGt, 1}, {organization.FieldCreatedAt, organization.OpGte, 2},
		} {
			if got := list(organization.OrgRequest{FilterField: c.f, FilterOperator: c.op, FilterValue: at}).Total; got != c.want {
				t.Errorf("%s %s bob's join = %d, want %d", c.f, c.op, got, c.want)
			}
		}
		for _, bad := range []organization.OrgRequest{
			{FilterField: organization.FieldJoinedAt, FilterValue: "yesterday"},
			{FilterField: organization.FieldJoinedAt, FilterOperator: organization.OpContains, FilterValue: at},
			{FilterField: organization.FieldName, FilterOperator: organization.OpGt, FilterValue: "A"},
		} {
			bad.OrgID = w.o.ID
			_, err := w.org.ListMembers(w.ownerCtx(), bad)
			p3OrgWant(t, "bad filter", err, organization.ErrBadQuery)
		}
	})
}

// TestP3Org_ResendAndRefuseRepeat: resend extends and re-mails the pending
// invitation instead of adding one; RefuseRepeatInvites makes a second
// invitation to the same address already_invited; the creator-role rule
// covers the resent invitation's own role.
func TestP3Org_ResendAndRefuseRepeat(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, organization.RefuseRepeatInvites())
		const dave = "dave@example.com"
		invite := func(ctx context.Context, role organization.Role, resend bool) error {
			return w.org.Invite(ctx, organization.InviteRequest{OrgID: w.o.ID, Email: dave, Role: role, Resend: resend})
		}
		pending := func() []organization.Invitation {
			t.Helper()
			var out []organization.Invitation
			for _, inv := range must[[]organization.Invitation](t)(w.org.ListInvitations(w.ownerCtx(), w.o.ID)) {
				if inv.Email == dave && inv.Status == organization.StatusPending {
					out = append(out, inv)
				}
			}
			return out
		}
		if err := invite(w.ownerCtx(), organization.RoleOwner, false); err != nil {
			t.Fatal(err)
		}
		first := pending()
		p3OrgWant(t, "second invite", invite(w.ownerCtx(), organization.RoleMember, false), organization.ErrAlreadyInvited)
		// bob is an admin: he may invite, but not resend an owner invitation.
		p3OrgWant(t, "admin resends an owner invitation", invite(w.as(w.bob), organization.RoleMember, true), organization.ErrForbidden)

		mails := len(e.mail.To(w.a, dave))
		e.clock.Advance(time.Hour)
		if err := invite(w.ownerCtx(), organization.RoleMember, true); err != nil {
			t.Fatal(err)
		}
		again := pending()
		if len(again) != 1 || again[0].ID != first[0].ID || again[0].Role != organization.RoleOwner || !again[0].ExpiresAt.Equal(first[0].ExpiresAt.Add(time.Hour)) {
			t.Fatalf("after resend = %+v, first = %+v", again, first)
		}
		if got := len(e.mail.To(w.a, dave)); got != mails+1 {
			t.Fatalf("mails after resend = %d, want %d", got, mails+1)
		}
		// Resend with nothing pending is an ordinary invitation.
		const erin = "erin@example.com"
		if err := w.org.Invite(w.ownerCtx(), organization.InviteRequest{OrgID: w.o.ID, Email: erin, Role: organization.RoleMember, Resend: true}); err != nil {
			t.Fatal(err)
		}
		if got := len(e.mail.To(w.a, erin)); got != 1 {
			t.Fatalf("erin's mails = %d", got)
		}

	})
}

// TestP3Org_ReplaceWinsOverRefuse: ReplacePendingInvites asks for the
// opposite of RefuseRepeatInvites, and wins.
func TestP3Org_ReplaceWinsOverRefuse(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := orgSetup(t, e, organization.RefuseRepeatInvites(), organization.ReplacePendingInvites())
		for range 2 {
			if err := w.org.Invite(request(w.a, w.owner.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "dave@example.com", Role: organization.RoleMember}); err != nil {
				t.Fatalf("replace wins over refuse: %v", err)
			}
		}
	})
}

// TestP3Org_PredefinedRoleAndActiveTeam: a configured role cannot be deleted
// or updated through the dynamic-role routes, and list-team-members without a
// team id reads the session's active team.
func TestP3Org_PredefinedRoleAndActiveTeam(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e, organization.DynamicRoles(organization.DynamicRolesConfig{}), organization.Teams(organization.TeamsConfig{}))
		err := w.org.DeleteRole(w.ownerCtx(), organization.RoleRequest{OrgID: w.o.ID, RoleName: organization.RoleAdmin})
		p3OrgWant(t, "delete admin", err, organization.ErrPredefinedRole)
		name := organization.Role("boss")
		_, err = w.org.UpdateRole(w.ownerCtx(), organization.UpdateRoleRequest{OrgID: w.o.ID, RoleName: organization.RoleOwner, Data: organization.RoleUpdate{RoleName: &name}})
		p3OrgWant(t, "update owner", err, organization.ErrPredefinedRole)
		// An unknown dynamic name is still not found, and a member without
		// ac:delete still cannot learn which names are configured.
		err = w.org.DeleteRole(w.ownerCtx(), organization.RoleRequest{OrgID: w.o.ID, RoleName: "nope"})
		p3OrgWant(t, "unknown role", err, organization.ErrRoleNotFound)
		err = w.org.DeleteRole(w.as(w.carol), organization.RoleRequest{OrgID: w.o.ID, RoleName: organization.RoleAdmin})
		p3OrgWant(t, "member deletes", err, organization.ErrForbidden)

		_, err = w.org.ListTeamMembers(w.ownerCtx(), "")
		p3OrgWant(t, "no active team", err, organization.ErrNoActiveTeam)
		teams := must[[]organization.Team](t)(w.org.ListUserTeams(w.ownerCtx()))
		if len(teams) != 1 {
			t.Fatalf("owner's teams = %+v", teams)
		}
		must[organization.ActiveResult](t)(w.org.SetActiveTeam(w.ownerCtx(), teams[0].ID))
		got := must[[]organization.TeamMember](t)(w.org.ListTeamMembers(w.ownerCtx(), ""))
		if len(got) != 1 || got[0].User.ID != w.owner.User.ID {
			t.Fatalf("active team's members = %+v", got)
		}
	})
}

// TestP3Org_PlatformAPI: the trusted Go API over every organization: list
// with counts and search, read, update, members, roles, removal,
// invitations and delete, with the last-owner rule still in force.
func TestP3Org_PlatformAPI(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		w := r30Setup(t, e)
		ctx := context.Background()
		e.clock.Advance(time.Second)
		beta := must[organization.Org](t)(w.org.CreateFor(ctx, w.bob.User.ID, organization.CreateRequest{Name: "Beta", Slug: "beta-co"}))

		all := must[organization.AllOrgsResult](t)(w.org.ListAll(ctx, organization.AllOrgsRequest{}))
		if all.Total != 2 || len(all.Orgs) != 2 || all.Orgs[0].ID != beta.ID || all.Orgs[0].MemberCount != 1 || all.Orgs[1].MemberCount != 3 {
			t.Fatalf("all = %+v", all)
		}
		if got := must[organization.AllOrgsResult](t)(w.org.ListAll(ctx, organization.AllOrgsRequest{Search: " BETA"})); got.Total != 1 || got.Orgs[0].ID != beta.ID {
			t.Fatalf("search = %+v", got)
		}
		if got := must[organization.AllOrgsResult](t)(w.org.ListAll(ctx, organization.AllOrgsRequest{Search: "%"})); got.Total != 0 {
			t.Fatalf("search %% = %+v", got)
		}
		if got := must[organization.AllOrgsResult](t)(w.org.ListAll(ctx, organization.AllOrgsRequest{Page: 2, Limit: 1})); got.Total != 2 || len(got.Orgs) != 1 || got.Orgs[0].ID != w.o.ID || got.Page != 2 {
			t.Fatalf("page 2 = %+v", got)
		}
		_, err := w.org.GetFor(ctx, "org_nope")
		p3OrgWant(t, "unknown org", err, organization.ErrNotMember)

		renamed := "Acme Two"
		o := must[organization.Org](t)(w.org.UpdateFor(ctx, w.o.ID, organization.OrgUpdate{Name: &renamed}))
		if o.Name != renamed || must[organization.Org](t)(w.org.GetFor(ctx, w.o.ID)).Name != renamed {
			t.Fatalf("update = %+v", o)
		}
		taken := "beta-co"
		_, err = w.org.UpdateFor(ctx, w.o.ID, organization.OrgUpdate{Slug: &taken})
		p3OrgWant(t, "slug taken", err, organization.ErrSlugTaken)

		members := must[organization.MembersResult](t)(w.org.MembersFor(ctx, organization.OrgRequest{OrgID: w.o.ID, FilterField: organization.FieldRole, FilterValue: "admin"}))
		if members.Total != 1 || members.Members[0].User.ID != w.bob.User.ID {
			t.Fatalf("members = %+v", members)
		}
		_, err = w.org.MembersFor(ctx, organization.OrgRequest{OrgID: "org_nope"})
		p3OrgWant(t, "members of unknown", err, organization.ErrNotMember)

		p3OrgWant(t, "demote the last owner", w.org.SetRoleFor(ctx, w.o.ID, w.owner.User.ID, organization.RoleMember), organization.ErrLastOwner)
		p3OrgWant(t, "remove the last owner", w.org.RemoveMemberFor(ctx, w.o.ID, w.owner.User.ID), organization.ErrLastOwner)
		p3OrgWant(t, "bad role", w.org.SetRoleFor(ctx, w.o.ID, w.carol.User.ID, "emperor"), organization.ErrBadRole)
		if err := w.org.SetRoleFor(ctx, w.o.ID, w.carol.User.ID, organization.RoleOwner); err != nil {
			t.Fatal(err)
		}
		if err := w.org.SetRoleFor(ctx, w.o.ID, w.owner.User.ID, organization.RoleMember); err != nil {
			t.Fatalf("demote with another owner: %v", err)
		}
		if err := w.org.RemoveMemberFor(ctx, w.o.ID, w.bob.User.ID); err != nil {
			t.Fatal(err)
		}
		_, err = w.org.RoleOf(ctx, w.o.ID, w.bob.User.ID)
		p3OrgWant(t, "removed", err, organization.ErrNotMember)
		p3OrgWant(t, "remove a stranger", w.org.RemoveMemberFor(ctx, w.o.ID, w.bob.User.ID), organization.ErrNotMember)

		if err := w.org.Invite(request(w.a, w.carol.Token), organization.InviteRequest{OrgID: w.o.ID, Email: "zed@example.com", Role: organization.RoleMember}); err != nil {
			t.Fatal(err)
		}
		owner := must[auth.User](t)(w.a.User(ctx, w.owner.User.ID))
		invs := must[[]organization.Invitation](t)(w.org.InvitationsFor(ctx, w.o.ID))
		if len(invs) != 3 || invs[0].Email != "zed@example.com" {
			t.Fatalf("invitations = %+v", invs)
		}
		_, err = w.org.InvitationsFor(ctx, "org_nope")
		p3OrgWant(t, "invitations of unknown", err, organization.ErrNotMember)
		if err := w.org.CancelFor(ctx, invs[0].ID, owner); err != nil {
			t.Fatal(err)
		}
		p3OrgWant(t, "cancel twice", w.org.CancelFor(ctx, invs[0].ID, owner), organization.ErrInviteInvalid)
		p3OrgWant(t, "cancel accepted", w.org.CancelFor(ctx, invs[1].ID, owner), organization.ErrInviteInvalid)
		p3OrgWant(t, "cancel unknown", w.org.CancelFor(ctx, "inv_nope", owner), organization.ErrInviteInvalid)

		if err := w.org.DeleteFor(ctx, beta.ID); err != nil {
			t.Fatal(err)
		}
		p3OrgWant(t, "delete twice", w.org.DeleteFor(ctx, beta.ID), organization.ErrNotMember)
		if got := must[organization.AllOrgsResult](t)(w.org.ListAll(ctx, organization.AllOrgsRequest{})); got.Total != 1 {
			t.Fatalf("after delete = %+v", got)
		}
	})
}
