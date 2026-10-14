package organization

import (
	"context"

	"github.com/ubgo/auth"
)

// Hooks are the organization lifecycle hooks, better-auth's
// organizationHooks: every one is optional and runs inside the operation's
// transaction. A Before hook may change the row it is given (a pointer) or
// refuse with an error, which becomes the operation's error; an After hook's
// error fails the operation and rolls everything back.
//
// What a Before hook changes is checked again: a slug or a role it sets
// must pass the same rules as the request's, and the fields the checks were
// made for (ids, the invited address) are restored, so a hook can shape a
// row but never move it past an authorization check.
//
// A hook writes the app's own rows in the same transaction through the
// *auth.Auth: a.Conn(ctx) is that transaction, so pass WithHooksFrom, whose
// builder receives a, rather than WithHooks. The same ctx is the one to pass
// to any other library call the hook makes, which then joins it too.
//
// auth.OperationHook still works on every operation id; these hooks add the
// typed row and the power to change it.
type Hooks struct {
	BeforeCreateOrg func(ctx context.Context, org *Org, creator auth.User) error
	AfterCreateOrg  func(ctx context.Context, org Org, creator auth.User) error
	BeforeUpdateOrg func(ctx context.Context, old Org, org *Org) error
	AfterUpdateOrg  func(ctx context.Context, org Org) error
	BeforeDeleteOrg func(ctx context.Context, org Org) error
	AfterDeleteOrg  func(ctx context.Context, org Org) error

	// BeforeAddMember runs when someone joins (an accepted invitation,
	// AddMember), not for the creator, who joins in BeforeCreateOrg's
	// operation.
	BeforeAddMember        func(ctx context.Context, m *MemberChange) error
	AfterAddMember         func(ctx context.Context, m MemberChange) error
	BeforeRemoveMember     func(ctx context.Context, m MemberChange) error
	AfterRemoveMember      func(ctx context.Context, m MemberChange) error
	BeforeUpdateMemberRole func(ctx context.Context, m *MemberChange, old Role) error
	AfterUpdateMemberRole  func(ctx context.Context, m MemberChange, old Role) error

	// BeforeCreateInvitation may change the role, team and expiry.
	BeforeCreateInvitation func(ctx context.Context, inv *Invitation, inviter auth.User) error
	AfterCreateInvitation  func(ctx context.Context, inv Invitation, inviter auth.User) error
	BeforeAcceptInvitation func(ctx context.Context, inv Invitation, user auth.User) error
	AfterAcceptInvitation  func(ctx context.Context, inv Invitation, user auth.User) error
	BeforeRejectInvitation func(ctx context.Context, inv Invitation, user auth.User) error
	AfterRejectInvitation  func(ctx context.Context, inv Invitation, user auth.User) error
	BeforeCancelInvitation func(ctx context.Context, inv Invitation, by auth.User) error
	AfterCancelInvitation  func(ctx context.Context, inv Invitation, by auth.User) error

	BeforeCreateTeam       func(ctx context.Context, team *Team) error
	AfterCreateTeam        func(ctx context.Context, team Team) error
	BeforeUpdateTeam       func(ctx context.Context, old Team, team *Team) error
	AfterUpdateTeam        func(ctx context.Context, team Team) error
	BeforeDeleteTeam       func(ctx context.Context, team Team) error
	AfterDeleteTeam        func(ctx context.Context, team Team) error
	BeforeAddTeamMember    func(ctx context.Context, m TeamMemberChange) error
	AfterAddTeamMember     func(ctx context.Context, m TeamMemberChange) error
	BeforeRemoveTeamMember func(ctx context.Context, m TeamMemberChange) error
	AfterRemoveTeamMember  func(ctx context.Context, m TeamMemberChange) error
}

// MemberChange is a membership a member hook sees: who, where, and the role
// they get (add, update) or hold (remove).
type MemberChange struct {
	OrgID  string
	UserID string
	Role   Role
	// Fields are the member's extra columns on add; a BeforeAddMember hook
	// may set them, ServerOnly ones included.
	Fields auth.Fields
}

// TeamMemberChange is a team membership a team member hook sees.
type TeamMemberChange struct {
	OrgID  string
	TeamID string
	UserID string
}
