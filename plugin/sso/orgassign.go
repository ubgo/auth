package sso

import (
	"context"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/oauth"
)

// InvitationChecker is an optional Organizations upgrade: an organization
// system that knows pending invitations implements it, and joining at
// sign-in then leaves a user with a pending invitation to accept it, as
// better-auth does, so the invited role is not overwritten by the default.
type InvitationChecker interface {
	PendingInvitation(ctx context.Context, orgID, userID string) (bool, error)
}

// Assignment is the outcome of AssignByVerifiedDomain, better-auth's
// organization-assignment outcomes.
type Assignment string

const (
	AssignAssigned          Assignment = "assigned"
	AssignAlreadyMember     Assignment = "already-member"
	AssignAmbiguous         Assignment = "ambiguous-target"
	AssignIneligibleSource  Assignment = "ineligible-source"
	AssignInvitationPending Assignment = "invitation-pending"
	AssignNoTarget          Assignment = "no-target"
	AssignDisabled          Assignment = "provisioning-disabled"
	AssignUnverified        Assignment = "unverified-identity"
)

// AssignmentValues is every Assignment.
var AssignmentValues = []Assignment{AssignAssigned, AssignAlreadyMember, AssignAmbiguous, AssignIneligibleSource,
	AssignInvitationPending, AssignNoTarget, AssignDisabled, AssignUnverified}

// AssignByVerifiedDomain adds a user who signed in some other way (social
// OAuth, a password) to the organization whose domain-verified provider
// covers their verified email: exactly one such organization, or nothing.
// An unverified address never assigns, since anyone can type one.
func (p *Plugin) AssignByVerifiedDomain(ctx context.Context, userID, email string, emailVerified bool) (Assignment, error) {
	switch {
	case p.orgs == nil || p.orgProvisioning.Disabled:
		return AssignDisabled, nil
	case email == "" || !emailVerified:
		return AssignUnverified, nil
	}
	all, err := p.providersWhere(ctx)
	if err != nil {
		return "", err
	}
	orgs := map[string]Provider{}
	for _, pr := range append(append([]Provider{}, p.defaults...), all...) {
		if pr.OrganizationID != "" && (pr.Default || pr.DomainVerified) && DomainMatches(pr.Domains(), emailDomain(email)) {
			orgs[pr.OrganizationID] = pr
		}
	}
	switch len(orgs) {
	case 0:
		return AssignNoTarget, nil
	case 1:
	default:
		return AssignAmbiguous, nil
	}
	var orgID string
	for id := range orgs { // the one entry
		orgID = id
	}
	return p.join(ctx, ProvisionEvent{User: auth.User{ID: userID}, Info: UserInfo{Email: email, EmailVerified: true}, Provider: orgs[orgID]}, orgID)
}

// OAuthAssignment is AssignByVerifiedDomain as a plugin/oauth hook: pass
// it to oauth.OnResolved and a social sign-in with a verified address in a
// verified domain joins that domain's organization. A link flow is not a
// sign-in and is left alone.
func (p *Plugin) OAuthAssignment() oauth.ResolvedHook {
	return func(ctx context.Context, _ *auth.Call, ev oauth.ResolvedEvent) error {
		_, err := p.AssignOAuth(ctx, ev)
		return err
	}
}

// AssignOAuth is the assignment of one plugin/oauth sign-in: a link flow
// or a provider-initiated sign-in (nothing ties it to a person of this
// app) is AssignIneligibleSource; anything else AssignByVerifiedDomain.
func (p *Plugin) AssignOAuth(ctx context.Context, ev oauth.ResolvedEvent) (Assignment, error) {
	if ev.Linked || ev.ProviderInitiated {
		return AssignIneligibleSource, nil
	}
	return p.AssignByVerifiedDomain(ctx, ev.UserID, ev.Profile.Email, ev.Profile.EmailVerified)
}

// join adds the user to orgID unless they are a member or have a pending
// invitation.
func (p *Plugin) join(ctx context.Context, ev ProvisionEvent, orgID string) (Assignment, error) {
	_, member, err := p.orgs.Role(ctx, orgID, ev.User.ID)
	if err != nil {
		return "", err
	}
	if member {
		return AssignAlreadyMember, nil
	}
	if ic, ok := p.orgs.(InvitationChecker); ok {
		pending, err := ic.PendingInvitation(ctx, orgID, ev.User.ID)
		if err != nil {
			return "", err
		}
		if pending {
			return AssignInvitationPending, nil
		}
	}
	role := firstOf(p.orgProvisioning.DefaultRole, RoleMember)
	if p.orgProvisioning.Role != nil {
		if role, err = p.orgProvisioning.Role(ctx, ev); err != nil {
			return "", err
		}
	}
	return AssignAssigned, p.orgs.AddMember(ctx, orgID, ev.User.ID, role)
}
