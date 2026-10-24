// Package organization adds workspaces and membership to the auth core.
//
// Unlike the phone and username plugins this one owns real tables, because a
// workspace is not a way of naming a user — it is a separate entity with its
// own lifecycle. It is also the plugin that demonstrates the join a plugin
// makes back INTO the core: a member list is meaningless without the email
// address that lives on auth_user.
//
// # Why the invite lookup is the important code here
//
// The published account-takeover advisories in comparable auth libraries are
// overwhelmingly invitation bugs: an invitation addressed to an email is
// matched against an identity the claimant never proved they own. The fix is
// one predicate, and it is applied in PendingInvitesQuery below.
package organization

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// PluginName is the stable identity of this plugin.
const PluginName = "organization"

// Table names owned by this plugin.
const (
	TableNameOrg    = "auth_org"
	TableNameMember = "auth_org_member"
	TableNameInvite = "auth_org_invite"
	// TableNameTeam and TableNameTeamMember hold teams, created only with
	// the Teams option.
	TableNameTeam       = "auth_org_team"
	TableNameTeamMember = "auth_org_team_member"
	// TableNameRole holds roles created at run time per organization,
	// created only with the DynamicRoles option.
	TableNameRole = "auth_org_role"
	// TableNameActive holds each session's active organization and team.
	// Keyed by session id rather than a column on auth_session, so it works
	// with every session store, as plugin/sessiondata does.
	TableNameActive = "auth_org_active"
)

// Table aliases owned by this plugin. None may collide with the core's
// reserved aliases or another plugin's; auth.New rejects a collision at wire
// time rather than letting it surface as an ambiguous column at query time.
const (
	TableAliasOrg        = "og"
	TableAliasMember     = "om"
	TableAliasInvite     = "oi"
	TableAliasIdentity   = "oid"
	TableAliasTeam       = "ot"
	TableAliasTeamMember = "otm"
	TableAliasRole       = "orl"
	TableAliasActive     = "oa"
)

// Column names on auth_org.
const (
	ColOrgID        = "id"
	ColOrgSlug      = "slug"
	ColOrgName      = "name"
	ColOrgCreatedAt = "created_at"
	ColOrgLogo      = "logo"
	ColOrgMetadata  = "metadata"
)

// Column names on auth_org_member.
const (
	ColMemberOrgID    = "org_id"
	ColMemberUserID   = "user_id"
	ColMemberRole     = "role"
	ColMemberJoinedAt = "joined_at"
)

// Column names on auth_org_invite.
const (
	ColInviteID    = "id"
	ColInviteOrgID = "org_id"
	// ColInviteEmail holds the invited address when the invitation is
	// addressed by email, and "" for any other kind: the email field, kept
	// so a reader of email invitations needs no change.
	ColInviteEmail = "email"
	// ColInviteKind and ColInviteIdentifier address the invitation for every
	// kind (InviteBy): the identifier kind and its normalized value. They are
	// the pair PendingInvitesQuery matches against a verified identity; for
	// an email invitation ColInviteIdentifier equals ColInviteEmail.
	ColInviteKind       = "identifier_kind"
	ColInviteIdentifier = "identifier"
	ColInviteRole       = "role"
	ColInviteInvitedBy  = "invited_by"
	ColInviteExpiresAt  = "expires_at"
	ColInviteAccepted   = "accepted_at"
	ColInviteCreatedAt  = "created_at"
	ColInviteStatus     = "status"
	ColInviteTeamID     = "team_id"
)

// Column names on auth_org_team.
const (
	ColTeamID        = "id"
	ColTeamOrgID     = "org_id"
	ColTeamName      = "name"
	ColTeamCreatedAt = "created_at"
	ColTeamUpdatedAt = "updated_at"
)

// Column names on auth_org_team_member.
const (
	ColTeamMemberTeamID    = "team_id"
	ColTeamMemberUserID    = "user_id"
	ColTeamMemberCreatedAt = "created_at"
)

// Column names on auth_org_role.
const (
	ColRoleID         = "id"
	ColRoleOrgID      = "org_id"
	ColRoleName       = "role"
	ColRolePermission = "permission"
	ColRoleCreatedAt  = "created_at"
	ColRoleUpdatedAt  = "updated_at"
)

// Column names on auth_org_active.
const (
	ColActiveSessionID = "session_id"
	ColActiveUserID    = "user_id"
	ColActiveOrgID     = "org_id"
	ColActiveTeamID    = "team_id"
	ColActiveExpiresAt = "expires_at"
)

// InviteStatus is where an invitation is in its life. Stored on the row, so
// an admin's list shows what became of every invitation.
type InviteStatus string

// Invitation states.
const (
	StatusPending  InviteStatus = "pending"
	StatusAccepted InviteStatus = "accepted"
	StatusRejected InviteStatus = "rejected"
	StatusCanceled InviteStatus = "canceled"
)

// InviteStatusValues is the canonical list of invitation states.
var InviteStatusValues = []InviteStatus{StatusPending, StatusAccepted, StatusRejected, StatusCanceled}

// Role is a membership role. A named type rather than a bare string so a role
// cannot be passed where an org id is expected — both are strings and they
// appear adjacent in almost every membership signature.
//
// A member may hold several roles; they are stored comma-joined in one
// column ("admin,billing"), and Parts splits
// them. JoinRoles builds one.
type Role string

// Built-in membership roles, granted DefaultRoles' permissions. An app adds
// its own with WithRoles (fixed at start-up) or DynamicRoles (created per
// organization at run time); every role check goes through the permission
// statements (HasPermission), never through the role's name.
const (
	//ds:def id=roleowner-szv8n5ye owner=@khanakia stability=stable
	RoleOwner Role = "owner"
	//ds:def id=roleadmin-cghbz3fj owner=@khanakia stability=stable
	RoleAdmin Role = "admin"
	//ds:def id=rolemember-k755wabe owner=@khanakia stability=stable
	RoleMember Role = "member"
)

// RoleValues is the canonical iteration order, from most to least privileged.
// Seeds, permission checks and any role selector read from this one list.
var RoleValues = []Role{RoleOwner, RoleAdmin, RoleMember}

// Rank returns the privilege level of the built-in roles, higher being more
// privileged; for several roles, the highest. Custom roles rank 0: their
// power is their permissions, which HasPermission checks.
//
// Derived from position in RoleValues rather than stored as a separate number,
// so adding a role in the right place is the only edit required and the two
// cannot disagree.
func (r Role) Rank() int {
	best := 0
	for _, part := range r.Parts() {
		for i, known := range RoleValues {
			if known == part && len(RoleValues)-i > best {
				best = len(RoleValues) - i
			}
		}
	}
	return best // unknown roles rank below every known one, so a typo grants nothing
}

// roleSeparator joins several roles in one stored value.
const roleSeparator = ","

// Parts splits a stored role into the roles it holds, trimmed, empty ones
// dropped.
func (r Role) Parts() []Role {
	var out []Role
	for _, part := range strings.Split(string(r), roleSeparator) {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, Role(part))
		}
	}
	return out
}

// Has reports whether r holds role among its parts.
func (r Role) Has(role Role) bool {
	for _, part := range r.Parts() {
		if part == role {
			return true
		}
	}
	return false
}

// JoinRoles is the stored form of several roles, duplicates dropped, in the
// order given.
func JoinRoles(roles ...Role) Role {
	seen := map[Role]bool{}
	var parts []string
	for _, r := range roles {
		for _, part := range r.Parts() {
			if !seen[part] {
				seen[part] = true
				parts = append(parts, string(part))
			}
		}
	}
	return Role(strings.Join(parts, roleSeparator))
}

// AtLeast reports whether r is at least as privileged as need.
//
//ds:def id=role-atleast-wxmtstyb owner=@khanakia stability=stable
func (r Role) AtLeast(need Role) bool { return r.Rank() >= need.Rank() }

// Tables this plugin declares.
var (
	TableOrg    = sqlb.Table{Name: TableNameOrg, Alias: TableAliasOrg}
	TableMember = sqlb.Table{Name: TableNameMember, Alias: TableAliasMember}
	TableInvite = sqlb.Table{Name: TableNameInvite, Alias: TableAliasInvite}

	TableTeam       = sqlb.Table{Name: TableNameTeam, Alias: TableAliasTeam}
	TableTeamMember = sqlb.Table{Name: TableNameTeamMember, Alias: TableAliasTeamMember}
	TableRole       = sqlb.Table{Name: TableNameRole, Alias: TableAliasRole}
	TableActive     = sqlb.Table{Name: TableNameActive, Alias: TableAliasActive}

	// TableIdentity is the core identity table under this plugin's alias, used
	// to match an invitation against a verified address.
	TableIdentity = sqlb.Table{Name: auth.TableNameIdentity, Alias: TableAliasIdentity}
)

// Typed columns, for an app that joins this plugin's tables into its own
// queries; reads are open, writes go through the operations.
var (
	OrgID        = sqlb.Col[string](TableOrg, ColOrgID)
	OrgSlug      = sqlb.Col[string](TableOrg, ColOrgSlug)
	OrgName      = sqlb.Col[string](TableOrg, ColOrgName)
	OrgCreatedAt = sqlb.Col[time.Time](TableOrg, ColOrgCreatedAt)
	OrgLogo      = sqlb.Col[*string](TableOrg, ColOrgLogo)
	OrgMetadata  = sqlb.Col[auth.AppData](TableOrg, ColOrgMetadata)

	MemberOrgID    = sqlb.Col[string](TableMember, ColMemberOrgID)
	MemberUserID   = sqlb.Col[string](TableMember, ColMemberUserID)
	MemberRole     = sqlb.Col[Role](TableMember, ColMemberRole)
	MemberJoinedAt = sqlb.Col[time.Time](TableMember, ColMemberJoinedAt)

	InviteID        = sqlb.Col[string](TableInvite, ColInviteID)
	InviteOrgID     = sqlb.Col[string](TableInvite, ColInviteOrgID)
	InviteEmail     = sqlb.Col[string](TableInvite, ColInviteEmail)
	InviteKind      = sqlb.Col[auth.IdentifierKindName](TableInvite, ColInviteKind)
	InviteIdent     = sqlb.Col[string](TableInvite, ColInviteIdentifier)
	InviteRole      = sqlb.Col[Role](TableInvite, ColInviteRole)
	InviteInvitedBy = sqlb.Col[string](TableInvite, ColInviteInvitedBy)
	InviteExpiresAt = sqlb.Col[time.Time](TableInvite, ColInviteExpiresAt)
	InviteAccepted  = sqlb.Col[*time.Time](TableInvite, ColInviteAccepted)
	InviteCreatedAt = sqlb.Col[time.Time](TableInvite, ColInviteCreatedAt)
	InviteStatusCol = sqlb.Col[InviteStatus](TableInvite, ColInviteStatus)
	InviteTeamID    = sqlb.Col[*string](TableInvite, ColInviteTeamID)

	TeamID        = sqlb.Col[string](TableTeam, ColTeamID)
	TeamOrgID     = sqlb.Col[string](TableTeam, ColTeamOrgID)
	TeamName      = sqlb.Col[string](TableTeam, ColTeamName)
	TeamCreatedAt = sqlb.Col[time.Time](TableTeam, ColTeamCreatedAt)
	TeamUpdatedAt = sqlb.Col[time.Time](TableTeam, ColTeamUpdatedAt)

	TeamMemberTeamID    = sqlb.Col[string](TableTeamMember, ColTeamMemberTeamID)
	TeamMemberUserID    = sqlb.Col[string](TableTeamMember, ColTeamMemberUserID)
	TeamMemberCreatedAt = sqlb.Col[time.Time](TableTeamMember, ColTeamMemberCreatedAt)

	RoleID         = sqlb.Col[string](TableRole, ColRoleID)
	RoleOrgID      = sqlb.Col[string](TableRole, ColRoleOrgID)
	RoleName       = sqlb.Col[Role](TableRole, ColRoleName)
	RolePermission = sqlb.Col[PermissionDoc](TableRole, ColRolePermission)
	RoleCreatedAt  = sqlb.Col[time.Time](TableRole, ColRoleCreatedAt)
	RoleUpdatedAt  = sqlb.Col[time.Time](TableRole, ColRoleUpdatedAt)

	ActiveSessionID = sqlb.Col[string](TableActive, ColActiveSessionID)
	ActiveUserID    = sqlb.Col[string](TableActive, ColActiveUserID)
	ActiveOrgID     = sqlb.Col[*string](TableActive, ColActiveOrgID)
	ActiveTeamID    = sqlb.Col[*string](TableActive, ColActiveTeamID)
	ActiveExpiresAt = sqlb.Col[time.Time](TableActive, ColActiveExpiresAt)

	IdentityUserID     = sqlb.Col[string](TableIdentity, auth.ColIdentityUserID)
	IdentityKind       = sqlb.Col[auth.IdentifierKindName](TableIdentity, auth.ColIdentityKind)
	IdentityValue      = sqlb.Col[string](TableIdentity, auth.ColIdentityValue)
	IdentityVerifiedAt = sqlb.Col[*time.Time](TableIdentity, auth.ColIdentityVerifiedAt)
)

// Member is a user plus their membership, as MembersQuery scans it. The user
// is embedded because its columns live on auth_user itself (ADR-0001).
type Member struct {
	auth.User
	Role     Role
	JoinedAt time.Time
}

// Org is a workspace. Slug is unique across the deployment and normalized to
// lowercase at creation. Logo and Metadata are optional: a logo URL, and
// free-form JSON the app keeps on the organization (at most
// MaxMetadataSize bytes).
type Org struct {
	ID        string       `json:"id"`
	Slug      string       `json:"slug"`
	Name      string       `json:"name"`
	Logo      *string      `json:"logo,omitempty"`
	Metadata  auth.AppData `json:"metadata,omitempty"`
	CreatedAt time.Time    `json:"createdAt"`
	// Fields are the extra columns WithFields declares.
	Fields auth.Fields `json:"fields,omitempty"`
}

// MaxMetadataSize bounds an organization's metadata, in bytes: room for
// settings and identifiers, not for documents, which belong in the app's own
// tables keyed by the organization id.
const MaxMetadataSize = 16 << 10

// orgBindings binds every auth_org column to o, the one list every read of
// an organization scans, so a column added later cannot be forgotten in one
// of them.
func orgBindings(o *Org) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(OrgID, &o.ID), sqlb.Bind(OrgSlug, &o.Slug), sqlb.Bind(OrgName, &o.Name),
		sqlb.Bind(OrgLogo, &o.Logo), sqlb.Bind(OrgMetadata, &o.Metadata), sqlb.Bind(OrgCreatedAt, &o.CreatedAt),
	}
}

// Invite is a pending invitation as its invitee sees it: OrgName is joined in
// so an invitations page needs no second query.
type Invite struct {
	ID      string `json:"id"`
	OrgID   string `json:"orgId"`
	OrgName string `json:"orgName"`
	// Email is the invited address of an email invitation, "" for another
	// kind; Kind and Identifier address every invitation.
	Email      string                  `json:"email"`
	Kind       auth.IdentifierKindName `json:"kind"`
	Identifier string                  `json:"identifier"`
	Role       Role                    `json:"role"`
	ExpiresAt  time.Time               `json:"expiresAt"`
}

// Invitation is an invitation row as an organization's members see it: every
// state, who sent it, and the team it joins.
type Invitation struct {
	ID    string `json:"id"`
	OrgID string `json:"orgId"`
	// Email is the invited address of an email invitation, "" for another
	// kind; Kind and Identifier address every invitation.
	Email      string                  `json:"email"`
	Kind       auth.IdentifierKindName `json:"kind"`
	Identifier string                  `json:"identifier"`
	Role       Role                    `json:"role"`
	Status     InviteStatus            `json:"status"`
	InviterID  string                  `json:"inviterId"`
	TeamID     *string                 `json:"teamId,omitempty"`
	ExpiresAt  time.Time               `json:"expiresAt"`
	CreatedAt  time.Time               `json:"createdAt"`
	// Fields are the extra columns WithFields declares.
	Fields auth.Fields `json:"fields,omitempty"`
}

// invitationBindings binds every auth_org_invite column the Invitation view
// carries.
func invitationBindings(i *Invitation) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(InviteID, &i.ID), sqlb.Bind(InviteOrgID, &i.OrgID), sqlb.Bind(InviteEmail, &i.Email),
		sqlb.Bind(InviteKind, &i.Kind), sqlb.Bind(InviteIdent, &i.Identifier),
		sqlb.Bind(InviteRole, &i.Role), sqlb.Bind(InviteStatusCol, &i.Status), sqlb.Bind(InviteInvitedBy, &i.InviterID),
		sqlb.Bind(InviteTeamID, &i.TeamID), sqlb.Bind(InviteExpiresAt, &i.ExpiresAt), sqlb.Bind(InviteCreatedAt, &i.CreatedAt),
	}
}

// Operation ids. They are permanent: rate rules, hooks and every transport
// route address an operation by id, so renaming one breaks deployed clients.
const (
	EndpointCreate       auth.EndpointID = "organization.create"
	EndpointList         auth.EndpointID = "organization.list"
	EndpointMembers      auth.EndpointID = "organization.members"
	EndpointInvite       auth.EndpointID = "organization.invite"
	EndpointInvites      auth.EndpointID = "organization.invites"
	EndpointAccept       auth.EndpointID = "organization.accept"
	EndpointRemoveMember auth.EndpointID = "organization.remove-member"
	EndpointSetRole      auth.EndpointID = "organization.set-role"
	EndpointCheckSlug    auth.EndpointID = "organization.check-slug"
	EndpointInvitation   auth.EndpointID = "organization.invitation"
	EndpointRole         auth.EndpointID = "organization.role"

	EndpointGet             auth.EndpointID = "organization.get"
	EndpointGetFull         auth.EndpointID = "organization.get-full"
	EndpointUpdate          auth.EndpointID = "organization.update"
	EndpointDelete          auth.EndpointID = "organization.delete"
	EndpointSetActive       auth.EndpointID = "organization.set-active"
	EndpointActive          auth.EndpointID = "organization.active"
	EndpointReject          auth.EndpointID = "organization.reject"
	EndpointCancel          auth.EndpointID = "organization.cancel"
	EndpointListInvitations auth.EndpointID = "organization.list-invitations"
	EndpointHasPermission   auth.EndpointID = "organization.has-permission"

	EndpointCreateTeam       auth.EndpointID = "organization.create-team"
	EndpointListTeams        auth.EndpointID = "organization.list-teams"
	EndpointUpdateTeam       auth.EndpointID = "organization.update-team"
	EndpointRemoveTeam       auth.EndpointID = "organization.remove-team"
	EndpointSetActiveTeam    auth.EndpointID = "organization.set-active-team"
	EndpointListUserTeams    auth.EndpointID = "organization.list-user-teams"
	EndpointListTeamMembers  auth.EndpointID = "organization.list-team-members"
	EndpointAddTeamMember    auth.EndpointID = "organization.add-team-member"
	EndpointRemoveTeamMember auth.EndpointID = "organization.remove-team-member"

	EndpointCreateRole auth.EndpointID = "organization.create-role"
	EndpointUpdateRole auth.EndpointID = "organization.update-role"
	EndpointDeleteRole auth.EndpointID = "organization.delete-role"
	EndpointGetRole    auth.EndpointID = "organization.get-role"
	EndpointListRoles  auth.EndpointID = "organization.list-roles"
)

// PurposeInvite is the message sent to an invited address. A mailer switches
// on it to pick the invitation template.
//
//ds:def id=purposeinvite-48v8gjic owner=@khanakia stability=stable
const PurposeInvite auth.Purpose = "organization.invite"

// The invitation's default English wording, sent as the message's
// DefaultSubject and DefaultText. The email plugin cannot import this package
// (this package imports it), so the words travel with the message and are used
// only when the app's templates have no case for PurposeInvite. The body says
// the address must be verified because an unverified one sees no invitation.
const (
	inviteSubject  = "You are invited to join an organization"
	inviteTextHead = "You were invited to join an organization. Sign in with this address, verify it if you have not, and accept the invitation here:\n\n"
)

// DefaultInviteTTL is how long an invitation stays acceptable: a week covers
// an invitee who is away for a few days, and anything longer leaves a
// forgotten invitation usable by whoever controls that inbox months later.
//
//ds:def id=defaultinvitettl-q2vrh7rg owner=@khanakia stability=stable
const DefaultInviteTTL = 7 * 24 * time.Hour

const (
	// DefaultInviteLimit and DefaultInviteWindow bound invitation mail per
	// client address: 50 an hour lets an admin onboard a team in one sitting
	// and keeps a stolen session from turning the app's mail domain into a
	// spam relay. InviteLimit changes both.
	//ds:def id=invitelimit-6wd9gmj5 owner=@khanakia stability=stable
	DefaultInviteLimit = 50
	//ds:def id=invitewindow-fhrf25ap owner=@khanakia stability=stable
	DefaultInviteWindow = time.Hour

	// DefaultMembersPage and MaxMembersPage bound the members list: a page
	// an org settings screen shows, and a cap so one request cannot read a
	// huge organization at once. A larger limit is clamped, not refused.
	DefaultMembersPage = 50
	MaxMembersPage     = 200

	// idPrefixOrg, idPrefixInvite, idPrefixTeam and idPrefixRole make an
	// id's kind readable in logs and support tickets ("org_…", "inv_…").
	idPrefixOrg    = "org"
	idPrefixInvite = "inv"
	idPrefixTeam   = "team"
	idPrefixRole   = "role"

	// DefaultInvitationLimit is the default InvitationLimit: at most this
	// many pending invitations per organization, so a stolen admin session
	// cannot fill the table. InvitationLimit changes it; zero is no cap.
	DefaultInvitationLimit = 100

	// Ledger names of this plugin's migrations. They are recorded in
	// auth_migrations, so none may change once shipped. Teams and roles are
	// separate migrations so that turning the option on later creates the
	// table then.
	migrationName   = "0001_organization"
	migrationFields = "0002_organization_fields"
	migrationActive = "0003_organization_active"
	migrationTeams  = "0004_organization_teams"
	migrationRoles  = "0005_organization_roles"
	// migrationIdentifier adds the invitation's identifier kind and value,
	// filled for every invitation made before, all of which were email.
	migrationIdentifier = "0006_organization_invite_identifier"

	// indexUserSuffix names the user index of the active table, appended to
	// its real name so two prefixed instances never collide.
	indexUserSuffix = "_user_idx"
)

// DefaultInvitePage is the app page an invitation mail links to; it lists the
// signed-in user's invitations through organization.invites.
//
//ds:def id=defaultinvitepage-ffc5fetf owner=@khanakia stability=stable
const DefaultInvitePage = "/invitations"

// SlugPattern is what an organization slug may look like: 2 to 48 lowercase
// letters, digits and dashes, not starting with a dash. It appears in URLs and
// subdomains, so it is restricted to what needs no escaping in either, and 48
// keeps it inside a 63-character DNS label with room for an app's prefix.
var SlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,47}$`)

// Errors a client may see. Each carries a stable code for programmatic checks.
var (
	// ErrNotMember answers a non-member with 404, never 403, so a stranger
	// cannot tell an organization they may not see from one that does not
	// exist.
	ErrNotMember = auth.NewError("organization.not_member", http.StatusNotFound, "Not found.")
	// ErrForbidden is a member whose role is too low for the request.
	ErrForbidden = auth.NewError("organization.forbidden", http.StatusForbidden, "Your role does not allow this.")
	// ErrSlugTaken is a slug another organization already uses.
	ErrSlugTaken = auth.NewError("organization.slug_taken", http.StatusConflict, "This address is already in use.")
	// ErrBadSlug is a slug that does not match SlugPattern.
	ErrBadSlug = auth.NewError("organization.bad_slug", http.StatusBadRequest, "Use lowercase letters, digits and dashes.")
	// ErrBadRole is a role outside RoleValues.
	ErrBadRole = auth.NewError("organization.bad_role", http.StatusBadRequest, "This role does not exist.")
	// ErrLastOwner refuses to remove or demote the only owner, which would
	// leave an organization nobody can administer.
	ErrLastOwner = auth.NewError("organization.last_owner", http.StatusConflict, "An organization needs at least one owner.")
	// ErrInviteInvalid is an invitation that is unknown, expired, already
	// accepted, or addressed to an address the caller has not verified. One
	// error for all four, so a guessed id reveals nothing.
	ErrInviteInvalid = auth.NewError("organization.invite_invalid", http.StatusNotFound, "This invitation is not valid any more.")
	// ErrCreateForbidden is a user the CreateGate refused.
	ErrCreateForbidden = auth.NewError("organization.create_forbidden", http.StatusForbidden, "You cannot create an organization.")
	// ErrLimitReached is a user who already owns MaxOwned organizations.
	ErrLimitReached = auth.NewError("organization.limit_reached", http.StatusConflict, "You have reached the number of organizations you can own.")
	// ErrMembersLimit is an organization that already has MaxMembers members.
	ErrMembersLimit = auth.NewError("organization.members_limit", http.StatusConflict, "This organization is full.")
	// ErrNoActiveOrg is a request that named no organization while its
	// session has none active.
	ErrNoActiveOrg = auth.NewError("organization.no_active", http.StatusBadRequest, "No organization is active.")
	// ErrAlreadyMember refuses to invite or add a member, with
	// RejectExistingMembers.
	ErrAlreadyMember = auth.NewError("organization.already_member", http.StatusConflict, "This user is already a member.")
	// ErrInvitationLimit is an organization with InvitationLimit pending
	// invitations already.
	ErrInvitationLimit = auth.NewError("organization.invitation_limit", http.StatusConflict, "This organization has too many pending invitations.")
	// ErrBadMetadata is metadata that is not a JSON object or exceeds
	// MaxMetadataSize.
	ErrBadMetadata = auth.NewError("organization.bad_metadata", http.StatusBadRequest, "Metadata must be a JSON object of at most 16 KiB.")
	// ErrTeamNotFound is a team that does not exist or that the caller may
	// not see; one answer for both, like ErrNotMember.
	ErrTeamNotFound = auth.NewError("organization.team_not_found", http.StatusNotFound, "Not found.")
	// ErrTeamsLimit is an organization with TeamsConfig.MaxTeams teams.
	ErrTeamsLimit = auth.NewError("organization.teams_limit", http.StatusConflict, "This organization has reached its number of teams.")
	// ErrTeamMembersLimit is a team with TeamsConfig.MaxMembersPerTeam
	// members.
	ErrTeamMembersLimit = auth.NewError("organization.team_members_limit", http.StatusConflict, "This team is full.")
	// ErrLastTeam refuses to remove an organization's only team, unless
	// TeamsConfig.AllowRemovingAllTeams.
	ErrLastTeam = auth.NewError("organization.last_team", http.StatusConflict, "An organization needs at least one team.")
	// ErrRoleNotFound is a dynamic role that does not exist in the
	// organization.
	ErrRoleNotFound = auth.NewError("organization.role_not_found", http.StatusNotFound, "This role does not exist.")
	// ErrRoleTaken is a role name the organization, or the static roles,
	// already use.
	ErrRoleTaken = auth.NewError("organization.role_taken", http.StatusConflict, "A role with this name already exists.")
	// ErrRolesLimit is an organization with DynamicRolesConfig.MaxRoles
	// roles.
	ErrRolesLimit = auth.NewError("organization.roles_limit", http.StatusConflict, "This organization has reached its number of roles.")
	// ErrRoleInUse refuses to delete a role members still hold.
	ErrRoleInUse = auth.NewError("organization.role_in_use", http.StatusConflict, "Members still hold this role.")
	// ErrBadPermission is a permission outside the access-control
	// statements, or one the caller does not hold and so cannot grant.
	ErrBadPermission = auth.NewError("organization.bad_permission", http.StatusBadRequest, "This permission cannot be granted.")
	// ErrPredefinedRole answers delete-role or update-role naming a role
	// fixed in configuration (owner, admin, member, or one of
	// WithRoles'), which only a deploy changes.
	ErrPredefinedRole = auth.NewError("organization.predefined_role", http.StatusBadRequest, "This role is part of the configuration and cannot be changed here.")
	// ErrNoActiveTeam answers list-team-members with no teamId when the
	// session has no active team.
	ErrNoActiveTeam = auth.NewError("organization.no_active_team", http.StatusBadRequest, "No team is active.")
	// ErrAlreadyInvited answers invite, with RefuseRepeatInvites, for an
	// address that already holds a pending invitation to the organization.
	// The caller holds invitation:create there, so it reveals nothing a
	// list-invitations does not.
	ErrAlreadyInvited = auth.NewError("organization.already_invited", http.StatusConflict, "This address already has a pending invitation.")
	// ErrInviteAddress is an invitee or member named two ways at once
	// (Email and an Identifier), or by a kind InviteBy does not allow.
	ErrInviteAddress = auth.NewError("organization.invite_address", http.StatusBadRequest, "Name the person by one address of a kind this app invites by.")
)

// Plugin adds organizations. Build it with New; the zero value has no
// operations.
type Plugin struct {
	// optErrs collects what the options found while they ran, such as a
	// nil func or interface (auth.ErrNilOption); see OptionErr.
	optErrs   auth.OptionErrors
	inviteTTL time.Duration
	links     func() string
	core      *auth.Auth

	// createGate decides who may create an organization (CreateGate); nil
	// lets every signed-in user.
	createGate func(ctx context.Context, u auth.User) (bool, error)
	// maxOwned caps the organizations a user may own (MaxOwned); zero is no
	// cap.
	maxOwned int
	// maxMembers caps an organization's members (MaxMembers); zero is no cap.
	maxMembers int
	// replacePending withdraws an address's pending invitations when it is
	// invited again (ReplacePendingInvites).
	replacePending bool
	// refuseRepeat refuses an invite to an address with a pending
	// invitation (RefuseRepeatInvites).
	refuseRepeat bool
	// inviteLimit and inviteWindow are the invite rate rule (InviteLimit).
	inviteLimit  int
	inviteWindow time.Duration
	// message words the invitation mail (InviteMessage); nil uses the
	// plugin's default wording.
	message func(m InviteMail) (subject, text string)
	// inviteKinds are the identifier kinds an invitation may be addressed
	// to (InviteBy), the first being the one an InviteRequest without a
	// Kind uses; [email] by default. noInvitations turns the invitation
	// operations off (WithoutInvitations).
	inviteKinds   []auth.IdentifierKindName
	noInvitations bool

	// creatorRole is the role a creator gets, and the role the owner
	// protections guard (CreatorRole); RoleOwner by default.
	creatorRole Role
	// ac is the permission vocabulary (WithAccessControl); roles are the
	// static roles built from it, DefaultRoles merged with WithRoles.
	ac    *access.AccessControl
	roles map[Role]access.Role
	// authorizer decides every permission (WithAuthorizer; RoleAuthorizer
	// by default); customAuthorizer is true once WithAuthorizer replaced it,
	// which turns off the creator's API-key shortcut of the role model.
	authorizer       Authorizer
	customAuthorizer bool
	// invitationLimit caps pending invitations per organization
	// (InvitationLimit); zero is no cap.
	invitationLimit int
	// rejectMembers refuses to invite or add an existing member
	// (RejectExistingMembers).
	rejectMembers bool
	hooks         Hooks
	// hooksSet is true once WithHooks ran; hooksFrom is WithHooksFrom's
	// builder, run in Init. Validate refuses both, since one would silently
	// replace the other.
	hooksSet  bool
	hooksFrom func(a *auth.Auth) Hooks
	// teams is nil unless Teams was given; dynamic is nil unless
	// DynamicRoles was given; domains is nil unless Domains was given.
	teams   *TeamsConfig
	dynamic *DynamicRolesConfig
	domains *DomainsConfig
	// fields are the extra columns per table (WithFields).
	fields FieldsConfig

	checkSlug    *auth.Op[SlugRequest, SlugResult]
	invitation   *auth.Op[AcceptRequest, Invite]
	role         *auth.Op[OrgRequest, RoleResult]
	create       *auth.Op[CreateRequest, Org]
	list         *auth.Op[struct{}, ListResult]
	members      *auth.Op[OrgRequest, MembersResult]
	invite       *auth.Op[InviteRequest, auth.Done]
	invites      *auth.Op[struct{}, InvitesResult]
	accept       *auth.Op[AcceptRequest, Org]
	removeMember *auth.Op[MemberRequest, auth.Done]
	setRole      *auth.Op[SetRoleRequest, auth.Done]

	get             *auth.Op[GetRequest, Org]
	getFull         *auth.Op[GetRequest, FullOrg]
	update          *auth.Op[UpdateRequest, Org]
	deleteOrg       *auth.Op[OrgRequest, auth.Done]
	setActive       *auth.Op[SetActiveRequest, ActiveResult]
	active          *auth.Op[struct{}, ActiveResult]
	reject          *auth.Op[AcceptRequest, auth.Done]
	cancel          *auth.Op[AcceptRequest, auth.Done]
	listInvitations *auth.Op[OrgRequest, InvitationsResult]
	hasPermission   *auth.Op[PermissionRequest, PermissionResult]

	createTeam       *auth.Op[CreateTeamRequest, Team]
	listTeams        *auth.Op[OrgRequest, TeamsResult]
	updateTeam       *auth.Op[UpdateTeamRequest, Team]
	removeTeam       *auth.Op[TeamRequest, auth.Done]
	setActiveTeam    *auth.Op[TeamRequest, ActiveResult]
	listUserTeams    *auth.Op[struct{}, TeamsResult]
	listTeamMembers  *auth.Op[TeamRequest, TeamMembersResult]
	addTeamMember    *auth.Op[TeamMemberRequest, auth.Done]
	removeTeamMember *auth.Op[TeamMemberRequest, auth.Done]

	createRole *auth.Op[CreateRoleRequest, OrgRole]
	updateRole *auth.Op[UpdateRoleRequest, OrgRole]
	deleteRole *auth.Op[RoleRequest, auth.Done]
	getRole    *auth.Op[RoleRequest, OrgRole]
	listRoles  *auth.Op[OrgRequest, RolesResult]

	addDomain        *auth.Op[AddDomainRequest, OrgDomain]
	listDomains      *auth.Op[DomainsRequest, DomainsResult]
	verifyDomain     *auth.Op[DomainRequest, OrgDomain]
	updateDomain     *auth.Op[UpdateDomainRequest, OrgDomain]
	removeDomain     *auth.Op[DomainRequest, auth.Done]
	suggestions      *auth.Op[struct{}, SuggestionsResult]
	acceptSuggestion *auth.Op[DomainRequest, MembershipRequest]
	listRequests     *auth.Op[DomainsRequest, MembershipRequestsResult]
	approveRequest   *auth.Op[RequestIDRequest, auth.Done]
	rejectRequest    *auth.Op[RequestIDRequest, auth.Done]
}

// OptionErr is every error the options recorded, such as auth.ErrNilOption
// naming an option given nil; auth.New refuses to start while it is not
// nil (auth.OptionChecker).
func (p *Plugin) OptionErr() error { return p.optErrs.OptionErr() }

// Option configures the plugin; pass options to New.
type Option func(*Plugin)

// WithInviteTTL overrides DefaultInviteTTL, for a product whose invitations
// should lapse sooner or later than a week.
func WithInviteTTL(d time.Duration) Option { return func(p *Plugin) { p.inviteTTL = d } }

// InviteLink sets the page an invitation mail links to, for an app whose
// invitations page is not BaseURL + DefaultInvitePage. It is called per mail,
// so it may read configuration that changes at run time.
func InviteLink(fn func() string) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("organization.InviteLink", fn) {
			return
		}
		p.links = fn
	}
}

// CreateGate decides whether a signed-in user may create an organization, for
// example only on a paid plan. A refusal is `organization.create_forbidden`;
// an error from fn fails the request. Without it every signed-in user may.
func CreateGate(fn func(ctx context.Context, u auth.User) (bool, error)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("organization.CreateGate", fn) {
			return
		}
		p.createGate = fn
	}
}

// MaxOwned caps how many organizations one user may own; creating another is
// refused with `organization.limit_reached`. Counted as memberships holding
// the creator role, so an owner who was promoted counts and one who left
// does not. Zero, the default, is no cap.
func MaxOwned(n int) Option { return func(p *Plugin) { p.maxOwned = n } }

// MaxMembers caps the members of an organization; an acceptance or AddMember
// that would exceed it is refused with `organization.members_limit`.
// Invitations are still sent, because the count is checked when someone
// joins. Zero, the default, is no cap.
func MaxMembers(n int) Option { return func(p *Plugin) { p.maxMembers = n } }

// ReplacePendingInvites makes inviting an address that already has pending
// invitations to the same organization withdraw them first, so the invitee
// has one valid invitation and one fresh mail. Without it, the default,
// each invite creates another pending invitation.
func ReplacePendingInvites() Option { return func(p *Plugin) { p.replacePending = true } }

// RefuseRepeatInvites makes inviting an address that already holds a
// pending, unexpired invitation to the organization fail with
// `organization.already_invited`, unless the request
// sets Resend. ReplacePendingInvites wins over it, since it asks for the
// opposite. Without either, the default, each invite creates another
// pending invitation.
func RefuseRepeatInvites() Option { return func(p *Plugin) { p.refuseRepeat = true } }

// InviteLimit replaces DefaultInviteLimit and DefaultInviteWindow: at most
// limit invitations per window from one client address. Both must be
// positive; Validate refuses anything else.
func InviteLimit(limit int, window time.Duration) Option {
	return func(p *Plugin) { p.inviteLimit, p.inviteWindow = limit, window }
}

// InvitationLimit caps the pending invitations of one organization
// (invitationLimit); one more is `organization.invitation_limit`.
// DefaultInvitationLimit unless set; zero is no cap. It complements
// InviteLimit, which bounds mail per client address over time.
func InvitationLimit(n int) Option { return func(p *Plugin) { p.invitationLimit = n } }

// InviteMessage words the invitation mail from the invitation, the
// organization, the inviter and the link, for an app that wants "Alice
// invited you to Acme" rather than the plugin's generic text. It sets the
// message's default wording, so an email.Templates case for PurposeInvite
// still wins.
func InviteMessage(fn func(m InviteMail) (subject, text string)) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("organization.InviteMessage", fn) {
			return
		}
		p.message = fn
	}
}

// InviteBy sets the identifier kinds an invitation may be addressed to, in
// place of email alone: InviteBy(phone.KindPhone) for a phone-only app,
// InviteBy(email.KindEmail, phone.KindPhone) for either. The first kind is
// the one an InviteRequest naming no Kind uses. Each kind must be
// registered by an identifier plugin that delivers messages (email and
// phone do; username does not): auth.New refuses any other kind with
// auth.ErrNoDeliverer (auth.Config.CanDeliver), rather than the first
// invite failing. Whatever the kind, an
// invitation is accepted only by a user holding the VERIFIED identity of
// that kind and value (PendingInvitesQuery). The email plugin is required
// only when email is among the kinds.
func InviteBy(kinds ...auth.IdentifierKindName) Option {
	return func(p *Plugin) { p.inviteKinds = kinds }
}

// WithoutInvitations turns the invitation operations off (invite, invites,
// accept, invitation, reject-invitation, cancel-invitation,
// list-invitations), for an app that adds members only from the server
// (AddMember, AddMemberWith). No identifier plugin, invitation link or
// BaseURL is then required.
func WithoutInvitations() Option { return func(p *Plugin) { p.noInvitations = true } }

// CreatorRole sets the role the creator of an organization gets
// (creatorRole). It is also the role the owner protections
// guard: only its holders may grant it, change or remove a holder, and the
// last holder cannot leave or be demoted. RoleOwner by default; Validate
// refuses a role that is not a static role.
func CreatorRole(r Role) Option { return func(p *Plugin) { p.creatorRole = r } }

// WithAccessControl replaces DefaultStatements with the app's own
// vocabulary. The plugin's operations check the resources of
// DefaultStatements (organization, member, invitation, team, ac), so an app
// adding its own resources should start from DefaultStatements.
func WithAccessControl(ac *access.AccessControl) Option { return func(p *Plugin) { p.ac = ac } }

// WithRoles adds static roles, or replaces a built-in one under the same
// name, each a role of the access control (WithAccessControl or the
// default). Validate refuses a role naming a statement the access control
// does not declare.
func WithRoles(roles map[Role]access.Role) Option {
	return func(p *Plugin) {
		for name, r := range roles {
			p.roles[name] = r
		}
	}
}

// RejectExistingMembers refuses to invite an address that already belongs
// to a member, and AddMember of a member, with `organization.already_member`.
// Without it, the default, the invitation is sent and
// accepting it keeps the member's role.
func RejectExistingMembers() Option { return func(p *Plugin) { p.rejectMembers = true } }

// WithHooks sets the lifecycle hooks; see Hooks. For hooks that write the
// app's own rows, which need the *auth.Auth, use WithHooksFrom.
func WithHooks(h Hooks) Option {
	return func(p *Plugin) { p.hooks, p.hooksSet = h, true }
}

// WithHooksFrom sets the lifecycle hooks from build, which Init calls once
// with the *auth.Auth: the options are built before auth.New returns it, so
// this is how a hook gets it without a variable bound after start-up. Every
// hook runs inside its operation's transaction and ctx carries it, so a hook
// writes the app's own rows through a.Conn(ctx) or a.Exec(ctx, …) and they
// commit or roll back with the organization's. Giving WithHooks as well is
// refused by auth.New.
func WithHooksFrom(build func(a *auth.Auth) Hooks) Option {
	return func(p *Plugin) {
		if p.optErrs.RefuseNil("organization.WithHooksFrom", build) {
			return
		}
		p.hooksFrom = build
	}
}

// Teams turns teams on: sub-groups inside an organization, with their own
// members and an active team per session.
func Teams(cfg TeamsConfig) Option { return func(p *Plugin) { p.teams = &cfg } }

// DynamicRoles lets organizations create roles at run time, each a
// permission map stored in auth_org_role.
func DynamicRoles(cfg DynamicRolesConfig) Option { return func(p *Plugin) { p.dynamic = &cfg } }

// InviteMail is what InviteMessage receives.
type InviteMail struct {
	Invite  Invite
	Org     Org
	Inviter auth.User
	// Link is the invitations page, from InviteLink or the base URL.
	Link string
}

var (
	_ auth.OperationProvider = (*Plugin)(nil)
	_ auth.TypedMigrator     = (*Plugin)(nil)
	_ auth.TableOwner        = (*Plugin)(nil)
	_ auth.UserTableOwner    = (*Plugin)(nil)
	_ auth.Dependent         = (*Plugin)(nil)
	_ auth.Validator         = (*Plugin)(nil)
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.RateLimiter       = (*Plugin)(nil)
	_ auth.Sweeper           = (*Plugin)(nil)
	_ auth.SessionLifecycle  = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
)

// New builds the plugin with DefaultInviteTTL and the invitation page at
// BaseURL + DefaultInvitePage unless opts say otherwise.
func New(opts ...Option) *Plugin {
	p := &Plugin{
		inviteTTL: DefaultInviteTTL, inviteLimit: DefaultInviteLimit, inviteWindow: DefaultInviteWindow,
		creatorRole: RoleOwner, ac: DefaultAccessControl, roles: DefaultRoles(), invitationLimit: DefaultInvitationLimit,
		inviteKinds: []auth.IdentifierKindName{email.KindEmail},
	}
	p.authorizer = p.RoleAuthorizer()
	for _, o := range opts {
		o(p)
	}
	signedIn := func(id auth.EndpointID, kind auth.OpKind, path string) auth.OpInfo {
		return auth.OpInfo{ID: id, Kind: kind, Require: auth.SignedIn, Path: path}
	}
	p.checkSlug = auth.Define(signedIn(EndpointCheckSlug, auth.Query, "/check-slug"), p.doCheckSlug)
	p.invitation = auth.Define(signedIn(EndpointInvitation, auth.Query, "/invite"), p.doInvitation)
	p.role = auth.Define(signedIn(EndpointRole, auth.Query, "/role"), p.doRole)
	p.create = auth.Define(signedIn(EndpointCreate, auth.Mutation, "/create"), p.doCreate)
	p.list = auth.Define(signedIn(EndpointList, auth.Query, "/list"), p.doList)
	p.members = auth.Define(signedIn(EndpointMembers, auth.Query, "/members"), p.doMembers)
	p.invite = auth.Define(signedIn(EndpointInvite, auth.Mutation, "/invite"), p.doInvite)
	p.invites = auth.Define(signedIn(EndpointInvites, auth.Query, "/invites"), p.doInvites)
	p.accept = auth.Define(signedIn(EndpointAccept, auth.Mutation, "/accept"), p.doAccept)
	p.removeMember = auth.Define(signedIn(EndpointRemoveMember, auth.Mutation, "/remove-member"), p.doRemoveMember)
	p.setRole = auth.Define(signedIn(EndpointSetRole, auth.Mutation, "/set-role"), p.doSetRole)

	p.get = auth.Define(signedIn(EndpointGet, auth.Query, "/get-organization"), p.doGet)
	p.getFull = auth.Define(signedIn(EndpointGetFull, auth.Query, "/get-full-organization"), p.doGetFull)
	p.update = auth.Define(signedIn(EndpointUpdate, auth.Mutation, "/update"), p.doUpdate)
	p.deleteOrg = auth.Define(signedIn(EndpointDelete, auth.Mutation, "/delete"), p.doDelete)
	p.setActive = auth.Define(signedIn(EndpointSetActive, auth.Mutation, "/set-active"), p.doSetActive)
	p.active = auth.Define(signedIn(EndpointActive, auth.Query, "/active"), p.doActive)
	p.reject = auth.Define(signedIn(EndpointReject, auth.Mutation, "/reject-invitation"), p.doReject)
	p.cancel = auth.Define(signedIn(EndpointCancel, auth.Mutation, "/cancel-invitation"), p.doCancel)
	p.listInvitations = auth.Define(signedIn(EndpointListInvitations, auth.Query, "/list-invitations"), p.doListInvitations)
	p.hasPermission = auth.Define(signedIn(EndpointHasPermission, auth.Mutation, "/has-permission"), p.doHasPermission)

	p.createTeam = auth.Define(signedIn(EndpointCreateTeam, auth.Mutation, "/create-team"), p.doCreateTeam)
	p.listTeams = auth.Define(signedIn(EndpointListTeams, auth.Query, "/list-teams"), p.doListTeams)
	p.updateTeam = auth.Define(signedIn(EndpointUpdateTeam, auth.Mutation, "/update-team"), p.doUpdateTeam)
	p.removeTeam = auth.Define(signedIn(EndpointRemoveTeam, auth.Mutation, "/remove-team"), p.doRemoveTeam)
	p.setActiveTeam = auth.Define(signedIn(EndpointSetActiveTeam, auth.Mutation, "/set-active-team"), p.doSetActiveTeam)
	p.listUserTeams = auth.Define(signedIn(EndpointListUserTeams, auth.Query, "/list-user-teams"), p.doListUserTeams)
	p.listTeamMembers = auth.Define(signedIn(EndpointListTeamMembers, auth.Query, "/list-team-members"), p.doListTeamMembers)
	p.addTeamMember = auth.Define(signedIn(EndpointAddTeamMember, auth.Mutation, "/add-team-member"), p.doAddTeamMember)
	p.removeTeamMember = auth.Define(signedIn(EndpointRemoveTeamMember, auth.Mutation, "/remove-team-member"), p.doRemoveTeamMember)

	p.createRole = auth.Define(signedIn(EndpointCreateRole, auth.Mutation, "/create-role"), p.doCreateRole)
	p.updateRole = auth.Define(signedIn(EndpointUpdateRole, auth.Mutation, "/update-role"), p.doUpdateRole)
	p.deleteRole = auth.Define(signedIn(EndpointDeleteRole, auth.Mutation, "/delete-role"), p.doDeleteRole)
	p.getRole = auth.Define(signedIn(EndpointGetRole, auth.Query, "/get-role"), p.doGetRole)
	p.listRoles = auth.Define(signedIn(EndpointListRoles, auth.Query, "/list-roles"), p.doListRoles)
	p.defineDomainOps(signedIn)
	return p
}

// Name identifies the plugin.
func (p *Plugin) Name() string { return PluginName }

// Tables declares every table this plugin can bring into a statement. The
// team and role tables are declared only when their option is on, so an app
// without teams has no auth_org_team to rename or migrate.
func (p *Plugin) Tables() []sqlb.Table {
	t := []sqlb.Table{TableOrg, TableMember, TableInvite, TableIdentity, TableActive}
	if p.teams != nil {
		t = append(t, TableTeam, TableTeamMember)
	}
	if p.dynamic != nil {
		t = append(t, TableRole)
	}
	if p.domains != nil {
		t = append(t, TableDomain, TableDomainRequest)
	}
	return t
}

// UserTables declares the rows that belong to the user in user_id, so
// DeleteUser removes them (no foreign key does, ADR-0002): memberships, team
// memberships and active selections. Invitations keep their invited_by: they
// belong to the organization, not to the inviter.
func (p *Plugin) UserTables() []auth.UserTable {
	t := []auth.UserTable{{Table: TableMember, Column: ColMemberUserID}, {Table: TableActive, Column: ColActiveUserID}}
	if p.teams != nil {
		t = append(t, auth.UserTable{Table: TableTeamMember, Column: ColTeamMemberUserID})
	}
	if p.domains != nil {
		t = append(t, auth.UserTable{Table: TableDomainRequest, Column: ColRequestUserID})
	}
	return t
}

// Requires names the email plugin when invitations are addressed by email,
// which they are by default; InviteBy without email, or WithoutInvitations,
// requires nothing.
func (p *Plugin) Requires() []string {
	if p.invitesBy(email.KindEmail) {
		return []string{email.PluginName}
	}
	return nil
}

// invitesBy reports whether invitations are on and may be addressed to kind.
func (p *Plugin) invitesBy(kind auth.IdentifierKindName) bool {
	return !p.noInvitations && slices.Contains(p.inviteKinds, kind)
}

// Validate asserts the plugin can function. Invitations to a kind no plugin
// registers would match nobody, and discovering that at start-up beats
// discovering it when the first invite goes nowhere. Requires only checks
// plugin names, so every kind is checked here too: a plugin that is merely
// named "email" does not make invitations deliverable.
func (p *Plugin) Validate(c *auth.Config) error {
	if p.hooksSet && p.hooksFrom != nil {
		return errors.New("organization: give WithHooks or WithHooksFrom, not both")
	}
	if !p.noInvitations {
		if err := p.validateInvitations(c); err != nil {
			return err
		}
	}
	if p.ac == nil {
		return errors.New("organization: WithAccessControl needs an access control")
	}
	if _, ok := p.roles[p.creatorRole]; !ok || len(p.creatorRole.Parts()) != 1 {
		return fmt.Errorf("organization: CreatorRole %q is not a static role", p.creatorRole)
	}
	for name, r := range p.roles {
		if len(name.Parts()) != 1 || string(name) != strings.TrimSpace(string(name)) {
			return fmt.Errorf("organization: role name %q must be one name without commas", name)
		}
		if err := p.ac.Check(r.Permissions()); err != nil {
			return fmt.Errorf("organization: role %q: %w", name, err)
		}
	}
	if p.invitationLimit < 0 {
		return errors.New("organization: InvitationLimit cannot be negative")
	}
	if p.teams != nil && (p.teams.MaxTeams < 0 || p.teams.MaxMembersPerTeam < 0) {
		return errors.New("organization: team limits cannot be negative")
	}
	if p.dynamic != nil && p.dynamic.MaxRoles < 0 {
		return errors.New("organization: DynamicRolesConfig.MaxRoles cannot be negative")
	}
	if p.domains != nil {
		if err := p.validateDomains(); err != nil {
			return err
		}
	}
	return p.validateFields()
}

// validateInvitations checks what the invitation operations need: at least
// one kind, each registered by a plugin that delivers, a link, and a
// positive rate rule.
func (p *Plugin) validateInvitations(c *auth.Config) error {
	if len(p.inviteKinds) == 0 {
		return errors.New("organization: InviteBy needs at least one identifier kind; use WithoutInvitations to turn invitations off")
	}
	for _, k := range p.inviteKinds {
		switch {
		case c.CanDeliver(k):
			continue
		case c.HasIdentifier(k):
			return fmt.Errorf("organization.InviteBy: invitations are addressed by %q, whose plugin cannot deliver messages: %w", k, auth.ErrNoDeliverer)
		case k == email.KindEmail:
			return errors.New("organization.InviteBy: invitations are addressed by email; add the email plugin")
		}
		return fmt.Errorf("organization.InviteBy: invitations are addressed by %q, which no plugin registers", k)
	}
	if p.links == nil && c.BaseURL == "" {
		return errors.New("organization: invitation links need auth.WithBaseURL or organization.InviteLink")
	}
	if p.inviteLimit < 1 || p.inviteWindow <= 0 {
		return errors.New("organization: InviteLimit needs a positive limit and window")
	}
	return nil
}

// Init captures the core handle, builds WithHooksFrom's hooks and, when no
// InviteLink was given, fixes the invitation link to BaseURL +
// DefaultInvitePage.
func (p *Plugin) Init(a *auth.Auth) error {
	p.core = a
	if p.hooksFrom != nil {
		p.hooks = p.hooksFrom(a)
	}
	if p.links == nil {
		base := strings.TrimSuffix(a.Config().BaseURL, "/")
		p.links = func() string { return base + DefaultInvitePage }
	}
	return nil
}

// Operations lists every operation; the team and role operations only when
// their option is on, so a route that cannot work is never mounted.
func (p *Plugin) Operations() []auth.Operation {
	ops := []auth.Operation{
		p.create, p.list, p.members, p.invite, p.invites, p.accept, p.removeMember, p.setRole, p.checkSlug, p.invitation, p.role,
		p.get, p.getFull, p.update, p.deleteOrg, p.setActive, p.active, p.reject, p.cancel, p.listInvitations, p.hasPermission,
	}
	if p.noInvitations {
		invitation := []auth.Operation{p.invite, p.invites, p.accept, p.invitation, p.reject, p.cancel, p.listInvitations}
		ops = slices.DeleteFunc(ops, func(o auth.Operation) bool { return slices.Contains(invitation, o) })
	}
	if p.teams != nil {
		ops = append(ops, p.createTeam, p.listTeams, p.updateTeam, p.removeTeam, p.setActiveTeam, p.listUserTeams, p.listTeamMembers, p.addTeamMember, p.removeTeamMember)
	}
	if p.dynamic != nil {
		ops = append(ops, p.createRole, p.updateRole, p.deleteRole, p.getRole, p.listRoles)
	}
	if p.domains != nil {
		ops = append(ops, p.domainOps()...)
	}
	return ops
}

// RateLimits bounds invitation mail (none without invitations, whose
// operation the rule would name) and verify-domain's DNS lookups.
func (p *Plugin) RateLimits() []auth.RateRule {
	var rules []auth.RateRule
	if !p.noInvitations {
		rules = append(rules, auth.RateRule{Match: EndpointInvite, Key: auth.ByIP, Limit: p.inviteLimit, Window: p.inviteWindow})
	}
	if p.domains != nil {
		rules = append(rules, auth.RateRule{Match: EndpointVerifyDomain, Key: auth.ByIP, Limit: DefaultVerifyLimit, Window: DefaultVerifyWindow})
	}
	return rules
}

// TypedMigrations creates the tables for engine, or fails for an engine the core
// does not support. 0001 is the shipped schema; 0002 adds the organization's
// logo and metadata and the invitation's status and team; 0003 the active
// selection; 0004 and 0005 the team and role tables when their option is on;
// 0006 the invitation's identifier kind and value (InviteBy); 0007 the
// domain tables when Domains is on.
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	org := p.core.TableName(TableOrg)
	invite := p.core.TableName(TableInvite)
	st := []string{
		"CREATE TABLE IF NOT EXISTS " + org + " (" +
			ColOrgID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColOrgSlug + " " + t.Key + " NOT NULL UNIQUE, " +
			ColOrgName + " " + t.Text + " NOT NULL, " +
			ColOrgCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableMember) + " (" +
			ColMemberOrgID + " " + t.ID + " NOT NULL, " +
			ColMemberUserID + " " + t.ID + " NOT NULL, " +
			ColMemberRole + " " + t.Key + " NOT NULL, " +
			ColMemberJoinedAt + " " + t.Timestamp + " NOT NULL, " +
			"PRIMARY KEY (" + ColMemberOrgID + ", " + ColMemberUserID + "))" + t.TableSuffix,
		"CREATE TABLE IF NOT EXISTS " + invite + " (" +
			ColInviteID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColInviteOrgID + " " + t.ID + " NOT NULL, " +
			ColInviteEmail + " " + t.Value + " NOT NULL, " +
			ColInviteRole + " " + t.Key + " NOT NULL, " +
			ColInviteInvitedBy + " " + t.ID + " NOT NULL, " +
			ColInviteExpiresAt + " " + t.Timestamp + " NOT NULL, " +
			ColInviteAccepted + " " + t.Timestamp + " NULL, " +
			ColInviteCreatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
	}
	fields := []string{
		"ALTER TABLE " + org + " ADD COLUMN " + ColOrgLogo + " " + t.Long + " NULL",
		"ALTER TABLE " + org + " ADD COLUMN " + ColOrgMetadata + " " + t.Doc + " NULL",
		"ALTER TABLE " + invite + " ADD COLUMN " + ColInviteStatus + " " + t.Key + " NOT NULL DEFAULT '" + string(StatusPending) + "'",
		"ALTER TABLE " + invite + " ADD COLUMN " + ColInviteTeamID + " " + t.ID + " NULL",
		// Invitations accepted before the status existed say so.
		"UPDATE " + invite + " SET " + ColInviteStatus + " = '" + string(StatusAccepted) + "' WHERE " + ColInviteAccepted + " IS NOT NULL",
	}
	active := p.core.TableName(TableActive)
	index := active + indexUserSuffix
	createActive := "CREATE TABLE IF NOT EXISTS " + active + " (" +
		ColActiveSessionID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
		ColActiveUserID + " " + t.ID + " NOT NULL, " +
		ColActiveOrgID + " " + t.ID + " NULL, " +
		ColActiveTeamID + " " + t.ID + " NULL, " +
		ColActiveExpiresAt + " " + t.Timestamp + " NOT NULL"
	var activeSt []string
	if engine == auth.EngineMySQL {
		// MySQL has no CREATE INDEX IF NOT EXISTS, so the index is declared
		// inside the CREATE TABLE.
		activeSt = []string{createActive + ", INDEX " + index + " (" + ColActiveUserID + "))" + t.TableSuffix}
	} else {
		activeSt = []string{createActive + ")" + t.TableSuffix, "CREATE INDEX IF NOT EXISTS " + index + " ON " + active + " (" + ColActiveUserID + ")"}
	}
	out := []auth.Migration{
		{Owner: PluginName, Name: migrationName, Statements: st},
		{Owner: PluginName, Name: migrationFields, Statements: fields},
		{Owner: PluginName, Name: migrationActive, Statements: activeSt},
	}
	if p.teams != nil {
		out = append(out, auth.Migration{Owner: PluginName, Name: migrationTeams, Statements: []string{
			"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableTeam) + " (" +
				ColTeamID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
				ColTeamOrgID + " " + t.ID + " NOT NULL, " +
				ColTeamName + " " + t.Text + " NOT NULL, " +
				ColTeamCreatedAt + " " + t.Timestamp + " NOT NULL, " +
				ColTeamUpdatedAt + " " + t.Timestamp + " NOT NULL)" + t.TableSuffix,
			"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableTeamMember) + " (" +
				ColTeamMemberTeamID + " " + t.ID + " NOT NULL, " +
				ColTeamMemberUserID + " " + t.ID + " NOT NULL, " +
				ColTeamMemberCreatedAt + " " + t.Timestamp + " NOT NULL, " +
				"PRIMARY KEY (" + ColTeamMemberTeamID + ", " + ColTeamMemberUserID + "))" + t.TableSuffix,
		}})
	}
	if p.dynamic != nil {
		out = append(out, auth.Migration{Owner: PluginName, Name: migrationRoles, Statements: []string{
			"CREATE TABLE IF NOT EXISTS " + p.core.TableName(TableRole) + " (" +
				ColRoleID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
				ColRoleOrgID + " " + t.ID + " NOT NULL, " +
				ColRoleName + " " + t.Key + " NOT NULL, " +
				ColRolePermission + " " + t.Doc + " NOT NULL, " +
				ColRoleCreatedAt + " " + t.Timestamp + " NOT NULL, " +
				ColRoleUpdatedAt + " " + t.Timestamp + " NOT NULL, " +
				"UNIQUE (" + ColRoleOrgID + ", " + ColRoleName + "))" + t.TableSuffix,
		}})
	}
	out = append(out, auth.Migration{Owner: PluginName, Name: migrationIdentifier, Statements: []string{
		// Every invitation made before this was addressed by email, which is
		// what the default and the copy say.
		"ALTER TABLE " + invite + " ADD COLUMN " + ColInviteKind + " " + t.Key + " NOT NULL DEFAULT '" + string(email.KindEmail) + "'",
		"ALTER TABLE " + invite + " ADD COLUMN " + ColInviteIdentifier + " " + t.Value + " NOT NULL DEFAULT ''",
		"UPDATE " + invite + " SET " + ColInviteIdentifier + " = " + ColInviteEmail,
	}})
	if p.domains != nil {
		out = append(out, p.domainMigration(t))
	}
	return append(out, p.fieldMigrations(t)...), nil
}

// CreateRequest is the input of create.
type CreateRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
	// Logo and Metadata are optional (Org).
	Logo     *string      `json:"logo,omitempty"`
	Metadata auth.AppData `json:"metadata,omitempty"`
	// KeepActive leaves the session's active organization as it is; by
	// default the new organization becomes active
	// (keepCurrentActiveOrganization).
	KeepActive bool `json:"keepCurrentActiveOrganization,omitempty"`
	// Fields set the organization's extra columns (WithFields).
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds top-level body keys for fieldSet.merge; never set from Go.
	top auth.Fields
}

// OrgRequest names an organization, as the input of members, role, delete
// and the list operations; an empty OrgID means the session's active
// organization. Page and Limit page the members list (strings in JSON
// because a Query's input arrives as URL values); Sort and Filter order and
// narrow it. All but OrgID are optional.
type OrgRequest struct {
	OrgID string `json:"orgId,omitempty"`
	Page  int    `json:"page,omitempty,string"`
	Limit int    `json:"limit,omitempty,string"`
	// SortBy and SortDirection order the members list (MemberSort,
	// DefaultMemberSort ascending by default).
	SortBy        MemberSort `json:"sortBy,omitempty"`
	SortDirection Direction  `json:"sortDirection,omitempty"`
	// FilterField, FilterOperator and FilterValue narrow the members list:
	// in and not_in compare with each of the comma-separated values, and a
	// joinedAt/createdAt value is RFC 3339 (memberFilter).
	FilterField    MemberField    `json:"filterField,omitempty"`
	FilterOperator FilterOperator `json:"filterOperator,omitempty"`
	FilterValue    string         `json:"filterValue,omitempty"`
}

// SlugRequest is the input of check-slug.
type SlugRequest struct {
	Slug string `json:"slug"`
}

// SlugResult says whether a slug may be used, and the normalized form that
// create would store. A slug that fails SlugPattern is not available.
type SlugResult struct {
	Slug      string `json:"slug"`
	Available bool   `json:"available"`
}

// RoleResult is the output of role: the caller's role in the organization.
type RoleResult struct {
	Role Role `json:"role"`
}

// ListResult is the output of list.
type ListResult struct {
	Orgs []OrgWithRole `json:"orgs"`
}

// OrgWithRole is one organization and the caller's role in it.
type OrgWithRole struct {
	Org
	Role Role `json:"role"`
}

// MemberView is one row of members, with the user reduced to the fields safe
// to show another member.
type MemberView struct {
	User     auth.UserView `json:"user"`
	Role     Role          `json:"role"`
	JoinedAt time.Time     `json:"joinedAt"`
	// Fields are the member's extra columns (WithFields).
	Fields auth.Fields `json:"fields,omitempty"`
}

// MembersResult is the output of members.
type MembersResult struct {
	Members []MemberView `json:"members"`
	// Total counts every member; Page and Limit are the values used.
	Total int64 `json:"total"`
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
}

// InviteRequest is the input of invite. The invitee is Email or, for any kind
// InviteBy allows, Kind and Identifier; a Kind left empty is InviteBy's first
// kind. Naming both Email and an Identifier, or a kind InviteBy does not
// allow, is ErrInviteAddress. The value is normalized by its kind before it
// is stored; an empty OrgID means the session's active organization. Role may
// hold several roles (a JSON array or a comma-joined string), and only a
// holder of the creator role may invite with it. TeamID, with Teams on, also
// joins the invitee to that team of the organization on acceptance.
type InviteRequest struct {
	OrgID      string                  `json:"orgId,omitempty"`
	Email      string                  `json:"email,omitempty"`
	Kind       auth.IdentifierKindName `json:"kind,omitempty"`
	Identifier string                  `json:"identifier,omitempty"`
	Role       Role                    `json:"role"`
	TeamID     string                  `json:"teamId,omitempty"`
	// Resend, when the address already holds a pending invitation to the
	// organization, sends that invitation again with a fresh expiry instead
	// of creating another. The existing invitation
	// keeps its id, role and team; Role must still be one the caller may
	// invite with. With no pending invitation it is an ordinary invite.
	Resend bool `json:"resend,omitempty"`
	// Fields set the invitation's extra columns (WithFields).
	Fields auth.Fields `json:"fields,omitempty"`
	// top holds top-level body keys for fieldSet.merge; never set from Go.
	top auth.Fields
}

// InvitesResult is the output of invites.
type InvitesResult struct {
	Invites []Invite `json:"invites"`
}

// AcceptRequest names an invitation, as the input of accept, reject, cancel
// and invitation.
type AcceptRequest struct {
	InviteID string `json:"inviteId"`
}

// MemberRequest names a member of an organization, as the input of
// remove-member.
type MemberRequest struct {
	OrgID  string `json:"orgId,omitempty"`
	UserID string `json:"userId,omitempty"`
	// Email names the member by a verified address instead of UserID, for a
	// settings page that lists addresses. An address nobody verified is
	// `organization.not_member`, the same as an unknown user id. Kind and
	// Identifier do the same for any identifier kind, such as a verified
	// phone number; naming both Email and an Identifier is ErrInviteAddress.
	Email      string                  `json:"email,omitempty"`
	Kind       auth.IdentifierKindName `json:"kind,omitempty"`
	Identifier string                  `json:"identifier,omitempty"`
}

// SetRoleRequest is the input of set-role. Role may hold several roles.
type SetRoleRequest struct {
	OrgID  string `json:"orgId,omitempty"`
	UserID string `json:"userId"`
	Role   Role   `json:"role"`
}

// UnmarshalJSON accepts a role as a string ("admin" or "admin,billing") or,
// for several, an array of strings.
func (r *Role) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*r = Role(one)
		return nil
	}
	var many []Role
	if err := json.Unmarshal(b, &many); err != nil {
		return ErrBadRole
	}
	*r = JoinRoles(many...)
	return nil
}

// Create makes an organization with the signed-in user as its owner.
func (p *Plugin) Create(ctx context.Context, in CreateRequest) (Org, error) {
	return p.create.Call(ctx, in)
}

// List returns the signed-in user's organizations.
func (p *Plugin) List(ctx context.Context) ([]OrgWithRole, error) {
	r, err := p.list.Call(ctx, struct{}{})
	return r.Orgs, err
}

// Members lists an organization the signed-in user belongs to.
func (p *Plugin) Members(ctx context.Context, orgID string) ([]MemberView, error) {
	r, err := p.members.Call(ctx, OrgRequest{OrgID: orgID})
	return r.Members, err
}

// ListMembers is Members with paging, sort and filter.
func (p *Plugin) ListMembers(ctx context.Context, in OrgRequest) (MembersResult, error) {
	return p.members.Call(ctx, in)
}

// Invite records an invitation for an address and mails it, as a signed-in
// member allowed to create invitations.
func (p *Plugin) Invite(ctx context.Context, in InviteRequest) error {
	_, err := p.invite.Call(ctx, in)
	return err
}

// Invites lists the invitations the signed-in user may accept.
func (p *Plugin) Invites(ctx context.Context) ([]Invite, error) {
	r, err := p.invites.Call(ctx, struct{}{})
	return r.Invites, err
}

// Accept accepts an invitation.
func (p *Plugin) Accept(ctx context.Context, inviteID string) (Org, error) {
	return p.accept.Call(ctx, AcceptRequest{InviteID: inviteID})
}

// RemoveMember removes a member, or lets the caller leave; see
// doRemoveMember for who may remove whom.
func (p *Plugin) RemoveMember(ctx context.Context, in MemberRequest) error {
	_, err := p.removeMember.Call(ctx, in)
	return err
}

// SetRole changes a member's role, as a signed-in member allowed to update
// members.
func (p *Plugin) SetRole(ctx context.Context, in SetRoleRequest) error {
	_, err := p.setRole.Call(ctx, in)
	return err
}

// CheckSlug says whether a slug is free, as the signed-in user.
func (p *Plugin) CheckSlug(ctx context.Context, slug string) (SlugResult, error) {
	return p.checkSlug.Call(ctx, SlugRequest{Slug: slug})
}

// Invitation returns one of the signed-in user's pending invitations by id,
// for an accept page; ErrInviteInvalid for any other id.
func (p *Plugin) Invitation(ctx context.Context, inviteID string) (Invite, error) {
	return p.invitation.Call(ctx, AcceptRequest{InviteID: inviteID})
}

// Role returns the signed-in user's role in an organization, or ErrNotMember.
func (p *Plugin) Role(ctx context.Context, orgID string) (Role, error) {
	r, err := p.role.Call(ctx, OrgRequest{OrgID: orgID})
	return r.Role, err
}

// CreateFor makes an organization owned by userID, from Go only: a seed, an
// import, a sign-up flow that creates the user's workspace. The CreateGate
// and MaxOwned do not apply, because the caller is trusted code, not a
// request; the slug rules and the hooks do. No session's active
// organization changes. It runs in one transaction (joining the caller's,
// if any), so a failing hook leaves nothing behind.
func (p *Plugin) CreateFor(ctx context.Context, userID string, in CreateRequest) (o Org, err error) {
	err = p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		u, err := p.core.User(ctx, userID)
		if err != nil {
			return err
		}
		o, err = p.createOrg(ctx, u, in, false)
		return err
	})
	return o, err
}

// AddMember adds a user to an organization with role, from Go only, without
// an invitation: an import, or a product that joins users to a workspace by
// rule. Someone already in the organization keeps their role, or is refused
// with RejectExistingMembers. MaxMembers and the member hooks apply. It runs
// in one transaction (joining the caller's, if any), like CreateFor.
func (p *Plugin) AddMember(ctx context.Context, orgID, userID string, role Role) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error { return p.addMemberTx(ctx, orgID, userID, role, nil) })
}

// addMemberTx is AddMember inside its transaction.
func (p *Plugin) addMemberTx(ctx context.Context, orgID, userID string, role Role, fields auth.Fields) error {
	if _, err := p.org(ctx, orgID); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return ErrNotMember
		}
		return err
	}
	if err := p.checkRole(ctx, orgID, role); err != nil {
		return err
	}
	if _, err := p.core.User(ctx, userID); err != nil {
		return err
	}
	if p.rejectMembers {
		if err := p.refuseMember(ctx, orgID, userID); err != nil {
			return err
		}
	}
	return p.join(ctx, orgID, userID, role, fields)
}

// AddMemberRequest is AddMemberWith's input: AddMember with the member's
// extra columns (WithFields).
type AddMemberRequest struct {
	OrgID  string
	UserID string
	Role   Role
	Fields auth.Fields
}

// AddMemberWith is AddMember with member fields, from Go only (a
// server-side add with extra fields); ServerOnly fields are
// allowed, since the caller is trusted code.
func (p *Plugin) AddMemberWith(ctx context.Context, in AddMemberRequest) error {
	return p.core.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		return p.addMemberTx(ctx, in.OrgID, in.UserID, in.Role, in.Fields)
	})
}

// refuseMember is ErrAlreadyMember when userID belongs to orgID, nil when
// they do not, and the database's error when it cannot tell.
func (p *Plugin) refuseMember(ctx context.Context, orgID, userID string) error {
	switch _, err := p.RoleOf(ctx, orgID, userID); {
	case err == nil:
		return ErrAlreadyMember
	case errors.Is(err, ErrNotMember):
		return nil
	default:
		return err
	}
}

// builtQuery is a statement that has already been built: the (Query, error)
// pair MembersQuery, PendingInvitesQuery and MembershipQuery return, so they
// run through the core's Exec/One/Each like any builder. Those functions
// return the built Query because they are exported for an app to run itself.
type builtQuery struct {
	q   sqlb.Query
	err error
}

func (b builtQuery) Build() (sqlb.Query, error) { return b.q, b.err }

// built adapts the result of an exported *Query function to auth.Statement.
func built(q sqlb.Query, err error) auth.Statement { return builtQuery{q: q, err: err} }

// normalizeSlug is the one place a slug is folded: create and check-slug
// must agree on what is stored. Empty when the slug is not acceptable.
func normalizeSlug(raw string) string {
	slug := strings.ToLower(strings.TrimSpace(raw))
	if !SlugPattern.MatchString(slug) {
		return ""
	}
	return slug
}

// checkMetadata accepts no metadata, or a JSON object within
// MaxMetadataSize. An object because metadata is a record, and
// a bare number or string would leave the app nowhere to add a second key.
func checkMetadata(d auth.AppData) error {
	if len(d) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if len(d) > MaxMetadataSize || json.Unmarshal(d, &obj) != nil || obj == nil {
		return ErrBadMetadata
	}
	return nil
}

// doCreate applies the gate and the ownership cap, then creates, and makes
// the new organization the session's active one unless KeepActive.
func (p *Plugin) doCreate(ctx context.Context, c *auth.Call, in CreateRequest) (Org, error) {
	if p.createGate != nil {
		ok, err := p.createGate(ctx, *c.User)
		if err != nil {
			return Org{}, err
		}
		if !ok {
			return Org{}, ErrCreateForbidden
		}
	}
	if p.maxOwned > 0 {
		n, err := p.ownedCount(ctx, c.User.ID)
		if err != nil {
			return Org{}, err
		}
		if n >= int64(p.maxOwned) {
			return Org{}, ErrLimitReached
		}
	}
	o, err := p.createOrg(ctx, *c.User, in, fromClient(c))
	if err != nil {
		return Org{}, err
	}
	c.Annotate(auth.AnnotationOrganization, o.ID)
	if !in.KeepActive && c.Session != nil && c.Session.APIKeyID == "" {
		if err := p.writeActive(ctx, *c.Session, &o.ID, nil); err != nil {
			return Org{}, err
		}
	}
	return o, nil
}

// createOrg inserts the organization, its creator with the creator role and,
// with Teams, its default team, between the organization hooks.
func (p *Plugin) createOrg(ctx context.Context, creator auth.User, in CreateRequest, client bool) (Org, error) {
	slug := normalizeSlug(in.Slug)
	if slug == "" {
		return Org{}, ErrBadSlug
	}
	if err := checkMetadata(in.Metadata); err != nil {
		return Org{}, err
	}
	fs := p.orgFields()
	fields, err := fs.merge(in.Fields, in.top)
	if err != nil {
		return Org{}, err
	}
	in.Fields = fields
	if _, err := fs.set(in.Fields, client, true); err != nil {
		return Org{}, err
	}
	id, err := p.core.NewID(idPrefixOrg)
	if err != nil {
		return Org{}, err
	}
	o := Org{ID: id, Slug: slug, Name: strings.TrimSpace(in.Name), Logo: in.Logo, Metadata: in.Metadata, CreatedAt: p.core.Now(), Fields: in.Fields}
	if h := p.hooks.BeforeCreateOrg; h != nil {
		if err := h(ctx, &o, creator); err != nil {
			return Org{}, err
		}
		// A hook may change the slug; it is held to the same rules.
		if o.Slug = normalizeSlug(o.Slug); o.Slug == "" {
			return Org{}, ErrBadSlug
		}
		if err := checkMetadata(o.Metadata); err != nil {
			return Org{}, err
		}
	}
	// The hook may set any field, server-only ones included.
	extra, err := fs.set(o.Fields, false, true)
	if err != nil {
		return Org{}, err
	}
	ins := sqlb.NewInsert(p.core.Dialect()).Into(TableOrg).Row(append([]sqlb.Assignment{sqlb.Set(OrgID, o.ID), sqlb.Set(OrgSlug, o.Slug), sqlb.Set(OrgName, o.Name),
		sqlb.Set(OrgLogo, o.Logo), sqlb.Set(OrgMetadata, o.Metadata), sqlb.Set(OrgCreatedAt, o.CreatedAt)}, extra...)...)
	if _, err := p.core.Exec(ctx, ins); err != nil {
		if auth.IsUniqueViolation(err) {
			return Org{}, ErrSlugTaken
		}
		return Org{}, err
	}
	if len(fs.fields) > 0 {
		// Read back, so the fields come back as stored, defaults included.
		if o, err = p.org(ctx, o.ID); err != nil {
			return Org{}, err
		}
	}
	if err := p.addMember(ctx, o.ID, creator.ID, p.creatorRole, nil); err != nil {
		return Org{}, err
	}
	if p.teams != nil && !p.teams.NoDefaultTeam {
		if err := p.createDefaultTeam(ctx, o, creator); err != nil {
			return Org{}, err
		}
	}
	if h := p.hooks.AfterCreateOrg; h != nil {
		if err := h(ctx, o, creator); err != nil {
			return Org{}, err
		}
	}
	return o, nil
}

// doCheckSlug answers whether create would accept the slug. It reads only
// the slug column, and a taken slug is public anyway (it is in URLs), so
// the answer leaks nothing.
func (p *Plugin) doCheckSlug(ctx context.Context, _ *auth.Call, in SlugRequest) (SlugResult, error) {
	slug := normalizeSlug(in.Slug)
	if slug == "" {
		return SlugResult{Slug: strings.ToLower(strings.TrimSpace(in.Slug))}, nil
	}
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableOrg).Where(sqlb.Eq(OrgSlug, slug))
	if err := p.core.One(ctx, q); err != nil {
		return SlugResult{}, err
	}
	return SlugResult{Slug: slug, Available: n == 0}, nil
}

// doRole answers the caller's own role (the active member role);
// a non-member gets ErrNotMember like everywhere else.
func (p *Plugin) doRole(ctx context.Context, c *auth.Call, in OrgRequest) (RoleResult, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return RoleResult{}, err
	}
	r, err := p.RoleOf(ctx, orgID, c.User.ID)
	return RoleResult{Role: r}, err
}

// doInvitation returns one pending invitation of the caller, by id, through
// the same verified-address match as accept.
func (p *Plugin) doInvitation(ctx context.Context, c *auth.Call, in AcceptRequest) (Invite, error) {
	inv, err := p.pendingByID(ctx, c.User.ID, in.InviteID)
	if err != nil {
		return Invite{}, err
	}
	return *inv, nil
}

// pendingByID finds one of userID's pending invitations by id, or
// ErrInviteInvalid.
func (p *Plugin) pendingByID(ctx context.Context, userID, inviteID string) (*Invite, error) {
	list, err := p.pending(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == inviteID {
			return &list[i], nil
		}
	}
	return nil, ErrInviteInvalid
}

// ownedCount counts the organizations userID holds the creator role in.
func (p *Plugin) ownedCount(ctx context.Context, userID string) (int64, error) {
	return p.countHolders(ctx, sqlb.Eq(MemberUserID, userID))
}

// countHolders counts the memberships matching where whose role holds the
// creator role. The roles are split in Go rather than matched with LIKE in
// SQL, so the comparison is exact on every engine (SQLite's LIKE ignores
// case) and a role name with % or _ in it means itself.
func (p *Plugin) countHolders(ctx context.Context, where sqlb.Predicate) (int64, error) {
	var r Role
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(MemberRole, &r)).From(TableMember).Where(where)
	err := p.core.Each(ctx, q, func() error {
		if r.Has(p.creatorRole) {
			n++
		}
		return nil
	})
	return n, err
}

// memberCount counts an organization's members.
func (p *Plugin) memberCount(ctx context.Context, orgID string) (int64, error) {
	var n int64
	q := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableMember).Where(sqlb.Eq(MemberOrgID, orgID))
	return n, p.core.One(ctx, q)
}

// join adds userID to orgID unless they are a member already, applying
// MaxMembers and the member hooks. Checked first rather than by catching the
// duplicate insert, which would abort the transaction on Postgres.
func (p *Plugin) join(ctx context.Context, orgID, userID string, role Role, fields auth.Fields) error {
	switch _, err := p.RoleOf(ctx, orgID, userID); {
	case err == nil:
		return nil // already a member: the role stays
	case !errors.Is(err, ErrNotMember):
		return err
	}
	if p.maxMembers > 0 {
		n, err := p.memberCount(ctx, orgID)
		if err != nil {
			return err
		}
		if n >= int64(p.maxMembers) {
			return ErrMembersLimit
		}
	}
	m := MemberChange{OrgID: orgID, UserID: userID, Role: role, Fields: fields}
	if h := p.hooks.BeforeAddMember; h != nil {
		if err := h(ctx, &m); err != nil {
			return err
		}
		if err := p.checkRole(ctx, orgID, m.Role); err != nil {
			return err
		}
	}
	if err := p.addMember(ctx, orgID, userID, m.Role, m.Fields); err != nil {
		return err
	}
	if h := p.hooks.AfterAddMember; h != nil {
		return h(ctx, m)
	}
	return nil
}

// addMember inserts a membership. Callers make sure the user is not already a
// member: a duplicate insert fails, and on Postgres a failed statement aborts
// the whole transaction, so it cannot be caught and stepped over.
func (p *Plugin) addMember(ctx context.Context, orgID, userID string, role Role, fields auth.Fields) error {
	extra, err := p.memberFields().set(fields, false, false)
	if err != nil {
		return err
	}
	q := sqlb.NewInsert(p.core.Dialect()).Into(TableMember).Row(append([]sqlb.Assignment{
		sqlb.Set(MemberOrgID, orgID), sqlb.Set(MemberUserID, userID), sqlb.Set(MemberRole, JoinRoles(role)), sqlb.Set(MemberJoinedAt, p.core.Now()),
	}, extra...)...)
	_, err = p.core.Exec(ctx, q)
	return err
}

func (p *Plugin) doList(ctx context.Context, c *auth.Call, _ struct{}) (ListResult, error) {
	var row OrgWithRole
	cols, done := p.orgCols(&row.Org)
	q := c.Auth.Select().Columns(append(cols, sqlb.Bind(MemberRole, &row.Role))...).From(TableMember).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: TableOrg, On: []sqlb.Predicate{sqlb.EqExpr(OrgID, MemberOrgID)}}).
		Where(sqlb.Eq(MemberUserID, c.User.ID)).Order(sqlb.OrderBy(OrgName, sqlb.SortAsc))
	out := ListResult{Orgs: []OrgWithRole{}}
	err := p.core.Each(ctx, q, func() error { done(); out.Orgs = append(out.Orgs, row); return nil })
	return out, err
}

// RoleOf returns userID's role in orgID, or ErrNotMember.
func (p *Plugin) RoleOf(ctx context.Context, orgID, userID string) (Role, error) {
	var r Role
	if err := p.core.One(ctx, built(MembershipQuery(p.core, orgID, userID, &r))); err != nil {
		if errors.Is(err, sqlb.ErrNoRows) {
			return "", ErrNotMember
		}
		return "", err
	}
	return r, nil
}

func (p *Plugin) doMembers(ctx context.Context, c *auth.Call, in OrgRequest) (MembersResult, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return MembersResult{}, err
	}
	if _, err := p.RoleOf(ctx, orgID, c.User.ID); err != nil {
		return MembersResult{}, err
	}
	return p.membersPage(ctx, orgID, in)
}

// membersPage is one page of orgID's members with in's sort and filter.
func (p *Plugin) membersPage(ctx context.Context, orgID string, in OrgRequest) (MembersResult, error) {
	order, err := memberOrder(in.SortBy, in.SortDirection)
	if err != nil {
		return MembersResult{}, err
	}
	where := []sqlb.Predicate{sqlb.Eq(MemberOrgID, orgID)}
	if in.FilterField != "" {
		f, err := memberFilter(p.core.Engine(), in.FilterField, in.FilterOperator, in.FilterValue)
		if err != nil {
			return MembersResult{}, err
		}
		where = append(where, f)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = DefaultMembersPage
	}
	if limit > MaxMembersPage {
		limit = MaxMembersPage
	}
	page := max(in.Page, 1)
	out := MembersResult{Members: []MemberView{}, Page: page, Limit: limit}
	err = p.eachMember(ctx, where, order, limit, (page-1)*limit, func(v MemberView) { out.Members = append(out.Members, v) })
	if err != nil {
		return MembersResult{}, err
	}
	cq := p.core.Select().Columns(sqlb.Bind(sqlb.Count(), &out.Total)).From(TableMember).
		Join(sqlb.Join{Type: sqlb.JoinInner, Table: auth.TableUser, On: []sqlb.Predicate{sqlb.EqExpr(auth.UserID, MemberUserID)}}).
		Where(where...)
	return out, p.core.One(ctx, cq)
}

// doInvite needs invitation:create, and only a holder of the creator role
// may invite with it. The address is stored normalized, so the
// verified-identity match at accept time is an exact comparison.
func (p *Plugin) doInvite(ctx context.Context, c *auth.Call, in InviteRequest) (auth.Done, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return auth.Done{}, err
	}
	mine, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.checkRole(ctx, orgID, in.Role); err != nil {
		return auth.Done{}, err
	}
	if err := p.authorize(ctx, c, orgID, mine, access.Request{ResourceInvitation: access.All(ActionCreate)}); err != nil {
		return auth.Done{}, err
	}
	if err := p.guardCreator(mine, in.Role); err != nil {
		return auth.Done{}, err
	}
	kind, addr, err := p.inviteAddress(c, in)
	if err != nil {
		return auth.Done{}, err
	}
	invFields := p.invitationFields()
	if in.Fields, err = invFields.merge(in.Fields, in.top); err != nil {
		return auth.Done{}, err
	}
	if _, err := invFields.set(in.Fields, fromClient(c), true); err != nil {
		return auth.Done{}, err
	}
	var teamID *string
	if in.TeamID != "" {
		if p.teams == nil {
			return auth.Done{}, ErrTeamNotFound
		}
		if _, err := p.teamIn(ctx, orgID, in.TeamID); err != nil {
			return auth.Done{}, err
		}
		teamID = &in.TeamID
	}
	if p.rejectMembers {
		switch idn, err := c.Auth.FindIdentity(ctx, kind, addr, false); {
		case err == nil:
			if err := p.refuseMember(ctx, orgID, idn.UserID); err != nil {
				return auth.Done{}, err
			}
		case !errors.Is(err, auth.ErrIdentityNotFound):
			return auth.Done{}, err
		}
	}
	org, err := p.org(ctx, orgID)
	if err != nil {
		return auth.Done{}, err
	}
	if in.Resend || (p.refuseRepeat && !p.replacePending) {
		open, err := p.invitations(ctx, orgID, sqlb.Eq(InviteKind, kind), sqlb.Eq(InviteIdent, addr), sqlb.Eq(InviteStatusCol, StatusPending), sqlb.Greater(InviteExpiresAt, c.Auth.Now()))
		if err != nil {
			return auth.Done{}, err
		}
		switch {
		case len(open) > 0 && in.Resend:
			// The invitation keeps its own role, so the creator-role rule
			// is checked against that role too.
			if err := p.guardCreator(mine, open[0].Role); err != nil {
				return auth.Done{}, err
			}
			return p.resend(ctx, c, open[0], org)
		case len(open) > 0:
			return auth.Done{}, ErrAlreadyInvited
		}
	}
	if p.replacePending {
		del := sqlb.NewDelete(c.Auth.Dialect()).From(TableInvite).
			Where(sqlb.Eq(InviteOrgID, orgID), sqlb.Eq(InviteKind, kind), sqlb.Eq(InviteIdent, addr), sqlb.Eq(InviteStatusCol, StatusPending))
		if _, err := p.core.Exec(ctx, del); err != nil {
			return auth.Done{}, err
		}
	}
	if p.invitationLimit > 0 {
		var n int64
		q := c.Auth.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(TableInvite).
			Where(sqlb.Eq(InviteOrgID, orgID), sqlb.Eq(InviteStatusCol, StatusPending), sqlb.Greater(InviteExpiresAt, c.Auth.Now()))
		if err := p.core.One(ctx, q); err != nil {
			return auth.Done{}, err
		}
		if n >= int64(p.invitationLimit) {
			return auth.Done{}, ErrInvitationLimit
		}
	}
	id, err := c.Auth.NewID(idPrefixInvite)
	if err != nil {
		return auth.Done{}, err
	}
	now := c.Auth.Now()
	mail := ""
	if kind == email.KindEmail {
		mail = addr
	}
	row := Invitation{ID: id, OrgID: orgID, Email: mail, Kind: kind, Identifier: addr, Role: JoinRoles(in.Role), Status: StatusPending, InviterID: c.User.ID, TeamID: teamID, ExpiresAt: now.Add(p.inviteTTL), CreatedAt: now, Fields: in.Fields}
	if h := p.hooks.BeforeCreateInvitation; h != nil {
		if err := h(ctx, &row, *c.User); err != nil {
			return auth.Done{}, err
		}
		// A hook may change the role or the expiry, never the address or
		// the organization the checks above were made for.
		row.ID, row.OrgID, row.Email, row.Kind, row.Identifier, row.Status, row.InviterID = id, orgID, mail, kind, addr, StatusPending, c.User.ID
		if err := p.checkRole(ctx, orgID, row.Role); err != nil {
			return auth.Done{}, err
		}
		if err := p.guardCreator(mine, row.Role); err != nil {
			return auth.Done{}, err
		}
	}
	extra, err := invFields.set(row.Fields, false, true)
	if err != nil {
		return auth.Done{}, err
	}
	q := sqlb.NewInsert(c.Auth.Dialect()).Into(TableInvite).Row(append([]sqlb.Assignment{
		sqlb.Set(InviteID, row.ID), sqlb.Set(InviteOrgID, row.OrgID), sqlb.Set(InviteEmail, row.Email), sqlb.Set(InviteKind, row.Kind), sqlb.Set(InviteIdent, row.Identifier), sqlb.Set(InviteRole, row.Role),
		sqlb.Set(InviteInvitedBy, row.InviterID), sqlb.Set(InviteExpiresAt, row.ExpiresAt), sqlb.Set(InviteCreatedAt, row.CreatedAt),
		sqlb.Set(InviteStatusCol, row.Status), sqlb.Set(InviteTeamID, row.TeamID),
	}, extra...)...)
	if _, err := p.core.Exec(ctx, q); err != nil {
		return auth.Done{}, err
	}
	if err := p.sendInvite(ctx, c, row, org); err != nil {
		return auth.Done{}, err
	}
	if h := p.hooks.AfterCreateInvitation; h != nil {
		if err := h(ctx, row, *c.User); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, nil
}

// inviteAddress resolves an InviteRequest's invitee to an allowed kind and
// its normalized value (InviteRequest says how).
func (p *Plugin) inviteAddress(c *auth.Call, in InviteRequest) (auth.IdentifierKindName, string, error) {
	kind, raw, err := p.addressOf(in.Email, in.Kind, in.Identifier)
	if err != nil {
		return "", "", err
	}
	if !slices.Contains(p.inviteKinds, kind) {
		return "", "", ErrInviteAddress
	}
	v, err := c.Auth.Normalize(kind, raw)
	return kind, v, err
}

// addressOf picks the kind and raw value a request names: Email is the email
// kind, otherwise Kind (InviteBy's first kind when empty) and Identifier.
// With neither set it is InviteBy's first kind with "", which the kind's
// normalizer refuses as before.
func (p *Plugin) addressOf(mail string, kind auth.IdentifierKindName, raw string) (auth.IdentifierKindName, string, error) {
	if mail != "" {
		if raw != "" || (kind != "" && kind != email.KindEmail) {
			return "", "", ErrInviteAddress
		}
		return email.KindEmail, mail, nil
	}
	if kind == "" {
		if raw != "" && len(p.inviteKinds) > 1 {
			return "", "", ErrInviteAddress
		}
		if len(p.inviteKinds) > 0 {
			kind = p.inviteKinds[0]
		}
	}
	return kind, raw, nil
}

// sendInvite delivers row's invitation to its address through the core's
// Deliver for the address's kind, with InvitationData as the message's typed
// payload.
func (p *Plugin) sendInvite(ctx context.Context, c *auth.Call, row Invitation, org Org) error {
	inv := Invite{ID: row.ID, OrgID: row.OrgID, OrgName: org.Name, Email: row.Email, Kind: row.Kind, Identifier: row.Identifier, Role: row.Role, ExpiresAt: row.ExpiresAt}
	link := p.links()
	subject, text := inviteSubject, inviteTextHead+link
	if p.message != nil {
		subject, text = p.message(InviteMail{Invite: inv, Org: org, Inviter: *c.User, Link: link})
	}
	data, err := p.invitationData(ctx, row, org, *c.User)
	if err != nil {
		return err
	}
	to := auth.Identity{Kind: row.Kind, Value: row.Identifier}
	return c.Auth.Deliver(ctx, to, auth.Message{Purpose: PurposeInvite, Link: link, DefaultSubject: subject, DefaultText: text, Data: data})
}

// resend extends row, a pending invitation, by the invitation lifetime from
// now and mails it again. It counts against no InvitationLimit, because no
// invitation is added; the per-IP InviteLimit still applies to the route.
// The creation hooks do not run, as no invitation is created.
func (p *Plugin) resend(ctx context.Context, c *auth.Call, row Invitation, org Org) (auth.Done, error) {
	row.ExpiresAt = c.Auth.Now().Add(p.inviteTTL)
	upd := sqlb.NewUpdate(c.Auth.Dialect()).Table(TableInvite).Set(sqlb.Set(InviteExpiresAt, row.ExpiresAt)).
		Where(sqlb.Eq(InviteID, row.ID), sqlb.Eq(InviteStatusCol, StatusPending))
	if _, err := p.core.Exec(ctx, upd); err != nil {
		return auth.Done{}, err
	}
	if err := p.sendInvite(ctx, c, row, org); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}

func (p *Plugin) pending(ctx context.Context, userID string) ([]Invite, error) {
	var row Invite
	out := []Invite{}
	err := p.core.Each(ctx, built(PendingInvitesQuery(p.core, userID, p.core.Now(), &row)), func() error { out = append(out, row); return nil })
	return out, err
}

func (p *Plugin) doInvites(ctx context.Context, c *auth.Call, _ struct{}) (InvitesResult, error) {
	list, err := p.pending(ctx, c.User.ID)
	return InvitesResult{Invites: list}, err
}

// doAccept accepts only an invitation from PendingInvitesQuery, which matches
// a VERIFIED address of the caller. Accepting by id alone would let anyone who
// saw an invite id join.
func (p *Plugin) doAccept(ctx context.Context, c *auth.Call, in AcceptRequest) (Org, error) {
	inv, err := p.pendingByID(ctx, c.User.ID, in.InviteID)
	if err != nil {
		return Org{}, err
	}
	c.Annotate(auth.AnnotationOrganization, inv.OrgID)
	row, err := p.invitationRow(ctx, inv.ID)
	if err != nil {
		return Org{}, err
	}
	if h := p.hooks.BeforeAcceptInvitation; h != nil {
		if err := h(ctx, row, *c.User); err != nil {
			return Org{}, err
		}
	}
	now := c.Auth.Now()
	upd := sqlb.NewUpdate(c.Auth.Dialect()).Table(TableInvite).Set(sqlb.Set(InviteAccepted, &now), sqlb.Set(InviteStatusCol, StatusAccepted)).
		Where(sqlb.Eq(InviteID, inv.ID), sqlb.IsNull(InviteAccepted), sqlb.Eq(InviteStatusCol, StatusPending))
	n, err := p.core.Exec(ctx, upd)
	if err != nil {
		return Org{}, err
	}
	if n != 1 {
		return Org{}, ErrInviteInvalid // accepted by a concurrent request
	}
	// Someone already in the organization keeps their role: an invitation
	// never demotes or promotes.
	if err := p.join(ctx, inv.OrgID, c.User.ID, inv.Role, nil); err != nil {
		return Org{}, err
	}
	if row.TeamID != nil && p.teams != nil {
		if err := p.joinTeam(ctx, inv.OrgID, *row.TeamID, c.User.ID); err != nil && !errors.Is(err, ErrTeamNotFound) {
			return Org{}, err
		}
	}
	row.Status = StatusAccepted
	if h := p.hooks.AfterAcceptInvitation; h != nil {
		if err := h(ctx, row, *c.User); err != nil {
			return Org{}, err
		}
	}
	return p.org(ctx, inv.OrgID)
}

func (p *Plugin) org(ctx context.Context, id string) (Org, error) {
	var o Org
	cols, done := p.orgCols(&o)
	q := p.core.Select().Columns(cols...).From(TableOrg).Where(sqlb.Eq(OrgID, id)).Limit(1)
	if err := p.core.One(ctx, q); err != nil {
		return Org{}, err
	}
	done()
	return o, nil
}

// owners counts the members holding the creator role.
func (p *Plugin) owners(ctx context.Context, orgID string) (int64, error) {
	return p.countHolders(ctx, sqlb.Eq(MemberOrgID, orgID))
}

// doRemoveMember lets a member leave, and a member with member:delete remove
// another; only a holder of the creator role may remove one, and the last
// one can do neither to themself. Their team memberships in the
// organization and any session's selection of it go with them.
func (p *Plugin) doRemoveMember(ctx context.Context, c *auth.Call, in MemberRequest) (auth.Done, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return auth.Done{}, err
	}
	mine, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return auth.Done{}, err
	}
	if in.UserID == "" && (in.Email != "" || in.Identifier != "") {
		// A verified address only: an unverified one proves nothing about who
		// the member is, and an unknown one answers like an unknown id.
		kind, raw, err := p.memberAddress(in)
		if err != nil {
			return auth.Done{}, err
		}
		idn, err := c.Auth.FindIdentity(ctx, kind, raw, true)
		switch {
		case errors.Is(err, auth.ErrIdentityNotFound), errors.Is(err, auth.ErrIdentifierInvalid):
			return auth.Done{}, ErrNotMember
		case err != nil:
			return auth.Done{}, err
		}
		in.UserID = idn.UserID
	}
	theirs, err := p.RoleOf(ctx, orgID, in.UserID)
	if err != nil {
		return auth.Done{}, err
	}
	if in.UserID != c.User.ID {
		if err := p.authorize(ctx, c, orgID, mine, access.Request{ResourceMember: access.All(ActionDelete)}); err != nil {
			return auth.Done{}, err
		}
		if err := p.guardCreator(mine, theirs); err != nil {
			return auth.Done{}, err
		}
	}
	return auth.Done{OK: true}, p.applyRemove(ctx, orgID, in.UserID, theirs)
}

// memberAddress picks the kind and raw value a MemberRequest names a member
// by. Any registered kind may name a member, invited by it or not; an
// Identifier without a Kind is InviteBy's first kind, or email with
// invitations off.
func (p *Plugin) memberAddress(in MemberRequest) (auth.IdentifierKindName, string, error) {
	if in.Email == "" && in.Kind == "" && (p.noInvitations || len(p.inviteKinds) == 0) {
		return email.KindEmail, in.Identifier, nil
	}
	if in.Email == "" && in.Kind != "" {
		return in.Kind, in.Identifier, nil
	}
	return p.addressOf(in.Email, in.Kind, in.Identifier)
}

// applyRemove removes userID, who holds theirs, from orgID between the
// member hooks; the last holder of the creator role cannot be removed.
func (p *Plugin) applyRemove(ctx context.Context, orgID, userID string, theirs Role) error {
	if theirs.Has(p.creatorRole) {
		n, err := p.owners(ctx, orgID)
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastOwner
		}
	}
	m := MemberChange{OrgID: orgID, UserID: userID, Role: theirs}
	if h := p.hooks.BeforeRemoveMember; h != nil {
		if err := h(ctx, m); err != nil {
			return err
		}
	}
	if err := p.deleteMembership(ctx, orgID, userID); err != nil {
		return err
	}
	if h := p.hooks.AfterRemoveMember; h != nil {
		return h(ctx, m)
	}
	return nil
}

// deleteMembership removes userID from orgID: the membership, their team
// memberships there, and every one of their sessions' selection of it.
func (p *Plugin) deleteMembership(ctx context.Context, orgID, userID string) error {
	d := p.core.Dialect()
	if _, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableMember).Where(sqlb.Eq(MemberOrgID, orgID), sqlb.Eq(MemberUserID, userID))); err != nil {
		return err
	}
	if p.teams != nil {
		teams := p.core.Select().Exprs(TeamID).From(TableTeam).Where(sqlb.Eq(TeamOrgID, orgID))
		del := sqlb.NewDelete(d).From(TableTeamMember).Where(sqlb.Eq(TeamMemberUserID, userID), sqlb.InSubquery(TeamMemberTeamID, teams))
		if _, err := p.core.Exec(ctx, del); err != nil {
			return err
		}
	}
	_, err := p.core.Exec(ctx, sqlb.NewDelete(d).From(TableActive).Where(sqlb.Eq(ActiveUserID, userID), sqlb.Eq(activeOrgKey, orgID)))
	return err
}

// doSetRole needs member:update. Only a holder of the creator role may grant
// it or change a holder's role, and the last holder cannot be demoted.
func (p *Plugin) doSetRole(ctx context.Context, c *auth.Call, in SetRoleRequest) (auth.Done, error) {
	orgID, err := p.resolveOrg(ctx, c, in.OrgID)
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.checkRole(ctx, orgID, in.Role); err != nil {
		return auth.Done{}, err
	}
	mine, err := p.RoleOf(ctx, orgID, c.User.ID)
	if err != nil {
		return auth.Done{}, err
	}
	if err := p.authorize(ctx, c, orgID, mine, access.Request{ResourceMember: access.All(ActionUpdate)}); err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, p.applyRole(ctx, orgID, in.UserID, in.Role, mine)
}

// applyRole gives userID role in orgID on behalf of a caller holding mine:
// the role hooks, the creator-role rule and the last-owner rule all apply.
func (p *Plugin) applyRole(ctx context.Context, orgID, userID string, role, mine Role) error {
	theirs, err := p.RoleOf(ctx, orgID, userID)
	if err != nil {
		return err
	}
	m := MemberChange{OrgID: orgID, UserID: userID, Role: JoinRoles(role)}
	if h := p.hooks.BeforeUpdateMemberRole; h != nil {
		if err := h(ctx, &m, theirs); err != nil {
			return err
		}
		m.OrgID, m.UserID = orgID, userID
		if err := p.checkRole(ctx, orgID, m.Role); err != nil {
			return err
		}
	}
	if err := p.guardCreator(mine, theirs, m.Role); err != nil {
		return err
	}
	if theirs.Has(p.creatorRole) && !m.Role.Has(p.creatorRole) {
		n, err := p.owners(ctx, orgID)
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastOwner
		}
	}
	q := sqlb.NewUpdate(p.core.Dialect()).Table(TableMember).Set(sqlb.Set(MemberRole, m.Role)).
		Where(sqlb.Eq(MemberOrgID, orgID), sqlb.Eq(MemberUserID, userID))
	if _, err := p.core.Exec(ctx, q); err != nil {
		return err
	}
	if h := p.hooks.AfterUpdateMemberRole; h != nil {
		if err := h(ctx, m, theirs); err != nil {
			return err
		}
	}
	return nil
}

// MembersQuery lists an organization's members with their core user fields.
//
// This is the canonical plugin-joins-core statement: the membership rows are
// this plugin's, the email and name are the core's, and both are typed because
// the plugin imports the core and uses its exported columns rather than
// hardcoding names.
func MembersQuery(a *auth.Auth, orgID string, dst *Member) (sqlb.Query, error) {
	return a.Select().
		Columns(sqlb.Bindings(
			auth.UserBindings(&dst.User),
			[]sqlb.Binding{
				sqlb.Bind(MemberRole, &dst.Role),
				sqlb.Bind(MemberJoinedAt, &dst.JoinedAt),
			},
		)...).
		From(TableMember).
		Join(sqlb.Join{
			Type:  sqlb.JoinInner,
			Table: auth.TableUser,
			On:    []sqlb.Predicate{sqlb.EqExpr(auth.UserID, MemberUserID)},
		}).
		Where(sqlb.Eq(MemberOrgID, orgID)).
		Order(sqlb.OrderBy(MemberJoinedAt, sqlb.SortAsc)).
		Build()
}

// MembersPageQuery is MembersQuery with a page: limit rows from offset, in
// the same joined-at order, so the pages of one listing never overlap.
func MembersPageQuery(a *auth.Auth, orgID string, dst *Member, limit, offset int) (sqlb.Query, error) {
	return membersSelect(a, dst).
		Where(sqlb.Eq(MemberOrgID, orgID)).
		Order(sqlb.OrderBy(MemberJoinedAt, sqlb.SortAsc), sqlb.OrderBy(MemberUserID, sqlb.SortAsc)).
		Limit(limit).Offset(offset).
		Build()
}

// membersSelect is the members join with no filter, order or page: the one
// statement MembersPageQuery and the members operation narrow. extra binds
// further columns, the plugin's member fields.
func membersSelect(a *auth.Auth, dst *Member, extra ...sqlb.Binding) *sqlb.AnySelect {
	return a.Select().
		Columns(sqlb.Bindings(
			auth.UserBindings(&dst.User),
			[]sqlb.Binding{
				sqlb.Bind(MemberRole, &dst.Role),
				sqlb.Bind(MemberJoinedAt, &dst.JoinedAt),
			},
			extra,
		)...).
		From(TableMember).
		Join(sqlb.Join{
			Type:  sqlb.JoinInner,
			Table: auth.TableUser,
			On:    []sqlb.Predicate{sqlb.EqExpr(auth.UserID, MemberUserID)},
		})
}

// PendingInvitesQuery lists the invitations a given user may accept.
//
// Every predicate here is load-bearing and one of them is the whole reason this
// function exists rather than being written inline at the call site:
//
// The join to auth_identity requires verified_at IS NOT NULL. Without it, a
// user who has merely TYPED the victim's address into their account settings —
// and never clicked anything in the victim's inbox — sees and can accept the
// victim's invitation. That is one missing clause and it is a full workspace
// takeover. It is also precisely the published CVE in at least one comparable
// library, which is why the check lives in this one exported function rather
// than at each call site.
//
// It is the same rule as auth.VerifiedIdentity, written out rather than called:
// that predicate is bound to the core's alias for auth_identity, and this
// statement joins the table under the plugin's own alias (TableIdentity, "oid")
// so it cannot collide with a core join in a composite query. Calling the core
// predicate here would reference an alias the statement does not have.
// TestPendingInvitesQuery_RequiresVerifiedIdentity pins the rendered clause.
//
// The address match is exact, on kind and value both (InviteBy): an
// invitation to a phone number is matched only by a verified phone identity
// with that number. An identity value is stored normalized, so an
// invitation's identifier is stored normalized too, through its kind's
// normalizer at the moment the invitation is written; an exact comparison of
// two normal forms then needs no lower() in SQL, which would be a second
// folding rule that differs between engines.
//
// The remaining predicates exclude accepted, rejected, canceled and expired
// invitations, all of which would otherwise be replayable indefinitely.
func PendingInvitesQuery(a *auth.Auth, userID string, now time.Time, dst *Invite) (sqlb.Query, error) {
	return a.Select().
		Columns(
			sqlb.Bind(InviteID, &dst.ID),
			sqlb.Bind(InviteOrgID, &dst.OrgID),
			sqlb.Bind(OrgName, &dst.OrgName),
			sqlb.Bind(InviteEmail, &dst.Email),
			sqlb.Bind(InviteKind, &dst.Kind),
			sqlb.Bind(InviteIdent, &dst.Identifier),
			sqlb.Bind(InviteRole, &dst.Role),
			sqlb.Bind(InviteExpiresAt, &dst.ExpiresAt),
		).
		From(TableInvite).
		Join(
			sqlb.Join{
				Type:  sqlb.JoinInner,
				Table: TableOrg,
				On:    []sqlb.Predicate{sqlb.EqExpr(OrgID, InviteOrgID)},
			},
			sqlb.Join{
				Type:  sqlb.JoinInner,
				Table: TableIdentity,
				On: []sqlb.Predicate{
					sqlb.EqExpr(IdentityValue, InviteIdent),
					sqlb.EqExpr(IdentityKind, InviteKind),
					sqlb.IsNotNull(IdentityVerifiedAt),
				},
			},
		).
		Where(
			sqlb.Eq(IdentityUserID, userID),
			sqlb.IsNull(InviteAccepted),
			sqlb.Eq(InviteStatusCol, StatusPending),
			sqlb.Greater(InviteExpiresAt, now),
		).
		Order(sqlb.OrderBy(InviteExpiresAt, sqlb.SortAsc)).
		Build()
}

// MembershipQuery resolves one user's role in one organization.
//
// Used by an authorization check, so it returns the role rather than a boolean:
// the caller compares with Role.AtLeast, which keeps the privilege ordering in
// one place instead of spreading a chain of equality tests across handlers.
func MembershipQuery(a *auth.Auth, orgID, userID string, dst *Role) (sqlb.Query, error) {
	return a.Select().
		Columns(sqlb.Bind(MemberRole, dst)).
		From(TableMember).
		Where(
			sqlb.Eq(MemberOrgID, orgID),
			sqlb.Eq(MemberUserID, userID),
		).
		Build()
}

// UserMembership is this plugin's contribution to a composite user.
//
// It demonstrates the other half of struct extension: unlike phone and
// username, which borrow the core's shared identity table under a private
// alias, this plugin contributes columns from a table it owns outright.
// Nothing in the Composite mechanism cares which of the two it is — a plugin
// supplies a join and bindings, and where the columns physically live is its
// own business.
//
// Nested rather than flattened into the user struct, following the same rule as
// every other plugin here: the columns live in auth_org_member, a table of this
// plugin's own, so they read as u.Membership.Role rather than u.OrgRole.
//
//ds:def id=usermembership-2dd9ujgq owner=@khanakia stability=stable
type UserMembership struct {
	// Role is the user's role in the organization the join was parameterised
	// with. Empty when they are not a member, because the join is LEFT and the
	// binding coalesces the null away.
	Role Role

	// JoinedAt is nil when they are not a member.
	//
	// A pointer rather than a bare time.Time because this column arrives via a
	// LEFT join and database/sql cannot scan NULL into a time.Time. Coalescing
	// it would mean inventing a fallback timestamp, which is worse than nil: a
	// zero time reads as a real value from 1 January year 1 and will eventually
	// be formatted into someone's interface.
	JoinedAt *time.Time
}

// IsMember reports whether the user belongs to the organization the composite
// query was built for. Prefer it over comparing Role to "" at the call site, so
// the meaning of the empty role lives in one place.
func (m *UserMembership) IsMember() bool { return m.Role != "" }

// UserJoin brings this user's membership of one specific organization into a
// composite user query.
//
// Why it takes an argument when the other plugins' joins do not: a user has one
// phone number but a membership only exists relative to an organization, so the
// join must be parameterised. The org id is BOUND inside the ON clause rather
// than interpolated, which is why the resulting statement carries an extra
// placeholder before the WHERE clause even begins.
//
// LEFT, so a user who is not a member still comes back rather than vanishing
// from a query that was only asking who they are.
//
//ds:def id=userjoin-m9umxmfp owner=@khanakia stability=stable
func UserJoin(orgID string) sqlb.Join {
	return sqlb.Join{
		Type:  sqlb.JoinLeft,
		Table: TableMember,
		On: []sqlb.Predicate{
			sqlb.EqExpr(MemberUserID, auth.UserID),
			sqlb.Eq(MemberOrgID, orgID),
		},
	}
}

// UserBindings binds this plugin's composite columns to dst.
//
// Role is coalesced because the LEFT join yields null for a non-member and Role
// is a named string type that cannot hold it. JoinedAt is bound to a pointer
// instead, because nil is the honest representation of "never joined" and any
// coalesced timestamp would be a fabricated date.
//
//ds:def id=userbindings-dcvjmyv7 owner=@khanakia stability=stable
func UserBindings(dst *UserMembership) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(sqlb.Coalesce(MemberRole, sqlb.Literal[Role]("''")), &dst.Role),
		sqlb.Bind(sqlb.Nullable(MemberJoinedAt), &dst.JoinedAt),
	}
}

// Sweep deletes invitations that expired unaccepted before cutoff, and the
// active selections of sessions whose hard stop is before cutoff. Accepted
// invitations stay: they record who invited whom.
//
//ds:def id=plugin-sweep-3qf5nypp owner=@khanakia stability=stable
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	q := sqlb.NewDelete(p.core.Dialect()).From(TableInvite).
		Where(sqlb.Less(InviteExpiresAt, cutoff), sqlb.IsNull(InviteAccepted))
	n, err := p.core.Exec(ctx, q)
	if err != nil {
		return n, err
	}
	m, err := p.core.Exec(ctx, sqlb.NewDelete(p.core.Dialect()).From(TableActive).Where(sqlb.LessEq(ActiveExpiresAt, cutoff)))
	return n + m, err
}

// RequireRole is middleware that refuses a request unless the signed-in user
// holds at least role in the organization orgID names — read from the path,
// a header or a subdomain, as the app routes. It must be inside
// authhttp.Middleware. A non-member gets ErrNotMember, a lower role
// ErrForbidden, so a stranger learns nothing about the organization.
//
//ds:def id=plugin-requirerole-nk7tdwhr owner=@khanakia stability=stable
func (p *Plugin) RequireRole(orgID func(r *http.Request) string, role Role) func(http.Handler) http.Handler {
	return authhttp.RequireFunc(func(r *http.Request) error {
		u, ok := auth.CurrentUser(r.Context())
		if !ok {
			return auth.ErrSignedOut
		}
		have, err := p.RoleOf(r.Context(), orgID(r), u.ID)
		if err != nil {
			return err
		}
		if !have.AtLeast(role) {
			return ErrForbidden
		}
		return nil
	})
}
