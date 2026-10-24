# github.com/ubgo/auth/plugin/organization

Adds workspaces to an app: users create organizations, invite colleagues by email, and hold roles (owner, admin, member, the app's own, or roles each organization creates) whose permission statements every operation and the app's own routes check. Optional: an active organization per session, teams, dynamic roles and lifecycle hooks.

## Install

```sh
go get github.com/ubgo/auth/plugin/organization
```

This is its own module because organizations are not authentication: an app with no groups never carries the code, and the plugin can be redesigned without touching the core. It brings no third-party dependency: the core, [`plugin/access`](../access) (the permission vocabulary, its own module) and `github.com/ubgo/sqlb`.

## Wire it

Taken from [`examples/organizations`](../../examples/organizations/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		organization.New(),
	),
)
// then: a.Migrate(ctx), and mount authhttp.Handler(a, authhttp.Prefix("/auth"))
```

Guard the app's own routes by role in the organization the request names:

```go
orgs, err := auth.PluginOf[*organization.Plugin](a)
mw := authhttp.Middleware(a)
orgInPath := func(r *http.Request) string { return r.PathValue("org") }
mux.Handle("GET /orgs/{org}/billing", mw(orgs.RequireRole(orgInPath, organization.RoleAdmin)(billing)))
```

`RequireRole` must sit inside `authhttp.Middleware`. A signed-out request gets `401 auth.signed_out`, a non-member `404 organization.not_member`, and a lower role `403 organization.forbidden`.

`auth.New` fails when:

| Condition | Error text |
|---|---|
| The `email` plugin is missing, and invitations are addressed by email (the default) | `"organization" requires "email"` (from `Requires`) |
| A plugin named `email` registers no email identifier kind | `invitations are addressed by email; add the email plugin` |
| `InviteBy` names a kind no plugin registers | `organization: invitations are addressed by "phone", which no plugin registers` |
| `InviteBy` names a kind whose plugin cannot deliver (username) | `organization: invitations are addressed by "username", whose plugin cannot deliver messages: …` (`errors.Is(err, auth.ErrNoDeliverer)`) |
| `InviteBy()` with no kind | `organization: InviteBy needs at least one identifier kind; use WithoutInvitations to turn invitations off` |
| Neither `auth.WithBaseURL` nor `organization.InviteLink` is set, with invitations on | `organization: invitation links need auth.WithBaseURL or organization.InviteLink` |

Invitations need not be email. `organization.InviteBy(phone.KindPhone)` addresses them by phone in a phone-only app (`{"kind":"phone","identifier":"+14155550123"}`; `email` still works and means kind `email`), delivered through that kind's plugin and accepted only by a user holding the verified identity of that kind and value. `organization.WithoutInvitations()` unmounts the invitation routes for an app that adds members only from Go (`AddMember`), and then needs no identifier plugin or `BaseURL`.

The invitation mail is sent through the email plugin with purpose [`organization.PurposeInvite`](ds:block?id=purposeinvite-48v8gjic) (`"organization.invite"`) and `Message.Link` set to the invitations page. Out of the box it reads "You are invited to join an organization", with a short body ending in the link: the plugin sends that wording as `Message.DefaultSubject` and `Message.DefaultText`, which the email plugin uses when the app's templates have no case for the purpose. To word it yourself, handle [`organization.PurposeInvite`](ds:block?id=purposeinvite-48v8gjic) in `email.Templates` as the example does. The message's `Data` is an `organization.InvitationData` (invitation id, address, role, team, expiry; organization id, name, slug and logo; inviter id, name and primary verified address), read with `m.Data.(organization.InvitationData)`; the plugin is an `auth.MessageDataDecoder`, so the type survives `auth.WithDeliveryOutbox`.

Tests: the `orgtest` package (`orgtest.New(env)`, `NewOrganization`, `SaveOrganization`, `AddMember`) builds and saves organizations for an `authtest.Env` through the plugin's own Go API.

## Options

| Option | What it does | Default |
|---|---|---|
| `organization.WithInviteTTL(d)` | How long an invitation stays acceptable | [7 days](ds:block?id=defaultinvitettl-q2vrh7rg) ([`DefaultInviteTTL`](ds:block?id=defaultinvitettl-q2vrh7rg)) |
| `organization.InviteLink(func() string)` | The page the invitation mail links to; called per mail | `BaseURL` + `/invitations` ([`DefaultInvitePage`](ds:block?id=defaultinvitepage-ffc5fetf)) |
| `organization.InviteBy(kinds...)` | Identifier kinds an invitation may be addressed to, such as `phone.KindPhone`; the first is used when a request names no kind. Each must be registered by a plugin that delivers messages ([`auth.Config.CanDeliver`](ds:block?id=core-config-candeliver-3wq8rn5t)), checked at `auth.New`; email requires the email plugin only when listed | `email.KindEmail` |
| `organization.WithoutInvitations()` | Unmounts invite, invites, accept, invitation, reject, cancel and list-invitations, for members added from Go only | invitations on |
| `organization.InviteMessage(func(InviteMail) (subject, text string))` | Words the invitation mail from the invitation, the organization, the inviter and the link; an `email.Templates` case for `PurposeInvite` still wins | the plugin's generic wording |
| `organization.InviteLimit(n, window)` | Invitations allowed per client address per window | [50](ds:block?id=invitelimit-6wd9gmj5) per [hour](ds:block?id=invitewindow-fhrf25ap) (`DefaultInviteLimit`, `DefaultInviteWindow`) |
| `organization.ReplacePendingInvites()` | Inviting an address again withdraws its pending invitations to that organization first, so one invitation and one fresh mail stand | off: every invite adds a pending invitation |
| `organization.RefuseRepeatInvites()` | Inviting an address that already holds a pending, unexpired invitation to the organization is `organization.already_invited`, unless the request sets `resend`; `ReplacePendingInvites` wins over it | off: every invite adds a pending invitation |
| `organization.CreateGate(func(ctx, auth.User) (bool, error))` | Decides who may create an organization, for example by plan; `false` is `organization.create_forbidden` | everyone signed in |
| `organization.MaxOwned(n)` | At most n organizations owned per user; counted as owner memberships | no cap |
| `organization.MaxMembers(n)` | At most n members per organization, checked when someone joins (accept, `AddMember`); invitations still go out | no cap |
| `organization.InvitationLimit(n)` | At most n pending invitations per organization; `0` is no cap | 100 (`DefaultInvitationLimit`) |
| `organization.RejectExistingMembers()` | Inviting or `AddMember` of someone already in the organization is `organization.already_member` | off: allowed, and accepting keeps the role |
| `organization.CreatorRole(r)` | The creator's role, and the role the owner protections guard | `RoleOwner` |
| `organization.WithAccessControl(ac)` | The permission vocabulary (`access.AccessControl`); start from `DefaultStatements` to keep the plugin's own checks | `DefaultAccessControl` |
| `organization.WithRoles(map[Role]access.Role)` | Static roles added to, or replacing, `DefaultRoles()` | owner, admin, member |
| `organization.WithAuthorizer(a)` | Decides every permission (`Authorizer`: `Authorize(ctx, AccessRequest) (bool, error)`; any error refuses): each operation's check, `has-permission`, `Can`, `RequirePermission`, the grant check of a dynamic role and `APIKeyPermission`. Wrap `p.RoleAuthorizer()` to add a rule to the roles. Under a custom authorizer the creator's API-key shortcut is off | `RoleAuthorizer()` |
| `organization.Teams(TeamsConfig{MaxTeams, MaxMembersPerTeam, AllowRemovingAllTeams, NoDefaultTeam, DefaultTeamName})` | Teams inside an organization; a default team with the creator unless `NoDefaultTeam` | off |
| `organization.DynamicRoles(DynamicRolesConfig{MaxRoles})` | Roles created per organization at run time (dynamic access control) | off |
| `organization.Domains(DomainsConfig{Verifier, RecordPrefix, TrustVerifiedEmail, IsPublicDomain, MaxDomains})` | Verified domains: an organization claims an email domain, proves it (a DNS TXT record through the replaceable [`DomainVerifier`](ds:block?id=domainverifier-xyngwy9v), or with `TrustVerifiedEmail` the admin's own verified address at it) and enrolls users whose email there becomes verified, by the domain's [enrollment mode](ds:block?id=enrollmentmode-3c3jpwcb); public mail domains are refused (`IsDefaultPublicDomain` unless replaced); 10 domains per organization (`DefaultMaxDomains`) | off |
| `organization.WithFields(FieldsConfig{Org, Member, Invitation, Team, Role})` | Extra columns per table, each a `Field{Name, Type, Nullable, Default, Required, ServerOnly}`, read and written as a `fields` object; one migration per field | none |
| `organization.WithHooks(Hooks{…})` | Typed Before/After hooks on organizations, members, invitations, teams and team members, inside the operation's transaction; a Before hook may change the row | none |
| `organization.WithHooksFrom(func(a *auth.Auth) Hooks)` | The same hooks, built in `Init` with the `*auth.Auth`, so a hook writes the app's rows through `a.Conn(ctx)` in the operation's transaction; refused together with `WithHooks` | none |

`Validate` refuses `InviteLimit` with a limit below 1 or a non-positive window (`organization: InviteLimit needs a positive limit and window`), a `CreatorRole` that is not one static role, a `WithRoles` role whose permissions the access control does not declare, a nil access control, a nil authorizer (`auth.ErrNilOption` naming `organization.WithAuthorizer`, as for every option given nil), and a negative `InvitationLimit`, team limit or `MaxRoles`.

## Routes and Go API

Routes are under the mount prefix (`/auth` below). A Query is served as GET with its input in the query string; a Mutation as POST with a JSON body.

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /auth/organization/create` `{name, slug, logo, metadata, keepCurrentActiveOrganization}` | `Create(ctx, CreateRequest)` | SignedIn; `CreateGate` and `MaxOwned` apply; becomes the session's active organization | none |
| `GET /auth/organization/check-slug?slug=` | `CheckSlug(ctx, slug)` | SignedIn | none |
| `GET /auth/organization/list` | `List(ctx)` | SignedIn | none |
| `GET /auth/organization/members?orgId=&page=&limit=&sortBy=&sortDirection=&filterField=&filterOperator=&filterValue=` | `Members(ctx, orgID)`, `ListMembers(ctx, OrgRequest)` | SignedIn, member | none |
| `GET /auth/organization/role?orgId=` | `Role(ctx, orgID)` | SignedIn, member | none |
| `POST /auth/organization/invite` `{orgId, email, role, teamId, resend}` | `Invite(ctx, InviteRequest)` | SignedIn, `invitation:create`; only a creator-role holder invites with that role; `InvitationLimit` | [50](ds:block?id=invitelimit-6wd9gmj5) per [hour](ds:block?id=invitewindow-fhrf25ap) per IP by default (`InviteLimit`) |
| `GET /auth/organization/invites` | `Invites(ctx)` | SignedIn | none |
| `GET /auth/organization/invite?inviteId=` | `Invitation(ctx, inviteID)` | SignedIn, verified invited address | none |
| `POST /auth/organization/accept` `{inviteId}` | `Accept(ctx, inviteID)` | SignedIn, verified invited address; `MaxMembers` applies | none |
| `POST /auth/organization/remove-member` `{orgId, userId}`, `{orgId, email}` or `{orgId, kind, identifier}` | `RemoveMember(ctx, MemberRequest)` | SignedIn; the caller leaving, or `member:delete`; only a creator-role holder removes one | none |
| `POST /auth/organization/set-role` `{orgId, userId, role}` (role a string or an array) | `SetRole(ctx, SetRoleRequest)` | SignedIn, `member:update`; only a creator-role holder grants it or changes a holder | none |
| `GET /auth/organization/get-organization?orgId=` or `?orgSlug=` | `Get(ctx, GetRequest)` | SignedIn, member | none |
| `GET /auth/organization/get-full-organization?orgId=&membersLimit=` | `GetFull(ctx, GetRequest)` | SignedIn, member | none |
| `POST /auth/organization/update` `{orgId, data: {name, slug, logo, metadata}}` | `Update(ctx, UpdateRequest)` | SignedIn, `organization:update` | none |
| `POST /auth/organization/delete` `{orgId}` | `Delete(ctx, orgID)` | SignedIn, `organization:delete` | none |
| `POST /auth/organization/set-active` `{orgId}` or `{orgSlug}`, `{}` to clear | `SetActive(ctx, SetActiveRequest)` | SignedIn, member, a session (not an API key) | none |
| `GET /auth/organization/active` | `Active(ctx)` | SignedIn | none |
| `POST /auth/organization/reject-invitation` `{inviteId}` | `Reject(ctx, inviteID)` | SignedIn, verified invited address | none |
| `POST /auth/organization/cancel-invitation` `{inviteId}` | `Cancel(ctx, inviteID)` | SignedIn, `invitation:cancel` | none |
| `GET /auth/organization/list-invitations?orgId=` | `ListInvitations(ctx, orgID)` | SignedIn, member | none |
| `POST /auth/organization/has-permission` `{orgId, permissions, connector}` | `HasPermission(ctx, PermissionRequest)` | SignedIn, member | none |
| `POST /auth/organization/create-team`, `GET list-teams`, `POST update-team`, `POST remove-team`, `POST set-active-team`, `GET list-user-teams`, `GET list-team-members`, `POST add-team-member`, `POST remove-team-member` | `CreateTeam`, `ListTeams`, `UpdateTeam`, `RemoveTeam`, `SetActiveTeam`, `ListUserTeams`, `ListTeamMembers`, `AddTeamMember`, `RemoveTeamMember` | With `Teams` only; `team:create`, `team:update`, `team:delete` as the guide lists | none |
| `POST /auth/organization/create-role`, `POST update-role`, `POST delete-role`, `GET get-role`, `GET list-roles` | `CreateRole`, `UpdateRole`, `DeleteRole`, `GetRole`, `ListRoles` | With `DynamicRoles` only; `ac:create`, `ac:update`, `ac:delete`, `ac:read` | none |
| `POST /auth/organization/add-domain` `{orgId, domain, enrollmentMode, role}`, `GET list-domains?orgId=`, `POST verify-domain` `{domainId}`, `POST update-domain` `{domainId, enrollmentMode, role}`, `POST remove-domain` `{domainId}` | `AddDomain`, `ListDomains`, `VerifyDomain`, `UpdateDomain`, `RemoveDomain` | With `Domains` only; list needs membership, the rest `organization:update`; a domain never grants the creator role | `verify-domain`: 10 per minute per client address (`DefaultVerifyLimit`, `DefaultVerifyWindow`) |
| `GET /auth/organization/domain-suggestions`, `POST accept-suggestion` `{domainId}`, `GET list-membership-requests?orgId=`, `POST approve-membership-request` `{requestId}`, `POST reject-membership-request` `{requestId}` | `DomainSuggestions`, `AcceptSuggestion`, `ListMembershipRequests`, `ApproveMembershipRequest`, `RejectMembershipRequest` | With `Domains` only; suggestions are the caller's own verified emails; requests need `member:create`, and approval checks again that the domain and the requester's address are still verified | none |

Every operation that takes `orgId` uses the session's active organization when it is left out, and answers `organization.no_active` when there is none.

`invite` with `resend: true`, when the address already holds a pending invitation to the organization, mails that invitation again with a fresh expiry instead of creating another: it keeps its id, role and team, the caller needs `invitation:create` and, for an invitation carrying the creator role, that role; with nothing pending it is an ordinary invite. `members` filters with `filterField`, `filterOperator` and `filterValue`: on `role`, `userId` and `name` the operators `eq`, `ne`, `in`, `not_in` (comma-separated values), `contains`, `starts_with` and `ends_with`, all case-sensitive on every engine (GLOB on SQLite, whose LIKE ignores case) with `%` and `_` taken as text; on `joinedAt` (or `createdAt`, the same column) an RFC 3339 instant with `eq`, `ne`, `lt`, `lte`, `gt` and `gte`. `lt`/`gt` on text are `organization.bad_query`, because the order of two names depends on each engine's collation. `list-team-members` without `teamId` lists the session's active team (`organization.no_active_team` when there is none).

`check-slug` answers `{slug, available}` with the normalized slug; a slug outside `SlugPattern` is not available. `members` pages like the admin list: `limit` defaults to 50 (`DefaultMembersPage`) and is clamped to 200 (`MaxMembersPage`); the result carries `total`, `page` and `limit`. `remove-member` by `email` resolves a verified address; an unknown or unverified one is `organization.not_member`, like an unknown id.

Operation ids are the `Endpoint*` constants (`organization.create` and so on). From Go, with no transport:

| Function | Use |
|---|---|
| `(*Plugin).RoleOf(ctx, orgID, userID)` | The user's role, or `ErrNotMember` |
| `(*Plugin).Can(ctx, orgID, userID, access.Request, connector)` | Whether the authorizer (the user's roles by default) allows the request, or `ErrNotMember` |
| `(*Plugin).RequirePermission(orgID func(*http.Request) string, access.Request)` | Middleware like `RequireRole`, by permission |
| `(*Plugin).ActiveOrgID(ctx)` | The request's active organization |
| `(*Plugin).AddMemberWith(ctx, AddMemberRequest{OrgID, UserID, Role, Fields})` | `AddMember` with member fields |
| `(*Plugin).CreateFor(ctx, userID, CreateRequest)` | Creates an organization owned by userID from trusted code (a seed, an import); `CreateGate` and `MaxOwned` do not apply, the slug rules do |
| `(*Plugin).AddMember(ctx, orgID, userID, role)` | Adds a member without an invitation; an existing member keeps their role; `MaxMembers` applies |
| `(*Plugin).RequireRole(orgID func(*http.Request) string, role)` | Middleware, shown above |
| `(*Plugin).Sweep(ctx, cutoff)` | Deletes invitations that expired unaccepted before cutoff (accepted ones stay) and the active selections of expired sessions. Run by `auth sweep` |
| `(*Plugin).ListAll(ctx, AllOrgsRequest{Page, Limit, Search})` | Every organization of the app, newest first, with `MemberCount`, paged like the members list; `Search` matches inside the slug |
| `(*Plugin).MarkDomainVerified(ctx, domainID)` | Verifies a domain from trusted code with no proof, for an operator who checked ownership another way; never a route. Another organization's verified domain is still `organization.domain_taken` |
| `NormalizeDomain(raw)`, `EmailDomain(addr)`, `DNSVerifier{Resolver}`, `IsDefaultPublicDomain(d)` | The domain rules behind the operations, for an app's own screens or a verifier that wraps the DNS one |
| `(*Plugin).GetFor`, `UpdateFor`, `DeleteFor`, `MembersFor`, `SetRoleFor`, `RemoveMemberFor`, `InvitationsFor`, `CancelFor` | The platform API: the same operations on any organization, for an operator's admin screen (a dashboard organization overview). No session or membership is checked, so call them behind the app's own admin gate (for example `admin.RequireAdmin`); the slug rules, the last-owner rule (`ErrLastOwner`) and every hook still apply, and each runs in one transaction. They are Go calls, so they bypass the operation pipeline and its audit record, as `CreateFor` and `AddMember` do |
| `MembersQuery`, `MembersPageQuery`, `PendingInvitesQuery`, `MembershipQuery` | The typed statements behind the operations, for an app's own queries |
| `UserJoin(orgID)` + `UserBindings(&UserMembership{})` | Adds one organization's membership to a composite user query (LEFT join; `IsMember()` is false for a non-member) |

Built-in roles, most privileged first: [`RoleOwner`](ds:block?id=roleowner-szv8n5ye), [`RoleAdmin`](ds:block?id=roleadmin-cghbz3fj), [`RoleMember`](ds:block?id=rolemember-k755wabe) (`RoleValues`), with these permissions (`DefaultStatements`, `DefaultRoles()`; resources `organization`, `member`, `invitation`, `team`, `ac`). A stored role may hold several, comma-joined (`Role.Parts`, `Role.Has`, `JoinRoles`); a member passes a check when any one of their roles does. `Role.AtLeast(need)` compares the built-in ranks; a custom role ranks 0.

## Tables and columns

| Table (alias) | Columns | Keys |
|---|---|---|
| `auth_org` (`og`) | `id`, `slug`, `name`, `created_at`, `logo`, `metadata` | `id` primary key, `slug` unique |
| `auth_org_member` (`om`) | `org_id`, `user_id`, `role`, `joined_at` | primary key (`org_id`, `user_id`); no foreign keys: `a.DeleteUser` removes a user's memberships (`UserTables`), and removing a member is the plugin's own operation |
| `auth_org_invite` (`oi`) | `id`, `org_id`, `email` (the address of an email invitation, `""` for another kind), `identifier_kind`, `identifier` (every invitation's kind and normalized value), `role`, `invited_by`, `expires_at`, `accepted_at`, `created_at`, `status`, `team_id` | `id` primary key; no foreign keys |
| `auth_org_active` (`oa`) | `session_id`, `user_id`, `org_id`, `team_id`, `expires_at` | `session_id` primary key, index on `user_id`; a user table (`a.DeleteUser`), cleared at sign-out (`auth.SessionLifecycle`) and by `Sweep` |
| `auth_org_team` (`ot`), with `Teams` | `id`, `org_id`, `name`, `created_at`, `updated_at` | `id` primary key |
| `auth_org_team_member` (`otm`), with `Teams` | `team_id`, `user_id`, `created_at` | primary key (`team_id`, `user_id`); a user table |
| `auth_org_role` (`orl`), with `DynamicRoles` | `id`, `org_id`, `role`, `permission` (JSON), `created_at`, `updated_at` | `id` primary key, unique (`org_id`, `role`) |
| `auth_org_domain` (`odm`), with `Domains` | `id`, `org_id`, `domain`, `verified_domain` (NULL until proved), `enrollment`, `role`, `token`, `created_by`, `verified_at`, `created_at` | `id` primary key, unique (`org_id`, `domain`), `verified_domain` unique: many organizations may claim a domain, only the first to prove it owns it |
| `auth_org_domain_request` (`odr`), with `Domains` | `id`, `org_id`, `user_id`, `domain_id`, `status` (`pending`, `approved`, `rejected`), `created_at`, `decided_at`, `decided_by` | `id` primary key, unique (`org_id`, `user_id`); a user table |

The plugin also reads `auth_identity` under the alias `oid` to match invitations to verified addresses. Migrations, on Postgres, MySQL and SQLite: `0001_organization` (the first three tables), `0002_organization_fields` (logo, metadata, status, team), `0003_organization_active`, `0004_organization_teams` and `0005_organization_roles` when their option is on, so turning one on later migrates then, and `0006_organization_invite_identifier` (the invitation's kind and identifier, filled from `email` for existing rows). Table names follow `auth.RenameTable` and `auth.WithTablePrefix`. Typed columns (`OrgID`, `MemberRole`, `InviteEmail`, …) and the `Col*` name constants are exported for joins. The plugin's tables are not in the stability contract (`stability_test.go` covers only `auth_user`, `auth_identity` and `auth_session`), so treat their columns as stable only by convention within a version.

A slug is 2 to 48 lowercase letters, digits and dashes, not starting with a dash (`SlugPattern`), and is lowercased before it is checked.

## Errors

| Error variable | Code | HTTP | When |
|---|---|---|---|
| `ErrNotMember` | `organization.not_member` | 404 | The caller (or the target) is not a member; 404 so a stranger cannot tell the organization exists |
| `ErrForbidden` | `organization.forbidden` | 403 | The caller's role is too low |
| `ErrSlugTaken` | `organization.slug_taken` | 409 | Another organization has the slug |
| `ErrBadSlug` | `organization.bad_slug` | 400 | The slug does not match `SlugPattern` |
| `ErrBadRole` | `organization.bad_role` | 400 | The role is not one of `RoleValues` |
| `ErrLastOwner` | `organization.last_owner` | 409 | Removing or demoting the only owner |
| `ErrInviteInvalid` | `organization.invite_invalid` | 404 | Unknown, expired, already accepted, or not addressed to a verified address of the caller |
| `ErrCreateForbidden` | `organization.create_forbidden` | 403 | The `CreateGate` refused the caller |
| `ErrLimitReached` | `organization.limit_reached` | 409 | The caller already owns `MaxOwned` organizations |
| `ErrMembersLimit` | `organization.members_limit` | 409 | The organization already has `MaxMembers` members |
| `ErrNoActiveOrg` | `organization.no_active` | 400 | No `orgId` and no active organization |
| `ErrAlreadyMember` | `organization.already_member` | 409 | With `RejectExistingMembers` |
| `ErrInvitationLimit` | `organization.invitation_limit` | 409 | `InvitationLimit` pending invitations |
| `ErrBadMetadata` | `organization.bad_metadata` | 400 | Metadata not a JSON object, or over `MaxMetadataSize` |
| `ErrBadQuery` | `organization.bad_query` | 400 | An unsupported members sort or filter |
| `ErrTeamNotFound` | `organization.team_not_found` | 404 | Unknown team, or one of an organization the caller is not in |
| `ErrTeamsLimit`, `ErrTeamMembersLimit`, `ErrLastTeam` | `organization.teams_limit`, `organization.team_members_limit`, `organization.last_team` | 409 | Team limits |
| `ErrRoleNotFound` | `organization.role_not_found` | 404 | Unknown dynamic role |
| `ErrRoleTaken`, `ErrRolesLimit`, `ErrRoleInUse` | `organization.role_taken`, `organization.roles_limit`, `organization.role_in_use` | 409 | Dynamic role name in use, `MaxRoles`, or held by members |
| `ErrBadPermission` | `organization.bad_permission` | 400 | A permission outside the statements, or one the caller does not hold |
| `ErrPredefinedRole` | `organization.predefined_role` | 400 | `delete-role` or `update-role` naming a configured role (owner, admin, member, `WithRoles`) |
| `ErrNoActiveTeam` | `organization.no_active_team` | 400 | `list-team-members` with no `teamId` and no active team |
| `ErrAlreadyInvited` | `organization.already_invited` | 409 | With `RefuseRepeatInvites`, the address already holds a pending invitation |
| `ErrInviteAddress` | `organization.invite_address` | 400 | An invitee or member named by both `email` and `identifier`, or by a kind `InviteBy` does not allow |
| `ErrDomainNotFound` | `organization.domain_not_found` | 404 | Unknown domain, or one of an organization the caller is not in |
| `ErrBadDomain` | `organization.bad_domain` | 400 | Not a domain name of two or more labels (`NormalizeDomain`) |
| `ErrPublicDomain` | `organization.public_domain` | 400 | A public mail domain (`DomainsConfig.IsPublicDomain`) |
| `ErrDomainTaken` | `organization.domain_taken` | 409 | Another organization proved the domain, or this one added it already |
| `ErrDomainsLimit` | `organization.domains_limit` | 409 | `MaxDomains` domains |
| `ErrDomainNotVerified` | `organization.domain_not_verified` | 409 | `verify-domain` found no matching TXT record yet |
| `ErrDomainCheckFailed` | `organization.domain_check_failed` | 503 | The verifier could not look (a DNS outage) |
| `ErrBadEnrollment` | `organization.bad_enrollment` | 400 | An enrollment mode outside `EnrollmentModeValues` |
| `ErrDomainRole` | `organization.domain_role` | 400 | A domain given the creator role |
| `ErrRequestInvalid` | `organization.request_invalid` | 404 | A suggestion or membership request that is unknown, not the caller's, decided, or whose domain or address is no longer verified |

### Conditions that share a code

Several distinct conditions answer with one code. Each such case is one of three folds, each on purpose:

| Fold | Conditions | Here | Why |
|---|---|---|---|
| A stranger cannot tell what exists | An unknown organization, an unknown member, a user who is not a member, a caller who is not a member or may not access the organization | `organization.not_member` (404) | An unknown organization and one the caller may not see answer alike, so a guessed id reveals nothing |
| | An unknown invitation, one addressed to someone else, one that waits for the invitee to verify their address, and one expired, accepted, rejected or canceled | `organization.invite_invalid` (404) | Telling the holder of a guessed id that it is addressed to someone else, or still waits for a verification, confirms that the invitation and its address exist |
| | An unknown or invalid team id, the members of a team the caller may not read, and a team the caller is not in on `set-active-team` | `organization.team_not_found` (404) | A team of another organization answers like an unknown one; `remove-team-member` of someone not in the team answers `organization.not_member` |
| One code per kind, the action is the route | A role too low for the action, whatever the action (update or delete the organization, invite, cancel, delete or update a member, create, update or delete a team or team member, create, read, list, get, update or delete a role, invite with this role) | `organization.forbidden` (403) | The client knows which route it called; the code says the role is too low |
| Same meaning, one name | An existing organization and a taken slug; the only owner leaving and an organization left without an owner; creating a role outside an organization and having no active organization | `organization.slug_taken`, `organization.last_owner`, `organization.no_active` | Each pair is one condition |

A missing access control is a configuration error, refused by `Validate` at start-up instead of on a request. An invitation whose inviter has since left the organization stays valid: it can be accepted, so it is shown as one.

## Security notes

| Property | Pinned by |
|---|---|
| An invitation is accepted only by a user who has VERIFIED the invited address; typing the address into an account is not enough | `TestOrganization_InviteNeedsAVerifiedAddress`, `TestPendingInvitesQuery_RequiresVerifiedIdentity` |
| The address match is exact on normalized values, with no `lower()` in SQL | `TestPendingInvitesQuery_RequiresVerifiedIdentity` |
| An invitation to another kind (`InviteBy`) matches only a verified identity of that same kind and value | `TestPendingInvitesQuery_RequiresVerifiedIdentity`, `TestOrgAddress_PhoneOnlyAppInvitesByPhone` |
| An `InviteBy` kind whose plugin cannot deliver is refused at `auth.New` with `auth.ErrNoDeliverer`; a delivering kind beside it wires | `TestValidate_InviteKindMustDeliver` |
| An invitation cannot be accepted twice, including by two concurrent requests | `TestOrganization_RolesAndRemoval`, `TestOrgCov_ConcurrentAcceptLosesTheRace` |
| Accepting an invitation as an existing member does not change their role | `TestOrgCov_AcceptingAsAMemberKeepsTheRole` |
| An admin cannot invite above their own role or remove an owner; only an owner changes roles; the last owner stays | `TestOrgCov_RefusalsAndRoleRules`, `TestOrganization_RolesAndRemoval` |
| A stranger gets 404, not 403, from `RequireRole` and from every operation | `TestMiddleware_ScopeAndRole`, `TestOrgCov_RequireRoleRefusals` |
| The org id in `UserJoin` is bound, never interpolated | `TestUserJoin_BindsOrgIDRatherThanInterpolating` |
| Every database failure in every operation reaches the caller | `TestOrgCov_EveryDatabaseFailureSurfaces`, `TestR30_FaultSweep` |
| Every operation checks a permission; only a creator-role holder grants or touches that role; a member cannot create a dynamic role stronger than their own | `TestR30_PermissionsAndCustomRoles`, `TestR30_DynamicRoles` |
| A rejected or canceled invitation cannot be accepted; only its addressee rejects it; a stranger canceling learns nothing | `TestR30_InvitationStates` |
| A hook cannot move a row past a check (ids and the invited address are restored); a failing hook leaves nothing behind | `TestR30_Hooks`, `TestR30_EveryHookCanFail` |
| Leaving an organization leaves its teams and drops the active selection; deleting an organization removes every row of it | `TestR30_Teams`, `TestR30_ActiveOrganization`, `TestR30_FieldsGetUpdateDelete` |

| An extra field is written only when declared and of its column's type; a client cannot set a `ServerOnly` one; `Required` is enforced on create | `TestR30_AdditionalFields`, `TestR30_FieldsValidate` |
| A domain enrolls a user only from a VERIFIED email (an identity created verified, or one whose `verified_at` is set), only when the organization has proved the domain, and an enrollment refusal (`MaxMembers`, a hook) never fails the user's own verification | `TestDomains_AutoJoinOnlyAfterVerification` (examples/org-domains), `TestEnroll_IgnoresWhatIsNotAVerifiedEmail` |
| A proved domain belongs to one organization (the unique `verified_domain` decides, for a sequential and a concurrent attempt alike; add-domain also refuses a domain already proved); a claim another organization cannot prove blocks nobody; a member cannot add or remove a domain; public mail domains are refused | `TestDomains_AutoJoinOnlyAfterVerification` |
| A suggestion becomes a membership only through an admin's approval, which checks again that the domain and the address are still verified; a rejected user is not suggested again | `TestDomains_SuggestionAndInvitation`, `TestDomains_RequestDecidedConcurrently`, `TestDomains_ApprovalAfterCreatorRoleChanged` |
| The DNS record is compared in constant time and exactly; a lookup failure is `organization.domain_check_failed`, never a pass | `TestDNSVerifier` |

Limits: an organization's name is not validated beyond trimming. Invitations are addressed by email only. Columns cannot be renamed (tables can, with `auth.RenameTable`). Extra fields are accepted in a `fields` object or as top-level keys beside the built-in ones; a field sent both ways is `auth.field_invalid`, an unknown top-level key `auth.bad_request`; responses carry them in `fields`.

## Example

- Runnable recipe: [`examples/organizations`](../../examples/organizations/) (`go run ./organizations` from `examples/`).
- Verified domains: [`examples/org-domains`](../../examples/org-domains/) (`go run ./org-domains`).
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/organization
