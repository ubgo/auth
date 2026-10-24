# Organizations

You will have workspaces in your app: a user creates an organization, invites colleagues by email, members hold roles that grant permissions, your own routes require a role or a permission, and your own queries join the membership. On top of that, as far as you need it: an active organization per session, invitations that can be rejected and canceled, teams inside an organization, roles your app defines at start-up or each organization creates at run time, and hooks around every change. An invitation can be accepted only by someone who has proved they own the invited address.

## Before you start

- An app with email sign-in, as in [your first app](../start/first-app.md). By default the organization plugin requires the [email plugin](email.md): invitations are addressed to email, and `auth.New` fails without it. A phone-only or username-only app invites by another kind, or adds members only from the server; see [Inviting by phone, or not at all](#inviting-by-phone-or-not-at-all).
- The example is [`examples/organizations`](../../examples/organizations): Alice creates Acme and invites Bob, Bob accepts once his address is verified, and two app pages are guarded by role. `go run ./organizations` in `examples/` serves it on `localhost:8081`; `go test ./organizations` runs it. The transcripts below come from that program.
- Steps 9 and 12 to 14 and inviting by phone are built from a second example, [`examples/org-teams`](../../examples/org-teams): teams, the active organization and team, a role Acme creates for itself, typed hooks, and invitations by email and by text message. `go run ./org-teams` serves it on `localhost:8081`; `go test ./org-teams` runs the whole flow, two users and a phone number included.
- The plugin is its own module (`go get github.com/ubgo/auth/plugin/organization`), because organizations are not authentication: an app with no groups never carries the code, and the plugin can be redesigned (nested levels, app-defined permissions) without touching the core.
- What the plugin owns: `auth_org`, `auth_org_member`, `auth_org_invite` and `auth_org_active` (each session's active organization and team), plus `auth_org_team` and `auth_org_team_member` with `organization.Teams`, and `auth_org_role` with `organization.DynamicRoles`. No foreign keys: deleting an organization, a member or a user removes the rows in Go, in one transaction.
- Roles are `owner`, `admin` and `member` out of the box, with default permissions; a role is a set of permission statements from the [access](access.md) module, so an app adds its own roles and resources the same way. A member may hold several roles.

## Step 1 — Wire the plugin

Add `organization.New()` next to the email plugin. The invitation mail needs a page to link to, so either `auth.WithBaseURL` is set (the link is then the base URL plus [`/invitations`](ds:block?id=defaultinvitepage-ffc5fetf)) or `organization.InviteLink` names one.

<!-- ds:block id=newauth-yt5aa3nm -->
**newAuth** · [`examples/organizations/main.go:110-120`](../../examples/organizations/main.go#L110-L120)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m), email.Templates(mailTemplates)),
			password.New(),
			organization.New(),
		),
	)
}
```
<!-- /ds:block hash=a62e2d -->

Check: `auth.New` refuses a setup nobody could be invited in. Without the email plugin: `auth: plugin dependency not registered: "organization" requires "email"`. Without a base URL or `InviteLink`: `auth: plugin "organization": organization: invitation links need auth.WithBaseURL or organization.InviteLink`.

## Step 2 — Create an organization

`POST /auth/organization/create` with a name and a slug. The slug appears in URLs, so it is 2 to 48 lowercase letters, digits and dashes and may not start with a dash; it is lowercased before the check, and it is unique across the deployment. The creator becomes the owner.

```sh
O='Origin: http://localhost:8081'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H "$O" -d '{"name":"Acme","slug":"-Acme"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H "$O" -d '{"name":"Acme","slug":"Acme"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H "$O" -d '{"name":"Acme 2","slug":"acme"}'
```

```json
{"error":{"code":"organization.bad_slug","message":"Use lowercase letters, digits and dashes."}}
{"id":"org_7n2gshuichmdexqwfljzp56x","slug":"acme","name":"Acme","createdAt":"2026-10-01T05:19:20.39302Z"}
{"error":{"code":"organization.slug_taken","message":"This address is already in use."}}
```

From Go: `org.Create(ctx, organization.CreateRequest{Name: "Acme", Slug: "acme"})` returns the `Org`; `ctx` must carry the signed-in request (`a.WithRequest`). `org.List(ctx)` returns the caller's organizations with their role in each:

```sh
curl -s -b alice.txt localhost:8081/auth/organization/list
```

```json
{"orgs":[{"id":"org_7n2gshuichmdexqwfljzp56x","slug":"acme","name":"Acme","createdAt":"2026-10-01T05:19:20.39302Z","role":"owner"}]}
```

## Step 3 — Invite by email

An admin or owner invites an address with a role no higher than their own. The address is normalized and stored, and a mail goes out through the email plugin with purpose [`organization.invite`](ds:block?id=purposeinvite-48v8gjic). Invitations are limited to [50](ds:block?id=invitelimit-6wd9gmj5) per [hour](ds:block?id=invitewindow-fhrf25ap) per client address.

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/invite -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","email":"Bob@Example.com","role":"member"}'
```

```text
{"ok":true}

2026/10/01 10:49:20 mail to=bob@example.com subject="You are invited to join a team"
You were invited to join an organization. Sign in with this address, verify it if you have not, and accept the invitation here:

http://localhost:8081/invitations
```

The example words the mail itself with `email.Templates`; without that, the plugin's own wording goes out ("You are invited to join an organization", with the link at the end):

<!-- ds:block id=mailtemplates-6y8uywp9 -->
**mailTemplates** · [`examples/organizations/main.go:126-131`](../../examples/organizations/main.go#L126-L131)

```go
func mailTemplates(m auth.Message) (subject, text string) {
	if m.Purpose == organization.PurposeInvite {
		return inviteSubject, inviteText + m.Link
	}
	return email.DefaultTemplates(m)
}
```
<!-- /ds:block hash=549868 -->

Every invitation message also carries a typed payload, `m.Data`, an `organization.InvitationData` (type-safe template variables): the invitation id, the invited address and role, the team, the expiry, the organization's id, name, slug and logo, and the inviter's id, name and primary verified address. A template reads it with a type assertion, so a renamed field is a compile error, not an empty line in a mail:

```go
if d, ok := m.Data.(organization.InvitationData); ok {
	return d.InviterName + " invited you to " + d.OrganizationName, "Join as " + string(d.Role) + ":\n\n" + m.Link
}
```

Under `auth.WithDeliveryOutbox` the message is stored as JSON and sent later; the plugin implements `auth.MessageDataDecoder`, so the template still receives an `InvitationData`, never a map.

A role outside `owner`, `admin`, `member` is `400 organization.bad_role`:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/invite -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","email":"dave@example.com","role":"root"}'
```

```json
{"error":{"code":"organization.bad_role","message":"This role does not exist."}}
```

### Inviting by phone, or not at all

Invitations are addressed by email unless `organization.InviteBy(kinds...)` names other identifier kinds: `organization.InviteBy(phone.KindPhone)` for a phone-only app, `organization.InviteBy(email.KindEmail, phone.KindPhone)` for either. The request then names the invitee as `{"kind":"phone","identifier":"+14155550123","role":"member"}` (the `email` field still works and means kind `email`; `kind` may be left out when only one kind is allowed). The value is normalized by its kind, the invitation is delivered through that kind's plugin (an SMS for phone), and it is accepted only by a user holding a **verified** identity of that kind and value, exactly as for email. Every kind must be registered by an identifier plugin, or `auth.New` fails; the email plugin is required only when email is among the kinds. A kind whose plugin cannot deliver messages (username) fails `auth.New` with `auth.ErrNoDeliverer` (the plugin asks [`auth.Config.CanDeliver`](ds:block?id=core-config-candeliver-3wq8rn5t) at start-up), rather than the first invite. Naming both `email` and `identifier`, or a kind `InviteBy` does not allow, is `400 organization.invite_address`. Invitations carry `kind` and `identifier` for every kind, and `email` only for an email invitation.

The [`org-teams`](../../examples/org-teams) example invites by either kind. Its `newAuth` is in Step 12; inviting Carol by her number, as she would type it:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/invite -H 'Origin: http://localhost:8081' \
  -d '{"kind":"phone","identifier":"+1 (555) 010-0177","role":"member"}'
```

```text
{"ok":true}

2026/10/09 08:42:19 sms to=+15550100177
You were invited to join an organization. Sign in with this address, verify it if you have not, and accept the invitation here:

http://localhost:8081/invitations
```

Carol signs up with her email, adds the number (`POST /auth/phone/add`), verifies it with the texted code (`POST /auth/phone/verify`), and only then does `GET /auth/organization/invites` list the invitation, with `"kind":"phone","identifier":"+15550100177"`. Check: `TestOrgTeams_TeamsRolesAndInvites` in `examples/org-teams`.

An app that adds members only from the server (`org.AddMember`) passes `organization.WithoutInvitations()`: the invitation routes are not mounted, and no identifier plugin, `BaseURL` or `InviteLink` is needed.

## Step 4 — Accept, with a verified address only

Bob signs up with the invited address. His list of invitations, `GET /auth/organization/invites`, is empty until he verifies it, because anyone can type any address at sign-up; the invitation is matched against the identities the user has verified, exactly, on the normalized value.

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"bob@example.com","password":"correct horse battery staple","name":"Bob"}'
curl -s -b bob.txt localhost:8081/auth/organization/invites
curl -s -b bob.txt -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"<token from the mailed link>"}'
curl -s -b bob.txt localhost:8081/auth/organization/invites
```

```json
{"user":{"id":"usr_ruqwnkq3nklnfdhqjrdmtbfd","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"invites":[]}
{"email":"bob@example.com"}
{"invites":[{"id":"inv_vpe2ps24ob223xsawzo4ranh","orgId":"org_7n2gshuichmdexqwfljzp56x","orgName":"Acme","email":"bob@example.com","role":"member","expiresAt":"2026-10-08T05:19:20.498563Z"}]}
```

Carol, signed in with a different verified address, cannot accept Bob's invitation by its id. Bob accepts once; the second time it is gone:

```sh
curl -s -b carol.txt -X POST localhost:8081/auth/organization/accept -H "$O" -d '{"inviteId":"inv_vpe2ps24ob223xsawzo4ranh"}'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/accept -H "$O" -d '{"inviteId":"inv_vpe2ps24ob223xsawzo4ranh"}'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/accept -H "$O" -d '{"inviteId":"inv_vpe2ps24ob223xsawzo4ranh"}'
curl -s -b bob.txt localhost:8081/auth/organization/list
```

```json
{"error":{"code":"organization.invite_invalid","message":"This invitation is not valid any more."}}
{"id":"org_7n2gshuichmdexqwfljzp56x","slug":"acme","name":"Acme","createdAt":"2026-10-01T05:19:20.39302Z"}
{"error":{"code":"organization.invite_invalid","message":"This invitation is not valid any more."}}
{"orgs":[{"id":"org_7n2gshuichmdexqwfljzp56x","slug":"acme","name":"Acme","createdAt":"2026-10-01T05:19:20.39302Z","role":"member"}]}
```

Accepting as someone who is already a member changes nothing: an invitation never promotes or demotes. Invitations expire after [a week](ds:block?id=defaultinvitettl-q2vrh7rg) (`organization.WithInviteTTL` changes it); `auth sweep` deletes expired unaccepted ones through the plugin's `Sweep`, together with the active-organization selections of expired sessions, and accepted ones stay as a record of who invited whom.

<!-- ds:block id=plugin-sweep-3qf5nypp -->
**Plugin.Sweep** · [`plugin/organization/organization.go:2588-2597`](../../plugin/organization/organization.go#L2588-L2597)

```go
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
```
<!-- /ds:block hash=2e436f -->

## Step 5 — Roles

Every operation checks a permission, `resource:action`, against the caller's roles; the built-in roles grant these defaults (`organization.DefaultRoles`):

| Role | Permissions | In words |
|---|---|---|
| [`owner`](ds:block?id=roleowner-szv8n5ye) | every statement of `organization.DefaultStatements` | Everything, including deleting the organization. Only an owner may grant the owner role or change or remove an owner, and the last owner can neither leave nor be demoted |
| [`admin`](ds:block?id=roleadmin-cghbz3fj) | `organization:update`, `member:create/update/delete`, `invitation:create/cancel`, `team:create/update/delete`, `ac:create/read/update/delete` | Run the organization except deleting it or touching owners |
| [`member`](ds:block?id=rolemember-k755wabe) | `ac:read` | List members and teams; leave |

Every member may read the organization, its members and its invitations, and leave. A member holding several roles (`"admin,billing"`, or `["admin","billing"]` in JSON) may do what any one of them allows. `Role.AtLeast` compares the built-in roles by rank, for code that only knows those three:

<!-- ds:block id=role-atleast-wxmtstyb -->
**Role.AtLeast** · [`plugin/organization/organization.go:251`](../../plugin/organization/organization.go#L251-L251)

```go
func (r Role) AtLeast(need Role) bool { return r.Rank() >= need.Rank() }
```
<!-- /ds:block hash=5f25d8 -->

Alice lists the members; Carol, not a member, gets `404 organization.not_member`, the same answer as for an organization that does not exist; Bob, a member, may not invite:

```sh
curl -s -b alice.txt 'localhost:8081/auth/organization/members?orgId=org_7n2gshuichmdexqwfljzp56x'
curl -s -b carol.txt 'localhost:8081/auth/organization/members?orgId=org_7n2gshuichmdexqwfljzp56x'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/invite -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","email":"carol@example.com","role":"member"}'
```

```json
{"members":[{"user":{"id":"usr_m3mzjqnkozbyecm67f6evmxp","name":"Alice","image":""},"role":"owner","joinedAt":"2026-10-01T05:19:20.393135Z"},{"user":{"id":"usr_ruqwnkq3nklnfdhqjrdmtbfd","name":"Bob","image":""},"role":"member","joinedAt":"2026-10-01T05:19:24.933532Z"}]}
{"error":{"code":"organization.not_member","message":"Not found."}}
{"error":{"code":"organization.forbidden","message":"Your role does not allow this."}}
```

Alice promotes Bob to admin with `POST /auth/organization/set-role`. He may now invite a member or an admin, but not an owner, and he may change the roles of members and admins but not make anyone an owner:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/set-role -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","userId":"usr_ruqwnkq3nklnfdhqjrdmtbfd","role":"admin"}'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/invite -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","email":"carol@example.com","role":"owner"}'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/invite -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","email":"carol@example.com","role":"admin"}'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/set-role -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","userId":"usr_ruqwnkq3nklnfdhqjrdmtbfd","role":"owner"}'
```

```json
{"ok":true}
{"error":{"code":"organization.forbidden","message":"Your role does not allow this."}}
{"ok":true}
{"error":{"code":"organization.forbidden","message":"Your role does not allow this."}}
```

The last owner stays. Alice cannot demote herself or leave while she is the only owner; Bob, an admin, cannot remove her; Bob may leave:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/set-role -H "$O" \
  -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","userId":"usr_m3mzjqnkozbyecm67f6evmxp","role":"member"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/remove-member -H "$O" -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","userId":"usr_m3mzjqnkozbyecm67f6evmxp"}'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/remove-member -H "$O" -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","userId":"usr_m3mzjqnkozbyecm67f6evmxp"}'
curl -s -b bob.txt -X POST localhost:8081/auth/organization/remove-member -H "$O" -d '{"orgId":"org_7n2gshuichmdexqwfljzp56x","userId":"usr_ruqwnkq3nklnfdhqjrdmtbfd"}'
curl -s -b bob.txt localhost:8081/auth/organization/list
```

```json
{"error":{"code":"organization.last_owner","message":"An organization needs at least one owner."}}
{"error":{"code":"organization.last_owner","message":"An organization needs at least one owner."}}
{"error":{"code":"organization.forbidden","message":"Your role does not allow this."}}
{"ok":true}
{"orgs":[]}
```

From Go: `org.SetRole(ctx, organization.SetRoleRequest{…})`, `org.RemoveMember(ctx, organization.MemberRequest{…})`, and `org.RoleOf(ctx, orgID, userID)` for your own checks, which returns `organization.ErrNotMember` for a non-member.

## Step 6 — Require a role on your own routes

`RequireRole` is middleware for the app's routes. It takes a function that finds the organization in the request (a path value, a header, a subdomain) and the least role allowed, and it must sit inside `authhttp.Middleware`. A stranger gets 404, a lower role 403:

<!-- ds:block id=plugin-requirerole-nk7tdwhr -->
**Plugin.RequireRole** · [`plugin/organization/organization.go:2606-2621`](../../plugin/organization/organization.go#L2606-L2621)

```go
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
```
<!-- /ds:block hash=49dbaa -->

The example guards two pages, a dashboard for every member and billing for admins and owners:

<!-- ds:block id=newhandler-kn3pd8s3 -->
**newHandler** · [`examples/organizations/main.go:139-150`](../../examples/organizations/main.go#L139-L150)

```go
func newHandler(a *auth.Auth) (http.Handler, error) {
	orgs, err := auth.PluginOf[*organization.Plugin](a)
	if err != nil {
		return nil, err
	}
	mw := authhttp.Middleware(a)
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /orgs/{"+pathOrgParam+"}/dashboard", mw(orgs.RequireRole(orgInPath, organization.RoleMember)(page("dashboard"))))
	mux.Handle("GET /orgs/{"+pathOrgParam+"}/billing", mw(orgs.RequireRole(orgInPath, organization.RoleAdmin)(page("billing"))))
	return mux, nil
}
```
<!-- /ds:block hash=9d26f4 -->

<!-- ds:block id=orginpath-kmt4xuts -->
**orgInPath** · [`examples/organizations/main.go:156`](../../examples/organizations/main.go#L156-L156)

```go
func orgInPath(r *http.Request) string { return r.PathValue(pathOrgParam) }
```
<!-- /ds:block hash=4d387b -->

From the example's own [walkthrough](../../examples/organizations/README.md), Bob as a member and Alice as the owner:

```sh
curl -s -b bob.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/dashboard
curl -s -b bob.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/billing
curl -s -b alice.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/billing
curl -s -b carol.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/dashboard
```

```json
{"page":"dashboard","orgId":"org_uthxqr3x3c4pgpfee2v6hs6m","user":"Bob"}
{"error":{"code":"organization.forbidden","message":"Your role does not allow this."}}
{"page":"billing","orgId":"org_uthxqr3x3c4pgpfee2v6hs6m","user":"Alice"}
{"error":{"code":"organization.not_member","message":"Not found."}}
```

## Step 7 — Your own workspace data

Everything of yours that belongs to a workspace references `auth_org.id`, the way a user's rows reference `auth_user.id`; reading and joining the plugin's tables is open to the app, writing them is not (the invariants live in the operations). The typed columns are exported (`organization.OrgID`, `organization.MemberRole`, …), so a query against them is checked at compile time.

To bring one organization's membership into a composite user query, join with `UserJoin` and bind with `UserBindings`. The join is LEFT, so a non-member still comes back, with an empty role and a nil `JoinedAt`:

<!-- ds:block id=userjoin-m9umxmfp -->
**UserJoin** · [`plugin/organization/organization.go:2557-2566`](../../plugin/organization/organization.go#L2557-L2566)

```go
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
```
<!-- /ds:block hash=5f6400 -->

<!-- ds:block id=usermembership-2dd9ujgq -->
**UserMembership** · [`plugin/organization/organization.go:2523-2537`](../../plugin/organization/organization.go#L2523-L2537)

```go
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
```
<!-- /ds:block hash=7185a9 -->

<!-- ds:block id=userbindings-dcvjmyv7 -->
**UserBindings** · [`plugin/organization/organization.go:2576-2581`](../../plugin/organization/organization.go#L2576-L2581)

```go
func UserBindings(dst *UserMembership) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(sqlb.Coalesce(MemberRole, sqlb.Literal[Role]("''")), &dst.Role),
		sqlb.Bind(sqlb.Nullable(MemberJoinedAt), &dst.JoinedAt),
	}
}
```
<!-- /ds:block hash=575f13 -->

The org id is bound as a parameter inside the `ON` clause, never interpolated, so a value from the URL is safe to pass. See [databases](../concepts/databases.md) for the composite user itself.

Writing your own rows is where the transaction matters. An app table keyed by `org_id` (projects, billing, settings) should never disagree with `auth_org`: no organization without its first row, no rows left after the organization is deleted. [`examples/org-workspace`](../../examples/org-workspace) keeps a `project` table that way, in two places.

Every organization, created over HTTP or from Go, gets its first project from an `AfterCreateOrg` hook, and `BeforeDeleteOrg` removes the projects. Hooks run inside the operation's transaction, and `a.Conn(ctx)` returns that transaction, so an error in either hook rolls the organization back too. The hooks need the `*auth.Auth`, which does not exist yet when the plugin's options are built, so they are passed with `organization.WithHooksFrom(hooks)`: the plugin calls `hooks(a)` once, when `auth.New` initializes it.

<!-- ds:block id=orgworkspace-hooks-4k8wq2vn -->
**hooks** · [`examples/org-workspace/main.go:159-174`](../../examples/org-workspace/main.go#L159-L174)

```go
func hooks(a *auth.Auth) organization.Hooks {
	return organization.Hooks{
		AfterCreateOrg: func(ctx context.Context, org organization.Org, _ auth.User) error {
			_, err := addProject(ctx, a, org.ID, defaultProject)
			return err
		},
		BeforeDeleteOrg: func(ctx context.Context, org organization.Org) error {
			conn, err := a.Conn(ctx)
			if err != nil {
				return err
			}
			_, err = conn.ExecContext(ctx, deleteProjects, org.ID)
			return err
		},
	}
}
```
<!-- /ds:block hash=97a026 -->

When your code creates the organization itself (an import, a sign-up that also creates the company), wrap it in `a.Tx`. `CreateFor` joins the transaction, so a row of yours that cannot be written undoes the organization as well:

<!-- ds:block id=orgworkspace-import-7n3vx5qe -->
**importWorkspace** · [`examples/org-workspace/main.go:219-234`](../../examples/org-workspace/main.go#L219-L234)

```go
func importWorkspace(ctx context.Context, a *auth.Auth, orgs *organization.Plugin, in ImportRequest) (organization.Org, error) {
	var org organization.Org
	err := a.Tx(ctx, func(ctx context.Context, _ *sql.Tx) error {
		var err error
		if org, err = orgs.CreateFor(ctx, in.OwnerID, organization.CreateRequest{Name: in.Name, Slug: in.Slug}); err != nil {
			return err
		}
		for _, name := range in.Projects {
			if _, err := addProject(ctx, a, org.ID, name); err != nil {
				return err
			}
		}
		return nil
	})
	return org, err
}
```
<!-- /ds:block hash=49a175 -->

Try it: `go test ./org-workspace` in `examples`. `TestOrgWorkspace_ImportIsAllOrNothing` imports a workspace whose project collides with the default one and finds neither the organization nor any project afterwards; `TestOrgWorkspace_DeleteTakesTheProjects` deletes one organization over HTTP and keeps another's projects. The app's own routes over the table check the request's origin themselves (the library checks it only on its own routes), which the example's README shows with a real run:

```json
{"orgId":"org_jzvh7nimq3wewbk76cqil6bq","projects":[{"id":"prj_kfkjxpw7wg7wxvegd4skpot5","name":"General"}]}
{"error":{"code":"project.name_taken","message":"A project with this name already exists."}}
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

## Step 8 — Logo, metadata, update and delete

`create` also takes `logo` (a URL) and `metadata` (a JSON object of at most 16 KiB, `organization.MaxMetadataSize`), and both come back on every read of the organization. A member reads one organization with `GET /auth/organization/get-organization?orgId=` (or `orgSlug=`), and a settings page reads everything at once with `GET /auth/organization/get-full-organization`: the organization, its members (`membersLimit`, default 50), its pending invitations and, with teams on, its teams.

`POST /auth/organization/update` with `{orgId, data: {name, slug, logo, metadata}}` needs `organization:update` (owner, admin); a field left out stays, an empty `logo` clears it, and the slug follows the create rules. `POST /auth/organization/delete` with `{orgId}` needs `organization:delete` (owner only) and removes the organization with its members, invitations, teams, dynamic roles and every session's selection of it, in one transaction. From Go: `org.Get`, `org.GetFull`, `org.Update`, `org.Delete`.

## Step 9 — The active organization

Each session may have an active organization (`activeOrganizationId`). Creating an organization makes it active (send `keepCurrentActiveOrganization: true` to keep the current one); `POST /auth/organization/set-active` with `{orgId}` or `{orgSlug}` switches, for members only, and `{}` clears it. `GET /auth/organization/active` answers `{activeOrganizationId, activeTeamId, organization}`.

Every operation that takes an `orgId` uses the active organization when it is left out, so a frontend that has selected a workspace can call `members`, `invite`, `list-invitations` and the rest without repeating it; with neither, the answer is `400 organization.no_active`. In your own handlers, `org.ActiveOrgID(ctx)` returns it.

The selection lives in `auth_org_active`, keyed by session id, not as a column of `auth_session`, so it works with every [session store](../concepts/sessions.md) (SQL, Redis, memory, stateless). Signing out drops it, a pending second-factor session hands it to the full session, removing a member drops theirs, and `auth sweep` removes the selections of expired sessions. An API-key request has no session and gets `409 auth.session_data_unavailable` from `set-active`.

An app route that scopes its own queries to the selection reads it from Go. The example's `/workspace` page answers the active organization and team:

<!-- ds:block id=orgteams-workspace-6t3hs8qe -->
**workspace** · [`examples/org-teams/main.go:181-199`](../../examples/org-teams/main.go#L181-L199)

```go
func workspace(orgs *organization.Plugin) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		active, err := orgs.Active(r.Context())
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		if active.OrgID == nil {
			authhttp.WriteError(w, errNoWorkspace)
			return
		}
		out := workspaceResponse{OrgID: *active.OrgID}
		if active.TeamID != nil {
			out.TeamID = *active.TeamID
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out) // a client that hung up cannot be told
	}
}
```
<!-- /ds:block hash=523e2e -->

Right after Alice creates Acme, it is her active organization:

```sh
curl -s -b alice.txt localhost:8081/auth/organization/active
curl -s -b alice.txt localhost:8081/workspace
```

```json
{"activeOrganizationId":"org_cnovtgatzadaew2d5g6fmd4r","activeTeamId":null,"organization":{"id":"org_cnovtgatzadaew2d5g6fmd4r","slug":"acme","name":"Acme","createdAt":"2026-10-09T03:12:19.801789Z"}}
{"orgId":"org_cnovtgatzadaew2d5g6fmd4r"}
```

Check: `TestOrgTeams_TeamsRolesAndInvites` (the selection after create, and after `set-active-team`).

## Step 10 — Invitation states

An invitation is `pending`, `accepted`, `rejected` or `canceled` (`organization.InviteStatusValues`). The invitee declines with `POST /auth/organization/reject-invitation {inviteId}`, matched through the same verified address as accept. A member with `invitation:cancel` (owner, admin) withdraws one with `POST /auth/organization/cancel-invitation {inviteId}`; a stranger, an unknown id and an invitation that is no longer pending all get `404 organization.invite_invalid`. `GET /auth/organization/list-invitations?orgId=` lists every invitation of the organization, newest first, with its status, inviter and team, for any member.

To send a pending invitation again, invite the same address with `"resend": true`: the invitation keeps its id, role and team, gets a fresh expiry and a new mail, and no second invitation is created. With nothing pending, `resend` is an ordinary invite. To make a plain second invite fail instead of adding another pending invitation, turn on `organization.RefuseRepeatInvites()`; the second invite is then `409 organization.already_invited`.

An organization holds at most 100 pending invitations by default (`organization.InvitationLimit(n)`; `0` is no cap); one more is `409 organization.invitation_limit`. Inviting an existing member is allowed by default and accepting keeps their role; `organization.RejectExistingMembers()` refuses it with `409 organization.already_member`, and refuses `AddMember` of a member too.

## Step 11 — Permissions and your own roles

`POST /auth/organization/has-permission` with `{orgId, permissions: {"member": ["delete"]}, connector}` answers `{"success": true|false}` for the caller; `connector` is `AND` (default) or `OR` across resources. On the server, `org.Can(ctx, orgID, userID, access.Request{…}, access.And)` answers the same, and `RequirePermission` guards a route the way `RequireRole` does:

<!-- ds:block id=exampleplugin-requirepermission-ph8srha8 -->
**ExamplePlugin_RequirePermission** · [`plugin/organization/example_test.go:29-38`](../../plugin/organization/example_test.go#L29-L38)

```go
func ExamplePlugin_RequirePermission() {
	orgs := organization.New()
	orgInPath := func(r *http.Request) string { return r.PathValue("org") }
	createProject := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	mux := http.NewServeMux()
	// Inside authhttp.Middleware in a real app.
	mux.Handle("POST /orgs/{org}/projects", orgs.RequirePermission(orgInPath, access.Request{"project": access.All("create")})(createProject))
	fmt.Println("mounted")
	// Output: mounted
}
```
<!-- /ds:block hash=2f3da9 -->

To add resources of your own, build an access control from a copy of `organization.DefaultStatements` plus yours, and roles from it, with the [access](access.md) module:

<!-- ds:block id=examplewithroles-unstje3r -->
**ExampleWithRoles** · [`plugin/organization/example_test.go:14-24`](../../plugin/organization/example_test.go#L14-L24)

```go
func ExampleWithRoles() {
	s := access.Statements{"project": {"create", "share"}}
	for k, v := range organization.DefaultStatements {
		s[k] = v
	}
	ac := access.MustNew(s)
	billing := ac.MustRole(access.Permissions{"project": {"create"}, organization.ResourceInvitation: {organization.ActionCreate}})
	org := organization.New(organization.WithAccessControl(ac), organization.WithRoles(map[organization.Role]access.Role{"billing": billing}))
	fmt.Println(org.Name(), billing.Allows(access.Request{"project": access.All("create")}))
	// Output: organization true
}
```
<!-- /ds:block hash=4bafcc -->

`WithRoles` adds roles and replaces a built-in one given under its name; `auth.New` refuses a role that names a statement the access control does not declare. `organization.CreatorRole(r)` makes the creator `admin`, say, instead of `owner`; it is also the role the owner protections guard. `TestR30_PermissionsAndCustomRoles` in `integration/r30_test.go` runs this setup on all three engines.

**A model other than roles.** Every permission decision above (each operation's check, `has-permission`, `Can`, `RequirePermission`, the grant check of a dynamic role, and plugin/apikey's organization-key question) goes through one `organization.Authorizer`, and `organization.WithAuthorizer(a)` replaces the role check with yours: attributes, a relationship store, a policy engine. It receives an `organization.AccessRequest` (organization, user, the member's role, the `access.Request`, the connector, the operation and the call) and any error refuses. Membership stays the plugin's, so a non-member is refused before it is asked, and roles keep deciding which roles a member may be given and the owner protections. To keep the roles and add a rule, wrap `org.RoleAuthorizer()`. Under a custom authorizer the creator role's all-permissions shortcut for organization API keys is off: the authorizer decides those keys too. [Bring your own authorization](../extending/11-authorization.md) builds one on a relationship store.

## Step 12 — Teams

`organization.Teams(organization.TeamsConfig{…})` turns on teams, sub-groups inside an organization. Every new organization gets a default team named after it, with the creator in it (`NoDefaultTeam` turns that off, `DefaultTeamName` names it).

The [`org-teams`](../../examples/org-teams) example turns on teams, run-time roles, hooks and invitations by email or phone in one place; its limits are named constants of the app:

<!-- ds:block id=orgteams-newauth-4w7nq2xk -->
**newAuth** · [`examples/org-teams/main.go:115-131`](../../examples/org-teams/main.go#L115-L131)

```go
func newAuth(db *sql.DB, m email.Mailer, sms phone.SMSSender, joined func(organization.MemberChange)) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			phone.New(phone.WithSMS(sms)),
			password.New(),
			organization.New(
				organization.Teams(organization.TeamsConfig{MaxTeams: maxTeams, MaxMembersPerTeam: maxMembersPerTeam}),
				organization.DynamicRoles(organization.DynamicRolesConfig{MaxRoles: maxCustomRoles}),
				organization.InviteBy(email.KindEmail, phone.KindPhone),
				organization.WithHooks(hooks(joined)),
			),
		),
	)
}
```
<!-- /ds:block hash=3d07fb -->

Acme has its default team as soon as it exists, and Alice adds one; `orgId` is left out, so the active organization is used:

```sh
curl -s -b alice.txt localhost:8081/auth/organization/list-teams
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create-team -H 'Origin: http://localhost:8081' -d '{"name":"Design"}'
```

```json
{"teams":[{"id":"team_l4gxddx374afpejp3qxeb3lo","orgId":"org_cnovtgatzadaew2d5g6fmd4r","name":"Acme","createdAt":"2026-10-09T03:12:19.801889Z","updatedAt":"2026-10-09T03:12:19.801889Z","memberCount":1}]}
{"id":"team_y3ckjx5vzmybhohh7ltuyeov","orgId":"org_cnovtgatzadaew2d5g6fmd4r","name":"Design","createdAt":"2026-10-09T03:12:19.83225Z","updatedAt":"2026-10-09T03:12:19.83225Z","memberCount":0}
```


| Route | Needs |
|---|---|
| `POST /auth/organization/create-team {orgId, name}` | `team:create`; at most `MaxTeams` per organization (`409 organization.teams_limit`) |
| `GET /auth/organization/list-teams?orgId=` | membership; each team carries `memberCount` |
| `POST /auth/organization/update-team {teamId, data: {name}}` | `team:update` |
| `POST /auth/organization/remove-team {teamId}` | `team:delete`; the last team stays (`409 organization.last_team`) unless `AllowRemovingAllTeams` |
| `POST /auth/organization/add-team-member {teamId, userId}` | `team:update`; the user must be a member of the organization; at most `MaxMembersPerTeam` (`409 organization.team_members_limit`) |
| `POST /auth/organization/remove-team-member {teamId, userId}` | yourself, or `team:update` |
| `POST /auth/organization/set-active-team {teamId}` | being in the team; it also makes its organization active. `{}` clears the team and keeps the organization |
| `GET /auth/organization/list-user-teams` | signed in: the caller's teams in every organization |
| `GET /auth/organization/list-team-members?teamId=` | membership of the team's organization; without `teamId`, the session's active team (`400 organization.no_active_team` when there is none) |

A team of an organization the caller is not in answers `404 organization.team_not_found`, like an unknown one. An invitation may carry `teamId`, and accepting it joins that team too. Leaving or being removed from the organization removes the member from its teams; deleting a team clears it from the sessions that had it active.

In the example Bob is invited with `"teamId"` set to Design, so accepting puts him in it (`list-user-teams` answers that one team), and Carol chooses Design with `set-active-team`, after which `/workspace` answers both ids. Check: `TestOrgTeams_TeamsRolesAndInvites`.

## Step 13 — Roles created at run time

`organization.DynamicRoles(organization.DynamicRolesConfig{MaxRoles: n})` lets each organization define roles of its own, stored in `auth_org_role` (dynamic access control):

| Route | Needs |
|---|---|
| `POST /auth/organization/create-role {orgId, role, permission}` | `ac:create`, and holding every permission the role grants: nobody mints a role stronger than their own |
| `POST /auth/organization/update-role {orgId, roleId or roleName, data: {roleName, permission}}` | `ac:update`; renaming only while no member holds the role |
| `POST /auth/organization/delete-role {orgId, roleId or roleName}` | `ac:delete`; refused while a member holds it (`409 organization.role_in_use`) |
| `GET /auth/organization/get-role`, `GET /auth/organization/list-roles` | `ac:read` (every built-in role has it) |

`update-role` and `delete-role` naming a configured role (owner, admin, member, or one from `WithRoles`) answer `400 organization.predefined_role`: those change only with a deploy.

A dynamic role is assigned like any other (`set-role`, `invite`), and its permissions count in every check. Its name may not be a static role's (`409 organization.role_taken`), a permission outside the statements is `400 organization.bad_permission`, and an organization holds at most `MaxRoles` (`409 organization.roles_limit`).

Alice gives Acme a `designer` role that may add and remove team members and nothing else, then invites Bob with it:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create-role -H 'Origin: http://localhost:8081' \
  -d '{"role":"designer","permission":{"team":["update"]}}'
```

```json
{"id":"role_rqhepmdzzbbbiiqqj3pikous","orgId":"org_cnovtgatzadaew2d5g6fmd4r","role":"designer","permission":{"team":["update"]},"createdAt":"2026-10-09T03:12:19.855628Z","updatedAt":"2026-10-09T03:12:19.855628Z"}
```

As a designer Bob adds Carol to Design, and his `create-team` is `403 organization.forbidden`; while he holds the role, `delete-role` is `409 organization.role_in_use`. Check: `TestOrgTeams_TeamsRolesAndInvites` and `TestOrgTeams_ErrorsUndoTheOperation`.

## Step 14 — Hooks

`organization.WithHooks(organization.Hooks{…})` takes organization hooks as typed Go functions: `Before`/`After` for creating, updating and deleting an organization; adding, removing and re-roling a member; creating, accepting, rejecting and canceling an invitation; creating, updating and deleting a team; adding and removing a team member. They run inside the operation's transaction: a `Before` hook may change the row it gets as a pointer (rename the organization, set the invitation's expiry or role) or refuse with an error, and an `After` hook's error rolls the whole operation back. A hook that writes your own rows needs the `*auth.Auth` for `a.Conn(ctx)` (the operation's transaction) or `a.Exec`: pass `organization.WithHooksFrom(func(a *auth.Auth) organization.Hooks {…})` instead, which the plugin calls with it at start-up; `auth.New` refuses both options together. What a hook changes is checked again, and the ids and the invited address are restored, so a hook can shape a row but never move it past a permission check. `auth.OperationHook` still works on every operation id for logging and vetoes.

The example refuses one team name its UI keeps for itself, with an error of its own, and reports every new member:

<!-- ds:block id=orgteams-hooks-8m2kx5vd -->
**hooks** · [`examples/org-teams/main.go:139-152`](../../examples/org-teams/main.go#L139-L152)

```go
func hooks(joined func(organization.MemberChange)) organization.Hooks {
	return organization.Hooks{
		BeforeCreateTeam: func(_ context.Context, team *organization.Team) error {
			if strings.EqualFold(strings.TrimSpace(team.Name), reservedTeamName) {
				return ErrReservedTeamName
			}
			return nil
		},
		AfterAddMember: func(_ context.Context, m organization.MemberChange) error {
			joined(m)
			return nil
		},
	}
}
```
<!-- /ds:block hash=9cabf9 -->

The app's error reaches the client with its own code and status, and the refused team is not created:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create-team -H 'Origin: http://localhost:8081' -d '{"name":"Everyone"}'
```

```json
{"error":{"code":"app.team_name_reserved","message":"That team name is reserved."}}
```

Check: `TestOrgTeams_ErrorsUndoTheOperation` (the refusal leaves one team) and `TestOrgTeams_TeamsRolesAndInvites` (the hook saw Bob join as `designer` and Carol as `member`). Declare the error once at package level with `auth.NewError`, as the example does, so its code is registered once and the client can match it.

## Step 15 — Extra columns on the plugin's tables

`organization.WithFields(organization.FieldsConfig{Org: …, Member: …, Invitation: …, Team: …, Role: …})` adds columns of your own, each an `organization.Field{Name, Type, Nullable, Default, Required, ServerOnly}` with the core's column types (`auth.ColumnText`, `ColumnInt`, `ColumnBool`, `ColumnTimestamp`). Each field is one migration (`0006_field_<table>_<name>`), so declaring one later migrates then; a NOT NULL field needs a constant `Default`.

Requests carry the values in a `fields` object (`{"name":"Acme","slug":"acme","fields":{"seats":12}}`) or as top-level keys beside the request's own (`{"name":"Acme","slug":"acme","seats":12}`; inside `data` for an update), on create and update of an organization, team and dynamic role and on invite. A field sent both ways is `400 auth.field_invalid`, and a top-level key that is no field `400 auth.bad_request`. Every read returns them in `fields`, defaults included. A value must have the column's type (a number for an int, an RFC 3339 string for a timestamp, `null` only for a nullable field) and the name must be declared, or the answer is `400 auth.field_invalid`, which names neither. `Required` refuses a create without the field; `ServerOnly` refuses it from a client, so only Go calls and the `Before` hooks set it (a plan, an external id). Member fields are set from Go with `org.AddMemberWith(ctx, organization.AddMemberRequest{…, Fields})` or by `BeforeAddMember`; a member field cannot be `Required`, because a member joins by an invitation that carries none. `auth.New` refuses a name that is not a plain identifier or shadows a column, an unknown type, a default that is not a constant literal, and team or role fields without `Teams` or `DynamicRoles`. `TestR30_AdditionalFields` runs every table on the three engines.

## Step 16 — Verified domains

`organization.Domains(organization.DomainsConfig{…})` lets an organization claim its email domain (Clerk's verified domains). An admin adds `acme.com`, proves the organization owns it, and picks what happens to anyone whose address at `acme.com` becomes verified:

| `enrollmentMode` | What the user gets |
|---|---|
| `manual_invitation` (default) | Nothing; invite people by hand as before |
| `automatic_invitation` | A pending invitation in `GET /auth/organization/invites`, accepted like any other; no mail is sent, since the user is in the app verifying right now |
| `automatic_suggestion` | The organization in `GET /auth/organization/domain-suggestions`; `accept-suggestion` asks to join, and an admin approves with `approve-membership-request` (or `reject-membership-request`, after which it is not suggested again) |
| `automatic_join` | Membership with the domain's `role` (`member` by default) |

Only a VERIFIED address enrolls: the plugin listens for an email identity being created verified or having its `verified_at` set, so typing `bob@acme.com` into a sign-up form does nothing until Bob clicks the link. Only a PROVED domain enrolls: a claim alone does nothing, so several organizations may claim `acme.com`, and the first to prove it gets it; after that nobody else can add it. A domain never grants the creator role, public mail domains (`gmail.com` and the rest of `organization.DefaultPublicDomains`) are refused, and adding, verifying, changing and removing a domain needs `organization:update`.

The [`org-domains`](../../examples/org-domains) example wires it:

<!-- ds:block id=orgdomains-newauth-njgrxgyy -->
**newAuth** · [`examples/org-domains/main.go:98-111`](../../examples/org-domains/main.go#L98-L111)

```go
func newAuth(db *sql.DB, m email.Mailer, verifier organization.DomainVerifier) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			organization.New(organization.Domains(organization.DomainsConfig{
				Verifier:           verifier,
				TrustVerifiedEmail: true,
			})),
		),
	)
}
```
<!-- /ds:block hash=2f8ec2 -->

Proof is a DNS TXT record by default: `add-domain` answers the `recordName` and `recordValue` to publish, and `verify-domain` looks it up (at most 10 times a minute per client address). Replace the check with your own [`DomainVerifier`](ds:block?id=domainverifier-xyngwy9v) (an HTTP file, your registrar's API, a fake in tests); its error answers `503 organization.domain_check_failed`, never a pass. With `TrustVerifiedEmail`, as in the example, an admin who has a verified address at the domain proves it by adding it. That is off by default because it lets any employee with a work address claim the company's domain for an organization they made; DNS needs control of the zone. From Go, `org.MarkDomainVerified(ctx, domainID)` verifies one an operator checked another way.

Alice, with a verified `alice@acme.com`, adds `acme.com` in auto-join mode; `gmail.com` is refused:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/add-domain -H 'Origin: http://localhost:8081' \
  -d '{"orgId":"org_2ms64etgftxzv7ummx3vlsqe","domain":"acme.com","enrollmentMode":"automatic_join","role":"member"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/add-domain -H 'Origin: http://localhost:8081' \
  -d '{"orgId":"org_2ms64etgftxzv7ummx3vlsqe","domain":"gmail.com"}'
```

```json
{"id":"odom_sky2r55agi7eqwzzlxe3jqv2","orgId":"org_2ms64etgftxzv7ummx3vlsqe","domain":"acme.com","enrollmentMode":"automatic_join","role":"member","verified":true,"verifiedAt":"2026-10-13T12:40:09.662605Z","recordName":"_auth-verification.acme.com","recordValue":"auth-domain-verification=svIv7ocaELO3T1vfV7dyC8X6MkHaJ2cZf3YDLfI94CU","createdAt":"2026-10-13T12:40:09.662482Z"}
{"error":{"code":"organization.public_domain","message":"This is a public email domain and cannot belong to an organization."}}
```

Bob signs up with `bob@acme.com`. He is in no organization until he verifies the address, and in Acme right after:

```sh
curl -s -b bob.txt localhost:8081/auth/organization/list
curl -s -b bob.txt -X POST localhost:8081/auth/email/verify -H 'Origin: http://localhost:8081' -d '{"token":"…"}'
curl -s -b bob.txt localhost:8081/auth/organization/list
```

```json
{"orgs":[]}
{"email":"bob@acme.com"}
{"orgs":[{"id":"org_2ms64etgftxzv7ummx3vlsqe","slug":"acme","name":"Acme","createdAt":"2026-10-13T12:40:09.649952Z","role":"member"}]}
```

People who verified an `acme.com` address before the domain was proved are not enrolled retroactively; suggestions are worked out when listed, so they do see those. Enrollment that the organization's own rules refuse (`MaxMembers`, a `BeforeAddMember` hook) is logged and skipped rather than failing the user's verification. Removing a domain drops its pending requests; invitations it created stay until canceled or expired.

## Options you may want

| Option | What it does | Default |
|---|---|---|
| `organization.WithInviteTTL(d)` | How long an invitation stays acceptable | a week (`organization.DefaultInviteTTL`) |
| `organization.InviteLink(func() string)` | The page the mail links to; called per mail | `BaseURL` + `/invitations` |
| `organization.InviteBy(kinds...)` | The identifier kinds an invitation may be addressed to, such as `phone.KindPhone`; the first is used when a request names no kind | email |
| `organization.WithoutInvitations()` | No invitation routes; members are added from Go only (`AddMember`). Requires no identifier plugin | invitations on |
| `organization.InviteMessage(func(organization.InviteMail) (subject, text string))` | Word the mail yourself from the invitation, the organization, the inviter and the link ("Alice invited you to Acme") | the plugin's wording |
| `email.Templates(fn)` on the email plugin | Your own wording for `organization.PurposeInvite`, which wins over `InviteMessage`; `m.Data.(organization.InvitationData)` gives it the invitation's fields | the plugin's wording |
| `organization.InviteLimit(n, window)` | How many invitations one client address may send per window | 50 per hour |
| `organization.ReplacePendingInvites()` | Inviting an address again withdraws its pending invitations to that organization and sends one fresh mail | off: each invite adds a pending invitation |
| `organization.RefuseRepeatInvites()` | Inviting an address that already has a pending invitation is `409 organization.already_invited`, unless the request sets `resend` | off: each invite adds a pending invitation |
| `organization.CreateGate(func(ctx, auth.User) (bool, error))` | Who may create an organization, for example only on a paid plan; `false` answers `403 organization.create_forbidden` | everyone signed in |
| `organization.MaxOwned(n)` | How many organizations one user may own; the next create is `409 organization.limit_reached` | no cap |
| `organization.MaxMembers(n)` | How many members an organization may have; accepting or `AddMember` into a full one is `409 organization.members_limit`, invitations still go out | no cap |
| `organization.InvitationLimit(n)` | Pending invitations one organization may hold; `0` is no cap | 100 |
| `organization.RejectExistingMembers()` | Refuse to invite or add someone already in the organization | off: the invitation goes out and accepting keeps the role |
| `organization.CreatorRole(r)` | The role the creator gets, and the one the owner protections guard | `owner` |
| `organization.WithAccessControl(ac)`, `organization.WithRoles(map)` | Your permission vocabulary and roles (Step 11) | `DefaultStatements`, `DefaultRoles()` |
| `organization.Teams(organization.TeamsConfig{…})` | Teams (Step 12): `MaxTeams`, `MaxMembersPerTeam`, `AllowRemovingAllTeams`, `NoDefaultTeam`, `DefaultTeamName` | off |
| `organization.DynamicRoles(organization.DynamicRolesConfig{MaxRoles: n})` | Roles created per organization at run time (Step 13) | off |
| `organization.Domains(organization.DomainsConfig{…})` | Verified domains (Step 16): `Verifier`, `RecordPrefix`, `TrustVerifiedEmail`, `IsPublicDomain`, `MaxDomains` | off |
| `organization.WithHooks(organization.Hooks{…})` | Lifecycle hooks (Step 14) | none |
| `organization.WithHooksFrom(func(a *auth.Auth) organization.Hooks)` | The same hooks, built once at start-up with the `*auth.Auth`, for hooks that write through `a.Conn(ctx)`; not with `WithHooks` | none |
| `organization.WithFields(organization.FieldsConfig{…})` | Extra columns on the plugin's tables (Step 15) | none |

Three more reads help a frontend: `GET /auth/organization/check-slug?slug=` answers `{slug, available}` before the create form submits; `GET /auth/organization/role?orgId=` is the caller's own role; `GET /auth/organization/invite?inviteId=` is one of the caller's pending invitations, for an accept page. `members` takes `page` and `limit` (default 50, at most 200) and returns `total`, and orders and narrows with `sortBy` (`joinedAt` or its other name `createdAt`, `name`, `role`, `userId`), `sortDirection` (`asc`, `desc`), `filterField`, `filterOperator` and `filterValue`: on `role`, `userId` and `name` the operators `eq`, `ne`, `in` and `not_in` (comma-separated values), `contains`, `starts_with` and `ends_with`, which keep case on every engine; on `joinedAt` or `createdAt` an RFC 3339 time with `eq`, `ne`, `lt`, `lte`, `gt` and `gte` ("members who joined after the first of October"); anything else is `400 organization.bad_query`; `remove-member` takes `email` instead of `userId` for a page that lists addresses, or `kind` and `identifier` for any other verified identifier.

From Go only, for a seed or an import: `org.CreateFor(ctx, userID, organization.CreateRequest{…})` creates an organization owned by a user without the gate or the cap, and `org.AddMember(ctx, orgID, userID, role)` adds a member without an invitation (an existing member keeps their role; `MaxMembers` and the hooks apply). Each runs in one transaction, joining the caller's when there is one.

For an operator's own admin screen, over every organization of the app: `org.ListAll(ctx, organization.AllOrgsRequest{Page, Limit, Search})` pages through all organizations with their member counts, and `GetFor`, `UpdateFor`, `DeleteFor`, `MembersFor`, `SetRoleFor`, `RemoveMemberFor`, `InvitationsFor` and `CancelFor` act on any one of them. They check no session or membership, so put them behind your admin check (the admin plugin's `RequireAdmin`, for example); the last owner still cannot be demoted or removed, and the hooks run.

The `/invitations` page is yours to build: it lists `GET /auth/organization/invites` and posts the chosen id to `accept`.

## Test fixtures

`github.com/ubgo/auth/plugin/organization/orgtest` creates organizations, saves them and adds members for an `authtest.Env` whose Auth has this plugin: `f := orgtest.New(env)`, then `fix := f.NewOrganization(ownerID, "")` builds one in memory (`orgtest.DefaultOrgName`, a random slug), `fix.Members` lists who else joins, and `f.SaveOrganization(fix)` writes it through `CreateFor` and `AddMember`, so every rule and hook runs. `f.AddMember(orgID, userID, role)` adds one more. Any refusal fails the test. It lives in this module because the core's `authtest` cannot import the plugin, and like `authtest` it imports no database driver.

[`examples/org-workspace`](../../examples/org-workspace) builds its organizations this way. The fixtures go through `CreateFor` and `AddMember`, so the example's create hook gives a fixture organization its default project, exactly as the HTTP route does:

<!-- ds:block id=orgworkspace-fixtures-3m9xw5kd -->
**TestOrgWorkspace_RolesGuardTheData** · [`examples/org-workspace/main_test.go:121-148`](../../examples/org-workspace/main_test.go#L121-L148)

```go
func TestOrgWorkspace_RolesGuardTheData(t *testing.T) {
	a := newApp(t)
	alice, bob, eve := a.env.CreateUser("Alice"), a.env.CreateUser("Bob"), a.env.CreateUser("Eve")
	fix := a.f.NewOrganization(alice.ID, "Acme")
	fix.Members = []orgtest.Member{{UserID: bob.ID, Role: organization.RoleMember}}
	org := a.f.SaveOrganization(fix)

	asBob := a.env.Browser(a.h)
	asBob.SetSession(a.env.SignIn(bob.ID))
	var list listResponse
	asBob.Get("/orgs/" + org.ID + "/projects").Expect(http.StatusOK).Decode(&list)
	if len(list.Projects) != 1 || list.Projects[0].Name != defaultProject {
		t.Fatalf("a fixture organization's projects = %+v", list.Projects)
	}
	if code := asBob.Post("/orgs/"+org.ID+"/projects", createRequest{Name: "Roadmap"}).Expect(http.StatusForbidden).ErrorCode(); code != organization.ErrForbidden.Code {
		t.Fatalf("a member creating: %q", code)
	}

	asEve := a.env.Browser(a.h)
	asEve.SetSession(a.env.SignIn(eve.ID))
	if code := asEve.Get("/orgs/" + org.ID + "/projects").Expect(http.StatusNotFound).ErrorCode(); code != organization.ErrNotMember.Code {
		t.Fatalf("a stranger reading: %q", code)
	}

	// Adding Eve as an admin with the fixture lets her create.
	a.f.AddMember(org.ID, eve.ID, organization.RoleAdmin)
	asEve.Post("/orgs/"+org.ID+"/projects", createRequest{Name: "Roadmap"}).Expect(http.StatusCreated)
}
```
<!-- /ds:block hash=8e7f73 -->

## From TypeScript

Use this when the workspace switcher, the members page and the invitations page run in a browser or an app. The [typed client](../client/README.md) has every route of this guide on `client.organization`; list `organization()` in `plugins`. Creating an organization, inviting, listing and switching are in [Flows › Organizations](../client/flows.md#organizations-a-first-tour); the blocks here are the pages after that.

The page the invitation mail links to (Step 4) lists the invitations for the user's verified addresses and accepts them by id:

<!-- ds:block id=tsp-org-invitations-5kq2wx8m -->
**acceptAllInvitations** · [`clients/ts/examples/plugin-organization.ts:14-22`](../../clients/ts/examples/plugin-organization.ts#L14-L22)

```typescript
export async function acceptAllInvitations(): Promise<string[]> {
  const { data } = await auth.organization.invites();
  const joined: string[] = [];
  for (const invitation of data?.invites ?? []) {
    const { data: org, error } = await auth.organization.accept({ inviteId: invitation.id });
    if (!error) joined.push(`${org.name} as ${invitation.role}`);
  }
  return joined;
}
```
<!-- /ds:block hash=b34441 -->

Members and a role change:

<!-- ds:block id=tsp-org-members-8mw3qk2x -->
**promote** · [`clients/ts/examples/plugin-organization.ts:27-33`](../../clients/ts/examples/plugin-organization.ts#L27-L33)

```typescript
export async function promote(orgId: string, userId: string): Promise<string> {
  const { data } = await auth.organization.members({ orgId, limit: "100" });
  if (!(data?.members ?? []).some((m) => m.user.id === userId)) return "Not a member.";
  const { error } = await auth.organization.setRole({ orgId, userId, role: "admin" });
  if (!error) return "Promoted.";
  return error.code === "organization.forbidden" ? "Only an owner or admin can change roles." : error.message;
}
```
<!-- /ds:block hash=4cc921 -->

A permission check to hide a button the caller could not use (Step 11's vocabulary):

<!-- ds:block id=tsp-org-permission-3nx7wk9q -->
**canInvite** · [`clients/ts/examples/plugin-organization.ts:38-41`](../../clients/ts/examples/plugin-organization.ts#L38-L41)

```typescript
export async function canInvite(orgId: string): Promise<boolean> {
  const { data } = await auth.organization.hasPermission({ orgId, permissions: { invitation: ["create"] } });
  return data?.success ?? false;
}
```
<!-- /ds:block hash=50b127 -->

The active organization (Step 9) and teams (Step 12):

<!-- ds:block id=tsp-org-active-6qk2mw4n -->
**switchTo** · [`clients/ts/examples/plugin-organization.ts:46-51`](../../clients/ts/examples/plugin-organization.ts#L46-L51)

```typescript
export async function switchTo(slug: string): Promise<string | null> {
  const switched = await auth.organization.setActive({ orgSlug: slug });
  if (switched.error) return null; // organization.not_member
  const { data } = await auth.organization.active();
  return data?.organization?.name ?? null;
}
```
<!-- /ds:block hash=d75e86 -->

<!-- ds:block id=tsp-org-teams-9wq4kx7m -->
**teamWith** · [`clients/ts/examples/plugin-organization.ts:55-60`](../../clients/ts/examples/plugin-organization.ts#L55-L60)

```typescript
export async function teamWith(orgId: string, name: string, userId: string): Promise<string | null> {
  const team = await auth.organization.createTeam({ orgId, name });
  if (team.error) return null;
  const added = await auth.organization.addTeamMember({ teamId: team.data.id, userId });
  return added.error ? null : team.data.id;
}
```
<!-- /ds:block hash=3814bb -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `organization.forbidden` (the caller's role does not allow it), `organization.not_member`, `organization.slug_taken` (check first with `checkSlug`), `organization.bad_slug`, `organization.bad_role`, `organization.last_owner`, `organization.already_member`, `organization.already_invited`, `organization.invite_invalid`, `organization.limit_reached` and the other `*_limit` codes, `organization.no_active` when a call relies on an active organization that is not set.

Try it: `examples/ts-client-flows` creates an organization, invites a colleague (who gets a mail), lists the caller's organizations with their role and makes one active, from Node ([Flows › Try it](../client/flows.md#try-it)).

Pitfalls:

- **An invitation is accepted only by a verified address.** A user who signed up with the invited address but has not verified it sees no invitations; send them to verify first.
- **`orgId` is optional wherever the server falls back to the active organization.** `setActive` takes `orgId` or `orgSlug` (neither clears the selection), `removeMember` takes `userId`, `email` or `kind` with `identifier`, `updateRole` takes `roleId` or `roleName`; send the one you have. Operations on an organization (`invite`, `removeMember`, `setRole`, `hasPermission`, `createTeam`, `update`, `createRole`, `updateRole`) act on the session's active organization when `orgId` is left out, and answer `organization.no_active` when there is none.
- **Paging and filter inputs of list routes are strings** (`members({ orgId, limit: "100" })`), because they travel in the query string.
- **Teams and dynamic roles exist only when the server enables them** (`Teams()`, `DynamicRoles()`); the prebuilt client has their methods because it was generated with both, and a server without them answers `auth.unknown_operation`.

Every method with its route and types: [TypeScript client reference › organization](../reference/ts-client.md#organization).

## What can go wrong

- `auth: plugin dependency not registered: "organization" requires "email"` — the email plugin is missing from `auth.WithPlugins`. Add it, or invite by another kind (`organization.InviteBy`) or not at all (`organization.WithoutInvitations`).
- `auth: plugin "organization": organization: invitations are addressed by "phone", which no plugin registers` — `InviteBy` names a kind whose identifier plugin is not in `auth.WithPlugins`.
- `auth: plugin "organization": organization: invitations are addressed by "username", whose plugin cannot deliver messages: auth: the identifier kind's plugin cannot deliver messages` — `InviteBy` names a kind nobody can send an invitation to; address invitations by email or phone instead.
- `auth: plugin "organization": organization: invitation links need auth.WithBaseURL or organization.InviteLink` — no page for the mail to link to.
- `400 organization.bad_slug` ("Use lowercase letters, digits and dashes.") — the slug does not match the pattern above.
- `409 organization.slug_taken` ("This address is already in use.") — another organization has the slug.
- `400 organization.bad_role` ("This role does not exist.") — a role that is neither a static role (built-in or `WithRoles`) nor a dynamic role of the organization.
- `404 organization.not_member` ("Not found.") — the caller, or the target of remove-member or set-role, is not a member. Also what a stranger sees from `RequireRole`.
- `403 organization.forbidden` ("Your role does not allow this.") — the caller's roles lack the permission the operation checks (a member inviting, an admin deleting the organization), a non-owner granting the owner role or touching an owner, or a role below the one `RequireRole` asks for, or a permission `RequirePermission` asks for.
- `409 organization.last_owner` ("An organization needs at least one owner.") — demoting or removing the only owner. Make someone else an owner first.
- `404 organization.invite_invalid` ("This invitation is not valid any more.") — the id is unknown, expired, already accepted, or addressed to an address the caller has not verified. One error for all four, so a guessed id reveals nothing.
- `429 auth.rate_limited` on `invite` — more than 50 invitations in an hour from one address, or whatever `organization.InviteLimit` set.
- `403 organization.create_forbidden` ("You cannot create an organization.") — the `CreateGate` said no for this user.
- `409 organization.limit_reached` ("You have reached the number of organizations you can own.") — `MaxOwned`; promote someone else to owner and leave, or raise the cap.
- `409 organization.members_limit` ("This organization is full.") — `MaxMembers`; the invitation stays pending until there is room.
- `auth: plugin "organization": organization: InviteLimit needs a positive limit and window` — `InviteLimit` with a zero limit or window.
- `400 organization.no_active` ("No organization is active.") — the request left out `orgId` and its session has no active organization (Step 9).
- `400 organization.bad_metadata` — metadata that is not a JSON object, or over 16 KiB.
- `400 organization.bad_query` — a members sort or filter outside the lists above.
- `409 organization.invitation_limit`, `409 organization.already_member` — Step 10.
- `404 organization.team_not_found`, `409 organization.teams_limit`, `409 organization.team_members_limit`, `409 organization.last_team` — Step 12.
- `404 organization.role_not_found`, `409 organization.role_taken`, `409 organization.roles_limit`, `409 organization.role_in_use`, `400 organization.bad_permission` — Step 13.
- `400 organization.bad_domain`, `400 organization.public_domain`, `409 organization.domain_taken`, `409 organization.domains_limit`, `409 organization.domain_not_verified`, `503 organization.domain_check_failed`, `400 organization.bad_enrollment`, `400 organization.domain_role`, `404 organization.domain_not_found`, `404 organization.request_invalid` — Step 16.
- A colleague at the domain was not enrolled — their address is not verified yet, the domain is not verified (`verified: false` in `list-domains`), the mode is `manual_invitation`, or they verified before the domain was proved (they still see it as a suggestion in suggestion mode).
- `auth: plugin "organization": organization: CreatorRole "…" is not a static role`, `organization: role "…": access: unknown resource …` — a creator role or a `WithRoles` role that does not fit the access control.
- A hook's own error — a `Before` or `After` hook returned it, and the whole operation was rolled back. An `*auth.Error` keeps its code and status (`400 app.team_name_reserved` in the example); any other error is answered `500 auth.internal` with no detail, so give a refusal the client should see an `auth.NewError` code.
- The invited user sees no invitation — their address is not verified yet, or it differs from the invited one after normalization. Verification first, then the list fills.

## Next

- [Bring your own authorization](../extending/11-authorization.md): decide every organization permission with your own model; [`examples/authorizer`](../../examples/authorizer) runs a policy table in place of the roles.
- [Enterprise SSO](sso.md): attach a customer's identity provider to their organization, so their people join it on first sign-in.
- [Email](email.md): verification, which is what makes an invitation acceptable.
- [Databases](../concepts/databases.md): the composite user and joining plugin tables.
- [Migrations and maintenance](../concepts/migrations-and-maintenance.md): `auth sweep`, which clears expired invitations.
- The plugin's [README](../../plugin/organization/README.md) is the reference for its routes, tables and errors.
