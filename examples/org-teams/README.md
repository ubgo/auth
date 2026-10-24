# Organizations with teams, run-time roles, hooks and phone invitations

The organization plugin the way a team product uses it: every organization has teams, each session has an active organization and team, an organization defines roles of its own while the app runs, typed hooks refuse a reserved team name and report every new member, and an invitation goes by email or by text message. The basics (create, invite by email, accept, guard a route by role) are in [organizations](../organizations).

## Run it

```sh
cd examples
go run ./org-teams
```

It creates `org-teams.db` (SQLite) and listens on `http://localhost:8081`. Mail and text messages are printed to the log instead of sent. Run the tests with `go test ./org-teams`: they drive the whole flow below with three users and a phone number.

## Walkthrough

Alice signs up, verifies her address with the token from the mailed link, and creates Acme. Creating made it her active organization, and it already has a team named after it, with her in it:

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/verify -H 'Origin: http://localhost:8081' \
  -d '{"token":"kt4ISQtiyuuRUFH1cbn5AK5GiEJejuKI4_OsRcb_m_o"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H 'Origin: http://localhost:8081' \
  -d '{"name":"Acme","slug":"acme"}'
curl -s -b alice.txt localhost:8081/auth/organization/active
curl -s -b alice.txt localhost:8081/auth/organization/list-teams
```

```json
{"user":{"id":"usr_33nwm2fkhjv4j3qyfbaaf4tf","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"alice@example.com"}
{"id":"org_cnovtgatzadaew2d5g6fmd4r","slug":"acme","name":"Acme","createdAt":"2026-10-09T03:12:19.801789Z"}
{"activeOrganizationId":"org_cnovtgatzadaew2d5g6fmd4r","activeTeamId":null,"organization":{"id":"org_cnovtgatzadaew2d5g6fmd4r","slug":"acme","name":"Acme","createdAt":"2026-10-09T03:12:19.801789Z"}}
{"teams":[{"id":"team_l4gxddx374afpejp3qxeb3lo","orgId":"org_cnovtgatzadaew2d5g6fmd4r","name":"Acme","createdAt":"2026-10-09T03:12:19.801889Z","updatedAt":"2026-10-09T03:12:19.801889Z","memberCount":1}]}
```

She adds a Design team; `orgId` is left out, so the active organization is used. The app's hook refuses the name its UI keeps for itself, with the app's own error:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create-team -H 'Origin: http://localhost:8081' -d '{"name":"Design"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create-team -H 'Origin: http://localhost:8081' -d '{"name":"Everyone"}'
```

```json
{"id":"team_y3ckjx5vzmybhohh7ltuyeov","orgId":"org_cnovtgatzadaew2d5g6fmd4r","name":"Design","createdAt":"2026-10-09T03:12:19.83225Z","updatedAt":"2026-10-09T03:12:19.83225Z","memberCount":0}
{"error":{"code":"app.team_name_reserved","message":"That team name is reserved."}}
```

Acme defines a `designer` role that may add and remove team members, and nothing else:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create-role -H 'Origin: http://localhost:8081' \
  -d '{"role":"designer","permission":{"team":["update"]}}'
```

```json
{"id":"role_rqhepmdzzbbbiiqqj3pikous","orgId":"org_cnovtgatzadaew2d5g6fmd4r","role":"designer","permission":{"team":["update"]},"createdAt":"2026-10-09T03:12:19.855628Z","updatedAt":"2026-10-09T03:12:19.855628Z"}
```

Alice invites Carol by her phone number, as Carol would type it. The plugin stores it normalized and texts the invitation:

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

The app's own `/workspace` page answers the session's active organization, and its team once one is chosen with `set-active-team`:

```sh
curl -s -b alice.txt localhost:8081/workspace
```

```json
{"orgId":"org_cnovtgatzadaew2d5g6fmd4r"}
```

The test goes on from here: Bob is invited by email into Design as a `designer` and accepts; Carol signs up with her email, adds and verifies the number, and only then sees and accepts her invitation; Bob adds Carol to Design (his role grants `team:update`) but cannot create a team (`403 organization.forbidden`); Carol chooses Design and `/workspace` answers both ids; the hook saw Bob join as `designer` and Carol as `member`; and `delete-role` while Bob holds the role is `409 organization.role_in_use`.

```text
=== RUN   TestOrgTeams_TeamsRolesAndInvites
2026/10/09 08:44:56 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestOrgTeams_TeamsRolesAndInvites (0.34s)
=== RUN   TestOrgTeams_ErrorsUndoTheOperation
2026/10/09 08:44:56 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestOrgTeams_ErrorsUndoTheOperation (0.23s)
PASS
ok  	github.com/ubgo/auth/examples/org-teams	0.932s
```

## The code

The whole setup is one `auth.New`. The limits are named constants of the app, because each is a business decision:

<!-- ds:block id=orgteams-newauth-4w7nq2xk -->
**newAuth** · [`examples/org-teams/main.go:115-131`](main.go#L115-L131)

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

The hooks run inside the operation's transaction, so a refusal or an error from either undoes the whole operation:

<!-- ds:block id=orgteams-hooks-8m2kx5vd -->
**hooks** · [`examples/org-teams/main.go:139-152`](main.go#L139-L152)

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

`ErrReservedTeamName` is declared once at package level with `auth.NewError`, so the client gets its code and status like any of the library's errors; any other error from a hook would be answered `500 auth.internal` with no detail.

Limits of this example: the hook only logs a join; a real app would write its own audit row or start onboarding there. The `/invitations` page the messages link to is the app's to build, as in [organizations](../organizations).

## What this used

- [`plugin/organization`](https://pkg.go.dev/github.com/ubgo/auth/plugin/organization): `Teams`, `DynamicRoles`, `InviteBy`, `WithHooks`, `Plugin.Active`
- [`plugin/phone`](https://pkg.go.dev/github.com/ubgo/auth/plugin/phone): the phone identifier, its verification codes and the invitation text
- [`plugin/access`](https://pkg.go.dev/github.com/ubgo/auth/plugin/access): the permission shape of a run-time role
- Guide: [organizations, steps 9 and 12 to 14](../../docs/plugins/organization.md#step-12--teams). Related: [organizations](../organizations), [authorizer](../authorizer) (a policy of your own instead of roles).
