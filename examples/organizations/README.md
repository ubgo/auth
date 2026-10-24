# Organizations: teams, invitations and roles

Teams on top of email and password sign-in. Alice creates an organization and invites Bob by email; Bob can accept only once he has verified that address; the app's own pages are guarded by the caller's role in the organization the URL names, and a stranger cannot tell the organization exists.

## Run it

```sh
cd examples
go run ./organizations
```

It creates `organizations.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./organizations`.

## Walkthrough

Alice signs up, verifies her address with the token from the mailed link, and creates an organization. She becomes its owner.

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/verify -H 'Origin: http://localhost:8081' \
  -d '{"token":"5mg3tmmia4jTGa2BM0MYYNtot0EnMFY7QENLMiBofas"}'
curl -s -b alice.txt -X POST localhost:8081/auth/organization/create -H 'Origin: http://localhost:8081' \
  -d '{"name":"Acme","slug":"acme"}'
```

```json
{"user":{"id":"usr_2e3dbg5rjkmyimi6sgapi2hk","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"alice@example.com"}
{"id":"org_uthxqr3x3c4pgpfee2v6hs6m","slug":"acme","name":"Acme","createdAt":"2026-09-29T08:21:34.96741Z"}
```

She invites Bob as a member. The invitation goes out by mail, in the app's own words:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/invite -H 'Origin: http://localhost:8081' \
  -d '{"orgId":"org_uthxqr3x3c4pgpfee2v6hs6m","email":"bob@example.com","role":"member"}'
```

```text
{"ok":true}

2026/09/29 13:51:34 mail to=bob@example.com subject="You are invited to join a team"
You were invited to join an organization. Sign in with this address, verify it if you have not, and accept the invitation here:

http://localhost:8081/invitations
```

Bob signs up with that address. His invitations list is empty until he verifies it, because anyone can type any address at sign-up; an invitation is matched only to a verified one.

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"bob@example.com","password":"correct horse battery staple","name":"Bob"}'
curl -s -b bob.txt localhost:8081/auth/organization/invites
curl -s -b bob.txt -X POST localhost:8081/auth/email/verify -H 'Origin: http://localhost:8081' \
  -d '{"token":"lQORTiJTt6iddr8EJ9aeROlqGuUcYQwpS45_ANZZUBY"}'
curl -s -b bob.txt localhost:8081/auth/organization/invites
```

```json
{"user":{"id":"usr_rkqyj6gk5u3432qtiuu4w5sg","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"invites":[]}
{"email":"bob@example.com"}
{"invites":[{"id":"inv_loknanum3nsn2bt6wqo3dthc","orgId":"org_uthxqr3x3c4pgpfee2v6hs6m","orgName":"Acme","email":"bob@example.com","role":"member","expiresAt":"2026-10-06T08:21:34.985015Z"}]}
```

He accepts, and Alice sees two members:

```sh
curl -s -b bob.txt -X POST localhost:8081/auth/organization/accept -H 'Origin: http://localhost:8081' \
  -d '{"inviteId":"inv_loknanum3nsn2bt6wqo3dthc"}'
curl -s -b alice.txt 'localhost:8081/auth/organization/members?orgId=org_uthxqr3x3c4pgpfee2v6hs6m'
```

```json
{"id":"org_uthxqr3x3c4pgpfee2v6hs6m","slug":"acme","name":"Acme","createdAt":"2026-09-29T08:21:34.96741Z"}
{"members":[{"user":{"id":"usr_2e3dbg5rjkmyimi6sgapi2hk","name":"Alice","image":""},"role":"owner","joinedAt":"2026-09-29T08:21:34.967443Z"},{"user":{"id":"usr_rkqyj6gk5u3432qtiuu4w5sg","name":"Bob","image":""},"role":"member","joinedAt":"2026-09-29T08:21:35.430134Z"}]}
```

The app's own pages check the role. Bob, a member, reaches the dashboard but not billing; Alice, the owner, reaches billing:

```sh
curl -s -b bob.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/dashboard
curl -s -b bob.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/billing
curl -s -b alice.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/billing
```

```json
{"page":"dashboard","orgId":"org_uthxqr3x3c4pgpfee2v6hs6m","user":"Bob"}
{"error":{"code":"organization.forbidden","message":"Your role does not allow this."}}
{"page":"billing","orgId":"org_uthxqr3x3c4pgpfee2v6hs6m","user":"Alice"}
```

Carol, signed in but not a member, gets 404, the same answer as for an organization that does not exist:

```sh
curl -s -b carol.txt localhost:8081/orgs/org_uthxqr3x3c4pgpfee2v6hs6m/dashboard
```

```json
{"error":{"code":"organization.not_member","message":"Not found."}}
```

## The code

The organization plugin requires the email plugin (`auth.New` fails without it): invitations are addressed to emails. The mail template words the invitation and leaves every other message to the defaults:

```go
email.New(email.Login(), email.Recover(), email.WithMailer(m), email.Templates(mailTemplates)),
password.New(),
organization.New(),
```

```go
func mailTemplates(m auth.Message) (subject, text string) {
	if m.Purpose == organization.PurposeInvite {
		return inviteSubject, inviteText + m.Link
	}
	return email.DefaultTemplates(m)
}
```

`RequireRole` guards the app's routes. It takes a function that finds the organization in the request, here a path wildcard (a subdomain or a header work the same way), and the least role allowed. Roles are ranked owner > admin > member:

```go
orgs, err := auth.PluginOf[*organization.Plugin](a)
mux.Handle("GET /orgs/{org}/dashboard", mw(orgs.RequireRole(orgInPath, organization.RoleMember)(page("dashboard"))))
mux.Handle("GET /orgs/{org}/billing", mw(orgs.RequireRole(orgInPath, organization.RoleAdmin)(page("billing"))))
```

The routes under `/auth/organization/`: `create`, `list`, `members`, `invite`, `invites`, `accept`, `remove-member`, `set-role`. An admin cannot invite above their own role, and the last owner can neither leave nor be demoted.

`main_test.go` runs this flow, promotes Bob to admin and checks he then reaches billing, and checks that Carol cannot accept Bob's invitation by its id.

Limits of this example: the `/invitations` page the mail links to is not built here; the app would list `GET /auth/organization/invites` there with an accept button. Invitations expire after a week (`organization.WithInviteTTL`), and `auth sweep` (see [cli](../cli)) deletes expired ones.

## What this used

- [`plugin/organization`](https://pkg.go.dev/github.com/ubgo/auth/plugin/organization): `New`, `RequireRole`, `Role`, `PurposeInvite`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): `Templates`, `DefaultTemplates`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `PluginOf`
- Related: [quickstart](../quickstart), [saas-workspace](../saas-workspace) (a workspace row created at sign-up), [api-keys-and-jwt](../api-keys-and-jwt).
