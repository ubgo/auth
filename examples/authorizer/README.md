# Authorizer: decide permissions with your own model

Each plugin that decides a permission asks one interface, and this app gives each a model of its own choosing instead of the built-in roles:

- **Organizations** ask a policy of the app's own: a table of `(role, resource, action)` lines, the shape of a Casbin policy, plus one attribute rule (a frozen organization may be read but not changed). It is a small Go function, so the example needs no policy engine; with Casbin or OPA the same function would call the engine.
- **Admin** asks the `accessadmin` adapter from the [access](../../plugin/access) module, which keeps better-auth's `admin` and `user` roles and adds `support`, who may look users up but not ban them.
- **API keys** carry permissions from the app's own vocabulary (`project:read`, `project:deploy`) through the `accessapikey` adapter, and an app route, `/deploy`, accepts only a key allowed to deploy.

## Run it

```sh
cd examples
go run ./authorizer
```

It creates `authorizer.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log. The interesting parts need a second user, an admin grant and keys minted from Go, so the tests are the walkthrough: `go test -v ./authorizer`.

## Walkthrough

```sh
go test -v ./authorizer
```

```text
=== RUN   TestAuthorizer_SupportRole
2026/10/09 08:44:48 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestAuthorizer_SupportRole (0.32s)
=== RUN   TestAuthorizer_OrganizationPolicy
2026/10/09 08:44:48 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestAuthorizer_OrganizationPolicy (0.25s)
=== RUN   TestAuthorizer_KeyPermissions
2026/10/09 08:44:48 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestAuthorizer_KeyPermissions (0.23s)
PASS
ok  	github.com/ubgo/auth/examples/authorizer	1.190s
```

- `TestAuthorizer_SupportRole`: Alice is made the first admin from Go and gives Sam the `support` role with `set-role`. Sam's `GET /auth/admin/users` answers; his `ban` is `403 admin.forbidden`. `set-role` with `auditor`, a role nobody defined, is `400 admin.bad_role`.
- `TestAuthorizer_OrganizationPolicy`: Bob, a plain member of Acme, invites Carol, which the built-in roles would refuse; `has-permission` for `member:delete` answers `false` for him. Once the app freezes Acme, even Alice's `update` is `403 organization.forbidden`, and reading the organization still works.
- `TestAuthorizer_KeyPermissions`: a key minted with `project:deploy` reaches `/deploy`, a `project:read` key gets `403 apikey.permission_denied`, a string that is no key `401 auth.signed_out`, and a key with `project:delete`, which the vocabulary does not declare, cannot be made (`apikey.ErrBadPermissions`).

Against the running server, after Alice signs up, verifies her address and creates Acme as in [organizations](../organizations), her own check as its owner, and the deploy route without a real key:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/organization/has-permission -H 'Origin: http://localhost:8081' \
  -d '{"orgId":"org_6vzqy62glhf3abhas4fgcb7l","permissions":{"member":["delete"]}}'
curl -s -X POST localhost:8081/deploy -H 'Deploy-Key: not-a-key'
```

```json
{"success":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## The code

Each plugin gets its model in one option:

<!-- ds:block id=authz-newauth-3r6kp8ve -->
**newAuth** · [`examples/authorizer/main.go:229-241`](main.go#L229-L241)

```go
func newAuth(db *sql.DB, m email.Mailer, frozen *frozenOrgs) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			admin.New(admin.WithAuthorizer(adminAuthorizer())),
			organization.New(organization.WithAuthorizer(orgAuthorizer(orgPolicy, frozen))),
			apikey.New(apikey.WithPermissions(accessapikey.New(keyAccess))),
		),
	)
}
```
<!-- /ds:block hash=8e3ab5 -->

The organization policy is data, and the authorizer reads it:

<!-- ds:block id=authz-orgpolicy-9h4mt6rw -->
**orgPolicy** · [`examples/authorizer/main.go:124-131`](main.go#L124-L131)

```go
var orgPolicy = []policyLine{
	{organization.RoleOwner, wildcard, wildcard},
	{organization.RoleAdmin, organization.ResourceMember, wildcard},
	{organization.RoleAdmin, organization.ResourceInvitation, wildcard},
	{organization.RoleAdmin, organization.ResourceOrganization, organization.ActionUpdate},
	{organization.RoleMember, organization.ResourceInvitation, organization.ActionCreate},
	{organization.RoleMember, organization.ResourceAC, organization.ActionRead},
}
```
<!-- /ds:block hash=11fa8b -->

<!-- ds:block id=authz-orgauthorizer-7c3ny5kd -->
**orgAuthorizer** · [`examples/authorizer/main.go:166-197`](main.go#L166-L197)

```go
func orgAuthorizer(policy []policyLine, frozen *frozenOrgs) organization.AuthorizerFunc {
	allows := func(roles []organization.Role, resource, action string) bool {
		return slices.ContainsFunc(policy, func(l policyLine) bool {
			return slices.Contains(roles, l.Role) &&
				(l.Resource == wildcard || l.Resource == resource) &&
				(l.Action == wildcard || l.Action == action)
		})
	}
	return func(_ context.Context, req organization.AccessRequest) (bool, error) {
		if len(req.Request) == 0 || frozen.frozen(req.OrgID) {
			return false, nil
		}
		roles := req.Role.Parts()
		anyResource := false
		for resource, want := range req.Request {
			ok := len(want.Actions) > 0
			for _, action := range want.Actions {
				has := allows(roles, resource, action)
				if want.Connector == access.Or && has {
					ok = true
					break
				}
				ok = ok && has
			}
			if !ok && req.Connector != access.Or {
				return false, nil
			}
			anyResource = anyResource || ok
		}
		return anyResource, nil
	}
}
```
<!-- /ds:block hash=360d38 -->

An error from an authorizer refuses the request, so a policy engine that is down fails closed. Membership stays the organization plugin's: a non-member is answered `404 organization.not_member` before the policy is asked.

The deploy route asks what the key itself allows. The key travels in a header of its own, not `Authorization`, so it does not sign the script in as its owner:

<!-- ds:block id=authz-deploy-8f2qz4lu -->
**deploy** · [`examples/authorizer/main.go:268-283`](main.go#L268-L283)

```go
func deploy(keys *apikey.Plugin) http.HandlerFunc {
	want := apikey.Permissions{resourceProject: {actionDeploy}}
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := keys.VerifyPermissions(r.Context(), r.Header.Get(deployKeyHeader), want)
		if err != nil {
			authhttp.WriteError(w, err)
			return
		}
		if !v.Valid {
			authhttp.WriteError(w, v.Reason)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(deployResponse{Deployed: true, By: v.UserID}) // a client that hung up cannot be told
	}
}
```
<!-- /ds:block hash=ce349e -->

Limits of this example: the frozen set lives in memory; a real app reads that attribute from its own billing table.

## What this used

- [`plugin/organization`](https://pkg.go.dev/github.com/ubgo/auth/plugin/organization): `WithAuthorizer`, `AuthorizerFunc`, `AccessRequest`
- [`plugin/access`](https://pkg.go.dev/github.com/ubgo/auth/plugin/access): `MustNew`, and the adapters `accessadmin.MustNew` and `accessapikey.New`
- [`plugin/admin`](https://pkg.go.dev/github.com/ubgo/auth/plugin/admin): `WithAuthorizer`, `Grant`
- [`plugin/apikey`](https://pkg.go.dev/github.com/ubgo/auth/plugin/apikey): `WithPermissions`, `CreateFor`, `VerifyPermissions`
- Guides: [bring your own authorization](../../docs/extending/11-authorization.md), [access control](../../docs/plugins/access.md). Related: [org-teams](../org-teams), [admin-ops](../admin-ops), [api-keys-and-jwt](../api-keys-and-jwt).
