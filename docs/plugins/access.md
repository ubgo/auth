# Access control

You will check permissions in your app: declare which actions exist on which resources, define roles as subsets of them, and ask a role whether it may do something. It is the vocabulary the [organization plugin](organization.md) builds its roles from.

## Before you start

- `go get github.com/ubgo/auth/plugin/access`. It is its own module, because a permission model is a policy: the admin and organization plugins ask an `Authorizer`, and roles from this module are one way to answer. Package `access` imports only the standard library, keeps no state and has no routes.
- The reference for every name is the package's [README](../../plugin/access/README.md).
- The example for Steps 4 and 5 is [`examples/authorizer`](../../examples/authorizer): an admin `support` role through `accessadmin`, API-key permissions through `accessapikey`, and a policy of the app's own for organizations. `go test ./authorizer` in `examples/` runs it.

## Step 1 — Declare the vocabulary and the roles

A role may name only what the statements declare, so a misspelled resource or action fails when the role is built, at start-up, rather than silently granting nothing:

<!-- ds:block id=example-gwg3tegh -->
**Example** · [`plugin/access/example_test.go:12-28`](../../plugin/access/example_test.go#L12-L28)

```go
func Example() {
	ac := access.MustNew(access.Statements{
		"project": {"create", "share", "delete"},
		"billing": {"read", "update"},
	})
	editor := ac.MustRole(access.Permissions{"project": {"create", "share"}})
	accountant := ac.MustRole(access.Permissions{"billing": {"read", "update"}})

	fmt.Println(editor.Allows(access.Request{"project": access.All("create", "share")}))
	fmt.Println(editor.Authorize(access.Request{"project": access.Any("delete", "share")}, access.And) == nil)
	err := accountant.Authorize(access.Request{"project": access.All("create")}, access.And)
	fmt.Println(errors.Is(err, access.ErrDenied), err)
	// Output:
	// true
	// true
	// true access: denied: You are not allowed to access resource: project
}
```
<!-- /ds:block hash=e6c032 -->

## Step 2 — Check

`role.Authorize(req, connector)` returns `nil` when allowed. Per resource, `access.All(...)` needs every action and `access.Any(...)` one of them; across resources, `access.And` (the default) needs every resource and `access.Or` one. A resource the role grants nothing on fails at once, whatever the connector, and an empty request is denied: asking for nothing proves nothing. Every denial wraps `access.ErrDenied` with a fixed wording, so `errors.Is` works and a frontend can show the same text.

Permissions that arrive at run time (a role an administrator edits, a request body) go through `ac.Check(perms)` before they are stored or used, the same validation `NewRole` applies.

## Step 3 — With organizations

The organization plugin's own checks use the resources of `organization.DefaultStatements` (`organization`, `member`, `invitation`, `team`, `ac`). To add your own, start from a copy of those, build your roles from the result, and pass both with `organization.WithAccessControl` and `organization.WithRoles`; [organizations, step 11](organization.md#step-11--permissions-and-your-own-roles) shows it, with `has-permission`, `Can` and `RequirePermission`.

## Step 4 — With the admin plugin

The admin plugin's operations ask for permissions of `admin.DefaultStatements` (`user`: create, list, set-role, ban, impersonate, impersonate-admins, delete, set-password, set-email, get, update; `session`: list, revoke, delete). The admin plugin is in the core module and carries no permission engine: its built-in roles are `admin` and `user`. For roles of your own, build them from `accessadmin.DefaultAccessControl` (or a vocabulary starting from a copy of `admin.DefaultStatements`) and pass `admin.WithAuthorizer(accessadmin.MustNew(ac, roles))`. The example adds a support desk role that may look users and their sessions up, and nothing else:

<!-- ds:block id=authz-adminauthorizer-2k7xv9pm -->
**adminAuthorizer** · [`examples/authorizer/main.go:100-107`](../../examples/authorizer/main.go#L100-L107)

```go
func adminAuthorizer() *accessadmin.Authorizer {
	ac := accessadmin.DefaultAccessControl
	support := ac.MustRole(access.Permissions{
		admin.ResourceUser:    {admin.ActionList, admin.ActionGet},
		admin.ResourceSession: {admin.ActionList},
	})
	return accessadmin.MustNew(ac, map[string]access.Role{roleSupport: support})
}
```
<!-- /ds:block hash=eba011 -->

`accessadmin.MustNew` starts from the built-in `admin` and `user` roles (`accessadmin.DefaultRoles`), adds yours or replaces one given under its name, and refuses a role naming something the access control does not declare, or a name with a comma (several roles are stored comma-joined). The adapter is also an `admin.RoleCatalog`, so `set-role` accepts `support` and refuses a name it does not define with `400 admin.bad_role`. One user may hold several roles; a request is allowed when one of them grants all of it.

An admin then gives the role over HTTP, and the holder can list users but not ban one:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-role -H 'Origin: http://localhost:8081' -d '{"userId":"usr_…","role":["support"]}'
```

Check: `TestAuthorizer_SupportRole` in `examples/authorizer` (Sam lists users, his ban is `403 admin.forbidden`, the role `auditor` is `400 admin.bad_role`). [Admin, step 6](admin.md#step-6--grant-and-remove-admin-rights) covers granting and removing admin rights; to decide with something other than roles, see [bring your own authorization](../extending/11-authorization.md).

## Step 5 — With the apikey plugin

API-key permissions are checked by an `apikey.PermissionChecker`; the built-in one is `apikey.Vocabulary`. To make your access control's statements the vocabulary of your keys too, pass `apikey.WithPermissions(accessapikey.New(ac))` from the `accessapikey` package of this module. The example's keys may be allowed to read or to deploy a project:

<!-- ds:block id=authz-keyaccess-5n8wq2tc -->
**keyAccess** · [`examples/authorizer/main.go:90`](../../examples/authorizer/main.go#L90-L90)

```go
var keyAccess = access.MustNew(access.Statements{resourceProject: {actionRead, actionDeploy}})
```
<!-- /ds:block hash=d63b06 -->

<!-- ds:block id=authz-newauth-3r6kp8ve -->
**newAuth** · [`examples/authorizer/main.go:229-241`](../../examples/authorizer/main.go#L229-L241)

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

Permissions on a key are set from Go only (`CreateFor`, `DefaultPermissions`), never from a client body, because a user must not grant their own key powers the app did not decide. A permission outside the vocabulary is refused with `apikey.ErrBadPermissions` when the key is made. An app route then asks what the key itself allows; the example's deploy script sends its key in a header of its own, so the key does not sign the script in as its owner:

<!-- ds:block id=authz-deploy-8f2qz4lu -->
**deploy** · [`examples/authorizer/main.go:268-283`](../../examples/authorizer/main.go#L268-L283)

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

The adapter gives the same error codes and messages as the built-in checker, and the same `Grants` answers: a held permission the statements no longer declare is ignored, and asking for it is denied. A key that still stores such a permission is refused outright on a request anyway, because the apikey plugin runs `Check` on the stored permissions first. See [apikey, step 10](apikey.md#step-10--keys-owned-by-an-organization-and-permissions-on-keys).

Check: `TestAuthorizer_KeyPermissions` (the deploy key reaches `/deploy`, a read-only key gets `403 apikey.permission_denied`, a bad key `401 auth.signed_out`, and a `project:delete` key cannot be made).

## Try it

```sh
cd examples
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

`go run ./authorizer` serves the same app on `localhost:8081`. With no key, or a key that is not one, `/deploy` answers as a bearer request with a bad key would:

```sh
curl -s -X POST localhost:8081/deploy -H 'Deploy-Key: not-a-key'
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## Options you may want

| Situation | Use | What it changes |
|---|---|---|
| A user may hold several roles | store them comma-joined (organization `role`, admin `set-role` with a list) | allowed when one of the roles grants the whole request, in both the admin adapter and the organization role check |
| Permissions edited at run time (an admin screen, a request body) | `ac.Check(perms)` before storing them | the same validation `NewRole` applies, so an unknown resource is refused, not silently ignored |
| Organization roles of your own | `organization.WithAccessControl(ac)`, `organization.WithRoles(map)` | [organizations, step 11](organization.md#step-11--permissions-and-your-own-roles) |
| Organization roles each customer creates | `organization.DynamicRoles(…)` | roles stored per organization, validated against the same access control |
| Admin roles of your own | `admin.WithAuthorizer(accessadmin.MustNew(ac, roles))` | Step 4 |
| API-key permissions from your vocabulary | `apikey.WithPermissions(accessapikey.New(ac))` | Step 5 |
| A model other than roles | each plugin's `WithAuthorizer` | [bring your own authorization](../extending/11-authorization.md) |

## From TypeScript

This module adds no route, so the [typed client](../client/README.md) has no `access` factory. The permission questions a frontend asks are routes of the plugins that use it: `client.organization.hasPermission` ([organization](organization.md#from-typescript)) and `client.admin.hasPermission` ([admin](admin.md#from-typescript)), both answering `{ success }`, with a resource-to-actions map in the vocabulary Step 1 declares. Use them to hide what a user cannot do; every real call is checked again on the server, and a refusal answers that plugin's `forbidden` code.

## What can go wrong

- `access: no statements` — `New` with an empty map.
- `access: resource "x" declares no action`, `... declares an empty or repeated action` — fix the statements.
- `access: unknown resource: "x"`, `access: unknown action: "y" on "x"` — a role or a `Check` naming something the statements do not declare.
- A role that allows nothing — the zero `Role`, or a role built from another `AccessControl`'s permissions that this one does not declare (the organization plugin refuses that at `auth.New`).
- `accessadmin: needs an access control` — `accessadmin.New(nil, …)`.
- `accessadmin: role name "a,b" must be one name without commas` — a role name with a comma or surrounding spaces.
- `accessadmin: role "x": access: unknown resource …` — a role naming something the access control does not declare; start the control from a copy of `admin.DefaultStatements` when you add resources.
- `400 apikey.bad_permissions` / `apikey.ErrBadPermissions` — a key given a permission the vocabulary does not declare; at `auth.New`, the same for `DefaultPermissions`.
- `403 apikey.permission_denied` — `VerifyPermissions` with a key whose permissions fall short.

## Next

- [Organizations](organization.md): the plugin whose roles are built from this module.
- [Admin operations](admin.md) and [API keys](apikey.md): the two plugins the adapters serve.
- [Bring your own authorization](../extending/11-authorization.md): replace the role check with a policy engine, a relationship store or a function of your own.
