# Bring your own authorization

You will have the admin and organization plugins deciding every permission with a model of your choice (policy lines, a relationship store, a policy engine, attributes, or rules of your own) instead of their built-in roles.

## Before you start

- The admin plugin ([admin](../plugins/admin.md)) or the organization plugin ([organizations](../plugins/organization.md)) wired into `auth.New`.
- A runnable app: [`examples/authorizer`](../../examples/authorizer) wires the organization plugin to a policy of its own (Step 4), the admin plugin to the `accessadmin` roles, and the apikey plugin to the `accessapikey` vocabulary, with no policy engine as a dependency. `go test ./authorizer` in `examples/` runs it end to end.
- The rule this guide follows, which is the library's own: every policy is an interface, and the library's implementation is only the default. Neither plugin decides a permission itself; each asks one `Authorizer`, and `WithAuthorizer` replaces it.

## Step 1 — Know what you are asked

The admin plugin asks its authorizer before every operation (before the target is looked up, so a refusal never reveals whether a user exists), for the `impersonate-admins` check, for `has-permission` and for `CheckRolePermission`:

<!-- ds:block id=authorizer-yr8g745x -->
**Authorizer** · [`plugin/admin/authorizer.go:86-88`](../../plugin/admin/authorizer.go#L86-L88)

```go
type Authorizer interface {
	Authorize(ctx context.Context, req AccessRequest) (bool, error)
}
```
<!-- /ds:block hash=571728 -->

`admin.AccessRequest` carries the user whose permission is decided, that user's roles as the plugin resolved them, the permissions asked for (a permission object, every action of a resource required) and the connector that joins the resources, the user the operation acts on, the operation, and the call itself (client IP, session, decoded input) for a rule on attributes. It is a struct so a field added later is a zero value to your implementation rather than a compile error.

The organization plugin asks its authorizer for every operation's permission, `has-permission`, `Can`, `RequirePermission`, the grant check of a dynamic role and plugin/apikey's organization-key question:

<!-- ds:block id=authorizer-nqtw4zda -->
**Authorizer** · [`plugin/organization/authorizer.go:50-52`](../../plugin/organization/authorizer.go#L50-L52)

```go
type Authorizer interface {
	Authorize(ctx context.Context, req AccessRequest) (bool, error)
}
```
<!-- /ds:block hash=571728 -->

`organization.AccessRequest` adds the organization and gives the request as an `access.Request`, where each resource carries its own connector (`access.All` or `access.Any`). Membership stays the plugin's: a non-member is refused before the authorizer is asked.

Both plugins treat any error as a refusal and never read the boolean of a call that failed, so a policy engine that is down fails closed.

## Step 2 — A policy table for the admin plugin

A policy engine answers `Enforce(subject, resource, action)` from policy lines. The adapter loops over what was asked and asks once per action; with a real engine, `enforce` calls it:

<!-- ds:block id=policyauthorizer-authorize-cad7rbjj -->
**policyAuthorizer.Authorize** · [`plugin/admin/example_authorizer_test.go:26-41`](../../plugin/admin/example_authorizer_test.go#L26-L41)

```go
func (p policyAuthorizer) Authorize(_ context.Context, req admin.AccessRequest) (bool, error) {
	if len(req.Permissions) == 0 {
		return false, nil // asking for nothing proves nothing
	}
	anyRes := false
	for res, acts := range req.Permissions {
		ok := len(acts) > 0 && slices.ContainsFunc(req.Roles, func(role string) bool {
			return !slices.ContainsFunc(acts, func(act string) bool { return !p.enforce(role, res, act) })
		})
		if !ok && req.Connector != admin.Or {
			return false, nil
		}
		anyRes = anyRes || ok
	}
	return anyRes, nil
}
```
<!-- /ds:block hash=582455 -->

Pass it with `admin.WithAuthorizer`. Implement `admin.RoleCatalog` (`DefinesRole(name) bool`) as well when `set-role` should accept role names other than the built-in `admin` and `user`; `auth.New` checks `AdminRoles` and `DefaultRole` against it:

<!-- ds:block id=example-policyauthorizer-27fwf8au -->
**Example_policyAuthorizer** · [`plugin/admin/example_authorizer_test.go:52-68`](../../plugin/admin/example_authorizer_test.go#L52-L68)

```go
func Example_policyAuthorizer() {
	authz := policyAuthorizer{lines: [][3]string{
		{"admin", admin.ResourceUser, admin.ActionBan},
		{"admin", admin.ResourceUser, admin.ActionGet},
		{"support", admin.ResourceUser, admin.ActionGet},
	}}
	p := admin.New(admin.WithAuthorizer(authz))

	ctx := context.Background()
	fmt.Println(p.CheckRolePermission(ctx, "support", admin.Permissions{admin.ResourceUser: {admin.ActionGet}}))
	fmt.Println(p.CheckRolePermission(ctx, "support", admin.Permissions{admin.ResourceUser: {admin.ActionBan}}))
	fmt.Println(p.CheckRolePermission(ctx, "support,admin", admin.Permissions{admin.ResourceUser: {admin.ActionBan}}))
	// Output:
	// true
	// false
	// true
}
```
<!-- /ds:block hash=5965d6 -->

## Step 3 — A relationship store for organizations

A relationship store answers "does this user have this relation to this object". Map each permission to a relation on the organization object and return the store's error, so a store that is down refuses:

<!-- ds:block id=relationauthorizer-authorize-2qt24ghh -->
**relationAuthorizer.Authorize** · [`plugin/organization/example_authorizer_test.go:29-53`](../../plugin/organization/example_authorizer_test.go#L29-L53)

```go
func (a relationAuthorizer) Authorize(ctx context.Context, req organization.AccessRequest) (bool, error) {
	if len(req.Request) == 0 {
		return false, nil
	}
	anyRes := false
	for res, want := range req.Request {
		ok := len(want.Actions) > 0
		for _, act := range want.Actions {
			has, err := a.store.Check(ctx, "user:"+req.UserID, "can_"+act+"_"+res, "organization:"+req.OrgID)
			if err != nil {
				return false, err
			}
			if want.Connector == access.Or && has {
				ok = true
				break
			}
			ok = ok && has
		}
		if !ok && req.Connector != access.Or {
			return false, nil
		}
		anyRes = anyRes || ok
	}
	return anyRes, nil
}
```
<!-- /ds:block hash=dc49a0 -->

Pass it with `organization.WithAuthorizer(authz)`. Roles keep their other jobs: which roles a member may be given, and the owner protections. The creator role's all-permissions rule for organization API keys belongs to the role model, so under your authorizer it decides those keys too.

## Step 4 — A policy table with an attribute rule, in a running app

Steps 2 and 3 are the adapter alone. In [`examples/authorizer`](../../examples/authorizer) a whole app runs on one: the organization policy is a table of `(role, resource, action)` lines, a `subject, object, action` policy, in which a plain member may invite people, something the built-in roles refuse:

<!-- ds:block id=authz-orgpolicy-9h4mt6rw -->
**orgPolicy** · [`examples/authorizer/main.go:124-131`](../../examples/authorizer/main.go#L124-L131)

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

The authorizer reads the table and one attribute besides the role, whether the organization is frozen. With a policy engine, `allows` would call the engine, or send `req` as the input document and read the decision:

<!-- ds:block id=authz-orgauthorizer-7c3ny5kd -->
**orgAuthorizer** · [`examples/authorizer/main.go:166-197`](../../examples/authorizer/main.go#L166-L197)

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

`organization.AuthorizerFunc` turns the function into an `organization.Authorizer`, and `organization.WithAuthorizer(orgAuthorizer(orgPolicy, frozen))` passes it. Under it Bob, a member, invites Carol; `has-permission` for `member:delete` answers `{"success":false}` for him; and once the app freezes Acme, even its owner's `update` is `403 organization.forbidden`, while reads still work, because membership reads ask no permission. Check: `TestAuthorizer_OrganizationPolicy`.

```sh
cd examples
go test -v -run OrganizationPolicy ./authorizer
```

```text
=== RUN   TestAuthorizer_OrganizationPolicy
2026/10/09 08:44:37 WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance
--- PASS: TestAuthorizer_OrganizationPolicy (0.35s)
PASS
ok  	github.com/ubgo/auth/examples/authorizer	1.543s
```

The same app gives the admin plugin the `accessadmin` roles plus a `support` role, and its API keys the `accessapikey` vocabulary; [access, steps 4 and 5](../plugins/access.md#step-4--with-the-admin-plugin) show those.

## Step 5 — Add a rule without replacing the roles

To keep the built-in role check and add one rule (refuse everything in a frozen organization, allow only from the office network), wrap the default. For organizations it is `p.RoleAuthorizer()`; for the admin plugin, call `admin.Grants` over a role table of your own, or wrap the `accessadmin` adapter from the [access](../plugins/access.md) module, which is the fine-grained role model of an access control and its roles.

## Options you may want

| Situation | Use | What it changes |
|---|---|---|
| Decide admin permissions with your model | `admin.WithAuthorizer(a)` | every admin operation, `has-permission`, `CheckRolePermission` |
| Let `set-role` accept your role names | implement `admin.RoleCatalog` too | `AdminRoles`, `DefaultRole` and `set-role` are checked against it |
| Decide organization permissions with your model | `organization.WithAuthorizer(a)` | every operation's check, `has-permission`, `Can`, `RequirePermission`, dynamic-role grants, organization API keys |
| A function rather than a type | `admin.AuthorizerFunc`, `organization.AuthorizerFunc` | no type to declare |
| Keep the roles, add one rule | wrap `p.RoleAuthorizer()` (organizations) or `accessadmin` (admin) | Step 5 |
| Fine-grained roles without a policy engine | the [access](../plugins/access.md) module and its adapters | an access control and roles built from it |

## What can go wrong

- `admin: WithAuthorizer needs an authorizer`, `organization: WithAuthorizer needs an authorizer` — `WithAuthorizer(nil)`, refused by `auth.New`.
- `admin: role "x" is not defined` at start-up — `AdminRoles` or `DefaultRole` names a role your authorizer does not define; implement `admin.RoleCatalog`.
- `admin.bad_role` (400) from `set-role` — the same, at run time.
- Every check answers 500 — your authorizer returns an error; the plugin refused rather than guessed.
- An admin can no longer do anything — a custom authorizer replaces the built-in `admin` role too, so it must grant your admins what they need.
- An organization member is refused before your authorizer runs — membership is the plugin's; a non-member gets `404 organization.not_member` and is never asked about.

## Next

- [Access control](../plugins/access.md): roles as permission statements, and the `accessadmin` and `accessapikey` adapters.
- [Organizations](../plugins/organization.md), step 11: the permission checks the authorizer answers.
- [Admin operations](../plugins/admin.md): the operations and the permissions each asks for.
