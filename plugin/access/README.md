# github.com/ubgo/auth/plugin/access

A permission vocabulary and the roles built from it: an access control declares the statements, roles are built from it, and a role authorizes a request. The [organization](../organization) plugin builds its roles from it, the [`accessadmin`](accessadmin) adapter gives the [admin](../admin) plugin fine-grained roles with it, and any app can use it on its own: package `access` has no storage, no transport and imports only the standard library.

## Install

```sh
go get github.com/ubgo/auth/plugin/access
```

Its own module, because a permission model is a policy, not authentication: the admin and organization plugins ask an `Authorizer` and the apikey plugin a `PermissionChecker`, and this is one way to answer them. An app that decides permissions with a policy engine, a relationship store or rules of its own never compiles it. It brings no third-party dependency.

## Use it

<!-- ds:block id=example-gwg3tegh -->
**Example** · [`plugin/access/example_test.go:12-28`](example_test.go#L12-L28)

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

## API

| Name | What it does |
|---|---|
| `Statements` | Resources and the actions each allows: the whole vocabulary |
| `New(Statements)`, `MustNew` | Declares the vocabulary; refuses an empty one, a resource with no action, and an empty or repeated action |
| `(*AccessControl).NewRole(Permissions)`, `MustRole` | A role granting a subset of the statements; `ErrUnknownResource` or `ErrUnknownAction` for anything undeclared, so a typo fails at start-up |
| `(*AccessControl).Check(Permissions)` | The same validation, for permissions stored at run time before they are saved |
| `(*AccessControl).Statements()` | A copy of the vocabulary |
| `Permissions` | Actions per resource; `Request()` turns it into a check requiring every action, `Clone()` copies it |
| `Request`, `All(actions...)`, `Any(actions...)` | A check: per resource, every action (AND) or one of them (OR) |
| `Role.Authorize(Request, Connector)` | `nil` when allowed; `And` (default) needs every resource, `Or` one. A resource the role grants nothing on fails at once, and an empty request is denied |
| `Role.Allows(Request)` | `Authorize` with `And`, as a boolean |
| `Role.Permissions()` | A copy of what the role grants |
| `ErrDenied` | Wrapped by every denial, with a message that names the resource: `You are not allowed to access resource: X`, `unauthorized to access resource "X"`, or `Not authorized` |

The zero `Role` grants nothing. An `AccessControl` and a `Role` are immutable once built and safe for concurrent use.

## With the admin plugin: accessadmin

Package `accessadmin` is the adapter that decides the admin plugin's permissions with access roles: `admin.WithAuthorizer(accessadmin.MustNew(ac, roles))`.

| Name | What it does |
|---|---|
| `DefaultAccessControl` | The access control of `admin.DefaultStatements` |
| `DefaultRoles()` | `admin.DefaultRoles()` as access roles: `admin` (everything but impersonate-admins) and `user` (nothing) |
| `New(ac, roles)`, `MustNew` | An `admin.Authorizer` and `admin.RoleCatalog`; `roles` are added to `DefaultRoles()` or replace one by name. Refuses a nil access control (`ErrNoAccessControl`), a role naming an undeclared statement and a role name that is empty, padded or has a comma |
| `(*Authorizer).Authorize` | Allowed when one of the request's roles passes the whole request under its connector; never fails |
| `(*Authorizer).DefinesRole` | The role names `set-role` accepts |

`TestDefaultRolesMatchTheBuiltIn` checks on 5000 random requests that the adapter's default roles answer exactly as the admin plugin's built-in ones.

## With the apikey plugin: accessapikey

Package `accessapikey` checks key permissions with an access control, so the statements your roles use are the vocabulary of your API keys too: `apikey.WithPermissions(accessapikey.New(ac))`. `Check` is `ac.Check` and `Grants` is `role.Allows` over the key's permissions that the statements still declare (a removed resource or action is skipped, and asking for it is denied, as `apikey.Vocabulary` does); a nil access control refuses every permission. `TestMatchesTheBuiltInVocabulary` and `TestShrunkVocabularyAgreesWithTheBuiltIn` check on 5000 random cases each, the second after a resource and an action were removed, that it answers as `apikey.Vocabulary` over the same statements, and `TestR36_KeyPermissionsWithAccess` runs the whole key-permission flow through it on every engine.
