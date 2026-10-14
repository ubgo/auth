# Ship a plugin

You will have your plugin in a Go module of its own that any app can `go get`, depending on the core and nothing else it does not need, with a README that tells an app author what it adds and what it refuses.

## Before you start

- A plugin that builds and has tests ([the testing guide](09-testing-plugins.md)).
- The two rules this guide follows, which are the library's own. First, the core module `github.com/ubgo/auth` depends on the standard library and `github.com/ubgo/sqlb` only, and a test ([deps_test.go](../../deps_test.go)) fails if its `go.mod` gains another requirement, because everything the core depends on becomes a dependency every consumer inherits forever. Second, a package that needs a third-party module is its own module, so an app downloads that module only when it imports the package: `plugin/password` for `golang.org/x/crypto`, `plugin/passkey` for WebAuthn, `contrib/redis` for the Redis client.

## Step 1 — One module per plugin

Put the plugin at the root of its own module, with its own `go.mod`. The module path is wherever the code lives; `github.com/you/authchat` is as good as a path under this repository. The library's own separate modules look like this ([plugin/password/go.mod](../../plugin/password/go.mod)):

```text
module github.com/ubgo/auth/plugin/password

go 1.24.0

require (
	github.com/ubgo/auth v0.0.0-20261014081355-f7af54573304
	github.com/ubgo/sqlb v0.1.1
	golang.org/x/crypto v0.42.0
)
```

Require the core at a released version, or, while the library has no tags, at the pseudo-version of a pushed commit that `go get github.com/ubgo/auth@latest` writes (the library's own modules do this; see [CONTRIBUTING](../../CONTRIBUTING.md#pinning-the-separate-modules)). Require `github.com/ubgo/sqlb` only if the plugin builds queries or declares typed columns itself (an identifier plugin that uses only `CreateIdentity`, `IssueCode` and `Deliver` does not).

Check: `go build ./...` in the plugin's directory downloads the core and nothing you did not ask for; `go mod graph | grep -v ubgo` lists exactly the third-party modules your plugin needs.

## Step 2 — Replace directives while developing against a checkout

While the plugin and the library change together, point the requirement at a working tree. A consumer's build ignores `replace` directives in its dependencies, so this is safe to leave in during development and must be removed, or the version bumped, before a release.

```text
// Development against a checkout of the library. A consumer's build ignores
// replace directives in dependencies.
replace github.com/ubgo/auth => ../auth
```

Check: `go list -m github.com/ubgo/auth` prints the replaced path while the directive is there and a version once it is gone.

## Step 3 — Depend only on what the plugin needs

The compiler checks every optional interface for you if you ask it to. A `var _ auth.X = (*Plugin)(nil)` line per interface turns a typo in a method signature into a build error instead of a capability that silently goes missing. The chat plugin declares five:

<!-- ds:block id=chat-t75jv2w3 -->
**_** · [`examples/plugin-delivery/chat/chat.go:91-97`](../../examples/plugin-delivery/chat/chat.go#L91-L97)

```go
var (
	_ auth.IdentifierProvider = (*Plugin)(nil)
	_ auth.Deliverer          = (*Plugin)(nil)
	_ auth.Initializer        = (*Plugin)(nil)
	_ auth.Validator          = (*Plugin)(nil)
	_ auth.OperationProvider  = (*Plugin)(nil)
)
```
<!-- /ds:block hash=f35d30 -->

If the plugin needs another plugin present, say so through `auth.Dependent` (`Requires() []string`) and the core refuses a wiring without it: `auth: plugin dependency not registered: "chat" requires "email"`. Do not import the other plugin's package to get its name; export your own constant and document the requirement.

Check: a guard like the core's own keeps the dependency list honest. Adapt [deps_test.go](../../deps_test.go) to your module with your own allow-list: it reads `go.mod` and fails on any `require` line not in the list, and fails too if it parsed no line at all, so it cannot pass vacuously.

## Step 4 — Export what an app and another plugin need

An app or another plugin reaches your plugin through its exported surface, so make it complete and nothing more:

- `PluginName`, the kind name and the `EndpointID` of every operation as constants, so another plugin's hook can name them without a bare string, and an app can rate-limit them.
- The columns struct and its `Bindings` function, for an app's composite user ([user columns](04-user-columns.md)).
- Every error as an `auth.NewError` value declared once at package level: it is both the sentinel for `errors.Is` and the source of the wire response (code, status, message), so REST, GraphQL and a Go caller see the same failure.
- A typed Go method per operation (`Add`, `Verify`) that calls `Op.Call`, so the Go API and the HTTP route run one pipeline.
- The functional options, wrapping `auth.KindOption` for identifier kinds so your plugin says `Login()`, `Recover()`, `Contact()` like the library's own.

Check: `go doc ./...` reads as the complete manual; anything an app must know and cannot see there is missing.

## Step 5 — Write the README

A plugin README answers an app author's questions in the order they come up. The library's own plugins ([plugin/password/README.md](../../plugin/password/README.md), [plugin/phone/README.md](../../plugin/phone/README.md)) all use these sections:

1. One sentence on what it adds.
2. **Install**: the `go get` line, and which third-party modules it brings, so the cost is visible before the import.
3. **Wire it**: the `auth.New` call from a runnable example, and the configurations `auth.New` refuses, each with the exact error text and the fix.
4. **Options**: a table of every option, what it does, and the default, with the constant that holds the default.
5. **Routes and Go API**: a table of every route with its Go method, its requirement (`Public`, `SignedIn`, `FreshSignIn`) and its rate limit.
6. **Tables and columns**: what the plugin adds to the schema, and which of it an app may read.
7. **Errors**: every `auth.NewError` the plugin answers, with code, status and when.
8. **Security notes**: what the plugin guarantees and the test that pins each guarantee.
9. **Example**: a link to a complete program with a real transcript.

Check: every number the README states (a limit, a TTL, a length) comes from a named constant in the code, and every error text is pasted from the code, not retyped.

## Step 6 — Release

Tag the module (`v0.1.0`), remove or bump past the `replace` directive, and run the whole gate once more from a clean module cache: `GOFLAGS=-mod=mod go build ./... && go vet ./... && go test ./...`. Then add the plugin to an app with `go get github.com/you/authchat@v0.1.0` and run that app's tests; the app's `go.sum` should gain your module and its direct dependencies and nothing else.

Two names are fixed from the first release on: the plugin name is the route prefix and the owner of the plugin's migrations, so renaming it orphans those migrations in every deployment; and an identifier kind's name is written to `auth_identity.kind`. Treat both as part of the API.

## What can go wrong

From `auth.New`:

| Error | When |
|---|---|
| `auth: duplicate plugin name: "chat"` | Two plugins in the list return the same `Name()`. |
| `auth: duplicate plugin name: a plugin may not be named "core"` | The name `core` belongs to the library's own operations and migrations. |
| `auth: operation description is not valid: plugin name "Chat" must match ^[a-z][a-z0-9_]{0,30}$` | The name is not lowercase letters, digits and underscores: it is a route segment and a migration owner. |
| `auth: plugin dependency not registered: "chat" requires "email"` | `Requires()` names a plugin that is not in the list. |
| `auth: two operations share an id or a route` | Two operations, in one plugin or two, declare the same `EndpointID` or the same path. |

From the module tooling:

| Symptom | Cause |
|---|---|
| An app that imports your plugin now downloads a module it never used | The plugin requires it. Move the code that needs it into a separate module, as the library does with `plugin/password`. |
| `go: github.com/ubgo/auth@v0.0.0: ... unknown revision v0.0.0` in a consumer | A `replace` directive hid an unreleased version during development. Require a tagged version or the pseudo-version of a pushed commit (`go get github.com/ubgo/auth@latest`). |

## Next

- Back to the start: [plugin anatomy](01-plugin-anatomy.md), [operations](02-operations.md), [hooks](03-hooks.md), [tables and migrations](05-tables-and-migrations.md), [session rules](07-session-rules.md) and [extend sessions](08-extend-sessions.md), for the capabilities this guide assumed.
- [examples/plugin-delivery](../../examples/plugin-delivery) and [examples/custom-plugin](../../examples/custom-plugin) are plugins written against the exported API alone, so each is a template for a module of your own.
