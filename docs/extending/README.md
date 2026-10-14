# Extending auth

Part of the [guides](../README.md). Step-by-step guides for extending `github.com/ubgo/auth`: writing a plugin, adding routes, columns, tables and identifier kinds, changing how sessions work, and testing and shipping what you built. Each guide builds one thing in numbered steps and ends with the errors you may meet.

Every code block in these guides is copied by [docsync](https://github.com/ubgo/docsync) from a program in [examples/](../../examples) that `task check` compiles and tests, so a guide cannot show code that no longer works. Do not edit the code between the `ds:block` markers by hand; `ds refresh` rewrites it.

## Build a plugin

| Guide | You will have built |
|---|---|
| [1. Plugin anatomy](01-plugin-anatomy.md) | A plugin of your own that `auth.New` wires, checks and refuses like the built-in ones |
| [2. Operations](02-operations.md) | A feature defined once and served as an HTTP route, a GraphQL field and a Go method, behind the rate limits and checks, handing back headers and redirects as effects |
| [3. Hooks](03-hooks.md) | A plugin that refuses, counts or follows up other plugins' operations and the core's writes |
| [4. User columns](04-user-columns.md) | A column on `auth_user`, filled at sign-up and read as a field of the app's own user struct |
| [5. Tables and migrations](05-tables-and-migrations.md) | A table of your own, created by a migration for each engine, queried with typed columns, and cleaned of expired rows by the sweep |
| [6. Identifiers and delivery](06-identifiers-and-delivery.md) | A new kind of identifier (a chat handle) that users verify with a code and that receives messages |

## Sessions

| Guide | You will have built |
|---|---|
| [7. Session rules](07-session-rules.md) | A condition every session must meet on every request, and a second step at sign-in |
| [8. Extend sessions](08-extend-sessions.md) | Sessions in a store of your choice, a cache in front of the lookup, and different lifetimes for browsers and apps |

## Policies

| Guide | You will have built |
|---|---|
| [11. Bring your own authorization](11-authorization.md) | The admin and organization plugins deciding permissions with Casbin-style policies, a relationship store or rules of your own |

## Finish

| Guide | You will have built |
|---|---|
| [9. Test a plugin](09-testing-plugins.md) | Tests that run against a real database in-process, drive the app over HTTP, control the clock and inject database failures; the contract suites for a session store and an OAuth provider |
| [10. Ship a plugin](10-ship-a-plugin.md) | A Go module of your own that any app can `go get` |

## Where else to look

- [plugin/](../../plugin) lists every built-in plugin; each folder's README is the reference for its options, routes, tables and errors.
- [examples/](../../examples) has a runnable program for every common setup, including the ones these guides are built from: `custom-plugin`, `plugin-hooks`, `plugin-tables`, `plugin-delivery` and `session-strategies`.
- The Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth).
