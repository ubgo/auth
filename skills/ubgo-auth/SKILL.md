---
name: ubgo-auth
description: Add authentication to a Go application with github.com/ubgo/auth, the embeddable auth library (users, sessions, email, password, phone, username, OAuth/OIDC, passkeys, magic links, two-factor, API keys, JWT, admin, organizations, enterprise SSO, SCIM, device codes, an OAuth/OIDC provider, agent auth) that runs inside the app's own binary and database. Use when wiring sign-in, sign-up, sessions, social login, a protected route, a plugin, a migration from Auth0/Clerk/Supabase/Auth.js/WorkOS, or debugging an auth error code in a Go project that imports github.com/ubgo/auth.
---

# ubgo/auth

This skill tells a coding agent how to work with `github.com/ubgo/auth` in an application. It is deliberately short and points at the repository's own guides instead of restating them, because a copy drifts from the code and the guides are tested: their code blocks are copies of example programs the test suite compiles and runs. Read the linked page before writing code for that task.

## What the library is

- A Go library imported into the app, not a service. Its tables live in the app's database (Postgres, MySQL 8 or SQLite).
- Every sign-in method and identifier kind is a plugin (`plugin/email`, `plugin/password`, `plugin/oauth`, …), passed to `auth.New(auth.WithPlugins(...))`. Opt-in protocols (`plugin/sso`, `scim`, `deviceauth`, `oauthproxy`, `oauthprovider`, `agentauth`) and `plugin/organization` are separate modules: `go get` each one used.
- Every feature is one typed operation that Go, HTTP (`authhttp`, gin, echo, fiber) and GraphQL (gqlgen) call through one pipeline: rate limit, origin check, session requirement, hooks, one transaction.

## Rules to follow in the app's code

1. Read auth tables freely (SELECT, JOIN with the typed `sqlb` columns); never INSERT, UPDATE or DELETE them. Write through the Go API (`a.UpdateProfile`, `auth.SetUserColumn`, a plugin's methods), because the invariants live in Go.
2. Run the migrations through the library (`a.Migrate(ctx)` or `authcli`'s `auth migrate`), never hand-written DDL.
3. Protect routes with `authhttp.Middleware` plus `authhttp.RequireUser`, or the framework adapter's equivalent; read the user with `authhttp.CurrentUser(r)` or `auth.CurrentUser(ctx)`.
4. Match errors by their stable code (`auth.ErrorOf(err).Code`), never by message text.
5. Set a secret (`auth.WithSecret`) and a base URL (`auth.WithBaseURL`) in production; list browser origins with `auth.WithTrustedOrigins`.
6. Do not turn off a safety default to make something work (PKCE, the origin check, constant-time comparison, enumeration-safe errors); every option that weakens one says so in its doc comment, and a reviewer should be told why it is needed.

## Where to read for each task

| Task | Read |
|---|---|
| Install and the first app | [docs/start/install.md](../../docs/start/install.md), [docs/start/first-app.md](../../docs/start/first-app.md) |
| Going to production (keys, cookies, HTTPS, several instances) | [docs/start/production.md](../../docs/start/production.md) |
| Tests in the app | [docs/start/testing.md](../../docs/start/testing.md) (the `authtest` package) |
| Every `auth.With…` option | [docs/concepts/configuration.md](../../docs/concepts/configuration.md) |
| Error codes and HTTP statuses | [docs/concepts/errors.md](../../docs/concepts/errors.md), [docs/reference/error-codes.md](../../docs/reference/error-codes.md) |
| Every route | [docs/reference/http-api.md](../../docs/reference/http-api.md), [docs/reference/openapi.json](../../docs/reference/openapi.json) |
| A plugin (options, routes, tables, errors) | `docs/plugins/<name>.md` and the package README `plugin/<name>/README.md` |
| net/http, chi, gin, echo, fiber, gqlgen | [docs/integrations/](../../docs/integrations/) |
| SPA, mobile and desktop clients | [spa-frontends.md](../../docs/integrations/spa-frontends.md), [mobile-apps.md](../../docs/integrations/mobile-apps.md), [desktop-apps.md](../../docs/integrations/desktop-apps.md) |
| Moving users from Auth0, Clerk, Supabase, Auth.js or WorkOS | [docs/migrating/](../../docs/migrating/README.md) |
| Writing a plugin | [docs/extending/](../../docs/extending/README.md) |
| A runnable recipe for almost any of the above | [examples/](../../examples/README.md), each with a README and a test |
| Something fails | [docs/reference/troubleshooting.md](../../docs/reference/troubleshooting.md) |

The whole map, one line per page, is [llms.txt](../../llms.txt).

## Install this skill

With the `skills` CLI: `npx skills add ubgo/auth`. Or copy this folder into your coding agent's skills directory as `ubgo-auth/`. Contributors working inside this repository follow [AGENTS.md](../../AGENTS.md) instead, which holds the rules for changing the library itself.
