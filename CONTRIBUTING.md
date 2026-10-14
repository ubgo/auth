# Contributing to auth

## The gate

```sh
task check
```

That runs gofmt, vet and tests in every module, the SQLite integration suite, the regenerated gqlgen example, the negative type-check build and the PoC's wiring guards. Everything must be green before a change is proposed.

A change that touches SQL also runs on all three engines:

```sh
task test:engines   # SQLite, Postgres and MySQL, race detector on
task cover          # statement coverage, unit and integration merged, per package
```

`task --list` shows every other command. CI runs the same gate on GitHub Actions (`.github/workflows/test.yml`): `task check` plus the Postgres and MySQL integration suites, on every push to `main`, on every pull request and on demand. `task ci` starts a run on the pushed `main` and `task ci:status` shows the latest runs and the failing job's last log lines, so the heavy suites need not run on your machine; run the touched package's tests locally while you work.

## Pinning the separate modules

The repository has no version tags. Each separate module (every plugin, `authui`, every `contrib` adapter, the examples) requires the core, and any sibling module it uses, at the pseudo-version of a pushed commit, such as `github.com/ubgo/auth v0.0.0-20261014081355-f7af54573304`. Its `replace` directives keep development in the repository on the working tree; a consumer's build ignores them and resolves the pseudo-version instead. A requirement of `v0.0.0` would be "unknown revision v0.0.0" for every app that runs `go get`.

After a change to the core, or to a module another one imports, is pushed:

```sh
task pin              # or: task pin REF=<sha>; the commit must be on origin/main
git commit -am "Pin the separate modules to <short sha>"
git push
```

`task pin` (`scripts/pin.sh`, needs `jq`) asks proxy.golang.org for the commit's pseudo-version, writes it into every requirement on `github.com/ubgo/auth` and its sub-modules, and runs `go mod tidy` in each module. The pinned commit's own `go.mod` files must already be pinned, because a sibling requirement reads them; that holds once every module has been pinned, so one run is enough. Check from outside the repository: in an empty module, `GOWORK=off GOPROXY=https://proxy.golang.org GOFLAGS=-mod=mod go get github.com/ubgo/auth/plugin/password@latest` succeeds.

## The rules a change is reviewed against

**Auth code is held to a higher bar.** A broken checkout produces a support ticket in an hour; a timing leak on a login endpoint produces nothing for years and then a breach. Every comparison of a secret is constant-time, every error path is enumeration-safe in message and timing, and no feature ships without the test that would catch its absence.

**The core module depends only on the standard library and sqlb.** `deps_test.go` fails otherwise. A package that needs a third-party module is its own module with a `replace` directive for development, added to the `contrib` task's list and the `cover` task's lists (its `for:` loop and `PKGS`, or its statements are never measured). So is a feature that is not authentication (organizations today; roles, permissions and other grouping later), even with no dependency, so an app that does not use it never carries it.

**Every feature is one typed operation.** Define it with `auth.Define[In, Out]`; the Go call, the HTTP route and the GraphQL resolver all run it through the same pipeline. Never add a route that calls store functions directly.

**Plugins never write core tables directly.** They go through the core API (`CreateIdentity`, `SetUserColumn`, …). `TestGuard_PluginsNeverWriteCoreTables` checks the syntax tree.

**Values are normalized in Go and compared exactly.** No `lower()` in SQL. Anything that depends on the engine gets a case in the integration suite.

**Every closed-set value is a named constant, every export has a doc comment** that says why it exists and what stays true, and no diagnostic is suppressed: no `//nolint`, no skipped test, no loosened assertion.

**A number a doc restates is bound to its constant.** Mark the constant with `//ds:def` (`ds def <file>#<Name>` writes it; the no-space form keeps it out of godoc) and cite it from the sentence with a `[text](ds:block?id=…)` link. `task docs:drift` (docsync's `ds check`) then fails when the constant changes until the sentence is fixed and acked. Every constant a package README names is bound this way (168 today).

**Guide code is copied, never typed.** A code block in `docs/` sits between `<!-- ds:block id=… -->` markers and is written by `ds refresh` from an example `task check` compiles and tests (docsync repo mode). `ds check` fails when a copy is edited by hand or its source changes; run `ds refresh` after changing the example.

**A test for every behaviour.** New logic comes with the test that fails without it. Database error paths are tested with the fault-injecting driver in `integration/faultdb_test.go` (`sweepFaults`), which fails each database call of an operation in turn.

## Adding a plugin

A plugin implements `Name()` plus the optional interfaces it needs: operations, hooks, columns on `auth_user`, its own tables and migrations, identifier kinds, delivery channels, session checks, second factors. The [extension guides](docs/extending) cover each one step by step. Look at `plugin/username` for the smallest complete one and `plugin/organization` for one that owns tables. Add its integration tests to `integration/`, and a cookbook example under `examples/` when it changes how an app is wired.

## Where a contribution lives

| You are adding | Where it goes | What it ships with |
|---|---|---|
| A framework adapter (a router, an RPC framework) | `contrib/<name>/`, its own module with a `replace` directive, added to the `contrib` task's list and the `cover` task's lists (its `for:` loop and `PKGS`, or its statements are never measured); it imports `authhttp`'s building blocks (`OperationHandler`, `Begin`, `WrapWriter`, `ApplyHeaderEffects`, `WriteError`) rather than reimplementing the transport | a fake-app test that signs up, signs in and reaches a protected route through the adapter, a README with the mount and the middleware, and a guide under `docs/integrations/`; `contrib/gin` is the model |
| An OAuth or OIDC provider | `plugin/oauth` when it is a constructor over the existing `OAuth2` or `OIDCProvider` types (as `Google`, `GitHub`, `Apple` are) with a profile fetcher and the provider's quirks documented at the constructor (a provider that renames `client_id`, joins scopes with commas, has no PKCE or needs a callback value at the exchange uses the `OAuth2` fields for it, as `TikTok`, `WeChat` and `VK` do); the shapes come from the provider's own documentation, named at the constants; anything that needs a dependency or a protocol of its own is its own module | a test against a fake provider server for the token exchange and the profile shape, and a row in the oauth README's provider table |
| A plugin that is authentication (a sign-in method, an identifier kind, a second factor) | `plugin/<name>/` in the core module when it needs only the standard library, its own module otherwise; it writes core tables only through the core API | integration tests on the three engines, a `sweepFaults` case for every database call, a README with options, routes, tables and errors, a guide under `docs/plugins/`, and an example under `examples/` when it changes how an app is wired |
| A plugin that is not authentication (grouping users, billing, roles) | its own module, even with no dependency, so an app that does not use it never carries it | the same as above; `plugin/organization` is the model |
| An opt-in protocol most apps never use (SSO, SCIM, device codes, an OAuth provider, agent authentication) | its own module, even with no dependency, so it is compiled only by apps that import it | the same as above; `plugin/oauthprovider` and `plugin/scim` are the models |
| Agent-facing documentation | `llms.txt` (one line per page), `AGENTS.md` (rules for changing this repository) and `skills/ubgo-auth/SKILL.md` (a skill for agents using the library in an app); each points at the guides rather than restating them, so a new guide gets a line in `llms.txt` and, when it is a task an app does, a row in the skill's table | `task docs:wrap` keeps them unwrapped |
| A plugin maintained outside this repository | your own module importing `github.com/ubgo/auth`; [ship a plugin](docs/extending/10-ship-a-plugin.md) is the checklist | the same tests, built with the public `authtest` package |

A core plugin is one the maintainers commit to keep working across releases; a community module tracks the core at its own pace. Open an issue before writing a core plugin so the scope is agreed first; an adapter or a provider needs no discussion beyond the pull request.

## Pull requests

Keep a pull request to one change. Update the README, the example READMEs, and CHANGELOG.md for anything a user can see; tag a security fix **[security]** and a breaking change **[breaking]**.
