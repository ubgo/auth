# AGENTS.md

Instructions for AI agents working in this repository. Humans should read [CONTRIBUTING.md](./CONTRIBUTING.md), which says the same things in the same order.

## What this is

An embeddable authentication library for Go: users, sessions, sign-in methods and account security inside the application's own binary and database. Every sign-in method and identifier kind is a plugin. Every feature is one typed operation that Go, HTTP and GraphQL callers run through one pipeline.

Read [README.md](./README.md) for the surface, [examples/](./examples/) for runnable recipes, and [CHANGELOG.md](./CHANGELOG.md) for the security properties the tests pin.

## Before you finish

```sh
task check          # every module, SQLite integration, gqlgen example, type and dependency gates
task test:engines   # when SQL changed: SQLite, Postgres and MySQL
task cover          # statement coverage per package, unit and integration merged
```

If it is not green, the change is not done.

## Rules that override your defaults

**Never suppress a diagnostic to make a gate pass.** No `//nolint`, no deleted assertion, no skipped test, no loosened type. Fix the cause.

**The core module depends only on the standard library and `github.com/ubgo/sqlb`.** `deps_test.go` enforces it. A package that needs another module is its own module (like `plugin/password`, `plugin/passkey`, `authui`, `contrib/*`) with a `replace` directive, and so is a feature that is not authentication (`plugin/organization`; permissions and ACL later), even with no dependency,, and is added to the `contrib` task in `Taskfile.yml`.

**Auth code is held to a higher bar.** Every comparison of a secret is constant-time (`guard_test.go` checks the syntax tree), sign-in hashes a password even for an unknown account (a timing test), and every error path is enumeration-safe. No feature ships without the test that would catch its absence.

**Every feature is an operation.** Use `auth.Define[In, Out]`. Never add a route or a public Go function that bypasses the pipeline: the pipeline is where the rate limit, the origin check, the session requirement and the hooks live.

**Plugins write core tables only through the core API.** `TestGuard_PluginsNeverWriteCoreTables` enforces it.

**Every closed-set value is a named constant; every export has its own doc comment** saying why it exists and what stays true.

**Database error paths are tested, not assumed.** Use `sweepFaults` from `integration/faultdb_test.go`: it fails each database call of an operation in turn and asserts the failure reaches the caller.

**Docs cite code, they do not copy it.** A value a README restates is a `//ds:def` block cited with `[text](ds:block?id=…)`; `task docs:drift` (`ds check`) lists every sentence whose code changed.

**Never commit or push without the owner's approval.**

## Where things live

| Path | What goes there |
|---|---|
| `/*.go` | the core: users, identities, sessions, codes, the operation pipeline, rate limits, migrations |
| `authhttp/` | the net/http transport and middleware |
| `authcli/` | `auth migrate`, `auth sweep` and `auth maintain` (plugins' scheduled jobs), for the app's own binary |
| `authui/` | optional server-rendered pages (own module) |
| `plugin/<name>/` | one sign-in method, identifier kind or feature each; `password`, `passkey` and `organization` are their own modules |
| `contrib/<name>/` | framework adapters and optional backends, each its own module |
| `integration/` | the end-to-end suite on real databases (own module, holds the drivers) |
| `examples/` | runnable recipes, each with a README and a test (own module) |
| `docsi/` | private design docs and memory (a repolink symlink) |
| `.lore/` | tasks and decisions; `lore task list` |

<!-- docsync:begin -->
# docsync rules for an AI writer and reviewer

The tool knows which sentence depends on which block and whether the block changed. Read only what `check` lists; acks are recorded against the hash.

Writing:
1. Never cite a path and line. `ds def <file>#<symbol>` for the block, then `ds:block?id=…`.
2. Never paste code. Write a `ds:block` directive; the build renders it.
3. Never type a fact. Run `ds facts`; cite with `ds:cfg` if it exists; otherwise define once with an inline `ds:def`, then cite.
4. External links go through `ds:url`. Behaviour claims cite the test with `assert=true` when one exists.
5. Add `covers` for every id a new page introduces.
6. Start a session with `ds map`. When editing a page, start from `ds context <doc> --budget N --since ack`; nothing outside it needs rereading. Use `find`, `read`, `locate` instead of grep and file reads.
7. Run `ds check` before declaring done. Run `ds impact` before proposing a code change that touches defined blocks.
8. After a code change, `ds check --json` is the complete work list.
9. Before deleting or renaming code, `ds why <id>`, and handle dependents in the same change.

Reviewing:
1. `ds check --json` is the whole list.
2. For each `unacked`, read the sentence, the class, and the diff. Still true: `ack --note`. Not true: edit, then `ack --note`. Never ack a page wholesale.
3. For each `broken`, decide from the diff whether the block was deleted or moved without its def; re-add the def or rewrite and remove the reference.
4. Produce the patch and stop; a person or an explicitly delegated agent records acks (`ack --agent --delegated-by <human>`).
5. Leave anything needing a human unacked and say why.
<!-- docsync:end -->
