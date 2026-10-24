# github.com/ubgo/auth/authcli

Gives your app's own binary an `auth` command for operators: apply migrations, preview them, print them as SQL, list what no plugin owns any more, delete expired rows, run the plugins' scheduled jobs, and make the first admin.

## Install

```sh
go get github.com/ubgo/auth
```

It is part of the core module and uses only the standard library. It is a package rather than a binary because only your app knows its plugin list, and the plugin list decides the migrations.

## Wire it

From [examples/cli](../examples/cli/main.go): route the first argument to `authcli.Main` and exit with the code it returns.

```go
func main() {
	// ... open db, build a with auth.New ...
	ctx := context.Background()
	if len(os.Args) > 1 && os.Args[1] == "auth" {
		code := authcli.Main(ctx, a, os.Args[2:], os.Stdout, os.Stderr)
		_ = a.Close() // os.Exit skips the deferred calls
		os.Exit(code)
	}
	// ... serve ...
}
```

`args` excludes the program name and the word the app routed on. Output meant for a pipe (the SQL, the status table) goes to stdout; usage and errors go to stderr. `Main` reads the process's standard input when a command asks for it (`admin create --password-stdin`); [`MainWithStdin`](ds:block?id=mainwithstdin-6kp3rq2w) takes another reader, for an app that embeds the command line behind its own and for tests.

## Options

None. `Main` takes the `*auth.Auth`, the arguments and the two writers; `MainWithStdin` adds the reader.

## Commands

| Command | What it does | Writes to the database |
|---|---|---|
| `auth migrate` | Applies every pending migration and prints `applied <owner>/<name>` for each, or `nothing to apply`. | yes |
| `auth migrate --dry-run` | Lists the pending and changed migrations without applying anything, then `N pending, N changed, N total`. | no |
| `auth migrate status` | Lists every migration as `applied`, `pending` or `CHANGED`, with its owner and name, then the same totals. | no |
| `auth migrate sql` | Prints every migration as SQL for this engine (`-- <owner> <name>` then the statements). It needs no database. | no |
| `auth generate` | The same as `auth migrate sql`, under a second name, for a migration tool the app already runs. |
| `auth migrate orphans` | Lists the tables, columns and owners in the database that no registered plugin claims now (`<kind>\t<name>`), then `N orphan(s)`. It deletes nothing; the operator decides. | no |
| `auth migrate check` | Compares the database with the code: pending and changed migrations from the ledger, and the tables and columns the migrations create against the catalogue (`a.CheckSchema`). Prints `pending\t<owner/name>`, `CHANGED\t<owner/name>`, `missing table\t<name>` and `missing column\t<table.column>` lines, then fails with `auth.ErrSchemaBehind` and exit 1 when anything is listed, or prints `schema ok`. For a deploy script: `myapp auth migrate check && myapp serve`. | no |
| `auth sweep [--retention 168h]` | Runs `a.Sweep`: deletes expired sessions, verification tokens expired or spent more than `--retention` ago, finished rate-limit windows, delivery outbox rows past the retention and each plugin's expired rows. It prints `<owner.table>\t<count>` sorted by name; with `auth.WithDeliveryOutbox` it then runs `a.SendOutbox` and adds `outbox.sent` and `outbox.failed` lines. The default retention is [`auth.DefaultSweepRetention`](ds:block?id=defaultsweepretention-shqfpbr3) (7 days). | yes |
| `auth maintain [--dry-run]` | Runs `a.Maintain`: every registered plugin that implements [`auth.Maintainer`](ds:block?id=core-maintainer-8rm3wk5q), in registration order, such as `plugin/stale`'s mail to dormant accounts and, if turned on, their deletion. It prints `<plugin>.<counter>\t<count>` sorted by name, and nothing when no plugin has a job. `--dry-run` passes `auth.MaintainOptions{DryRun: true}`: the same counters, nothing sent, written or deleted. A plugin that fails stops the run; the counters it had are printed, the error goes to stderr and the exit code is 1. | yes, without `--dry-run` |
| `auth info [--json]` | Prints how this instance is wired, for a support request or a deployment check: the library version from the binary's build information (`(devel)` or `unknown` for a work-tree build), engine, base URL, number of trusted origins, fresh window, session lifetimes, plugins, identifier kinds, migrations, disabled operations, and every route with its method, requirement and id. `--json` prints the same as indented JSON (`authcli.Info`; lifetimes are strings such as `"720h0m0s"` under camelCase names, and the document decodes back into `authcli.Info`). It touches no database and holds no secret or user data. | no |
| `auth secret [--value]` | Prints `AUTH_SECRET=<value>`: [32 random bytes](ds:block?id=secretbytes-5kq2mw8n) from `crypto/rand`, base64-encoded, a value `auth.WithSecret` accepts; `--value` prints the value alone, for a pipe into a vault. Touches no database; a failing random source is exit 1, never a weak value. |
| `auth client ts --out <dir>` | Writes the typed TypeScript client of this app's routes into `<dir>` (created when missing) and lists the files: `authhttp.TypeScriptClient` over the app's own `*auth.Auth`, so its custom plugins, their input and output types and their error codes are typed exactly. Touches no database. A name the generator cannot give (two operations one method, a plugin named a TypeScript keyword) is exit 1 with the reason. Guide: [your own plugins in the TypeScript client](../docs/client/custom-plugins.md); example: [ts-client-custom](../examples/ts-client-custom/). | no |
| `auth admin grant --email x [--json] [--dry-run]` | Makes the owner of a verified address an admin through the admin plugin's `Grant`, found by interface ([`AdminGranter`](#plugins-found-by-interface)); the address is resolved through the identifier plugin that owns addresses, verified only, because admin rights for whoever typed an address at sign-up would be a takeover. Prints `<email> (<userId>) is an admin`, or the [`AdminResult`](ds:block?id=cli-adminresult-4wn8pq2k) as JSON. `--dry-run` resolves the user and changes nothing. Granting an admin again succeeds and changes nothing. | yes |
| `auth admin create --email x [--name y] [--password-stdin] [--json] [--dry-run]` | Creates a user with a verified address (the operator vouches for it), the password read from stdin when `--password-stdin` is given, and admin rights, in one transaction: a refused password or a taken address leaves no user. There is no `--password` flag, because argv is visible to other processes and lands in shell history; the password is the whole of stdin minus one trailing line break, as `docker login --password-stdin` reads it. Without a password the user exists and signs in another way (a magic link, OAuth, a reset). `--dry-run` checks that the address is free and changes nothing. | yes |
| `-h` on `migrate`, `sweep`, `maintain`, `info` or `admin` | Prints the usage. | no |

The command names are exported as [`CmdMigrate`](ds:block?id=cmdmigrate-mr367qab), [`CmdSQL`](ds:block?id=cmdsql-y9ntekef), [`CmdStatus`](ds:block?id=cmdstatus-cebt94q5), [`CmdOrphans`](ds:block?id=cmdorphans-ue59r4y3), [`CmdSweep`](ds:block?id=cmdsweep-nsszxzc2), [`CmdMaintain`](ds:block?id=cmdmaintain-4wn8qk3v), [`CmdInfo`](ds:block?id=cmdinfo-7wkd3xqn), [`CmdClient`](ds:block?id=cmdclient-5tq8nw2k) with `CmdClientTS`, and [`CmdAdmin`](ds:block?id=cmdadmin-5rk2wq8n) with [`AdminGrant`](ds:block?id=adminsubgrant-7mt4xk2p) and [`AdminCreate`](ds:block?id=adminsubcreate-9vq3nw6r).

### Plugins found by interface

`auth admin` imports no plugin. It finds, through `auth.PluginOf`, the registered plugin with each method it needs, so an app registers nothing extra and the core module stays free of the password module: `AdminGranter` (`Grant(ctx, userID)`, which `*admin.Plugin` has), `AddressSetter` (`Identifiers()` for the kind to look up and `SetFor(ctx, userID, address, verified)`, which `*email.Plugin` has) and `PasswordSetter` (`SetPassword(ctx, userID, password)`, which `*password.Plugin` has; needed only under `--password-stdin`). A missing one fails with exit 1 and names the plugin to register (`ErrNoAdminPlugin`, `ErrNoAddressPlugin`, `ErrNoPasswordPlugin`). `authcli.InfoOf(a)` returns the [`Info`](ds:block?id=cli-info-4jrw9p2d) that `auth info` prints, for an app that wants the same report on a status page.

### Exit codes

| Constant | Value | Meaning |
|---|---|---|
| [`ExitOK`](ds:block?id=exitok-gnrts3ej) | 0 | Done, including `-h`. |
| [`ExitFailed`](ds:block?id=exitfailed-ssu2cn9e) | 1 | The command ran and failed; the reason is on stderr. This includes no database (`auth: no database configured; pass auth.WithDB`), an engine without DDL for `migrate sql`, a write to stdout that failed, and any `CHANGED` migration in `status` or `--dry-run` (`auth.ErrChecksumMismatch`), because `migrate` would refuse to run. |
| [`ExitUsage`](ds:block?id=exitusage-d43sp75x) | 2 | The command never ran: no command, an unknown one, an unexpected argument, an unknown flag, a `--retention` that is not a duration, or a negative one, `admin` without `--email`, or `--password-stdin` with nothing on stdin (`ErrNoPassword`). |

A script can therefore tell a typo (2) from a broken database (1).

## Tables and columns

None of its own. `migrate` writes the core's ledger table `auth_migrations` ([`auth.TableNameMigrations`](ds:block?id=tablenamemigrations-xra38puh)) through `a.Migrate`, `sweep` deletes through `a.Sweep`, and `maintain` changes only what the plugins' jobs change, through `a.Maintain`.

## Errors

`Main` returns an exit code, not an error; the error text goes to stderr prefixed `auth migrate:`, `auth sweep:`, `auth maintain:`, `auth info:`, `auth admin grant:` or `auth admin create:`. The admin command's own errors are `ErrNoAdminPlugin`, `ErrNoAddressPlugin`, `ErrNoPasswordPlugin` (exit 1) and `ErrNoPassword` (exit 2); `auth.identity_not_found` is a grant to an unknown or unverified address and `auth.identity_taken` a create of an address another account holds.

## Security notes

| Property | Pinned by |
|---|---|
| `--dry-run` and `status` change nothing: after a dry run, `auth_user` does not exist. | `TestCLI_StatusDryRunMigrate` (integration) |
| A migration edited after it was applied is reported as `CHANGED` and fails the command. | `TestCLI_StatusDryRunMigrate` (integration) |
| Every database command fails with exit 1 and a reason when there is no database, never exit 0 with an empty report. | `TestMain_EveryDatabaseCommandFailsWithoutADatabase` |
| A status that cannot be written fails instead of passing silently. | `TestCLI_ReportsWhatIsLeftAndWriteFailures` (integration) |
| `orphans` only lists; it drops nothing. | `TestOrphans_ReportsWhatARemovedPluginLeft` (integration) |
| `migrate check` exits 1 for an empty database, for a dropped column with every migration applied, and for a database error; 0 only when nothing is missing. | `TestCLI_MigrateCheck` (integration) |
| `auth info` reads no database and reports no secret: the trusted origins and base URL are public addresses, the session block is configuration. | by construction: `InfoOf` reads `a.Config()`, `a.Plugins()`, `a.Operations()` and `a.Migrations()` only |
| `sweep` deletes only what can no longer work. | `TestSweep_DeletesOnlyWhatCanNoLongerWork` (integration) |
| `maintain` prints the counters sorted and passes `--dry-run` through; a failing job is exit 1 after the counters it had; an extra argument is a usage error; with no job it prints nothing. | `TestMain_MaintainPrintsSortedCountersAndPassesDryRun`, `TestMain_MaintainFailureIsExitFailedAfterTheCounters`, `TestMain_MaintainUsage`, `TestMain_MaintainWithNoMaintainerPrintsNothing` |
| `admin grant` refuses an unverified address with exit 1 and grants nobody; `--dry-run` resolves the user and grants nobody. | `TestCLI_AdminGrant` (integration) |
| `admin create` makes a user, a verified address, the stdin password and the admin grant in one transaction: a refused password or a taken address leaves no user, and the rehearsal creates nothing. | `TestCLI_AdminCreate` (integration) |
| The password never comes from argv: there is no `--password` flag, a value after `--password-stdin` is an unexpected argument, and an empty stdin is a usage error. | `TestAdmin_PasswordNeverComesFromArgv`, `TestAdmin_UsageErrors` |
| Every plugin the admin command works through is found by interface and its absence is named. | `TestAdmin_NamesTheMissingPlugin` |

Nothing runs the sweep or the maintenance jobs by itself (the library has no background workers), so schedule `auth sweep` and, when a plugin has a job, `auth maintain` from cron or your job runner. The sweep is idempotent and safe to run from several instances at once; a maintenance job is idempotent too, and `--dry-run` shows what it would do before it mails anyone.

## Example

- [examples/cli](../examples/cli/): the quick-start app with `auth migrate` and `auth sweep` built in, which refuses to serve while migrations are pending.
- [examples/stale-accounts](../examples/stale-accounts/): `auth maintain` running `plugin/stale`, with a dry run first.
- [examples/admin-ops](../examples/admin-ops/): routes `auth` to this package next to its own `grant` command, so `go run ./admin-ops auth admin create --email root@example.com --password-stdin` makes the first admin.
- https://pkg.go.dev/github.com/ubgo/auth/authcli
