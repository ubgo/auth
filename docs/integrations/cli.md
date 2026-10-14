# The operator's command line (authcli)

You will have one binary that serves your app and also runs `auth migrate`, `auth sweep`, `auth maintain` and `auth admin` for the operator and `auth client ts` for the frontend, with exit codes a deploy script can branch on, and a server that refuses to start against a schema that is behind.

## Before you start

- [Migrations and maintenance](../concepts/migrations-and-maintenance.md): what a migration is, the ledger table, and why nothing runs the sweep by itself.
- The example is [`examples/cli`](../../examples/cli/main.go). `go build -o myapp ./cli` in `examples/` builds it; `go test ./cli` runs its tests.
- `authcli` is a package in the core module, not a binary of its own: only your app knows its plugin list, and the plugin list decides the migrations. Nothing to install beyond `github.com/ubgo/auth`.

## Step 1 — Route a word of your choosing to authcli

Pick a first argument, here `auth`, and hand everything after it to `authcli.Main` with the `*auth.Auth` you built. `Main` returns the exit code; exit with it. Any other command line is the server's.

<!-- ds:block id=command-5hg2hb73 -->
**command** · [`examples/cli/main.go:112-117`](../../examples/cli/main.go#L112-L117)

```go
func command(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 || args[0] != authCommand {
		return authcli.ExitOK, false
	}
	return authcli.Main(ctx, a, args[1:], stdout, stderr), true
}
```
<!-- /ds:block hash=9befd6 -->

`Main`'s contract: `args` excludes the program name and the word you routed on; output meant for a pipe (the SQL, the status table) goes to `stdout`, usage and errors to `stderr`. It reads the process's standard input only when a command asks for it (Step 7's `--password-stdin`); `MainWithStdin` takes another reader.

<!-- ds:block id=main-tduqyp9t lines=1-3 -->
**Main** · [`authcli/authcli.go:125-127`](../../authcli/authcli.go#L125-L127)

```go
func Main(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) int {
	return MainWithStdin(ctx, a, args, os.Stdin, stdout, stderr)
}
```
<!-- /ds:block hash=87ca14 -->

Check: a typo is a usage error, exit code [`ExitUsage`](ds:block?id=exitusage-d43sp75x) (2), with the usage on stderr, so a script can tell it from a command that ran and failed, [`ExitFailed`](ds:block?id=exitfailed-ssu2cn9e) (1):

```sh
./myapp auth migrat; echo "exit $?"
```

```text
usage: auth sweep [--retention 168h] delete expired sessions, tokens and plugin rows;
                                     with WithDeliveryOutbox, send the outbox's due messages
       auth maintain [--dry-run]   run the plugins' scheduled jobs (mail to dormant accounts,
                                     deletion of the ones that never answered);
                                     --dry-run counts them and changes nothing
       auth migrate [--dry-run]    apply pending migrations
       auth migrate sql              print every migration as SQL, change nothing
       auth migrate status           list migrations and whether each is applied
       auth migrate orphans          list tables, columns and owners no plugin claims now
       auth migrate check            fail unless the database holds every table, column and migration the code needs
       auth generate                 the same as auth migrate sql
       auth info [--json]            print the wiring: version, engine, plugins, routes, lifetimes
       auth secret [--value]         print AUTH_SECRET=<a fresh random secret> (--value: the value alone)
       auth client ts --out dir      write the typed TypeScript client of this app's routes into dir
       auth admin grant --email x    make the owner of a verified address an admin
       auth admin create --email x [--name y] [--password-stdin]
                                     create a user with a verified address and admin rights
                                     (--json prints the result as JSON, --dry-run changes nothing)

examples:
  myapp auth migrate status
  myapp auth migrate --dry-run
  myapp auth migrate check && myapp serve
  myapp auth migrate sql > schema.sql
  myapp auth info --json
  myapp auth secret --value | gopass insert -f myapp/auth-secret
  myapp auth client ts --out web/src/auth
  myapp auth admin grant --email alice@example.com
  echo "$ADMIN_PASSWORD" | myapp auth admin create --email root@example.com --name Root --password-stdin
  myapp auth admin create --email root@example.com --dry-run --json
exit 2
```

## Step 2 — Preview, then apply the migrations

`auth migrate --dry-run` lists what would be applied and changes nothing; `auth migrate` applies it. A second run has nothing to do, so the command is safe in every deploy.

```sh
./myapp auth migrate --dry-run
```

```text
pending  core      0001_core_tables
pending  email     0000_identity_unique_email_verified
pending  email     0000_column_auth_user_primary_email
pending  email     0000_column_auth_user_email_verified_at
pending  password  0001_password
5 pending, 0 changed, 5 total
```

```sh
./myapp auth migrate
./myapp auth migrate
```

```text
applied core/0001_core_tables
applied email/0000_identity_unique_email_verified
applied email/0000_column_auth_user_primary_email
applied email/0000_column_auth_user_email_verified_at
applied password/0001_password
nothing to apply
```

Check: `auth migrate status` shows every migration as `applied`, `pending` or `CHANGED`. A migration whose statements changed after it was applied is `CHANGED`, and both `status` and `--dry-run` then exit 1 (`auth.ErrChecksumMismatch`), because `migrate` would refuse to run:

```sh
./myapp auth migrate status
```

```text
applied  core      0001_core_tables
applied  email     0000_identity_unique_email_verified
applied  email     0000_column_auth_user_primary_email
applied  email     0000_column_auth_user_email_verified_at
applied  password  0001_password
0 pending, 0 changed, 5 total
```

## Step 3 — Refuse to serve a schema that is behind

With several instances, the deploy job migrates once and the servers must not race it. The example's server checks the ledger instead of migrating by itself, so an instance started against an old schema fails at once, naming the command to run, rather than at its first query.

<!-- ds:block id=requiremigrated-nmbrfr8y -->
**requireMigrated** · [`examples/cli/main.go:128-139`](../../examples/cli/main.go#L128-L139)

```go
func requireMigrated(ctx context.Context, a *auth.Auth) error {
	states, err := a.MigrationStatus(ctx)
	if err != nil {
		return err
	}
	for _, s := range states {
		if !s.Applied || s.Changed {
			return errPending
		}
	}
	return nil
}
```
<!-- /ds:block hash=c6bc69 -->

Check: on an empty database the server refuses to start:

```sh
./myapp; echo "exit $?"
```

```text
2026/09/29 13:48:13 auth migrations are pending; run "auth migrate" first
exit 1
```

## Step 4 — Review the SQL and the leftovers

`auth migrate sql` prints every migration as SQL for the configured engine and needs no database, for a review or a DBA. `auth migrate orphans` lists tables, columns and owners in the database that no registered plugin claims any more, after a plugin was removed; it deletes nothing, the operator decides.

```sh
./myapp auth migrate sql | head -3
```

```text
-- core 0001_core_tables
CREATE TABLE IF NOT EXISTS auth_user (id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS auth_identity (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, value_raw TEXT NOT NULL DEFAULT '', verified_at TIMESTAMP NULL, is_primary BOOLEAN NOT NULL DEFAULT FALSE, scope_id TEXT NULL, created_at TIMESTAMP NOT NULL);
```

## Step 5 — Schedule the sweep

`auth sweep` deletes expired sessions, verification tokens expired or spent more than `--retention` ago (default `auth.DefaultSweepRetention`, 7 days, shown as `168h`), finished rate-limit windows and each plugin's expired rows, and prints a count per table. The library runs no background workers, so run it from cron, a Kubernetes CronJob or your job runner; it is idempotent and safe from several instances at once. A plugin with expiring rows of its own takes part by implementing `auth.Sweeper` and appears as its own line; [`examples/plugin-sweeper`](../../examples/plugin-sweeper/README.md) is one.

```sh
./myapp auth sweep
```

```text
core.auth_code	0
core.auth_session	0
core.auth_verification	0
```

### Run the plugins' jobs: auth maintain

[`auth maintain`](ds:block?id=cmdmaintain-4wn8qk3v) runs [`a.Maintain`](ds:block?id=core-maintain-6wx9nq3v): every registered plugin that implements `auth.Maintainer`, such as [`plugin/stale`](../plugins/stale.md)'s mail to dormant accounts and, if turned on, their deletion, or [`plugin/webhook`](../plugins/webhook.md)'s retries of failed sends. It prints each counter, sorted by name and prefixed with the plugin's name, one per line. It is a command of its own, not part of the sweep, because it can send mail and delete accounts; `--dry-run` prints the same counters and changes nothing, so run that first. With no maintainer registered it prints nothing and exits 0. A plugin that fails stops the run: the counters it had are printed, the error goes to stderr, and the exit code is [`ExitFailed`](ds:block?id=exitfailed-ssu2cn9e) (1). Schedule it daily, after the sweep (more often when a job is time-sensitive, such as webhook retries); a job is idempotent, so a second run finds nothing left to do.

[`examples/stale-accounts`](../../examples/stale-accounts/) routes the word `auth` the same way as Step 1; right after a sign-up its dry run counts nothing:

```sh
go run ./stale-accounts auth maintain --dry-run
```

```text
stale.active	0
stale.cleared	0
stale.deleted	0
stale.exempt	0
stale.failed	0
stale.no_channel	0
stale.warned	0
```

Check: `auth maintain extra` is a usage error (exit 2); `TestMain_MaintainFailureIsExitFailedAfterTheCounters` in `authcli/maintain_test.go` pins the failure path.

## Step 6 — Print the wiring for a support request

`auth info` prints what `auth.New` settled: the library version from the binary's build information, the engine, the base URL, the number of trusted origins, the fresh window and the session lifetimes, then one line per plugin, per disabled operation, per migration and per route (kind, route, requirement, id). It touches no database and holds no secret, so it is what to paste into a bug report. `--json` prints the same as one object.

```sh
./myapp auth info | head -8
```

```text
version              v0.3.0
engine               sqlite
base url             https://app.example.com
trusted origins      0
fresh window         10m0s
session              idle 168h0m0s, max 720h0m0s, refresh after 24h0m0s
plugins              2
identifiers          1
```

Check: `./myapp auth info --json | jq .operations[0]` is `{"id": "core.session", "kind": "query", "require": "signed_in", "route": "/session"}`, and `jq .session.maxLifetime` is `"720h0m0s"`: lifetimes are readable strings that decode back into `authcli.Info`. `TestCLI_ConfigFromEnvironment` in `examples/cli` decodes it that way after setting `AUTH_BASE_URL` and `AUTH_SESSION_IDLE`; the variables themselves are step 1 of the [production guide](../start/production.md).

### A new secret, and the SQL under another name

`auth secret` prints a fresh `AUTH_SECRET=` line (32 random bytes, base64), and `--value` the value alone, so it can go straight into a secret store without touching a file: `./myapp auth secret --value | gopass insert -f myapp/auth-secret`. `auth generate` is `auth migrate sql` under better-auth's name.

## Step 7 — Make the first admin

With the [admin plugin](../plugins/admin.md) registered, nobody can grant admin rights over HTTP until an admin exists, so the first one comes from the command line. `auth admin create` makes a user with a verified address, the password from stdin and admin rights in one transaction; `auth admin grant` makes an existing user with a verified address an admin. The password is never a flag, because argv is visible to other processes and lands in shell history. From [`examples/admin-ops`](../../examples/admin-ops/), which routes `auth` to `authcli` next to its own `grant` command:

```sh
echo "$ADMIN_PASSWORD" | go run ./admin-ops auth admin create --email root@example.com --name Root --password-stdin
go run ./admin-ops auth admin create --email root@example.com --dry-run
go run ./admin-ops auth admin grant --email root@example.com --json
go run ./admin-ops auth admin grant --email nobody@example.com
go run ./admin-ops auth admin create --email x@example.com --password-stdin < /dev/null
```

```text
created root@example.com (usr_6k5h7usufkslp5dxldxeofrk) as an admin with the password from stdin
auth admin create: auth.identity_taken
{
  "userId": "usr_6k5h7usufkslp5dxldxeofrk",
  "email": "root@example.com",
  "created": false,
  "granted": true,
  "passwordSet": false,
  "dryRun": false
}
auth admin grant: find a verified email "nobody@example.com": auth.identity_not_found
auth admin create: authcli: --password-stdin: nothing was read from stdin
```

The exit codes were 0, 1, 0, 1 and 2: the rehearsal of a taken address fails like the real thing, an unknown or unverified address is a failure, and an empty stdin is a usage error. The command finds the admin, email and password plugins by interface (`authcli.AdminGranter`, `AddressSetter`, `PasswordSetter`), so an app registers nothing extra and an app without passwords still has `grant` and a password-less `create`.

Check: `auth admin grant --email x` for an address that signed up but never verified exits 1 with `auth.identity_not_found`, and the user is not an admin; admin rights for whoever typed an address first would be a takeover.

## Step 8 — Write the app's TypeScript client: auth client ts

A frontend that calls your app needs a client that knows your app's routes: the plugins you wired, your own plugins' operations and their error codes. Only your binary knows that list, so the generator is an `authcli` command like the others. `auth client ts --out <dir>` writes five files (`client.ts`, `runtime.ts`, `error-codes.ts`, `extensions.ts`, `index.ts`) into the folder, creating it when it is missing. It reads the operation list `auth.New` settled and never touches the database, so it runs on a laptop with no `AUTH_DATABASE_URL` and in a CI job before anything is deployed.

From [`examples/ts-client-custom`](../../examples/ts-client-custom/), built to `./tscustom`, a real run:

```sh
./tscustom auth client ts --out web-auth; echo "exit $?"
```

```text
web-auth/client.ts
web-auth/error-codes.ts
web-auth/index.ts
web-auth/runtime.ts
exit 0
```

Each path goes to stdout, one per line, so a script can feed them to a formatter or `git add`. Without `--out` it is a usage error, exit [`ExitUsage`](ds:block?id=exitusage-d43sp75x) (2), with `auth client ts: --out is required` and the usage on stderr; an unknown language (`auth client js`) is the same exit with the usage alone.

Run it whenever a plugin, an operation, an input or output type, or an error code changes, and commit the five files. The guide [Your own plugins](../client/custom-plugins.md) walks through the whole loop: the plugin, the command, what the files hold, the calls from the frontend, and a Go test that fails when the committed copy is stale ([Step 7](../client/custom-plugins.md#step-7--fail-the-build-when-the-copy-is-stale)).

Check: `git diff --exit-code -- web/src/auth` right after the command exits 0 when the committed copy is current. The command refuses to write a client whose names would collide (two operations of one plugin that differ only in punctuation, a plugin named after a TypeScript keyword or a core method, a Go type named like a runtime export) and exits [`ExitFailed`](ds:block?id=exitfailed-ssu2cn9e) (1) with `auth client ts: authhttp: TypeScript name collision: ...` naming both sides, before it writes anything.

## Options you may want

| Need | Do |
|---|---|
| Keep spent tokens longer for support | `auth sweep --retention 720h` |
| See what a maintenance run would do before it mails anyone | `auth maintain --dry-run` |
| A rehearsal of the admin command, or its result for a script | `auth admin … --dry-run`, `auth admin … --json` (`authcli.AdminResult`) |
| The word `auth` clashes with a command of yours | Route on any other word; `authcli` never sees it. |
| The TypeScript client in a folder other than `web/src/auth` | `auth client ts --out <any dir>`; the files import each other by relative path, so the folder name is yours. |
| Your own CLI framework (cobra, urfave) | Call `authcli.Main(ctx, a, args, os.Stdout, os.Stderr)` from a subcommand and return its code; `authcli.MainWithStdin` when the framework owns stdin. |

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `auth migrate: auth: no database configured; pass auth.WithDB`, exit 1 | The `*auth.Auth` has no database. Only `migrate sql` works without one. | Build it with `auth.WithDB`. |
| `CHANGED` in `status`, exit 1 | A migration's statements differ from what the ledger recorded, usually an edited plugin migration. | Do not edit applied migrations; add a new one. |
| `exit 2` | Wrong arguments: an unknown command, an unexpected argument (`auth maintain extra`), an unknown flag, a `--retention` that is not a duration or is negative, `admin` without `--email`, `--password-stdin` with an empty stdin. | The usage on stderr names the forms. |
| `auth admin grant: authcli: the admin plugin is not registered`, exit 1 | The `*auth.Auth` has no plugin with a `Grant` method. | `auth.WithPlugins(admin.New())`; the same for the address (`email.New`) and, under `--password-stdin`, the password plugin. |
| `auth maintain: auth: maintain stale: …`, exit 1, after some counters | A plugin's job failed; the counters printed are what it had done. | Read the error; a later run retries, since each job is idempotent. |
| `WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance` on every command | `auth.New` logs it whenever no rate store is configured, even for a command that serves no request. | Harmless here; see [Redis](redis.md) or `auth.WithDBRateStore()` for the server. |

## Next

- [Migrations and maintenance](../concepts/migrations-and-maintenance.md) for upgrades and what each migration owner contributes.
- [Production](../start/production.md) for where the sweep and the maintenance jobs run in a deployment.
- [Stale accounts](../plugins/stale.md) for the job `auth maintain` runs today.
- The package's [README](../../authcli/README.md) is the reference for every command, flag and exit code.
