# The operator's command line: migrate and sweep

One binary that serves the app and also runs `auth migrate` and `auth sweep`. The library ships the command line as a package, `authcli`, not as a binary of its own, because only your app knows its plugin list, and the plugin list decides the migrations. Your `main` hands it the arguments after a word of your choosing.

## Run it

```sh
cd examples
go build -o myapp ./cli
./myapp auth migrate --dry-run
./myapp auth migrate
./myapp
```

The database is `cli.db` (SQLite) in the current directory. Unlike the other examples, the server does not migrate on start; it refuses to start until the schema is current. Run the tests with `go test ./cli`.

## Walkthrough

On an empty database the server refuses to start, and says what to run:

```sh
./myapp; echo "exit $?"
```

```text
2026/09/29 13:48:13 auth migrations are pending; run "auth migrate" first
exit 1
```

The dry run lists what would be applied and changes nothing:

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

Apply them. A second run has nothing to do, so it is safe in every deploy:

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

Every migration and its state. A migration whose recorded checksum no longer matches shows as `CHANGED`, and the command exits 1:

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

The schema as SQL for this engine, for a review or a DBA, without touching the database (first lines shown):

```sh
./myapp auth migrate sql | head -3
```

```text
-- core 0001_core_tables
CREATE TABLE IF NOT EXISTS auth_user (id TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL);
CREATE TABLE IF NOT EXISTS auth_identity (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, value_raw TEXT NOT NULL DEFAULT '', verified_at TIMESTAMP NULL, is_primary BOOLEAN NOT NULL DEFAULT FALSE, scope_id TEXT NULL, created_at TIMESTAMP NOT NULL);
```

The sweep deletes expired sessions, spent tokens and finished rate-limit windows, and prints how many rows it deleted per table. The library runs no background workers, so schedule this (cron, a Kubernetes CronJob, your job runner). On a fresh database there is nothing to delete:

```sh
./myapp auth sweep
```

```text
core.auth_code	0
core.auth_session	0
core.auth_verification	0
```

A typo is a usage error with exit code 2, so a script can tell it from a real failure (exit 1):

```sh
./myapp auth migrat; echo "exit $?"
```

```text
usage: auth sweep [--retention 168h] delete expired sessions, tokens and plugin rows
       auth migrate [--dry-run]    apply pending migrations
       auth migrate sql              print every migration as SQL, change nothing
       auth migrate status           list migrations and whether each is applied
       auth migrate orphans          list tables, columns and owners no plugin claims now

examples:
  myapp auth migrate status
  myapp auth migrate --dry-run
  myapp auth migrate sql > schema.sql
exit 2
```

Every command also prints `WARN auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance` to stderr first (left out above). `auth.New` logs it whenever no rate store is configured, even for a command that never serves a request.

### Configuration from the environment, and `auth info`

`newAuth` reads the `AUTH_*` variables with `auth.EnvOptions(os.LookupEnv)` and appends them after its own defaults, so a set variable wins. It logs which ones are set (never a value, because `AUTH_SECRET` is one of them). `auth info` prints what `auth.New` settled, without a database, for a support request; the log lines go to stderr:

```sh
AUTH_BASE_URL=https://app.example.com AUTH_SESSION_IDLE=48h ./myapp auth info 2>/dev/null | head -6
```

```text
version              (devel)
engine               sqlite
base url             https://app.example.com
trusted origins      0
fresh window         10m0s
session              idle 48h0m0s, max 720h0m0s, refresh after 24h0m0s
```

A malformed value stops the binary before it does anything:

```sh
AUTH_SESSION_IDLE=7d ./myapp auth info; echo "exit $?"
```

```text
2026/10/09 16:05:30 auth: AUTH_SESSION_IDLE="7d" is not a positive duration such as 168h
exit 1
```

## The code

The whole integration is one function in `main`; any other word, or no argument, starts the server:

```go
func command(ctx context.Context, a *auth.Auth, args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 || args[0] != authCommand {
		return authcli.ExitOK, false
	}
	return authcli.Main(ctx, a, args[1:], stdout, stderr), true
}
```

The server checks the ledger instead of migrating by itself, so with several instances the deploy job migrates once and an instance started against an old schema fails at once rather than at its first query:

```go
states, err := a.MigrationStatus(ctx)
for _, s := range states {
	if !s.Applied || s.Changed {
		return errPending
	}
}
```

`main_test.go` runs the command line the way `main` does: the server refusing an empty database, a dry run that applies nothing, migrate twice, status, the SQL print, the usage exit code, the environment read back from `auth info --json` (and the error for a malformed duration), and a sweep from an instance whose clock is two months later that deletes the expired session a sign-up created.

## What this used

- [`authcli`](https://pkg.go.dev/github.com/ubgo/auth/authcli): `Main`, `ExitOK`, `ExitFailed`, `ExitUsage`, and `auth migrate orphans` for tables and columns no plugin owns any more.
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `a.MigrationStatus`, `a.Migrate`, `a.MigrationSQL`, `a.Sweep`, `EnvOptions`, `EnvVars`
- [`authcli`](https://pkg.go.dev/github.com/ubgo/auth/authcli) `auth info` and its JSON form, `authcli.Info`
- Several instances sharing rate limits: [multi-instance](../multi-instance).
