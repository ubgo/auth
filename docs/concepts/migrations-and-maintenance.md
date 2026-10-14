# Migrations and maintenance

The library creates and upgrades its own tables, keeps a ledger of what it applied, and leaves the scheduling to you: running the sweep that deletes what expired, and the maintenance jobs some plugins have. This page explains `Migrate`, the operator's commands, the sweep, `Maintain`, and how upgrades of the library reach your database.

## Before you start

- [Databases](databases.md): the engines and the handle `Migrate` works on.
- The example is [`examples/cli`](../../examples/cli): one binary that serves the app and runs `myapp auth migrate` and `myapp auth sweep`.

## Step 1 — Apply migrations

`a.Migrate(ctx)` applies every migration not yet in the ledger — the core's, then each plugin's in list order — and returns their names. Run it at start-up, as most examples do, or from a deploy step with `authcli`. A second run finds nothing to do, so it is safe in every deploy.

<!-- ds:block id=core-migrate-p4m2kwpk -->
**Auth.Migrate** · [`migrate.go:195-230`](../../migrate.go#L195-L230)

```go
func (a *Auth) Migrate(ctx context.Context) ([]string, error) {
	ms, conn, err := a.migrationConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	engine := a.Engine()
	unlock, err := lockMigrations(ctx, conn, engine)
	if err != nil {
		return nil, err
	}
	defer unlock()

	ledger := a.TableName(TableMigrations)
	applied, err := readLedger(ctx, conn, a.typesFor(engine), ledger)
	if err != nil {
		return nil, err
	}

	var done []string
	for _, m := range ms {
		key := m.Owner + "/" + m.Name
		if sum, ok := applied[key]; ok {
			if sum != m.Checksum() {
				return done, fmt.Errorf("%w: %s", ErrChecksumMismatch, key)
			}
			continue
		}
		if err := applyOne(ctx, conn, engine, ledger, m, a.now().Format(ledgerTimeLayout)); err != nil {
			return done, fmt.Errorf("auth: migration %s: %w", key, err)
		}
		done = append(done, key)
	}
	return done, nil
}
```
<!-- /ds:block hash=ab5c22 -->

```text
2026/10/01 09:48:00 migrated core/0001_core_tables
2026/10/01 09:48:00 migrated core/0003_session_lifetimes
2026/10/01 09:48:00 migrated email/0000_identity_unique_email_verified
2026/10/01 09:48:00 migrated email/0000_column_auth_user_primary_email
2026/10/01 09:48:00 migrated email/0000_column_auth_user_email_verified_at
2026/10/01 09:48:00 migrated password/0001_password
```

One connection holds a lock for the whole run (an advisory lock on Postgres, a named lock on MySQL; SQLite has one writer anyway), so two instances starting at once do not race. On Postgres and SQLite each migration and its ledger row commit together; MySQL commits every DDL statement by itself, so a failure part-way leaves earlier statements applied and no row, and the error names the migration for you to repair before running again.

Check: `select owner, name from auth_migrations` lists every applied migration; running `Migrate` again returns an empty list.

## Step 2 — The ledger and the checksum

The ledger, `auth_migrations`, records each migration by `owner/name` with the checksum of its statements. A migration whose statements changed after it ran stops `Migrate` with `auth: a migration changed after it was applied`, because silently skipping it or running it again would both be wrong. This is also why a plugin never edits a shipped migration: a change is a new migration with a new name.

<!-- ds:block id=core-errchecksum-brj9fryp -->
**ErrChecksumMismatch** · [`migrate.go:63`](../../migrate.go#L63-L63)

```go
	ErrChecksumMismatch   = errors.New("auth: a migration changed after it was applied")
```
<!-- /ds:block hash=9c6fab -->

<!-- ds:block id=core-migrationstate-49ja73xz -->
**MigrationState** · [`migrate.go:235-243`](../../migrate.go#L235-L243)

```go
type MigrationState struct {
	Owner string
	Name  string
	// Applied is true when the ledger has a row for Owner and Name.
	Applied bool
	// Changed is true when the ledger has the migration with another
	// checksum: the next Migrate stops with ErrChecksumMismatch.
	Changed bool
}
```
<!-- /ds:block hash=a3abdf -->

<!-- ds:block id=core-migrationstatus-um9ygmfn -->
**Auth.MigrationStatus** · [`migrate.go:249-265`](../../migrate.go#L249-L265)

```go
func (a *Auth) MigrationStatus(ctx context.Context) ([]MigrationState, error) {
	ms, conn, err := a.migrationConn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	applied, err := readLedger(ctx, conn, a.typesFor(a.Engine()), a.TableName(TableMigrations))
	if err != nil {
		return nil, err
	}
	out := make([]MigrationState, 0, len(ms))
	for _, m := range ms {
		sum, ok := applied[m.Owner+"/"+m.Name]
		out = append(out, MigrationState{Owner: m.Owner, Name: m.Name, Applied: ok, Changed: ok && sum != m.Checksum()})
	}
	return out, nil
}
```
<!-- /ds:block hash=29196b -->

Check: `a.MigrationStatus(ctx)` lists every migration with `Applied` and `Changed`; nothing is `Changed` on a healthy database.

## Step 3 — Give the operator the commands

`authcli` is a package, not a binary, because only your app knows its plugin list and the plugin list decides the migrations. Your `main` hands it the arguments after a word of your choosing:

```go
if len(os.Args) > 1 && os.Args[1] == "auth" {
	os.Exit(authcli.Main(ctx, a, os.Args[2:], os.Stdout, os.Stderr))
}
```

| Command | Does | Changes the database |
| --- | --- | --- |
| `myapp auth migrate` | applies pending migrations, prints each | yes |
| `myapp auth migrate --dry-run` | lists pending and changed migrations | no |
| `myapp auth migrate status` | every migration: `applied`, `pending` or `CHANGED` | no |
| `myapp auth migrate sql` | every migration as SQL, for review or another tool | no |
| `myapp auth migrate orphans` | tables, columns and owners no registered plugin claims | no |
| `myapp auth migrate check` | fails (exit 1) unless the database holds every migration, table and column the code needs; `schema ok` otherwise | no |
| `myapp auth sweep [--retention 168h]` | deletes expired rows (delivery outbox rows past the retention among them); with `auth.WithDeliveryOutbox`, then sends the outbox's due messages and prints `outbox.sent` and `outbox.failed` | yes |
| `myapp auth maintain [--dry-run]` | runs every plugin's scheduled job (`plugin/stale`'s mail to dormant accounts and, if turned on, their deletion; `plugin/webhook`'s retries of failed sends) and prints its counters; `--dry-run` counts and changes nothing | yes, without `--dry-run` |
| `myapp auth info [--json]` | version, engine, plugins, routes, migrations, lifetimes, for a support request | no |

```text
pending  core      0001_core_tables
pending  email     0000_identity_unique_email_verified
pending  email     0000_column_auth_user_primary_email
pending  email     0000_column_auth_user_email_verified_at
pending  password  0001_password
5 pending, 0 changed, 5 total
```

Exit codes are [0](ds:block?id=exitok-gnrts3ej) for success, [1](ds:block?id=exitfailed-ssu2cn9e) for a command that ran and failed (the reason is on stderr) and [2](ds:block?id=exitusage-d43sp75x) for a usage error, so a script can tell them apart. The example's server refuses to start while migrations are pending, which is the strict choice for a deployment with a separate migrate step:

```text
2026/09/29 13:48:13 auth migrations are pending; run "auth migrate" first
exit 1
```

The schema check goes further than the ledger: `a.CheckSchema(ctx)` compares the tables and columns the migrations create (read from the `CREATE TABLE` and `ALTER TABLE … ADD COLUMN` statements themselves, a plugin's included) with what the database's catalogue reports, besides listing pending and changed migrations, so a column dropped by hand is found although every migration is recorded as applied. `a.RequireSchema(ctx)` is the start-up form: an app calls it after `auth.New` and before serving, and a deploy that forgot to migrate fails to start with `auth.ErrSchemaBehind` naming what is missing, instead of failing its users one request at a time. `myapp auth migrate check` is the same for a deploy script: `myapp auth migrate check && myapp serve`.

<!-- ds:block id=core-requireschema-2tk9vp7m -->
**Auth.RequireSchema** · [`schemacheck.go:135-144`](../../schemacheck.go#L135-L144)

```go
func (a *Auth) RequireSchema(ctx context.Context) error {
	r, err := a.CheckSchema(ctx)
	if err != nil {
		return err
	}
	if r.OK() {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrSchemaBehind, strings.TrimPrefix(r.Error(), ErrSchemaBehind.Error()+": "))
}
```
<!-- /ds:block hash=d4bddf -->

<!-- ds:block id=core-schemareport-6vm3kq8t -->
**SchemaReport** · [`schemacheck.go:21-34`](../../schemacheck.go#L21-L34)

```go
type SchemaReport struct {
	// PendingMigrations are the "owner/name" labels the ledger lacks, in
	// the order Migrate would apply them.
	PendingMigrations []string
	// ChangedMigrations are applied migrations whose statements changed
	// since; Migrate refuses to run while any exists.
	ChangedMigrations []string
	// MissingTables are tables the migrations create that the database
	// lacks.
	MissingTables []string
	// MissingColumns are "table.column" pairs the migrations create that the
	// database lacks, on tables that exist.
	MissingColumns []string
}
```
<!-- /ds:block hash=158493 -->

Check: `myapp auth migrate --dry-run` on production before a deploy shows exactly what the deploy will apply, and `myapp auth migrate check` exits 1 until it has.

## Step 4 — Review the SQL, or apply it with your own tool

`a.MigrationSQL()` and `myapp auth migrate sql` print every migration as one script in the engine's dialect. A team that applies schema changes through its own migration tool reviews or imports it; the ledger is then not written, so `Migrate` must not run as well, or it would apply everything again.

<!-- ds:block id=core-migrationsql-8w4m33nv -->
**Auth.MigrationSQL** · [`migrate.go:137-152`](../../migrate.go#L137-L152)

```go
func (a *Auth) MigrationSQL() (string, error) {
	ms, err := a.Migrations()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, m := range ms {
		fmt.Fprintf(&b, "-- %s %s\n", m.Owner, m.Name)
		for _, st := range m.Statements {
			b.WriteString(st)
			b.WriteString(";\n")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}
```
<!-- /ds:block hash=0cbe0a -->

It needs no database: `auth.WithDialect` names the engine, so CI can print the Postgres script from a build that never reaches a server. `examples/core-options` does exactly that, with the column types it overrides:

<!-- ds:block id=postgresmigrationsql-3nd8kq5v -->
**postgresMigrationSQL** · [`examples/core-options/main.go:209-222`](../../examples/core-options/main.go#L209-L222)

```go
func postgresMigrationSQL() (string, error) {
	a, err := auth.New(
		auth.WithDialect(sqlb.PostgresDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSQLTypes(auth.EnginePostgres, postgresTypes),
		auth.WithIDs(newUUIDv7),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(logMailer{})), password.New()),
	)
	if err != nil {
		return "", err
	}
	defer a.Close()
	return a.MigrationSQL()
}
```
<!-- /ds:block hash=e3d9fe -->

```sh
go run ./core-options sql | grep -E 'TABLE IF NOT EXISTS auth_(user|password) '
```

```sql
CREATE TABLE IF NOT EXISTS auth_user (id UUID NOT NULL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_password (user_id UUID NOT NULL PRIMARY KEY, hash TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
```

Check: the script starts with `-- core 0001_core_tables` and ends with the last plugin's migration; `TestSQLTypes` in `examples/core-options` reads the same script.

## Step 5 — Find what a removed plugin left

Removing a plugin from the list removes its routes and its migrations from `Migrations()`, but not its tables, its columns on `auth_user` or its ledger rows: the library never drops user data because configuration changed. `myapp auth migrate orphans` lists them, by kind (`owner`, `table`, `column`) and name, and you decide what to drop.

<!-- ds:block id=core-orphan-5rmbmqxz -->
**Orphan** · [`orphans.go:33-36`](../../orphans.go#L33-L36)

```go
type Orphan struct {
	Kind OrphanKind
	Name string
}
```
<!-- /ds:block hash=563d8f -->

Under `auth.WithTablePrefix` the library's tables carry the prefix, so a removed plugin's table is reported when it carries the prefix too (`billing_auth_account`); a table that plugin had been given with `auth.RenameTable` cannot be told from the app's own and is not reported.

<!-- ds:block id=core-orphans-fmffsrbr lines=1-8 -->
**Auth.Orphans** · [`orphans.go:50-114`](../../orphans.go#L50-L114)

```go
func (a *Auth) Orphans(ctx context.Context) ([]Orphan, error) {
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	owners := map[string]bool{CorePluginName: true}
	// By real name, since the catalogue reports real names.
	tables := map[string]bool{}
	for _, t := range a.declaredTables() {
```
<!-- /ds:block hash=18fefe -->

Check: remove a plugin, run `orphans`, and its table and ledger owner appear; add it back and the list is empty.

## Step 6 — Schedule the sweep

Expired sessions, spent or expired tokens older than the retention, expired codes and finished rate-limit windows are useless rows. `a.Sweep(ctx, retention)` deletes them and reports how many per table (a verification store outside the database, `auth.WithVerificationStore`, reports 0: its records expire by themselves); each plugin with rows of its own (phone codes, organization invitations) adds its own count. The default retention is [seven days](ds:block?id=defaultsweepretention-shqfpbr3), because a support person may want to see that a reset link was used and when. The library runs no background workers, so schedule the sweep — cron, a Kubernetes CronJob, your job runner — daily is plenty; it is idempotent and safe from several instances at once.

The result keys name each table by its label (`core.auth_session`) whatever its real name under `auth.WithTablePrefix` or `auth.RenameTable`, so an app that reads them sees the same keys in every deployment.

<!-- ds:block id=core-sweep-mvcuuk6r lines=1-8 -->
**Auth.Sweep** · [`sweep.go:48-126`](../../sweep.go#L48-L126)

```go
func (a *Auth) Sweep(ctx context.Context, retention time.Duration) (SweepResult, error) {
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	now := a.now()
	cutoff := now.Add(-retention)
	out := SweepResult{}
	d := a.cfg.Dialect
```
<!-- /ds:block hash=5c29ea -->

```text
core.auth_code	0
core.auth_session	0
core.auth_verification	0
```

Check: after a day with sign-ins and a few expired sessions, `myapp auth sweep` prints a non-zero `core.auth_session`.

### Plugins' scheduled jobs: Maintain

Some plugins have work that is neither a request nor a cleanup: [`plugin/stale`](../plugins/stale.md) mails the owners of dormant accounts and, if asked, deletes the ones that never answer, and [`plugin/webhook`](../plugins/webhook.md) retries the webhook sends that failed. Such a plugin implements [`auth.Maintainer`](ds:block?id=core-maintainer-8rm3wk5q), and [`a.Maintain(ctx, o)`](ds:block?id=core-maintain-6wx9nq3v) runs every one of them in registration order:

<!-- ds:block id=core-maintainer-8rm3wk5q -->
**Maintainer** · [`maintain.go:32-34`](../../maintain.go#L32-L34)

```go
type Maintainer interface {
	Maintain(ctx context.Context, o MaintainOptions) (map[string]int64, error)
}
```
<!-- /ds:block hash=93413c -->

It is kept apart from `Sweep` on purpose. A sweep only deletes what already stopped mattering and is safe to run on a whim; a maintenance job can send mail and delete accounts, so it is asked for by name, and [`auth.MaintainOptions{DryRun: true}`](ds:block?id=core-maintainoptions-4qv7nx2k) reports what it would do, in the same counters, without sending, writing or deleting anything. The counters come back in the same shape as a sweep's, each prefixed with the plugin's name (`stale.warned`, `stale.deleted`). A failing plugin stops the run after recording what it had done, so a later plugin never works on an earlier one's half-finished state, and the error names the plugin. With no `Maintainer` registered the result is empty.

As with the sweep, nothing runs by itself: schedule `myapp auth maintain` (Step 3) daily, or call `a.Maintain` from a job of your own. A job must be idempotent, because a scheduler may run it twice, and a second run right after the first finds nothing left to do.

Check: `myapp auth maintain --dry-run` with `plugin/stale` registered prints `stale.warned 0` and the other counters on a fresh database.

## Step 7 — Upgrade the library

A new version of the library may ship new migrations; it never changes a shipped one. Upgrading is `go get`, deploy, and `Migrate` applies what is new; the start-up log or `migrate status` shows it. For example, the pluggable-sessions release added `core/0003_session_lifetimes`, which adds three columns to `auth_session` and one to `auth_user` with `ALTER TABLE`, and left `0001_core_tables` untouched so every existing ledger still matched. Read the CHANGELOG entry for anything marked breaking before upgrading across a major version.

Check: `myapp auth migrate --dry-run` with the new binary lists the new migrations and no `CHANGED` ones.

## Step 8 — Import users from another system

`a.ImportUsers(ctx, users)` moves accounts in through the same core API every sign-up uses, so the uniqueness rules, the plugins' data hooks and the column extensions all apply and no core table is written by hand. Each user is its own transaction: a row that fails (an id or address already taken, a malformed value, a hook's refusal) leaves nothing behind and is reported in its result while the rest land; the call returns `auth.ErrImportFailed` when any did. Ids and creation times can be kept (`ImportUser.ID`, `CreatedAt`), so the app's own rows keep their foreign keys; identities the other system had verified are imported verified, the rest as claims the user still proves here. No message goes out: the context is `auth.Quiet`, which makes `Deliver` drop everything, because a verify link sent during a migration of ten thousand accounts is ten thousand confused users. Passwords and other credentials follow through their plugin's own import, with the user ids the results carry.

<!-- ds:block id=core-importusers-9zk3wq6p -->
**Auth.ImportUsers** · [`import.go:72-103`](../../import.go#L72-L103)

```go
func (a *Auth) ImportUsers(ctx context.Context, users []ImportUser) ([]ImportResult, error) {
	if a.db == nil {
		return nil, ErrNoDatabase
	}
	ctx = Quiet(ctx)
	out := make([]ImportResult, 0, len(users))
	failed := 0
	for i, in := range users {
		res := ImportResult{Index: i}
		res.Err = a.Tx(ctx, func(ctx context.Context, _ sqlbTx) error {
			u, err := a.CreateUser(ctx, NewUser{ID: in.ID, Name: in.Name, Image: in.Image, CreatedAt: in.CreatedAt})
			if err != nil {
				return err
			}
			for _, idn := range in.Identities {
				if _, err := a.CreateIdentity(ctx, NewIdentity{UserID: u.ID, Kind: idn.Kind, Raw: idn.Value, Verified: idn.Verified, Primary: idn.Primary}); err != nil {
					return fmt.Errorf("identity %s %q: %w", idn.Kind, idn.Value, err)
				}
			}
			res.User = u
			return nil
		})
		if res.Err != nil {
			failed++
		}
		out = append(out, res)
	}
	if failed > 0 {
		return out, fmt.Errorf("%w: %d of %d", ErrImportFailed, failed, len(users))
	}
	return out, nil
}
```
<!-- /ds:block hash=4e557a -->

<!-- ds:block id=core-importuser-4hq7nx2m -->
**ImportUser** · [`import.go:32-42`](../../import.go#L32-L42)

```go
type ImportUser struct {
	// ID keeps the other system's id when it fits (opaque text, unique);
	// empty makes a new one. Keeping ids lets the app's own rows keep their
	// foreign keys.
	ID    string
	Name  string
	Image string
	// CreatedAt keeps the original sign-up time; zero means now.
	CreatedAt  time.Time
	Identities []ImportIdentity
}
```
<!-- /ds:block hash=870b06 -->

Check: after an import, `select count(*) from auth_identity where verified_at is not null` matches the verified addresses you passed, and the mailbox stayed empty.

## What can go wrong

- `auth: a migration changed after it was applied: core/0001_core_tables` — the ledger's checksum differs from the code's. Either the database was migrated by a different version of a plugin that edited a migration (fix the plugin: new migration, not an edit), or someone edited `auth_migrations` by hand.
- `auth: migration password/0001_password: …` — a statement failed on the engine. On MySQL the earlier statements of that migration stayed applied; repair by hand, then run again.
- `auth: take migration lock: …` or `auth: another process holds the migration lock` — another instance is migrating; wait and retry. MySQL waits a minute before giving up.
- `auth migrations are pending; run "auth migrate" first` — the example's strict start; run the migrate step.
- `auth: no database configured; pass auth.WithDB` — `Migrate` or `Sweep` without `WithDB`.
- `auth: schema is behind the code: 1 missing column(s): auth_user.sessions_valid_after` — `RequireSchema` or `migrate check` found the database lacks something the code writes, with every migration applied: a hand-edited schema, or a database migrated by another tool from an older script. Apply the missing DDL (`migrate sql` prints it) and run the check again.
- `auth: engine not supported: "…"` — the dialect is not Postgres, MySQL or SQLite.
- A table that `orphans` reports although its plugin is registered — the plugin owns the table but does not list it in `Tables()`; that is the plugin's bug.

## Next

- [Databases](databases.md): what the tables hold and how to read them.
- [Tables and migrations](../extending/05-tables-and-migrations.md): how a plugin writes a migration.
