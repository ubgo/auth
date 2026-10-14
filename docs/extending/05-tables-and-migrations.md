# Tables and migrations

You will have a plugin that owns a table of its own: declared to the core, created by a migration the plugin writes once per engine, read and written through typed columns, and recorded in the same ledger as the core's tables.

## Before you start

- [Plugin anatomy](01-plugin-anatomy.md) and [Operations](02-operations.md): the table is read and written from operations.
- The example is [`examples/plugin-tables/devices`](../../examples/plugin-tables/devices/devices.go): each user names the devices they trust. `go test ./plugin-tables/...` in `examples/` runs it on SQLite; the library's own tables are tested on Postgres and MySQL too, and a plugin table should be.
- A column a plugin adds to `auth_user` is a different thing, and simpler: see [Hooks](03-hooks.md). Reach for a table when the data is many rows per user, or larger than a flag, a timestamp or a short string.

## Step 1 — Name the table and its columns, typed

Give the table the library's `auth_` prefix, so `auth migrate orphans` knows it is the library's once the plugin is gone, and a short alias no other plugin uses. Then declare every column with the Go type it holds: `sqlb.Col[time.Time]` cannot be compared with a string, so a wrong comparison is a compile error instead of a query that matches nothing.

The constant is the table's *label*, not necessarily its name in the database: an app may rename every table with `auth.WithTablePrefix` or yours alone with `auth.RenameTable(devices.TableDevice, "trusted_devices")`, and your plugin must keep working. The rule that makes that true is simple: **always build SQL through the Auth; never concatenate a table constant into SQL.** A statement built with `sqlb` and run through `a.Exec`, `a.One` or `a.Each` renders the real name by itself; DDL, which you write as text, names the table with `a.TableName(TableDevice)`. The library's own test suite enforces the rule on its plugins' source (`TestGuard_TableNamesNeverConcatenated`), and a second run of its integration suite with every table prefixed proves it on a database.

<!-- ds:block id=devices-columns-484sberx -->
**TableDevice** · [`examples/plugin-tables/devices/devices.go:80`](../../examples/plugin-tables/devices/devices.go#L80-L80)

```go
	TableDevice = sqlb.Table{Name: TableNameDevice, Alias: TableAliasDevice}
```
<!-- /ds:block hash=79e633 -->

The row type a query fills, with a `Bindings` function that pairs each column with its field:

<!-- ds:block id=devices-bindings-vwbmdb3p -->
**Bindings** · [`examples/plugin-tables/devices/devices.go:97-99`](../../examples/plugin-tables/devices/devices.go#L97-L99)

```go
func Bindings(d *Device) []sqlb.Binding {
	return []sqlb.Binding{sqlb.Bind(ID, &d.ID), sqlb.Bind(Name, &d.Name), sqlb.Bind(CreatedAt, &d.CreatedAt)}
}
```
<!-- /ds:block hash=30a53e -->

Check: the alias is not one of `auth.ReservedAliases` (`u`, `i`, `s`, `v`, `oc`) and not another plugin's. `auth.New` refuses a collision by name.

## Step 2 — Declare the table with TableOwner

`Tables` tells the core which tables and aliases the plugin brings into statements. The core refuses two plugins that claim one alias at `auth.New`, naming both, instead of the ambiguous-column error that would otherwise appear inside an unrelated query.

<!-- ds:block id=core-tableowner-pwddjxec -->
**TableOwner** · [`plugin.go:50-52`](../../plugin.go#L50-L52)

```go
type TableOwner interface {
	Tables() []sqlb.Table
}
```
<!-- /ds:block hash=753ff0 -->

<!-- ds:block id=devices-tables-abyjw3he -->
**Plugin.Tables** · [`examples/plugin-tables/devices/devices.go:192`](../../examples/plugin-tables/devices/devices.go#L192-L192)

```go
func (p *Plugin) Tables() []sqlb.Table { return []sqlb.Table{TableDevice} }
```
<!-- /ds:block hash=f52537 -->

Check: `auth migrate orphans` on a database that has your table, with the plugin registered, lists nothing. Remove the plugin from the list and it prints a `table` line for `auth_device`.

## Step 3 — Write the migration with TypedMigrator

A migration is a named list of statements with an owner, and the name is its identity for ever. The core asks each plugin for its migrations once per engine, after `Init`, so the plugin writes DDL in the engine's own spellings and names its table through the Auth it was given at `Init`: `a.TableName(TableDevice)`, which is the real name under the app's `auth.WithTablePrefix` or `auth.RenameTable` and the label otherwise. Write no foreign key and no `ON DELETE CASCADE`: the library creates none anywhere (ADR-0002), tables are plain storage, and a user's rows are removed in Go by the declaration in step 4 below. The library's own test suite refuses a plugin source that spells one (`TestGuard_NoForeignKeys`).

A table that needs only columns and indexes can be described instead of written: [`auth.TableSchema`](ds:block?id=core-tableschema-8nq2wk6x) (a text `ID` primary key, [`SchemaColumn`](ds:block?id=core-schemacolumn-5kq8wn2x)s with a portable `ColumnType`, `Nullable`, `Default`, `Unique`, and [`SchemaIndex`](ds:block?id=core-schemaindex-3wn7kq4d)es), turned into the engine's DDL by [`a.SchemaMigration(engine, owner, name, schema)`](ds:block?id=core-schemamigration-6wq3nk8x): `CREATE TABLE IF NOT EXISTS` under the real table name, indexes named `<table>_<index>` (inside the CREATE TABLE on MySQL, which has no `CREATE INDEX IF NOT EXISTS`). It is better-auth's plugin `schema`; there is no `references`, for the reason above. Hand-written DDL stays the way for anything else.

Implement [`auth.TypedMigrator`](ds:block?id=core-typedmigrator-5rk8wd3n): its `TypedMigrations(engine, t)` is handed the engine's spellings with the app's [`auth.WithSQLTypes`](ds:block?id=opt-withsqltypes-8pz4qm2k) overrides applied, so your `user_id` column gets the same type as the user id it holds. Type every column that holds a generated id or refers to one (your primary key from `a.NewID`, `user_id`) with `t.ID`, and other short indexed text (a status, a kind) with `t.Key`: an app that passes `SQLTypes{ID: "UUID"}` gets UUID ids, and a `Key` column must still hold `"active"`. A column that stores `""` for "none" stays `t.Key`, because a UUID column cannot hold `""`. The older `Migrator`, whose `Migrations(engine)` spells types with `auth.TypesFor`, still works, but `auth.New` refuses `WithSQLTypes` for the app's engine while a plugin implements only it, because its tables would keep the built-in types beside core tables that changed.

<!-- ds:block id=core-migrator-2zu9w44h -->
**Migrator** · [`migrate.go:56-58`](../../migrate.go#L56-L58)

```go
type Migrator interface {
	Migrations(engine string) ([]Migration, error)
}
```
<!-- /ds:block hash=b8c468 -->

<!-- ds:block id=core-migration-jfbu8by8 -->
**Migration** · [`migrate.go:31-41`](../../migrate.go#L31-L41)

```go
type Migration struct {
	// Owner is CorePluginName or the name of the plugin that ships it;
	// Migrations refuses a plugin migration that names another owner.
	Owner string
	// Name orders nothing; it only identifies. Prefix it with a number, as
	// "0001_tables", so a listing reads in the order it was written.
	Name string
	// Statements run in order, one ExecContext each, written for the engine
	// the migration was generated for.
	Statements []string
}
```
<!-- /ds:block hash=602f90 -->

<!-- ds:block id=core-sqltypes-m9pb5g5x -->
**SQLTypes** · [`migrate.go:400-434`](../../migrate.go#L400-L434)

```go
type SQLTypes struct {
	// ID is a column that holds a generated row id (Auth.NewID, or the
	// app's WithIDs generator) or refers to one: every primary key the
	// library generates, user_id, session_id, an organization's or a team's
	// id. Override it to give ids a native type (UUID on Postgres). A column
	// that may hold "" or a value the library did not generate (a provider's
	// client id, a JWT id, a connection name) is a Key instead, because a
	// native id type refuses those.
	ID string
	// Key is a short indexed text that is not a generated id: a kind, a
	// purpose, a status, an operation id, a slug, a provider's subject.
	Key string
	// Text is a short display string.
	Text string
	// Value is an identifier value or an address.
	Value string
	// Long is a URL, a user agent or free text up to a few kilobytes.
	Long string
	// Timestamp holds a UTC instant with at least microsecond precision.
	Timestamp string
	// Bool is a flag; MySQL spells it BOOLEAN, which is TINYINT(1).
	Bool string
	// Hash is a 32-byte digest.
	Hash string
	// Bytes is a short binary value such as a WebAuthn credential id, at most
	// 1024 bytes, and indexable on every engine.
	Bytes string
	// Doc is a large text value such as a JSON document, unindexed.
	Doc string
	// Int is a 64-bit integer: a counter or a numeric setting.
	Int string
	// TableSuffix ends every CREATE TABLE. On MySQL it sets the byte-exact
	// collation.
	TableSuffix string
}
```
<!-- /ds:block hash=609c09 -->

Start with `auth.CheckEngine`, so an engine the core has no spellings for is `auth.ErrEngineNotSupported` and not a statement that fails later. Keep constraints inline — `PRIMARY KEY`, `UNIQUE (…)` — because `CREATE INDEX IF NOT EXISTS` exists on Postgres and SQLite but not on MySQL, and end the statement with `t.TableSuffix`, which on MySQL sets the byte-exact collation every text column needs. An index you do create gets a name derived from the real table name (`a.TableName(TableDevice) + "_user_idx"`), because Postgres index names are schema-global and two prefixed instances in one schema would otherwise collide. The migration's `Name` is a ledger key and never changes with the table's name.

<!-- ds:block id=devices-migrations-kn89f6ym -->
**Plugin.TypedMigrations** · [`examples/plugin-tables/devices/devices.go:217-229`](../../examples/plugin-tables/devices/devices.go#L217-L229)

```go
func (p *Plugin) TypedMigrations(engine string, t auth.SQLTypes) ([]auth.Migration, error) {
	if err := auth.CheckEngine(engine); err != nil {
		return nil, err
	}
	return []auth.Migration{{Owner: PluginName, Name: "0001_devices", Statements: []string{
		"CREATE TABLE IF NOT EXISTS " + p.a.TableName(TableDevice) + " (" +
			ColID + " " + t.ID + " NOT NULL PRIMARY KEY, " +
			ColUserID + " " + t.ID + " NOT NULL, " +
			ColName + " " + t.Text + " NOT NULL, " +
			ColCreatedAt + " " + t.Timestamp + " NOT NULL, " +
			"UNIQUE (" + ColUserID + ", " + ColName + "))" + t.TableSuffix,
	}}}, nil
}
```
<!-- /ds:block hash=89573b -->


Check: `go run ./plugin-tables auth migrate sql` prints the statement under `-- devices 0001_devices`. Run it against each engine you support, because the engine is what finds a wrong spelling; the integration suite in this repository is the model.

## Step 4 — Declare which rows belong to a user

There is no foreign key, so the core must be told which column of your table holds the user id. `UserTableOwner` is that declaration: `a.DeleteUser` deletes the rows whose column equals the user's id, in plugin order, before the identities, the tokens, the sessions and the user row, all in the one deleting transaction. A table with a user column that is not listed keeps its rows after the user is gone; the library's integration suite refuses such a table among its own plugins (`TestGuard_UserTablesAreDeleted` reads every table a migration creates and every registered user table), and a plugin in your own repository should carry the same check.

<!-- ds:block id=core-usertable-8kq2mw4n -->
**UserTable** · [`usertables.go:25-32`](../../usertables.go#L25-L32)

```go
type UserTable struct {
	// Table is one the plugin declares through TableOwner; New refuses one
	// it does not, because the registry would then name a table nobody
	// creates.
	Table sqlb.Table
	// Column holds the user id, as "user_id".
	Column string
}
```
<!-- /ds:block hash=6ac7fa -->

<!-- ds:block id=core-usertableowner-3nv9qx7m -->
**UserTableOwner** · [`usertables.go:42-44`](../../usertables.go#L42-L44)

```go
type UserTableOwner interface {
	UserTables() []UserTable
}
```
<!-- /ds:block hash=41dd5f -->

<!-- ds:block id=devices-usertables-2hq7kx9m -->
**Plugin.UserTables** · [`examples/plugin-tables/devices/devices.go:200-202`](../../examples/plugin-tables/devices/devices.go#L200-L202)

```go
func (p *Plugin) UserTables() []auth.UserTable {
	return []auth.UserTable{{Table: TableDevice, Column: ColUserID}}
}
```
<!-- /ds:block hash=594fa6 -->

`auth.New` refuses a `UserTable` naming a table the plugin does not return from `Tables`, a column that is not an identifier, or a pair listed twice (`auth.ErrBadUserTable`). A plugin with parent-child rows of its own (an organization and its members, say) deletes the children in Go too, in the operation that deletes the parent; nothing in the database does it.

Check: `a.UserTables()` lists `auth_device.user_id`, and the test that deletes a user finds no devices left.

## Step 5 — Apply it: the ledger

The core keeps a ledger, `auth_migrations`, with one row per `owner/name` and the checksum of the statements. `Auth.Migrate` applies every migration not in the ledger, in order — the core's, then each plugin's in list order — and stops with `auth.ErrChecksumMismatch` when a recorded migration's statements changed, because silently skipping or re-running it would both be wrong. One connection holds a lock for the whole run, so two instances starting at once do not race. On Postgres and SQLite each migration and its ledger row commit together; MySQL commits every DDL statement by itself, so a failure part-way leaves earlier statements applied and no row, and the error names the migration for the operator to repair.

The app decides when to migrate. The example migrates at start-up; a deployment that wants control hands the arguments to `authcli`, whose `migrate` command knows the app's plugin list:

```sh
myapp auth migrate --dry-run   # list what would be applied, change nothing
myapp auth migrate             # apply, and print each migration applied
myapp auth migrate sql         # every migration as SQL, for review or another tool
myapp auth migrate status      # applied, pending or CHANGED, per migration
myapp auth migrate orphans     # tables, columns and owners no registered plugin claims
```

```text
applied  core      0001_core_tables
applied  core      0003_session_lifetimes
applied  email     0000_identity_unique_email_verified
applied  email     0000_column_auth_user_primary_email
applied  email     0000_column_auth_user_email_verified_at
applied  password  0001_password
applied  devices   0001_devices
0 pending, 0 changed, 7 total
```

Check: a second `auth migrate` prints `nothing to apply`. Change one character of a statement and `status` shows the migration as `CHANGED`; put it back. A change to a table that already shipped is a new migration with a new name, never an edit.

## Step 6 — Write rows with Exec, read them with One and Each

Every statement a plugin runs goes through the core handle: `Exec` for writes, `One` for a read that expects one row, `Each` for a read over every row. All three take a sqlb builder, render it, and run it on the connection for `ctx` — the open transaction when there is one, so a write inside a mutation joins the mutation's transaction and a failure rolls everything back together.

<!-- ds:block id=core-statement-bkwcgy25 -->
**Statement** · [`tx.go:141-143`](../../tx.go#L141-L143)

```go
type Statement interface {
	Build() (sqlb.Query, error)
}
```
<!-- /ds:block hash=9108ec -->

<!-- ds:block id=core-exec-yaek8r9j -->
**Auth.Exec** · [`tx.go:168-182`](../../tx.go#L168-L182)

```go
func (a *Auth) Exec(ctx context.Context, s Statement) (int64, error) {
	c, q, err := a.prepare(ctx, s)
	if err != nil {
		return 0, err
	}
	ctx, end := a.dbSpan(ctx, q.SQL)
	res, err := c.ExecContext(ctx, q.SQL, q.Args...)
	if err != nil {
		end(err)
		return 0, err
	}
	n, err := res.RowsAffected()
	end(err)
	return n, err
}
```
<!-- /ds:block hash=737168 -->

<!-- ds:block id=core-one-gc295a2p -->
**Auth.One** · [`tx.go:189-199`](../../tx.go#L189-L199)

```go
func (a *Auth) One(ctx context.Context, s Statement) error {
	c, q, err := a.prepare(ctx, s)
	if err != nil {
		return err
	}
	ctx, end := a.dbSpan(ctx, q.SQL)
	err = sqlb.One(ctx, c, q)
	// No row is an answer, not a failed statement.
	end(ignoreNoRows(err))
	return err
}
```
<!-- /ds:block hash=c426a7 -->

<!-- ds:block id=core-each-h7cmxjbg -->
**Auth.Each** · [`tx.go:214-223`](../../tx.go#L214-L223)

```go
func (a *Auth) Each(ctx context.Context, s Statement, fn func() error) error {
	c, q, err := a.prepare(ctx, s)
	if err != nil {
		return err
	}
	ctx, end := a.dbSpan(ctx, q.SQL)
	err = sqlb.Each(ctx, c, q, fn)
	end(err)
	return err
}
```
<!-- /ds:block hash=72b98b -->

An app that writes rows of its own in the same transaction as a sign-up wraps the call in `Auth.Tx`; every library call made with the `ctx` it hands out joins that transaction, and effects and messages wait for its commit:

<!-- ds:block id=core-tx-7y49gnwg -->
**Auth.Tx** · [`tx.go:38-66`](../../tx.go#L38-L66)

```go
func (a *Auth) Tx(ctx context.Context, fn func(ctx context.Context, tx *sql.Tx) error) error {
	if st := txFrom(ctx); st != nil {
		return fn(ctx, st.tx)
	}
	if a.db == nil {
		return ErrNoDatabase
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("auth: begin transaction: %w", err)
	}
	st := &txState{tx: tx}
	txCtx := context.WithValue(ctx, txKey{}, st)
	defer st.runAfterEnd(ctx)
	if err := fn(txCtx, tx); err != nil {
		_ = tx.Rollback() // the fn error is the one worth reporting
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("auth: commit: %w", err)
	}
	st.mu.Lock()
	work := st.afterCommit
	st.mu.Unlock()
	for _, w := range work {
		w(ctx)
	}
	return nil
}
```
<!-- /ds:block hash=b245f8 -->

The add operation counts, inserts, and maps the unique constraint's refusal to its own error with `auth.IsUniqueViolation`, which knows each engine's duplicate-key error:

<!-- ds:block id=devices-doadd-9uz3f877 -->
**Plugin.doAdd** · [`examples/plugin-tables/devices/devices.go:266-292`](../../examples/plugin-tables/devices/devices.go#L266-L292)

```go
func (p *Plugin) doAdd(ctx context.Context, c *auth.Call, in AddRequest) (auth.Done, error) {
	n := utf8.RuneCountInString(in.Name)
	if n == 0 || n > MaxNameLength {
		return auth.Done{}, ErrNameInvalid
	}
	var have int64
	if err := p.a.One(ctx, p.a.Select().Columns(sqlb.Bind(sqlb.Count(), &have)).From(TableDevice).Where(sqlb.Eq(UserID, c.User.ID))); err != nil {
		return auth.Done{}, err
	}
	if have >= int64(p.max) {
		return auth.Done{}, ErrTooMany
	}
	id, err := p.a.NewID(IDPrefix)
	if err != nil {
		return auth.Done{}, err
	}
	_, err = p.a.Exec(ctx, sqlb.NewInsert(p.a.Dialect()).Into(TableDevice).Row(
		sqlb.Set(ID, id), sqlb.Set(UserID, c.User.ID), sqlb.Set(Name, in.Name), sqlb.Set(CreatedAt, p.a.Now()),
	))
	if auth.IsUniqueViolation(err) {
		return auth.Done{}, ErrNameTaken
	}
	if err != nil {
		return auth.Done{}, err
	}
	return auth.Done{OK: true}, nil
}
```
<!-- /ds:block hash=d380a8 -->

The list reads rows in a fixed order. Order by a timestamp alone is not fixed: rows created in one clock tick come back in a different order on MySQL than on SQLite, so a second column breaks the tie:

<!-- ds:block id=devices-dolist-z8ny3ckw -->
**Plugin.doList** · [`examples/plugin-tables/devices/devices.go:298-306`](../../examples/plugin-tables/devices/devices.go#L298-L306)

```go
func (p *Plugin) doList(ctx context.Context, c *auth.Call, _ struct{}) (ListResult, error) {
	var row Device
	out := ListResult{Devices: []Device{}}
	q := p.a.Select().Columns(Bindings(&row)...).From(TableDevice).
		Where(sqlb.Eq(UserID, c.User.ID)).
		Order(sqlb.OrderBy(CreatedAt, sqlb.SortAsc), sqlb.OrderBy(ID, sqlb.SortAsc))
	err := p.a.Each(ctx, q, func() error { out.Devices = append(out.Devices, row); return nil })
	return out, err
}
```
<!-- /ds:block hash=1a0959 -->

The remove operation puts the user id in the `WHERE`, which is what keeps deleting by id safe; `Exec` returns how many rows matched, so another user's id is a clean "not found":

<!-- ds:block id=devices-doremove-625naawv -->
**Plugin.doRemove** · [`examples/plugin-tables/devices/devices.go:312-321`](../../examples/plugin-tables/devices/devices.go#L312-L321)

```go
func (p *Plugin) doRemove(ctx context.Context, c *auth.Call, in RemoveRequest) (auth.Done, error) {
	n, err := p.a.Exec(ctx, sqlb.NewDelete(p.a.Dialect()).From(TableDevice).Where(sqlb.Eq(ID, in.ID), sqlb.Eq(UserID, c.User.ID)))
	if err != nil {
		return auth.Done{}, err
	}
	if n == 0 {
		return auth.Done{}, ErrNotFound
	}
	return auth.Done{OK: true}, nil
}
```
<!-- /ds:block hash=1df232 -->

`One` returns `sqlb.ErrNoRows` when there is no row; map it to your own not-found error at the call site. Core tables stay closed: a plugin changes a core row only through the core API (`CreateIdentity`, `SetUserColumn`, …), whatever runs the statement, and the library's own tests enforce that on its plugins' source.

Check: `go test ./plugin-tables/...` passes, and the test that deletes a user finds no devices left, through the `UserTables` declaration of step 4.

## Step 7 — Clean up with Sweeper

Rows that stop mattering — expired codes, finished invitations — are deleted by `Auth.Sweep`, which an app runs from a scheduled job or with `myapp auth sweep`. A plugin with such rows implements `Sweeper`; the core calls it with the cutoff and reports the count under the plugin's name next to its own tables.

<!-- ds:block id=core-sweeper-53n87sy4 -->
**Sweeper** · [`sweep.go:23-25`](../../sweep.go#L23-L25)

```go
type Sweeper interface {
	Sweep(ctx context.Context, cutoff time.Time) (int64, error)
}
```
<!-- /ds:block hash=90499e -->

The devices table has nothing that expires. The tickets plugin in [`examples/plugin-sweeper`](../../examples/plugin-sweeper/README.md) does: each row is a link that opens for [five minutes](ds:block?id=tickets-defaultttl-7kq2wm4n), and its `Sweep` is one `DELETE` on an indexed column, safe to run from several instances at once.

<!-- ds:block id=tickets-sweep-9mw4xq2k -->
**Plugin.Sweep** · [`examples/plugin-sweeper/tickets/tickets.go:214-216`](../../examples/plugin-sweeper/tickets/tickets.go#L214-L216)

```go
func (p *Plugin) Sweep(ctx context.Context, cutoff time.Time) (int64, error) {
	return p.a.Exec(ctx, sqlb.NewDelete(p.a.Dialect()).From(TableTicket).Where(sqlb.Less(ExpiresAt, cutoff)))
}
```
<!-- /ds:block hash=79d9f2 -->

`Auth.Sweep(ctx, retention)` passes now minus the retention ([a week](ds:block?id=defaultsweepretention-shqfpbr3) from `auth sweep`, which `--retention` changes), so a row stays a while after it stopped working, which helps support, and then goes. Sweeping is storage hygiene, never a security boundary: the plugin's own read must refuse an expired row whether or not a sweep has run, as the tickets plugin's redeem does. Index the column you sweep by. The sweep is otherwise a full table scan, from a job that runs every few minutes.

Try it:

```sh
go run ./plugin-sweeper auth sweep
```

```text
core.auth_code	0
core.auth_session	0
core.auth_verification	0
tickets	0
```

Check: `myapp auth sweep` prints one line per table it touched, the core's first, then each plugin's name, with the count deleted. `TestTickets_ExpireThenSweep` expires a ticket with a test clock, finds it refused before any sweep, swept once under `tickets`, and a second sweep finding nothing; `TestTickets_RetentionKeepsRecentlyExpired` checks the retention.

## What can go wrong

- `auth: engine not supported: "oracle"` — the dialect given to `auth.WithDB` is one the core has no DDL for. `auth.CheckEngine` returns the same error from your `Migrations`.
- `auth: plugin "devices" migrations: …` — your `Migrations` returned an error; the core wraps it with the plugin's name.
- `auth: plugin "devices" ships a migration owned by "core"` — every migration a plugin returns must have `Owner` equal to its own name.
- `auth: table alias conflicts with a registered alias: alias "dv" claimed by plugin "x" and by plugin "devices" (table auth_device)` — two plugins chose one alias; rename yours.
- `auth: a migration changed after it was applied: devices/0001_devices` — a statement was edited after it ran somewhere. Restore it and add a new migration for the change.
- `auth: migration devices/0001_devices: …` — a statement failed on the engine. On MySQL the earlier statements of that migration stayed applied; repair by hand before running again.
- `auth: plugin writes a column it does not own: "devices" writes "name"` — `auth.SetUserColumn` is for a plugin's own column on `auth_user`; a plugin table is written with `Exec`.
- `no such table: auth_device` under `auth.WithTablePrefix` or `auth.RenameTable` — a statement named the table by its constant instead of through the Auth. Build it with `sqlb` against `TableDevice`, or name it with `a.TableName(TableDevice)`.
- `auth: RenameTable names a table that no registered plugin or the core declares: "auth_device"` — the app renamed your table but did not list your plugin, or your plugin does not return the table from `Tables`.
- `auth: user table is not valid: plugin "devices" lists "auth_devices", which it does not declare in Tables` — `UserTables` names a table `Tables` does not return; use the same table value in both.
- Rows of a deleted user are still in your table — the table is not in `UserTables`. Add it; there is no foreign key to fall back on.
- `sqlb: update or delete has no WHERE; call All() to affect every row` — a delete or update without a condition is refused at render time, before it reaches the database.

## Next

- [Session rules](07-session-rules.md): conditions on every session, and a second factor.
- [Extend sessions](08-extend-sessions.md): where sessions live, a cache in front of them, and lifetimes per client.
