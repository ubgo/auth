# Databases

The library owns a few tables in your database and reaches them through `database/sql` and sqlb, with no ORM. This page explains the engines and drivers, the connection settings each needs, how to read and join the auth tables from your own code, and which columns you may rely on.

## Before you start

- [Configuration](configuration.md): `auth.WithDB(db, dialect)` is where the handle and the engine enter.
- Reads are open, writes are closed. Your app may `SELECT` and `JOIN` the auth tables freely; it must never `INSERT`, `UPDATE` or `DELETE` them, because the rules live in Go, not in the schema. Everything below is about reading.

## Step 1 — Choose an engine and a driver

Postgres, MySQL and SQLite are supported the same way; the library's own tests run every query on all three. Pass the handle and the matching sqlb dialect:

| Engine | Dialect | Driver the tests use | Open |
| --- | --- | --- | --- |
| Postgres | `sqlb.PostgresDialect{}` | `github.com/jackc/pgx/v5/stdlib` | `sql.Open("pgx", "postgres://user:pass@host:5432/db?sslmode=disable")` |
| MySQL | `sqlb.MySQLDialect{}` | `github.com/go-sql-driver/mysql` | see step 2 |
| SQLite | `sqlb.SQLiteDialect{}` | `modernc.org/sqlite` (pure Go) | `sql.Open("sqlite", sqliteDSN("app.db"))`, see step 2 |

The core module depends on sqlb and the standard library only, so the driver is yours to choose and import; the dialect tells the library how to render placeholders and quoting.

<!-- ds:block id=opt-withdb-6nvjnp2w -->
**WithDB** · [`auth.go:460-467`](../../auth.go#L460-L467)

```go
func WithDB(db *sql.DB, d sqlb.Dialect) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithDB", d) {
			return
		}
		s.db, s.cfg.Dialect = db, d
	}
}
```
<!-- /ds:block hash=e383a8 -->

### Detect the engine: WithDBAuto

Use this when the app is handed a `*sql.DB` and should not have to name the engine a second time, or when the same binary runs on SQLite in tests and Postgres in production. To pass the handle alone, as better-auth takes a pool and infers the dialect, use [`auth.WithDBAuto(db)`](ds:block?id=opt-withdbauto-7kq3nw8d): `auth.DetectDialect` names the engine from the driver's package (pgx, lib/pq, go-sql-driver/mysql and the three common SQLite drivers) at no cost, and through a wrapper that hides the driver (otelsql) by probe queries only one engine answers (`sqlite_version()`, `version()` naming PostgreSQL, `@@version`). A database that is none of the three fails `auth.New` with `auth.ErrUnknownDialect`; nothing is guessed. The probes are bounded by [`auth.DetectTimeout`](ds:block?id=core-detecttimeout-2wq8nd5k); use `auth.WithDB(db, dialect)` when `auth.New` must run no query at all. `examples/core-options` passes the handle alone:

<!-- ds:block id=coreoptions-p4ag7zqk -->
**coreOptions** · [`examples/core-options/main.go:142-150`](../../examples/core-options/main.go#L142-L150)

```go
func coreOptions(db *sql.DB) []auth.Option {
	return []auth.Option{
		auth.WithDBAuto(db),
		auth.WithBaseURL(baseURL),
		auth.WithIDs(newUUIDv7),
		auth.WithDisabledOperations(password.EndpointSignUp),
		auth.WithFetchMetadata(),
	}
}
```
<!-- /ds:block hash=a02430 -->

Check: `a.Engine()` returns `postgres`, `mysql` or `sqlite`, and `a.MigrationSQL()` prints DDL in that engine's spellings. `TestDBAuto` in `examples/core-options` gets `sqlite` from the modernc driver and `auth.ErrUnknownDialect` from a driver that refuses every probe.

## Step 2 — Connection settings each engine needs

**SQLite** needs two pragmas on every connection: WAL so readers do not block the writer, and a busy timeout instead of an immediate `database is locked`. No foreign-key pragma: the library creates no foreign keys (ADR-0002, below). Every example sets them in the query of the SQLite URI, and builds that URI with the path escaped, because a `#` or `?` in a file path would otherwise end the path and open a different file:

<!-- ds:block id=sqlitepragmas-t73gzsxj -->
**sqlitePragmas** · [`examples/quickstart/main.go:58`](../../examples/quickstart/main.go#L58-L58)

```go
"_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
```
<!-- /ds:block hash=e1bd47 -->

<!-- ds:block id=sqlitedsn-6k7zzy93 -->
**sqliteDSN** · [`examples/quickstart/main.go:68-70`](../../examples/quickstart/main.go#L68-L70)

```go
func sqliteDSN(path string) string {
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + sqlitePragmas
}
```
<!-- /ds:block hash=9ba25c -->

**MySQL** needs `parseTime=true` so timestamps scan into `time.Time`, `loc=UTC` so they are read in the zone they were written, and `clientFoundRows=true` so `RowsAffected` counts matched rows, as the other two engines do; the library's "did this statement match a row" checks assume that. With the standard driver's DSN:

```go
db, err := sql.Open("mysql", "user:pass@tcp(127.0.0.1:3306)/app?parseTime=true&loc=UTC&clientFoundRows=true")
```

The library creates its MySQL tables with `utf8mb4_bin`, so values compare byte for byte: MySQL's default collation would make `josé` equal `jose` and merge two identities into one.

**Postgres** needs nothing special. Timestamps are `TIMESTAMPTZ`; the library writes UTC everywhere. To keep the auth tables in a schema of their own, set `search_path` on the connection (`?search_path=auth` in the DSN, or `options=-c search_path=auth`) and create the schema first: every statement and the migration ledger name their tables unqualified on purpose, so one binary serves whatever schema the connection points at and your own queries join `auth_user` without a prefix. There is no schema-name option, because a qualified name would have to appear in every statement the app writes against the tables too.

Check: on SQLite, two concurrent sign-ups succeed instead of one failing with `database is locked`; on MySQL, a verify link works exactly once.

## Step 3 — Know the tables

| Table | Holds | Rows per user |
| --- | --- | --- |
| `auth_user` | the user: id, name, image, timestamps, `sessions_valid_after`, plus every column a plugin added | one |
| `auth_identity` | every identifier of every kind: value, verified_at, is_primary, scope_id | several |
| `auth_session` | live sessions by token hash, with expiry, device, lifetime | several |
| `auth_verification` | single-use tokens: links, OAuth states (empty under `auth.WithVerificationStore`, which keeps them in Redis or another key-value store; see [Configuration](configuration.md)) | many, swept |
| `auth_code` | one-time codes with attempt counts; `code_sealed` holds a reusable generated code, sealed (`CodeOptions.Reuse`) | few, swept |
| `auth_rate_limit` | counters, with `WithDBRateStore` | not per user |
| `auth_migrations` | the ledger of applied migrations | none |

Plugins add tables with the same prefix (`auth_password`, `auth_two_factor`, `auth_api_key`, …); each plugin's README documents them.

### No foreign keys: tables are plain storage

The library creates no foreign keys and no `ON DELETE CASCADE`, on any engine, in the core or any plugin (ADR-0002, 2026-10-03). A table can therefore live on another database, shard or schema without a constraint tying it to `auth_user`, SQLite needs no pragma for deletions to be complete, and what is removed when a user goes is written in Go, where tests see it. Every table whose rows belong to a user declares its user column to the core (`auth.UserTableOwner`; the core's own tables are registered the same way), and `a.DeleteUser` deletes those rows itself, in one transaction: the app's `BeforeDelete` hooks first, then every registered table in plugin order, the identities, the verification tokens and codes filed under the user or its identities, the sessions (through the session store, so Redis and memory stores end them too, then the SQL table), and last the user row. `a.UserTables()` lists what it clears. Check: [`TestGuard_NoForeignKeys`](ds:block?id=testguard-noforeignkeys-2v4neb3f&assert=true) reads every string literal in the core and plugin sources and fails on one that spells a foreign key or a cascade, naming the file.

<!-- ds:block id=core-deleteuser-6tq4nw8k -->
**Auth.DeleteUser** · [`store.go:137-159`](../../store.go#L137-L159)

```go
func (a *Auth) DeleteUser(ctx context.Context, id string) error {
	return a.endAlways(ctx, func(ctx context.Context, m hookMode) error {
		return a.Tx(ctx, func(ctx context.Context, tx sqlbTx) error {
			u, err := a.User(ctx, id)
			if err != nil {
				return err
			}
			if err := runHooks(ctx, a, tx, pickUser, stageBeforeDelete, nil, &u); err != nil {
				return err
			}
			if err := a.fireUserSessionsEnded(ctx, tx, m, id, "", SessionEndUserDeleted); err != nil {
				return err
			}
			if err := a.deleteUserRows(ctx, id); err != nil {
				return err
			}
			a.EvictCachedSessions(ctx, id)
			q := sqlb.NewDelete(a.cfg.Dialect).From(TableUser).Where(sqlb.Eq(UserID, id))
			_, err = a.Exec(ctx, q)
			return err
		})
	})
}
```
<!-- /ds:block hash=9275ad -->

<!-- ds:block id=core-usertables-5pw8kq2t -->
**Auth.UserTables** · [`usertables.go:97-101`](../../usertables.go#L97-L101)

```go
func (a *Auth) UserTables() []UserTable {
	out := make([]UserTable, 0, len(a.userTables)+len(coreUserTables))
	out = append(out, a.userTables...)
	return append(out, coreUserTables...)
}
```
<!-- /ds:block hash=075475 -->

Your own tables that hold a user id are yours to clean: a `User.BeforeDelete` data hook runs inside the same transaction (`auth.WithDataHooks`), and `examples/admin-plan`, `examples/saas-workspace` and `examples/guest-sessions` show it. Integrity is the library's writes ("reads are open, writes are closed"): an app that deletes from the auth tables directly gets no database-level protection, which is the same as before, since the cascade only ever helped a delete the library made.

### Renaming the tables

The names above are the tables' *labels*: what the Go constants hold (`auth.TableNameUser`) and what this documentation calls them. Their *real* names, what the database sees, are yours to choose per `auth.New`, and the two ways compose:

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.PostgresDialect{}),
	auth.WithTablePrefix("billing_"),                 // every table: billing_auth_user, billing_auth_session, billing_auth_api_key, …
	auth.RenameTable(auth.TableUser, "members"),     // except this one, named exactly as given
	auth.RenameTable(apikey.TableKey, "api_keys"),   // a plugin's table, through its exported Table value
	auth.WithPlugins(email.New(email.Login(), email.Recover()), password.New(), apikey.New(apikey.Scopes("read"))),
)
```

<!-- ds:block id=opt-withtableprefix-4mv8xq7c -->
**WithTablePrefix** · [`tables.go:86-88`](../../tables.go#L86-L88)

```go
func WithTablePrefix(prefix string) Option {
	return func(s *settings) { s.tablePrefix = prefix }
}
```
<!-- /ds:block hash=b735ec -->

<!-- ds:block id=opt-renametable-7r3tqk2d -->
**RenameTable** · [`tables.go:74-76`](../../tables.go#L74-L76)

```go
func RenameTable(t sqlb.Table, realName string) Option {
	return func(s *settings) { s.tableRenames = append(s.tableRenames, tableRename{table: t, real: realName}) }
}
```
<!-- /ds:block hash=842c0f -->

`WithTablePrefix` prepends to every table the core and the registered plugins declare, the migration ledger and the rate-limit table included; `RenameTable` names one table and takes it out of the prefix. The table argument is a declared table value, never a string: a hand-built `sqlb.Table{Name: "x"}`, or a plugin's table whose plugin is not in `WithPlugins`, fails `auth.New` with `auth.ErrUnknownTable`, so a rename cannot sit in the configuration doing nothing. `auth.New` also refuses two tables mapped to one real name or a name another table already has (`auth.ErrTableNameConflict`), a name or prefix that is not a plain identifier or that makes a derived index name longer than 63 bytes (`auth.ErrBadTableName`), and, under renaming, a column named exactly like a table label, because the renderer could not tell them apart.

Everything that names a table follows: every statement the library renders, every `CREATE TABLE`, `ALTER TABLE` and index (`billing_auth_identity_user_idx`), the ledger, `a.CheckSchema`, `a.Orphans` and the `auth migrate` commands. Only the names change: columns keep theirs, and the migration names in the ledger (`0000_column_auth_user_primary_email`) and the `Sweep` result keys (`core.auth_session`) keep the labels, so an app that reads them sees the same keys in every deployment.

**Decide before the first deploy.** The ledger records which migrations ran, not what the tables were called, so changing a prefix or a rename on a database that exists makes `a.CheckSchema` report every table as missing and `Migrate` create a second set. Renaming later is an `ALTER TABLE old RENAME TO new` per table (and per index on Postgres), run by you, before the new configuration starts.

**SQL you write by hand** names a table through `a.TableName`, which returns the real name of any declared table and leaves an undeclared one (your own) unchanged:

<!-- ds:block id=core-tablename-9nq2wv5h -->
**Auth.TableName** · [`tables.go:104`](../../tables.go#L104-L104)

```go
func (a *Auth) TableName(t sqlb.Table) string { return a.realTableName(t.Name) }
```
<!-- /ds:block hash=4603cf -->

```go
row := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+a.TableName(auth.TableUser))
```

A statement built with `a.Select()`, `a.Exec`, `a.One` or `a.Each` needs nothing: the dialect those render through writes the real names. The Go API, the HTTP routes and the JSON they return are the same whatever the tables are called.

Check: `a.TableName(auth.TableUser)` returns `members` in the example above, `a.MigrationSQL()` names no `auth_user`, and `auth migrate orphans` lists nothing once migrated.

The types are the same few on every engine, spelled per engine by `auth.TypesFor`:

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

### Column types per engine: WithSQLTypes

Use this when a column type the library picks does not match your schema: native `UUID` ids on Postgres to join your own UUID keys, a wider text type on MySQL, or a spelling a compatible engine prefers. To change a spelling, pass [`auth.WithSQLTypes(engine, types)`](ds:block?id=opt-withsqltypes-8pz4qm2k) with only the fields you want different: `auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{ID: "UUID"})` for native UUID ids, a wider `Long` on MySQL, or a spelling a compatible engine prefers (CockroachDB as Postgres, MariaDB as MySQL, libSQL as SQLite). Empty fields keep the built-in spelling; [`a.SQLTypes()`](ds:block?id=core-auth-sqltypes-3hq7vn5x) returns the result. Every table the core writes follows it, the migrations ledger included, and so does every plugin that implements [`auth.TypedMigrator`](ds:block?id=core-typedmigrator-5rk8wd3n), whose `TypedMigrations(engine, types)` is handed the merged types. Every built-in plugin that creates tables implements it. A third-party plugin that still writes DDL through `Migrator` and `auth.TypesFor` would keep the built-in types beside core tables that changed, and a UUID user id joined to a TEXT one fails on Postgres, so `auth.New` refuses the override for the app's engine while such a plugin is registered, naming it. `ID` types only the columns that hold a generated row id or refer to one (every generated primary key, `user_id`, `session_id`, an organization's or team's id); `Key` types the other short indexed text (an identity's kind, a verification's purpose, statuses, slugs, a provider's subject or client id), so `UUID` belongs on `ID`, never on `Key`, which must hold `"email"`. An override that sets `Key` and not `ID` changes both, as it did before `ID` existed. A few id columns stay `Key` because they store `""` for "none" (the audit log's actor, subject and session, an SSO provider's organization and owner), so compare them to a UUID id as text. The override must still hold what the library writes: an id column typed `UUID` needs `auth.WithIDs` to generate UUIDs. By default `ID` is spelled exactly as `Key` on every engine, so a schema created before `ID` existed migrates unchanged.

It does not add a fourth engine. The upserts, the unique-violation check and the index statements are written per engine, and sqlb renders only the three dialects, so `auth.WithSQLTypes("sqlserver", …)` fails `auth.New` with `auth.ErrEngineNotSupported`.

`examples/core-options` gives Postgres native UUID ids, generated by its [own id function](configuration.md#your-own-ids-withids), and renders the migrations without a database, because `auth.WithDialect` names the engine and [`a.MigrationSQL()`](ds:block?id=core-migrationsql-8w4m33nv) only renders:

<!-- ds:block id=postgrestypes-6wq9xn3d -->
**postgresTypes** · [`examples/core-options/main.go:201`](../../examples/core-options/main.go#L201-L201)

```go
var postgresTypes = auth.SQLTypes{ID: "UUID"}
```
<!-- /ds:block hash=03bdae -->

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

Try it:

```sh
go run ./core-options sql | grep -E 'TABLE IF NOT EXISTS auth_(user|password) '
```

```sql
CREATE TABLE IF NOT EXISTS auth_user (id UUID NOT NULL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_password (user_id UUID NOT NULL PRIMARY KEY, hash TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
```

Without the override the same column is `id TEXT`. The password plugin's table follows because it implements [`auth.TypedMigrator`](ds:block?id=core-typedmigrator-5rk8wd3n) and writes `t.ID` for its user id; a plugin that writes a literal type keeps it. The override must still store what the core writes, so an id column typed `UUID` needs `WithIDs` to generate UUIDs. Set the types before the first migration: a migration's checksum covers its rendered statements, so changing a type on a database that already ran them stops the next `Migrate` with [`auth.ErrChecksumMismatch`](ds:block?id=core-errchecksum-brj9fryp), and altering the column is then a migration of your own. Check: `TestSQLTypes` in `examples/core-options` finds `UUID` with the override, `TEXT` without, and `auth.ErrEngineNotSupported` for `"sqlserver"`.

Check: `select owner, name from auth_migrations` lists who created what.

## Step 4 — Load the composite user in one statement

Your app has one user struct: the core's columns and each plugin's columns on `auth_user`, all flat, loaded in one statement. Embed `auth.User` and the plugins' column structs, make it an `auth.Scannable` with a `Bindings` method, and `a.LoadUser` fills it:

<!-- ds:block id=appuser-yeztggtk -->
**appUser** · [`examples/custom-plugin/main.go:121-125`](../../examples/custom-plugin/main.go#L121-L125)

```go
type appUser struct {
	auth.User
	email.EmailColumns
	referral.ReferralColumns
}
```
<!-- /ds:block hash=e7875a -->

<!-- ds:block id=appuser-bindings-rwjrxxbw -->
**appUser.Bindings** · [`examples/custom-plugin/main.go:130-132`](../../examples/custom-plugin/main.go#L130-L132)

```go
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), email.Bindings(&u.EmailColumns), referral.Bindings(&u.ReferralColumns))
}
```
<!-- /ds:block hash=e65fd4 -->

<!-- ds:block id=core-scannable-ub3d9d7d -->
**Scannable** · [`columns.go:166-168`](../../columns.go#L166-L168)

```go
type Scannable interface {
	Bindings() []sqlb.Binding
}
```
<!-- /ds:block hash=c250bc -->

<!-- ds:block id=core-joiner-27twn9va -->
**Joiner** · [`columns.go:174-176`](../../columns.go#L174-L176)

```go
type Joiner interface {
	Joins() []sqlb.Join
}
```
<!-- /ds:block hash=73e369 -->

<!-- ds:block id=core-loaduser-j69m8w4a -->
**Auth.LoadUser** · [`columns.go:182-188`](../../columns.go#L182-L188)

```go
func (a *Auth) LoadUser(ctx context.Context, id string, dst Scannable) error {
	var joins []sqlb.Join
	if j, ok := dst.(Joiner); ok {
		joins = j.Joins()
	}
	return a.loadUser(ctx, id, dst.Bindings(), joins...)
}
```
<!-- /ds:block hash=221f29 -->

<!-- ds:block id=core-userbindings-cw7gf4c3 -->
**UserBindings** · [`schema.go:107-116`](../../schema.go#L107-L116)

```go
func UserBindings(dst *User) []sqlb.Binding {
	return []sqlb.Binding{
		sqlb.Bind(UserID, &dst.ID),
		sqlb.Bind(UserName, &dst.Name),
		sqlb.Bind(UserImage, &dst.Image),
		sqlb.Bind(UserCreatedAt, &dst.CreatedAt),
		sqlb.Bind(UserUpdatedAt, &dst.UpdatedAt),
		sqlb.Bind(UserSessionsValidAfter, &dst.SessionsValidAfter),
	}
}
```
<!-- /ds:block hash=095cc7 -->

<!-- ds:block id=mehandler-brfx2pez -->
**meHandler** · [`examples/custom-plugin/main.go:145-155`](../../examples/custom-plugin/main.go#L145-L155)

```go
func meHandler(a *auth.Auth) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u appUser
		if err := a.LoadUser(r.Context(), authhttp.MustUser(r).ID, &u); err != nil {
			authhttp.WriteError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meResponse{ID: u.ID, PrimaryEmail: u.PrimaryEmail, ReferralCode: u.ReferralCode}) // a client that hung up cannot be told
	})
}
```
<!-- /ds:block hash=0135e6 -->

Data that lives in a plugin's own table joins through `auth.Joiner`; the phone example adds the number from the identity table this way:

<!-- ds:block id=appuser-joins-zpjfxhmt -->
**appUser.Joins** · [`examples/phone-only/main.go:135`](../../examples/phone-only/main.go#L135-L135)

```go
func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{phone.UserJoin()} }
```
<!-- /ds:block hash=e37f18 -->

The shape follows the schema: a column on `auth_user` is a flat field, anything reached by a join is a nested struct. That is a decision, not an accident: the struct tells you what one statement costs.

Check: `/me` in `examples/custom-plugin` answers the user with the plugin's `referralCode` and no second query.

## Step 5 — Query and join the auth tables yourself

The typed columns are exported — `auth.UserID`, `auth.UserCreatedAt`, `auth.IdentityValue`, `auth.SessionExpiresAt` — and `a.Select()` starts a statement in the configured dialect. A column carries the Go type it holds, so `sqlb.Eq(auth.UserCreatedAt, "yesterday")` does not compile. Join your own tables to `auth_user` on `auth.UserID`; `examples/admin-plan` lists users joined to the app's plan and project tables.

```go
var u auth.User
var plan string
q := a.Select().
	Columns(sqlb.Bindings(auth.UserBindings(&u), []sqlb.Binding{sqlb.Bind(planName, &plan)})...).
	From(auth.TableUser).
	Join(sqlb.Join{Type: sqlb.JoinLeft, Table: planTable, On: []sqlb.Predicate{sqlb.EqExpr(planUserID, auth.UserID)}}).
	Where(sqlb.Eq(auth.UserID, id)).Limit(1)
err := a.One(ctx, q)
```

Plain SQL works too: the column names are constants (`auth.ColUserID`, …) and the table name comes from `a.TableName(auth.TableUser)`, which is the real name under `auth.WithTablePrefix` or `auth.RenameTable` and the label otherwise, so a typo is a compile error and a renamed table is still found.

Check: `a.One` returns `sqlb.ErrNoRows` for no row; map it to your own not-found.

## Step 6 — Rely only on the stable columns

These columns are a contract within a major version; a test in the library reads its own `CREATE TABLE` statements and fails if one disappears. Anything else — an index, a flag the library uses internally — may change.

| Table | Stable columns |
| --- | --- |
| `auth_user` | `id`, `name`, `image`, `created_at`, `updated_at` |
| `auth_identity` | `id`, `user_id`, `kind`, `value`, `value_raw`, `verified_at`, `is_primary`, `scope_id`, `created_at` |
| `auth_session` | `id`, `user_id`, `expires_at`, `last_seen_at`, `ip`, `user_agent`, `created_at`, `second_factor_pending`, `impersonated_by` |

Query a plugin's tables through that plugin's exported sqlb column handles (for example `apikey.KeyName`), not through raw SQL strings: a renamed column then keeps working, and a removed one is a compile error at upgrade instead of a failure in production. Raw SQL against auth tables is the app's own risk across versions. The stable-column list above stays limited to the three core tables.

<!-- ds:block id=core-coreusercolumns-x6whdeje -->
**CoreUserColumns** · [`constants.go:58`](../../constants.go#L58-L58)

```go
var CoreUserColumns = []string{ColUserID, ColUserName, ColUserImage, ColUserCreatedAt, ColUserUpdatedAt, ColUserSessionsValidAfter}
```
<!-- /ds:block hash=1da8d3 -->

<!-- ds:block id=core-user-dxupgphj -->
**User** · [`types.go:15-33`](../../types.go#L15-L33)

```go
type User struct {
	// ID is the stable public identifier, and the foreign-key target for plugin
	// tables and app tables alike. It is opaque: nothing may parse it.
	ID string

	// Name and Image are display fields, set at sign-up or imported from a
	// social provider. Both may be empty.
	Name  string
	Image string

	CreatedAt time.Time
	UpdatedAt time.Time

	// SessionsValidAfter is set by DeleteUserSessions with no exception
	// ("sign out everywhere"): a session created before it is refused in
	// every session mode, which is what revokes stateless sessions, whose
	// tokens the server never stored. Nil until the first such call.
	SessionsValidAfter *time.Time
}
```
<!-- /ds:block hash=946114 -->

Ids are opaque strings, `usr_` and 24 base32 characters by default: index them, join on them, never parse them. Timestamps are UTC.

Check: `auth.UserBindings` binds exactly the stable user columns plus `sessions_valid_after`.

## What can go wrong

- `database is locked` on SQLite — `_pragma=busy_timeout` is missing from the DSN, or two processes share the file without WAL.
- `sql: Scan error … unsupported Scan, storing driver.Value type []uint8 into type *time.Time` on MySQL — `parseTime=true` is missing.
- A refused call on MySQL where the row was in fact matched — `clientFoundRows=true` is missing, so `RowsAffected` counts changed rows rather than matched ones. Set it.
- `auth: engine not supported: "…"` — the dialect is not one of the three. There is no adapter layer to add a fourth: the invariants (one uniqueness policy over `auth_identity`, a verification token spent by the database, `RowsAffected` meaning "matched") are SQL and Go together, and a document store or an ORM could not carry them unchanged. Column types can be overridden for the three engines (`auth.WithSQLTypes`, step 3). What is pluggable is where the short-lived records live: `auth.SessionStore`, `auth.SessionCache` and `auth.RateStore`, each with a Redis implementation in `contrib/redis`. A Postgres-, MySQL- or SQLite-compatible service (Neon, Supabase, PlanetScale, Turso, TiDB) works through its dialect.
- Two identities that should be one on MySQL — the table was created without `utf8mb4_bin`, by hand rather than by `Migrate`.
- A plugin table without its user — your app deleted the user with `DELETE FROM auth_user`; use `a.DeleteUser`, which runs the data hooks and deletes every registered user table, the core rows and the user in one transaction. There is no cascade to catch a direct delete.

## Next

- [Migrations and maintenance](migrations-and-maintenance.md): creating and upgrading these tables.
- [Transactions](transactions.md): writing your rows next to the library's.
