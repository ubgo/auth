# Choose a database and storage

This guide answers: which database, and which of the library's state should live somewhere other than that database? Users, identities and the rules that protect them always live in SQL (Postgres, MySQL or SQLite), because the invariants (one uniqueness policy over `auth_identity`, a verification token spent by the database, `RowsAffected` meaning "matched") are SQL and Go together. Around them, four kinds of state can move: sessions, rate counters, verification tokens and outgoing messages. The library's own tests run every query on all three engines.

## The database

| Situation | Choose | Why | Guide | Example |
|---|---|---|---|---|
| A new product with a server | Postgres (`sqlb.PostgresDialect{}`, driver `pgx`) | Needs nothing special; partial unique indexes and `TIMESTAMPTZ` | [Databases › Step 1](../concepts/databases.md#step-1--choose-an-engine-and-a-driver) | [core-options](../../examples/core-options/) (renders the Postgres DDL) |
| Your company runs MySQL | MySQL (`sqlb.MySQLDialect{}`) | Supported the same way; the tables are `utf8mb4_bin` so values compare byte for byte | [Databases › Step 2](../concepts/databases.md#step-2--connection-settings-each-engine-needs) | — |
| One machine, a desktop app, tests, a prototype | SQLite (`sqlb.SQLiteDialect{}`, `modernc.org/sqlite`, pure Go) | No server to run; every example uses it | [Databases › Step 2](../concepts/databases.md#step-2--connection-settings-each-engine-needs) | [quickstart](../../examples/quickstart/) |
| You would rather not name the dialect | `auth.WithDBAuto(db)` | `auth.New` detects the engine from the driver, or with a query; fails with `ErrUnknownDialect` on anything else | [Detect the engine](../concepts/databases.md#detect-the-engine-withdbauto) | [core-options](../../examples/core-options/) |
| The auth tables must not collide with yours | `auth.WithTablePrefix("billing_")` | Every table renamed; plugins follow | [Renaming the tables](../concepts/databases.md#renaming-the-tables) | [plugin-tables](../../examples/plugin-tables/) |
| Your schema uses native UUIDs or other column types | `auth.WithSQLTypes(engine, types)` with `auth.WithIDs` | Ids typed `UUID` on Postgres, a wider text type on MySQL; every built-in plugin follows | [Column types per engine](../concepts/databases.md#column-types-per-engine-withsqltypes) | [core-options](../../examples/core-options/) |
| You want ids of your own shape (UUIDv7, ULID) | `auth.WithIDs(fn)` | Every generated id comes from your function | [Your own ids](../concepts/configuration.md#your-own-ids-withids) | [core-options](../../examples/core-options/) |
| Secrets at rest must be sealed by a KMS or HSM | `auth.WithSealer(s)` | OAuth tokens, TOTP secrets and recovery codes are sealed by your key service | [Keys in a KMS](../concepts/security.md#keys-in-a-kms-the-sealer) | — |

A document store or a fourth SQL engine is not supported, and there is no adapter layer to add one: `auth.WithSQLTypes("sqlserver", …)` fails `auth.New` with `auth.ErrEngineNotSupported`.

## What can live outside the database

| State | Default | Alternatives | When to move it | Guide | Example |
|---|---|---|---|---|---|
| Sessions | `auth_session` | Redis, any key-value store, memory, stateless, your own | See [Choose a session strategy](sessions.md) | [Sessions › Step 6](../concepts/sessions.md#step-6--where-sessions-live-the-modes) | [session-strategies](../../examples/session-strategies/) |
| Rate counters | This process's memory | `auth.WithDBRateStore()`, `auth.WithRateStore(redis…)`, secondary storage | As soon as there is a second instance: each instance otherwise counts alone, and an attacker gets every instance's budget | [Rate limits › Step 3](../concepts/rate-limits.md#step-3--choose-where-the-counters-live) | [multi-instance](../../examples/multi-instance/) |
| Verification tokens (links, codes, OAuth state, passkey ceremonies) | `auth_verification` | `auth.WithVerificationStore`: `NewStorageVerificationStore` over a key-value store, contrib/redis, memory, your own checked by `verificationtest` | When the database should see no token traffic; the store joins no transaction | [Keep verification tokens elsewhere](../concepts/configuration.md#keep-verification-tokens-elsewhere-withverificationstore) | [delivery-outbox](../../examples/delivery-outbox/) |
| Outgoing mail and SMS | Sent after the commit, in the background; lost if the process dies first | `auth.WithDeliveryOutbox()`: the message is written, sealed, in the same transaction, and `a.SendOutbox` retries it | When a lost verification or reset message is a support ticket | [Survive a crash or a failing mailer](../concepts/identifiers-and-verification.md#survive-a-crash-or-a-failing-mailer-withdeliveryoutbox) | [delivery-outbox](../../examples/delivery-outbox/) |
| Background work | One goroutine per message | `auth.WithBackground(run)`: your worker pool or a serverless `waitUntil` | When a bare goroutine is wrong for your runtime | [Run deliveries on your own workers](../concepts/identifiers-and-verification.md#run-deliveries-on-your-own-workers-withbackground) | [delivery-outbox](../../examples/delivery-outbox/) |
| Sessions and counters together | — | `auth.WithSecondaryStorage(kv)`: four methods (`Get`, `Set` with a TTL, `Delete`, an atomic `Increment`) | You already run a key-value store and want one option | [Secondary storage](../concepts/sessions.md#keep-sessions-in-any-key-value-store-withsecondarystorage) | [session-tuning](../../examples/session-tuning/) |

## If X, then Y

- If you run more than one instance, move the rate counters first (`auth.WithDBRateStore()` needs no new service); the first counted call logs a warning until you do.
- If you deploy several instances, run migrations from the deploy (`myapp auth migrate`), not from every server at start-up ([production › Step 3](../start/production.md#step-3--migrate-from-the-deploy-not-from-the-server), [cli](../../examples/cli/)).
- If you read auth tables in your own queries, read freely and join them, but never `INSERT`, `UPDATE` or `DELETE` them: the invariants live in Go. Delete a user with `a.DeleteUser`, which also deletes every plugin's rows ([Databases › Step 5](../concepts/databases.md#step-5--query-and-join-the-auth-tables-yourself), [admin-plan](../../examples/admin-plan/)).
- If you need your rows and the library's in one transaction (create the workspace with the user), use `a.Tx` ([Transactions](../concepts/transactions.md#step-2--write-your-rows-next-to-the-librarys), [saas-workspace](../../examples/saas-workspace/)).
- If you move verification tokens to a key-value store, accept that a token spent by a call that then fails stays spent, and the user asks for a new link.
- If you turn on the outbox, schedule `a.SendOutbox` (or `myapp auth sweep`): nothing retries on its own, because the library runs nothing in the background.
- If tables must live in their own Postgres schema, set `search_path` on the connection and create the schema first.

## Pitfalls

- `database is locked` on SQLite: the busy-timeout pragma is missing from the DSN, or two processes share the file without WAL.
- A scan error into `time.Time` on MySQL: `parseTime=true` is missing. A refused call where the row matched: `clientFoundRows=true` is missing.
- Two identities that should be one on MySQL: the table was created by hand without `utf8mb4_bin`, not by `Migrate`.
- A plugin's rows left without their user: the app ran `DELETE FROM auth_user`. There are no foreign keys and no cascade by design ([No foreign keys](../concepts/databases.md#no-foreign-keys-tables-are-plain-storage)).
- `WithRateStore and WithDBRateStore both set` from `auth.New`: keep one.
- An unreachable rate store fails closed: every counted request answers 500 until it is back, because a failure must never read as "under the limit".
- `auth.WithDeliveryOutbox` without a database or a key is refused at `auth.New`; the key is derived from `auth.WithSecret` when none is passed.

## Next

- [Choose a session strategy](sessions.md)
- [Choose by kind of app](app-types.md)
