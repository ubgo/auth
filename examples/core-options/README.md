# Core options: switch operations off, detect the dialect, own the ids, retype columns, check Sec-Fetch-Site

Five options of `auth.New` that change how the core behaves rather than which plugins it runs, in one invite-only app:

- `auth.WithDisabledOperations(password.EndpointSignUp)` switches password sign-up off. Nobody can create an account; the app creates them itself.
- `auth.WithDBAuto(db)` names the SQL dialect from the driver, so the app passes the `*sql.DB` alone.
- `auth.WithIDs(newUUIDv7)` makes every user, identity and session id a UUIDv7 from the app's own generator.
- `auth.WithSQLTypes(auth.EnginePostgres, auth.SQLTypes{ID: "UUID"})` gives those ids the native `UUID` column type on Postgres.
- `auth.WithFetchMetadata()` refuses a sign-in that the browser marks `Sec-Fetch-Site: cross-site` from an untrusted origin, which closes login CSRF.

## Run it

```sh
cd examples
PORT=8098 go run ./core-options
```

It creates `core-options.db` (SQLite) in the current directory, creates the tables, creates the demo account `alice@example.com`, and listens on the port (8081 without `PORT`). The log names the engine `WithDBAuto` found:

```text
2026/10/09 08:56:29 listening on http://localhost:8098 (engine sqlite)
```

Run the tests with `go test ./core-options`.

## Walkthrough

Sign-up is switched off. The route answers like a path that does not exist:

```sh
curl -s -i -X POST localhost:8098/auth/password/sign-up -H 'Origin: http://localhost:8098' \
  -d '{"identifier":"bob@example.com","password":"another long password"}'
```

```text
HTTP/1.1 404 Not Found
{"error":{"code":"auth.unknown_operation","message":"Not found."}}
```

A sign-in from another site, as a hidden form on an attacker's page would send it, is refused although it carries no cookie yet. The browser sets `Sec-Fetch-Site` and no script can change it:

```sh
curl -s -i -X POST localhost:8098/auth/password/sign-in -H 'Origin: https://evil.example' -H 'Sec-Fetch-Site: cross-site' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```text
HTTP/1.1 403 Forbidden
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

The same sign-in from the app's own page passes, and the user id comes from the app's generator, a UUIDv7:

```sh
curl -s -c cookies.txt -X POST localhost:8098/auth/password/sign-in -H 'Origin: http://localhost:8098' -H 'Sec-Fetch-Site: same-origin' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8098/me
```

```json
{"user":{"id":"01a11eb2-af40-7c96-b9d8-c359961a046c","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"01a11eb2-af40-7c96-b9d8-c359961a046c"}
```

A client that sends no `Sec-Fetch-Site` (curl, a native app, an old browser) is unaffected, even with a foreign `Origin`, because the check only acts on what a browser declares:

```sh
curl -s -X POST localhost:8098/auth/password/sign-in -H 'Origin: https://evil.example' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"user":{"id":"01a11eb2-af40-7c96-b9d8-c359961a046c","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The Postgres migrations with the UUID type, rendered without a database:

```sh
go run ./core-options sql | grep -E 'TABLE IF NOT EXISTS auth_(user|password) '
```

```sql
CREATE TABLE IF NOT EXISTS auth_user (id UUID NOT NULL PRIMARY KEY, name TEXT NOT NULL DEFAULT '', image TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
CREATE TABLE IF NOT EXISTS auth_password (user_id UUID NOT NULL PRIMARY KEY, hash TEXT NOT NULL, updated_at TIMESTAMPTZ NOT NULL);
```

Without the override the same column is `id TEXT`. The password plugin's table follows because it implements `auth.TypedMigrator`.

## The code

The options, in `coreOptions`:

```go
auth.WithDBAuto(db),
auth.WithBaseURL(baseURL),
auth.WithIDs(newUUIDv7),
auth.WithDisabledOperations(password.EndpointSignUp),
auth.WithFetchMetadata(),
```

`newUUIDv7` is a dozen lines of `crypto/rand` and `time`: a 48-bit millisecond timestamp, then random bits, with the version and variant set (RFC 9562). It ignores the prefix the core passes (`usr`, `ses`, `idn`), because a `UUID` column stores nothing else. An error it returns fails the write that asked for the id.

With sign-up off, the app creates accounts itself, in one transaction: `a.CreateUser`, `a.CreateIdentity` with `Verified: true`, and the password plugin's `SetPassword`. `ensureAccount` treats `auth.ErrIdentityTaken` as "already there", so the program can restart on the same database.

`postgresMigrationSQL` builds a second `Auth` with `auth.WithDialect(sqlb.PostgresDialect{})` and `auth.WithSQLTypes`, and calls `a.MigrationSQL()`; no Postgres server is needed to read the DDL.

## What auth.New refuses

- `auth.WithDisabledOperations("password.signup")`, a misspelled id: `auth.ErrUnknownHookTarget`. Use the plugin's `Endpoint…` constant; a typo would otherwise leave the operation served.
- `auth.WithDBAuto(db)` on a database that is none of Postgres, MySQL and SQLite: `auth.ErrUnknownDialect`. A driver the library does not know by type is probed with up to three queries, bounded by `auth.DetectTimeout`; use `auth.WithDB(db, dialect)` when `auth.New` must run no query.
- `auth.WithSQLTypes("sqlserver", …)`: `auth.ErrEngineNotSupported`. It retypes columns, it does not add an engine.

From Go, the disabled operation's method (`passwords.SignUp`) returns `auth.ErrUnknownOperation`, the same refusal the route gives.

`main_test.go` runs `newApp` and `newHandler` behind an `httptest` TLS server on a temporary SQLite file and checks each behaviour above, plus the contrast: an `Auth` without `WithFetchMetadata` lets the cross-site sign-in through.

## What this used

- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithDisabledOperations`, `WithDBAuto`, `WithIDs`, `WithSQLTypes`, `SQLTypes`, `WithFetchMetadata`, `WithDialect`, `MigrationSQL`, `CreateUser`, `CreateIdentity`, `Tx`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): `EndpointSignUp`, `SetPassword`
- Related: [invite-only](../invite-only) lets invited people sign up; [behind-proxy](../behind-proxy) covers client addresses and origins behind a proxy; [plugin-tables](../plugin-tables) writes a plugin's own typed migrations.
