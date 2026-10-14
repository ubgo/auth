# Install

You will have the library and the plugins you need in your module, a database driver, and the two lines that tell you the whole thing compiles.

## Before you start

- Go 1.24 or later for the core module; the framework adapters (`contrib/gin`, `contrib/echo`, `contrib/fiber`, `contrib/gqlgen`), `contrib/redis`, `contrib/phonenumbers`, `contrib/goth`, `plugin/passkey` and `plugin/sso` need Go 1.25 (a dependency of each declares it); `task gomin` vets every module under the version its go.mod declares.
- A database: Postgres, MySQL 8 or SQLite. The library writes SQL for each engine itself and is tested on all three; SQLite through a pure-Go driver needs no server, which is what the examples use.
- The library is pre-release. The API can still change between versions; pin the version you install.

## Step 1 — Add the core and the plugins you use

The core module holds the users, sessions, identifiers, the HTTP transport (`authhttp`), the command line (`authcli`) and every plugin that needs only the standard library. A plugin that brings a third-party dependency is its own module, so an app pays for a dependency only when it imports the package; so is a feature that is not authentication, such as organizations.

```sh
go get github.com/ubgo/auth github.com/ubgo/auth/plugin/password
```

| You want | Add |
|---|---|
| Email, phone or username identifiers; magic links; two-factor codes; API keys; JWTs; admin; terms | nothing more: they are in `github.com/ubgo/auth` |
| Passwords | `github.com/ubgo/auth/plugin/password` (argon2id from `golang.org/x/crypto`) |
| Passkeys | `github.com/ubgo/auth/plugin/passkey` (WebAuthn) |
| Organizations (workspaces, teams) | `github.com/ubgo/auth/plugin/organization` (no dependency; separate because grouping users is not authentication) |
| Enterprise SSO (OIDC and SAML identity providers per customer) | `github.com/ubgo/auth/plugin/sso` (SAML through gosaml2) |
| SCIM provisioning from Okta, Entra ID and other IdPs | `github.com/ubgo/auth/plugin/scim` |
| Device codes for CLIs and TVs | `github.com/ubgo/auth/plugin/deviceauth` (and `plugin/deviceauth/oauthdevice` for OAuth tokens) |
| Sign-in on preview deployments, or from a popup | `github.com/ubgo/auth/plugin/oauthproxy` |
| Your app as an OAuth 2.1 / OpenID Connect provider | `github.com/ubgo/auth/plugin/oauthprovider` |
| AI agents acting for users | `github.com/ubgo/auth/plugin/agentauth` |
| Sign-in with an LDAP directory (OpenLDAP, Active Directory, FreeIPA) | `github.com/ubgo/auth/plugin/ldap` (go-ldap) |
| Sign-In with Ethereum | `github.com/ubgo/auth/plugin/siwe` (secp256k1, no go-ethereum) |
| Ready-made HTML pages | `github.com/ubgo/auth/authui` |
| gin, echo, fiber, gqlgen | `github.com/ubgo/auth/contrib/gin`, `contrib/echo`, `contrib/fiber`, `contrib/gqlgen` |
| Rate limits or sessions shared through Redis | `github.com/ubgo/auth/contrib/redis` |
| Phone numbers typed without the country code | `github.com/ubgo/auth/contrib/phonenumbers` |
| Sign-in through a [goth](https://github.com/markbates/goth) provider you already configure | `github.com/ubgo/auth/contrib/goth` |

Check: `go list -m all | grep ubgo` shows exactly the modules you asked for, and `github.com/ubgo/sqlb`, the typed SQL builder the core is built on, which comes with it.

## Step 2 — Add a database driver

The library talks to `database/sql`; any driver works. The dialect you pass to `auth.WithDB` tells it which SQL to write.

| Engine | Driver | Dialect |
|---|---|---|
| Postgres | `github.com/jackc/pgx/v5/stdlib` (`sql.Open("pgx", dsn)`) | `sqlb.PostgresDialect{}` |
| MySQL 8 | `github.com/go-sql-driver/mysql` with `parseTime=true`, `loc=UTC`, `clientFoundRows=true` | `sqlb.MySQLDialect{}` |
| SQLite | `modernc.org/sqlite` (pure Go, `sql.Open("sqlite", dsn)`) | `sqlb.SQLiteDialect{}` |

```sh
go get modernc.org/sqlite
```

For SQLite, open the file with the pragmas the library depends on: WAL so readers do not block the writer, and a busy timeout instead of an immediate "database is locked". No foreign-key pragma is needed: the library creates no foreign keys and deletes a user's rows itself.

```text
file:app.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)
```

The MySQL settings matter too: `parseTime` and `loc=UTC` so timestamps come back as `time.Time` in UTC, and `clientFoundRows` so an update reports matched rows the way Postgres and SQLite do. The [databases](../concepts/databases.md) page has the full DSNs.

Check: `go build ./...` succeeds with the import `_ "modernc.org/sqlite"` (or your driver) in `main`.

## Step 3 — Prove the wiring compiles before you have a database

`auth.New` needs no database to check a plugin list: pass `auth.WithDialect` instead of `auth.WithDB` and it still refuses a combination that cannot work, such as a password with no way to recover it. The repository's `examples/poc` does exactly this for every plugin and prints the routes and the migrations for each engine:

```sh
git clone https://github.com/ubgo/auth && cd auth/examples && go run ./poc | head -6
```

```text
wired plugins: email, phone, username, password, oauth, organization

=== routes, from the operation list (mounted under /auth) ===
  GET  /auth/session                         core.session               signed_in
  POST /auth/sign-out                        core.sign-out              signed_in
  POST /auth/sign-out-all                    core.sign-out-all          signed_in
```

Your own app can do the same in a test: build the `*auth.Auth` with `WithDialect` and assert `New` returned no error. This function from `examples/core-options` wires email and password for Postgres with no server, and prints the schema the first `Migrate` would create:

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

Check: the poc output starts with `wired plugins:` and a list of routes; `go run ./core-options sql` prints `CREATE TABLE IF NOT EXISTS auth_user …` without a database.

## What can go wrong

| Symptom | Fix |
|---|---|
| `go: github.com/ubgo/auth/contrib/gin@...: module requires Go 1.25` | Update Go; the adapters, `plugin/passkey` and `plugin/sso` need 1.25. |
| `auth: no sign-in method; add a plugin such as password or oauth` | The plugin list has identifiers but nothing that signs in. Add `password.New()`, `oauth.New(...)`, or give `email.New` or `phone.New` the `SignInWithCode()` option. |
| `auth: plugin "password": password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()` | Give an identifier plugin `Recover()`, or opt out of password reset by name. |
| `auth: plugin "email": email: links need auth.WithBaseURL or email.Links` | Set `auth.WithBaseURL` to the app's public URL; mailed links are built from it. |
| `sql: unknown driver "sqlite"` | The driver package is not imported. Add `_ "modernc.org/sqlite"` to `main`. |

## Next

- [Your first app](first-app.md): from an empty folder to sign-up, verification, sign-in, a protected page and sign-out.
- [Configuration](../concepts/configuration.md): every `auth.With*` option.
