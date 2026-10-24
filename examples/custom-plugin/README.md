# Write a plugin: a column and an endpoint

Every user gets a referral code at sign-up. The code is a column the plugin adds to `auth_user`, a data hook fills it inside the sign-up's transaction, and `GET /auth/referral/code` returns it. The plugin lives in [`referral/`](referral/referral.go) and uses only exported API, so a plugin in your own repository can do everything it does.

## Run it

```sh
cd examples
go run ./custom-plugin
```

It creates `custom-plugin.db` (SQLite), migrates it, and listens on `http://localhost:8081`. Run the tests with `go test ./custom-plugin/...`.

## Walkthrough

At start-up the core writes the plugin's column migration next to its own; the plugin wrote no SQL:

```text
2026/09/29 13:46:09 migrated core/0001_core_tables
2026/09/29 13:46:09 migrated email/0000_identity_unique_email_verified
2026/09/29 13:46:09 migrated email/0000_column_auth_user_primary_email
2026/09/29 13:46:09 migrated email/0000_column_auth_user_email_verified_at
2026/09/29 13:46:09 migrated password/0001_password
2026/09/29 13:46:09 migrated referral/0000_column_auth_user_referral_code
2026/09/29 13:46:09 listening on http://localhost:8081
```

The route requires a session, and the pipeline enforces that before the plugin's code runs:

```sh
curl -s localhost:8081/auth/referral/code
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Sign up, then ask for the code:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/auth/referral/code
```

```json
{"user":{"id":"usr_bosorbghsvrn3s44dmohlamy","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"code":"HVJ5H6HU"}
```

The app's `/me` loads its composite user in one statement; the plugin's column is an ordinary flat field (`primaryEmail` is null until the address is verified):

```sh
curl -s -b cookies.txt localhost:8081/me
```

```json
{"id":"usr_bosorbghsvrn3s44dmohlamy","primaryEmail":null,"referralCode":"HVJ5H6HU"}
```

In the database:

```sh
sqlite3 custom-plugin.db "select sql from sqlite_master where name in ('auth_user_referral_code_key'); select id, referral_code from auth_user; select owner, name from auth_migrations where owner='referral';"
```

```text
CREATE UNIQUE INDEX auth_user_referral_code_key ON auth_user (referral_code)
usr_bosorbghsvrn3s44dmohlamy|HVJ5H6HU
referral|0000_column_auth_user_referral_code
```

## The code

A plugin is one required method, `Name()`, plus whichever optional interfaces it needs. The compiler checks the ones this plugin claims:

```go
var (
	_ auth.Initializer       = (*Plugin)(nil)
	_ auth.ColumnExtender    = (*Plugin)(nil)
	_ auth.DataHooker        = (*Plugin)(nil)
	_ auth.OperationProvider = (*Plugin)(nil)
)
```

The column, typed, so a query that compares it with the wrong Go type does not compile:

```go
var Code = sqlb.Col[*string](auth.TableUser, ColCode)

func (p *Plugin) Columns() []auth.ColumnExtension {
	return []auth.ColumnExtension{{Table: auth.TableNameUser, Name: ColCode, Type: auth.ColumnText, Nullable: true, Unique: true}}
}
```

The hook runs inside the transaction that creates the user. `SetUserColumn` is the one sanctioned write to a core table, and it refuses a column the plugin did not add:

```go
AfterCreate: func(ctx context.Context, _ sqlb.DBTX, u *auth.User) error {
	code, err := newCode()
	if err != nil {
		return err
	}
	return auth.SetUserColumn(ctx, p.a, PluginName, u.ID, Code, &code)
},
```

The operation is declared once with `auth.Define`; the HTTP route, a GraphQL field and the Go method `Plugin.Code` all run it through the same pipeline:

```go
p.code = auth.Define(auth.OpInfo{ID: EndpointCode, Kind: auth.Query, Require: auth.SignedIn, Path: "/code"}, p.doCode)
```

The app embeds the plugin's column struct in its own user, and `a.LoadUser` fills everything in one `SELECT`:

```go
type appUser struct {
	auth.User
	email.EmailColumns
	referral.ReferralColumns
}
```

## The failure path

A second plugin that claims the same column is refused by `auth.New`, instead of appearing later as an ambiguous query. From `go test -v -run TwoOwners ./custom-plugin/`:

```text
auth.New: auth: two owners for one column: column "auth_user"."referral_code" is added by "referral" and by plugin "growth"
```

`main_test.go` also proves the transaction: a test plugin refuses Bob's identity row after the user row and its code were written, and afterwards the table holds one user with one code, Alice's.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `Plugin`, `ColumnExtension`, `DataHooks`, `TableHooks`, `SetUserColumn`, `Define`, `OpInfo`, `LoadUser`, `LoadUserColumns`
- [`github.com/ubgo/sqlb`](https://pkg.go.dev/github.com/ubgo/sqlb): `Col`, `Bind`, `Bindings`
- Related: [admin-plan](../admin-plan) reads plugin columns in the app's own query; [saas-workspace](../saas-workspace) writes app rows in the same transaction.
