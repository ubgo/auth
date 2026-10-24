# Write a plugin: a table of its own

A signed-in user names the devices they trust, lists them and removes them. The rows live in a table the plugin owns, `auth_device`, whose DDL the plugin writes once per engine with the core's type spellings. The plugin lives in [`devices/`](devices/devices.go) and uses only exported API, so a plugin in your own repository can do everything it does. The guide [Tables and migrations](../../docs/extending/05-tables-and-migrations.md) walks through it step by step.

## Run it

```sh
cd examples
go run ./plugin-tables
```

It creates `plugin-tables.db` (SQLite), migrates it, and listens on `http://localhost:8081`. `go run ./plugin-tables auth migrate sql` prints the schema and `go run ./plugin-tables auth migrate status` the ledger, through `authcli`. Run the tests with `go test ./plugin-tables/...`.

## Walkthrough

At start-up the core applies the plugin's migration after its own and the other plugins':

```text
2026/10/01 09:48:00 migrated core/0001_core_tables
2026/10/01 09:48:00 migrated core/0003_session_lifetimes
2026/10/01 09:48:00 migrated email/0000_identity_unique_email_verified
2026/10/01 09:48:00 migrated email/0000_column_auth_user_primary_email
2026/10/01 09:48:00 migrated email/0000_column_auth_user_email_verified_at
2026/10/01 09:48:00 migrated password/0001_password
2026/10/01 09:48:00 migrated devices/0001_devices
2026/10/01 09:48:00 listening on http://localhost:8081
```

Every route needs a session, and the pipeline enforces that before the plugin's code runs:

```sh
curl -s localhost:8081/auth/devices/list
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Sign up, then add two devices. A second device with the same name is refused with the plugin's own error code, which the database's unique constraint enforces:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/devices/add -H 'Origin: http://localhost:8081' -d '{"name":"Laptop"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/devices/add -H 'Origin: http://localhost:8081' -d '{"name":"Laptop"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/devices/add -H 'Origin: http://localhost:8081' -d '{"name":"Phone"}'
```

```json
{"user":{"id":"usr_3w6ebxtc2sy7gnztkbp3t3xf","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
{"error":{"code":"devices.name_taken","message":"You already have a device with that name."}}
{"ok":true}
```

List them, remove one (removing needs a recent sign-in; this one is seconds old), and list again:

```sh
curl -s -b cookies.txt localhost:8081/auth/devices/list
curl -s -b cookies.txt -X POST localhost:8081/auth/devices/remove -H 'Origin: http://localhost:8081' -d '{"id":"dev_d2p6hs5gn3nh2oqz7l4qgc4q"}'
curl -s -b cookies.txt localhost:8081/auth/devices/list
```

```json
{"devices":[{"id":"dev_d2p6hs5gn3nh2oqz7l4qgc4q","name":"Laptop","createdAt":"2026-10-01T04:18:00.790868Z"},{"id":"dev_iwdi54q5vz7y67h5eepgvege","name":"Phone","createdAt":"2026-10-01T04:18:00.813012Z"}]}
{"ok":true}
{"devices":[{"id":"dev_iwdi54q5vz7y67h5eepgvege","name":"Phone","createdAt":"2026-10-01T04:18:00.813012Z"}]}
```

The schema command prints the plugin's DDL next to the core's, in the engine's own spellings, and the ledger records it as applied:

```sh
go run ./plugin-tables auth migrate sql | sed -n '/-- devices/,/^$/p'
go run ./plugin-tables auth migrate status
```

```text
-- devices 0001_devices
CREATE TABLE IF NOT EXISTS auth_device (id TEXT NOT NULL PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, created_at TIMESTAMP NOT NULL, UNIQUE (user_id, name));

applied  core      0001_core_tables
applied  core      0003_session_lifetimes
applied  email     0000_identity_unique_email_verified
applied  email     0000_column_auth_user_primary_email
applied  email     0000_column_auth_user_email_verified_at
applied  password  0001_password
applied  devices   0001_devices
0 pending, 0 changed, 7 total
```

## What the tests pin

- The three operations over HTTP, with each refusal's code (`devices.name_invalid`, `devices.name_taken`, `devices.too_many`, `devices.not_found`), and that another user's device id matches nothing.
- The Go API (`Plugin.Add`) runs the same pipeline: a call with no session is `auth.ErrSignedOut`.
- `auth migrate sql` includes the table; `auth migrate status` lists the migration as applied.
- A device limit of zero is refused by `auth.New`, naming the plugin.
- Deleting a user deletes their devices: the plugin lists `auth_device.user_id` in `UserTables`, and `a.DeleteUser` removes the rows in Go; there is no foreign key.
- The plugin names its table through the core (`a.TableName(TableDevice)`), never by concatenating `TableNameDevice`, so an app that renames the tables with `auth.WithTablePrefix` or `auth.RenameTable(devices.TableDevice, …)` keeps working.
