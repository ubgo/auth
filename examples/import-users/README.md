# Import users from Auth0, Clerk, Supabase, Auth.js or WorkOS

One program that reads another system's export and moves its users in through the library's own API: users with their original ids and sign-up times, addresses, numbers and handles (verified only when the source had verified them), password hashes that keep working until they are re-hashed at the first sign-in, linked social accounts, authenticator secrets, the admin flag and bans with their end dates. One transaction per user, nothing written to an auth table by hand, no mail sent.

The guides that use it are under [docs/migrating](../../docs/migrating/README.md): one per source, with the export command, the field map and the cutover.

## Run it

```sh
cd examples
go run ./import-users -source auth0 -file export.ndjson -dry-run
go run ./import-users -source auth0 -file export.ndjson
go run ./import-users -source clerk -file users.csv
go run ./import-users -source supabase -file users.csv -identities identities.csv -factors factors.csv
go run ./import-users -source authjs -file users.json -identities accounts.json
go run ./import-users -source workos -file users.json
```

It writes `import.db` (SQLite) in the current directory (`-db` changes it) and creates the tables on the first real run. `-dry-run` reads and maps the whole export and prints the plan without opening a transaction or creating a table. Set `AUTH_TOTP_KEY` (64 hex characters) to import authenticator secrets; without it the twofactor plugin is not wired and the summary says which users lost their factor, rather than sealing secrets with a key that would be gone after the run. Run the tests with `go test ./import-users`.

## Walkthrough

The fixture under `testdata/` is an Auth0 export of four users: one with a bcrypt password, a Google account and an authenticator app; a GitHub-only user with a phone number; a blocked user; and a user whose address duplicates the first one's.

```sh
go run ./import-users -source auth0 -file import-users/testdata/auth0.ndjson -dry-run
```

```text
would import 4 user(s), 0 failed, 0 skipped
  note   ada@example.com: two-factor not imported: no twofactor plugin wired
```

```sh
AUTH_TOTP_KEY=$(openssl rand -hex 32) go run ./import-users -source auth0 -file import-users/testdata/auth0.ndjson
```

```text
imported 3 user(s), 1 failed, 0 skipped
  FAILED ada@example.com: identity email "ada@example.com": auth: identity taken
```

The duplicate fails alone and leaves nothing behind; the exit status is 1 so a script notices. Running the same import again imports nothing: every id exists (`auth: a user with this id exists`), and nothing already imported changes.

## The code

Every reader turns its format into the same `record`; the importer has one path:

```go
type record struct {
	ID, Name, Image string
	CreatedAt       time.Time
	Emails, Phones  []identifier // Value, Verified, Primary
	Username        string
	PasswordHash    string       // the old hash string, unchanged
	Accounts        []account    // Provider, AccountID, Email
	TOTPSecret      string
	Admin           bool
	Banned          bool
	BannedUntil     time.Time    // zero: permanent
	Skip            string       // why the row is not imported at all
}
```

`importRecords` runs one transaction per record: `a.ImportUsers` for the user and identities, then `password.ImportHash`, `oauth.ImportAccount` and `twofactor.ImportTOTP` for the credentials, `admin.Grant` for the flag and `admin.BanFor` for a ban the source had in force. A hash in a format no configured verifier recognizes fails the row at import time, not at the user's first sign-in; an account for a provider the app does not offer is a note, since nothing could ever match it. `-dry-run` produces the same notes without writing.

In your own app, call `importRecords` with your `auth.New`: the only requirements are `password.AcceptLegacyHashes` listing the formats the export carries and the oauth providers configured under the names the readers produce (`auth0.go` maps Auth0's `google-oauth2` to `google`).

| Source | File(s) | What the reader does |
|---|---|---|
| `auth0` | ndjson from a user export job or the support-provided password export | `identities[]` with `isSocial` become accounts, `mfa_factors[].totp.secret` the factor, `blocked` a permanent ban |
| `clerk` | the Dashboard's CSV | several addresses per user; `password_hasher` decides whether the digest is importable (`bcrypt`, `pbkdf2_sha256_django`, `argon2id`) |
| `supabase` | `\copy` CSVs of `auth.users`, `auth.identities`, `auth.mfa_factors` | anonymous and deleted rows skipped, `is_super_admin` granted, a `banned_until` still in force imported as a ban |
| `authjs` | JSON arrays of `users` and `accounts` | `oauth`/`oidc` accounts linked, `email`/`credentials` ones ignored; no passwords exist |
| `workos` | the User Management API's pages | no hashes exist; every user gets the "forgot flow" note |

## What this used

- [`auth.ImportUsers`](https://pkg.go.dev/github.com/ubgo/auth#Auth.ImportUsers), `auth.Quiet`
- [`password.ImportHash`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password#Plugin.ImportHash), `password.AcceptLegacyHashes`, `password.Bcrypt`, `password.DjangoPBKDF2`, `password.Scrypt`
- [`oauth.ImportAccount`](https://pkg.go.dev/github.com/ubgo/auth/plugin/oauth#Plugin.ImportAccount)
- [`twofactor.ImportTOTP`](https://pkg.go.dev/github.com/ubgo/auth/plugin/twofactor#Plugin.ImportTOTP)
- [`admin.Grant`](https://pkg.go.dev/github.com/ubgo/auth/plugin/admin#Plugin.Grant), [`admin.BanFor`](https://pkg.go.dev/github.com/ubgo/auth/plugin/admin#Plugin.BanFor)
