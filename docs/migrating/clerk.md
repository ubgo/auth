# Migrate from Clerk

You will have every Clerk user in your own database with their id, every address and number Clerk had (verified ones verified, the primary one primary), their handle, their bcrypt password working until it is re-hashed at the first sign-in, and their authenticator app still working; their organizations come along with members and roles; social accounts re-link themselves at the first sign-in because Clerk's export does not carry them.

## Before you start

- [Migrating](README.md) for what every import has in common, and an app wired as in [your first app](../start/first-app.md).
- The example program is [`examples/import-users`](../../examples/import-users); `go test ./import-users` in `examples/` runs it against a Clerk fixture, `go run ./import-users -source clerk -file users.csv` runs it for real.
- Clerk's CSV export includes password digests and TOTP secrets, so this is one of the two migrations where nobody resets anything.

## Step 1 — Export the users

In the Clerk Dashboard, open **Users**, then **Export** (top right): Clerk mails a CSV with one row per user. The import reads these columns by name and ignores any others:

`id`, `first_name`, `last_name`, `username`, `image_url`, `created_at`, `primary_email_address`, `primary_phone_number`, `verified_email_addresses`, `unverified_email_addresses`, `verified_phone_numbers`, `unverified_phone_numbers`, `totp_secret`, `password_digest`, `password_hasher`.

A column that is missing reads as empty, so an older export without `image_url` or `created_at` still imports.

Check: `head -1 users.csv` shows those headers; `wc -l` is your user count plus one.

## Step 2 — What each field becomes

<!-- ds:block id=import-readclerk-9t4xw6hn -->
**readClerk** · [`examples/import-users/clerk.go:51-71`](../../examples/import-users/clerk.go#L51-L71)

```go
func readClerk(in input) ([]record, error) {
	rd := csv.NewReader(in.Main)
	rd.FieldsPerRecord = -1 // a short row reads as empty cells rather than an error
	header, err := rd.Read()
	if err != nil {
		return nil, fmt.Errorf("clerk: header: %w", err)
	}
	col := indexColumns(header)
	var out []record
	for line := 2; ; line++ {
		row, err := rd.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("clerk line %d: %w", line, err)
		}
		out = append(out, clerkRecord(cell(col, row)))
	}
	return out, nil
}
```
<!-- /ds:block hash=51ad63 -->

| Clerk | Here | Note |
|---|---|---|
| `id` (`user_2abc…`) | `auth_user.id` | Kept, so your rows keep their foreign keys |
| `first_name` + `last_name` | `auth_user.name` | Joined with a space |
| `image_url` | `auth_user.image` | |
| `created_at` | `auth_user.created_at` | Zero (an export without it) means the import time |
| `verified_email_addresses`, `unverified_email_addresses` | one `email` identity each | Several per user: wire `email.Multiple()` |
| `primary_email_address` | the primary `email` identity | Only a verified address can be primary here; an unverified primary stays unverified and the first verified one becomes primary |
| `verified_phone_numbers`, `unverified_phone_numbers`, `primary_phone_number` | `phone` identities, the same way | |
| `username` | a `username` identity | |
| `password_digest` with `password_hasher` | `auth_password.hash`, unchanged | `bcrypt` and `pbkdf2_sha256_django` are verified by the plugin and re-hashed at the first sign-in; `argon2id` is the plugin's own format. Any other hasher (`scrypt_firebase`, `phpass`, `md5`, `sha256`, `scrypt_werkzeug`, `bcrypt_sha256_django`) is reported and the user sets a password through the forgot flow |
| `totp_secret` | the user's authenticator factor | Sealed with your twofactor key; backup codes are not exported, the user regenerates them |
| external accounts (Google, GitHub, …) | not in the CSV | See step 5: they re-link at the first sign-in |
| organizations, memberships, roles | organizations of the [organization plugin](../plugins/organization.md) | Not in the CSV; [step 6](#step-6--organizations) reads them from the Backend API |

Several addresses in one cell are separated by commas; the reader also accepts semicolons and pipes, since a file edited by hand often has them.

Check: `go run ./import-users -source clerk -file users.csv -dry-run` prints `would import N user(s)` and a `note` for every user whose hasher cannot be verified here.

## Step 3 — Wire the plugins

The same wiring as the [Auth0 guide](auth0.md#step-3--wire-the-plugins-the-export-needs), step 3: `password.AcceptLegacyHashes(password.Bcrypt(), password.DjangoPBKDF2())` covers Clerk's verifiable hashers, `email.Multiple()` keeps every address, and `AUTH_TOTP_KEY` brings the authenticator secrets.

## Step 4 — Import

```sh
AUTH_TOTP_KEY=$(openssl rand -hex 32) go run ./import-users -source clerk -file users.csv -db app.db
```

```text
imported 2 user(s), 0 failed, 0 skipped
  note   bob@example.com: password not imported: Clerk hasher scrypt_firebase is not verifiable here
```

Keep the `AUTH_TOTP_KEY`: it is your app's `twofactor.WithEncryptionKey` from now on.

Check: a user with a bcrypt digest signs in with the old password (`POST /auth/password/sign-in`), and `select hash from auth_password where user_id = …` then starts with `$argon2id$`.

## Step 5 — Social accounts re-link at the first sign-in

Clerk's export has no column for external accounts, so there is nothing to import. The oauth plugin covers it: name the providers in `oauth.TrustedProviders("google", "github")`, and when an imported user signs in with Google, the plugin links the Google account to the user who holds that verified address instead of creating a second account. The condition is that the address Google reports is one of the user's verified addresses here, which the import preserved from `verified_email_addresses`. A user whose provider address was never verified in Clerk signs in with their password or a magic link first, then links the provider from settings.

## Step 6 — Organizations

The CSV has no organizations. Save them from the Backend API, each with its memberships, as one JSON array (paginate with `offset` above 100):

```sh
H="Authorization: Bearer $CLERK_SECRET_KEY"
curl -s "https://api.clerk.com/v1/organizations?limit=100" -H "$H" | jq -c '.data[]' | while read -r org; do
  id=$(jq -r .id <<<"$org")
  ms=$(curl -s "https://api.clerk.com/v1/organizations/$id/memberships?limit=100" -H "$H" | jq '.data')
  jq -c --argjson m "$ms" '. + {memberships: $m}' <<<"$org"
done | jq -s . > orgs.json
```

[`examples/import-orgs`](../../examples/import-orgs) loads them into the [organization plugin](../plugins/organization.md), one transaction per organization, keeping Clerk's slug and name. Clerk has no owner role: the creator (`created_by`) becomes the owner and every other member keeps their role; a custom `org:…` role imports as member and is listed:

<!-- ds:block id=clerkorgroles-2w9dx6pb -->
**clerkOrgRoles** · [`examples/import-orgs/sources.go:134-137`](../../examples/import-orgs/sources.go#L134-L137)

```go
var clerkOrgRoles = map[string]organization.Role{
	"org:admin":  organization.RoleAdmin,
	"org:member": organization.RoleMember,
}
```
<!-- /ds:block hash=2db320 -->

```sh
go run ./import-orgs -source clerk -file orgs.json -db app.db
```

```text
imported 1 organization(s), 0 failed
  note   initech: user_2def is the owner (was admin): an organization starts with its creator as owner
  note   initech: user_2abc: role org:billing has no equivalent; imported as member
```

Clerk's organization id is kept in each organization's metadata as `sourceId`, since the plugin makes its own ids. Custom permissions behind a custom role are your app's: define them with the organization plugin's access control ([organization](../plugins/organization.md)) and set the role with `SetRole`.

Check: `select count(*) from auth_org` is your organization count.

## Step 7 — Cut over

1. Create your own OAuth applications at each provider (Clerk's were Clerk's) and set the callback to `https://your-app/auth/oauth/<provider>/callback`.
2. Deploy; every user signs in again. Passwords and authenticator apps work as before; users on an unsupported hasher use "Forgot password".
3. Organizations came over in step 6; invitations still pending in Clerk do not, so ask their senders to invite again.
4. Keep the Clerk instance for a while, then delete it.

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `FAILED … auth: identity taken` | Two Clerk users hold the same verified address or handle | Merge or drop one |
| `note … Clerk hasher X is not verifiable here` | Clerk imported that user from yet another system | Add a `password.Verifier` for the format, or let the user reset |
| `note … two-factor not imported` | `AUTH_TOTP_KEY` unset | Set it before the import |
| `FAILED <org>: member …: auth.user_not_found` | That member's user was not imported | Import the user, or drop the membership from `orgs.json`, and run import-orgs again |
| Google sign-in creates a second account | The provider's address is not a verified address of the imported user, or the provider is not in `TrustedProviders` | Verify the address first, or add the provider |

## Next

- [Password plugin](../plugins/password.md), [email plugin](../plugins/email.md) (`Multiple`), [two-factor](../plugins/twofactor.md).
- [Migrating](README.md) for the other sources.
