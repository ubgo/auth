# Migrate from Auth0

You will have every Auth0 user in your own database with the same id, the same sign-up date, their verified addresses and numbers, their Google or GitHub accounts linked, their authenticator app still working, and, with Auth0's password export, their password; the users you blocked stay blocked; your organizations come along with their members and roles, and your administrators keep the admin role; and nobody is mailed during the move.

## Before you start

- [Migrating](README.md) for what every import has in common, and an app wired as in [your first app](../start/first-app.md).
- The example program is [`examples/import-users`](../../examples/import-users); `go test ./import-users` in `examples/` runs it against an Auth0 fixture, `go run ./import-users -source auth0 -file export.ndjson` runs it for real.
- Auth0's password hashes are not in any self-service export. Open a support ticket asking for the password hash export of your tenant; Auth0 provides it to Enterprise customers as a JSON file whose user objects carry `password_hash`. Without it every user sets a new password through the forgot flow at their first sign-in.

## Step 1 — Export the users

A user export job writes one JSON object per line (ndjson), gzipped. Request it with the Management API, choosing the fields the import reads; identities and MFA factors are included when named:

```sh
curl -s -X POST "https://$AUTH0_DOMAIN/api/v2/jobs/users-exports" \
  -H "Authorization: Bearer $AUTH0_MGMT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"format":"json","fields":[{"name":"user_id"},{"name":"email"},{"name":"email_verified"},{"name":"phone_number"},{"name":"phone_verified"},{"name":"name"},{"name":"nickname"},{"name":"username"},{"name":"picture"},{"name":"created_at"},{"name":"blocked"},{"name":"identities"},{"name":"mfa_factors"}]}'
# poll GET /api/v2/jobs/{id} until "status":"completed", then download "location"
gunzip export.ndjson.gz
```

The User Import / Export extension in the Dashboard writes the same shape. If support sent you the password export, use that file instead: it holds the same users with `password_hash` on each.

Check: `wc -l export.ndjson` is your user count, and `head -1 export.ndjson | jq .user_id` prints something like `auth0|5f1a…`.

## Step 2 — What each field becomes

<!-- ds:block id=import-readauth0-3m8vk2qp -->
**readAuth0** · [`examples/import-users/auth0.go:69-90`](../../examples/import-users/auth0.go#L69-L90)

```go
func readAuth0(in input) ([]record, error) {
	var out []record
	sc := bufio.NewScanner(in.Main)
	sc.Buffer(make([]byte, 0, scanBufferSize), scanBufferSize)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var u auth0User
		if err := json.Unmarshal([]byte(raw), &u); err != nil {
			return nil, fmt.Errorf("auth0 line %d: %w", line, err)
		}
		out = append(out, auth0Record(u))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("auth0: %w", err)
	}
	return out, nil
}
```
<!-- /ds:block hash=6b6d6e -->

| Auth0 | Here | Note |
|---|---|---|
| `user_id` (`auth0\|…`, `google-oauth2\|…`) | `auth_user.id` | Kept as it is: opaque text, unique, so your own rows keep their foreign keys |
| `email`, `email_verified` | an `email` identity, verified when Auth0 said so, primary | An unverified address is a claim the user proves here before it signs in |
| `phone_number`, `phone_verified` | a `phone` identity | E.164 as Auth0 stores it |
| `name`, else `nickname` | `auth_user.name` | |
| `username` | a `username` identity | Verified: a handle is not something a person proves |
| `picture` | `auth_user.image` | A URL, served by whoever served it before |
| `created_at` | `auth_user.created_at` | The original sign-up time |
| `password_hash` | `auth_password.hash`, unchanged | bcrypt `$2a$`/`$2b$`; verified by `password.Bcrypt()` and replaced with argon2id at the first sign-in |
| `identities[]` with `isSocial: true` | an `auth_account` row per provider | `google-oauth2` becomes `google`, `windowslive` becomes `microsoft`; the database connection is the user, not an account |
| `mfa_factors[].totp.secret` | the user's authenticator factor | Sealed with your twofactor key; recovery codes are not exportable, the user regenerates them from settings |
| `blocked: true` | a permanent ban (`admin.BanFor`) with the reason `blocked in Auth0` | The user's sign-in is refused with `admin.banned` until an admin unbans them; a blocked user who was also an admin fails the row (`admin.admin_target`), since an admin cannot be banned |
| tenant roles | the admin plugin's `admin` role for the roles you name | [Step 5](#step-5--organizations-and-roles); every other role is your app's permission model |
| organizations, members, member roles | organizations of the [organization plugin](../plugins/organization.md) | [Step 5](#step-5--organizations-and-roles) |
| `app_metadata`, `user_metadata` | not imported | Arbitrary metadata is your app's tables; join them on the kept id |

Check: `go run ./import-users -source auth0 -file export.ndjson -dry-run` prints `would import N user(s)` and one `note` line per user whose password or account would not be imported, and creates nothing.

## Step 3 — Wire the plugins the export needs

The import program wires every plugin a user base may carry. The password plugin accepts bcrypt beside its own argon2id, the oauth providers are named so imported accounts have a provider to match, the twofactor plugin is wired only when `AUTH_TOTP_KEY` is set (a key made up for one run would strand every imported secret), and the admin plugin so `is_super_admin`-style flags can be granted:

<!-- ds:block id=import-newauth-6g9xc3lp -->
**newAuth** · [`examples/import-users/main.go:165-189`](../../examples/import-users/main.go#L165-L189)

```go
func newAuth(db *sql.DB, m email.Mailer, sms phone.SMSSender, totpKey []byte) (*auth.Auth, deps, error) {
	pw := password.New(password.AcceptLegacyHashes(password.Bcrypt(), password.DjangoPBKDF2(), password.Scrypt(password.BetterAuthScrypt)))
	op := oauth.New(oauth.WithProviders(
		oauth.Google(envOr("GOOGLE_CLIENT_ID"), envOr("GOOGLE_CLIENT_SECRET")),
		oauth.GitHub(envOr("GITHUB_CLIENT_ID"), envOr("GITHUB_CLIENT_SECRET")),
	), oauth.TrustedProviders("google", "github"))
	ad := admin.New()
	d := deps{Password: pw, OAuth: op, Admin: ad}
	plugins := []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.Multiple(), email.WithMailer(m)),
		phone.New(phone.WithSMS(sms)),
		username.New(),
		pw, op, ad,
	}
	if totpKey != nil {
		d.TwoFactor = twofactor.New(twofactor.WithEncryptionKey(totpKey))
		plugins = append(plugins, d.TwoFactor)
	}
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(plugins...),
	)
	return a, d, err
}
```
<!-- /ds:block hash=9c5bd8 -->

In your app, pass your own `auth.New` and plugins to `importRecords`; the only requirements are `password.AcceptLegacyHashes(password.Bcrypt())` and the oauth providers under the names the table above produces.

## Step 4 — Import

```sh
AUTH_TOTP_KEY=$(openssl rand -hex 32) go run ./import-users -source auth0 -file export.ndjson -db app.db
```

```text
imported 3 user(s), 1 failed, 0 skipped
  FAILED ada@example.com: identity email "ada@example.com": auth: identity taken
```

Each user is one transaction, created through the same code path as a sign-up:

<!-- ds:block id=import-credentials-4r8wn2kt -->
**importCredentials** · [`examples/import-users/record.go:204-238`](../../examples/import-users/record.go#L204-L238)

```go
func importCredentials(ctx context.Context, d deps, id string, r record) ([]string, error) {
	var notes []string
	switch {
	case r.PasswordHash != "" && d.Password == nil:
		return nil, errNoHasher
	case r.PasswordHash != "":
		if err := d.Password.ImportHash(ctx, id, r.PasswordHash); err != nil {
			return nil, fmt.Errorf("password: %w", err)
		}
	case r.PasswordNote != "":
		notes = append(notes, "password not imported: "+r.PasswordNote)
	}
	for _, acc := range r.Accounts {
		if d.OAuth == nil {
			notes = append(notes, "account "+acc.Provider+" not imported: no oauth plugin wired")
			continue
		}
		err := d.OAuth.ImportAccount(ctx, oauth.ImportAccount{UserID: id, Provider: acc.Provider, ProviderAccountID: acc.AccountID, Email: acc.Email})
		if errors.Is(err, oauth.ErrProviderUnknown) {
			notes = append(notes, "account "+acc.Provider+" not imported: provider not configured")
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("account %s: %w", acc.Provider, err)
		}
	}
	if r.TOTPSecret != "" {
		if d.TwoFactor == nil {
			notes = append(notes, "two-factor not imported: no twofactor plugin wired")
		} else if err := d.TwoFactor.ImportTOTP(ctx, id, r.TOTPSecret); err != nil {
			return nil, fmt.Errorf("two-factor: %w", err)
		}
	}
	return notes, nil
}
```
<!-- /ds:block hash=e077ee -->

The failed row above is the fixture's duplicate: Auth0 lets one address exist on a database user and on a social user; here one verified address belongs to one user, so the second row fails alone and is listed. Decide per row: merge them (import the second user's social identity as an account of the first), or drop one.

Keep the `AUTH_TOTP_KEY` you used: it is the key your app passes to `twofactor.WithEncryptionKey` from now on.

Check: `select count(*) from auth_user` is the imported count; `select count(*) from auth_identity where verified_at is not null` is the number of verified addresses, numbers and handles; your log shows no mail.

## Step 5 — Organizations and roles

With the users in, [`examples/import-orgs`](../../examples/import-orgs) loads Auth0 Organizations into the [organization plugin](../plugins/organization.md) and turns the tenant roles that mean "administrator" into the [admin plugin's](../plugins/admin.md) `admin` role. Skip this step if you used neither.

Save every organization with its members and their roles, then every tenant role with its users, as two JSON arrays (paginate with `page`/`per_page` above 50):

```sh
H="Authorization: Bearer $AUTH0_MGMT_TOKEN"
curl -s "https://$AUTH0_DOMAIN/api/v2/organizations?per_page=50" -H "$H" | jq -c '.[]' | while read -r org; do
  id=$(jq -r .id <<<"$org")
  members=$(curl -s "https://$AUTH0_DOMAIN/api/v2/organizations/$id/members?fields=user_id,roles&per_page=50" -H "$H")
  jq -c --argjson m "$members" '. + {members: $m}' <<<"$org"
done | jq -s . > orgs.json
curl -s "https://$AUTH0_DOMAIN/api/v2/roles" -H "$H" | jq -c '.[]' | while read -r role; do
  id=$(jq -r .id <<<"$role")
  users=$(curl -s "https://$AUTH0_DOMAIN/api/v2/roles/$id/users?per_page=50" -H "$H")
  jq -c --argjson u "$users" '. + {users: $u}' <<<"$role"
done | jq -s . > roles.json
```

Auth0 has no built-in organization roles, so member roles are matched by name, ignoring case, onto owner, admin and member; any other name imports as member and is listed. A member with several roles gets the highest:

<!-- ds:block id=auth0orgroles-8r4mv2xs -->
**auth0OrgRoles** · [`examples/import-orgs/sources.go:39-43`](../../examples/import-orgs/sources.go#L39-L43)

```go
var auth0OrgRoles = map[string]organization.Role{
	"owner":  organization.RoleOwner,
	"admin":  organization.RoleAdmin,
	"member": organization.RoleMember,
}
```
<!-- /ds:block hash=b232ea -->

An organization's Auth0 `name` (lowercase, dashes) becomes its slug and `display_name` its name; the creator (the first owner) creates it and every other member is added with their role, in one transaction per organization. Auth0's organization id is kept in the organization's metadata as `sourceId`, since the plugin makes its own ids. For tenant roles, `-admin-role` names the ones that become the `admin` role:

<!-- ds:block id=readauth0roles-5n7qc3wk -->
**readAuth0Roles** · [`examples/import-orgs/sources.go:97-112`](../../examples/import-orgs/sources.go#L97-L112)

```go
func readAuth0Roles(r io.Reader, adminRoles []string) (map[string][]string, error) {
	var in []auth0TenantRole
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return nil, fmt.Errorf("auth0 roles: want an array of roles: %w", err)
	}
	out := map[string][]string{}
	for _, role := range in {
		if !slices.ContainsFunc(adminRoles, func(n string) bool { return strings.EqualFold(n, role.Name) }) {
			continue
		}
		for _, u := range role.Users {
			out[u.UserID] = []string{admin.RoleAdmin}
		}
	}
	return out, nil
}
```
<!-- /ds:block hash=445600 -->

```sh
go run ./import-orgs -source auth0 -file orgs.json -roles roles.json -admin-role Admin -db app.db
```

```text
imported 1 organization(s), 1 failed
  note   acme: auth0|blocked0001: role Billing Viewer has no equivalent; imported as member
  FAILED globex: member auth0|dup0001: auth.user_not_found
set the admin role on 1 user(s), 0 failed
```

`globex` names the duplicate user whose import failed in step 4, so the whole organization was rolled back; settle that user, then run again (an organization already imported fails on its slug, `organization.slug_taken`, and is not touched). Add `-dry-run` first to see the plan.

Check: `select count(*) from auth_org` is the imported count, and `GET /auth/admin/users` as an imported administrator answers 200.

## Step 6 — Cut over

1. Point the Google, GitHub and other OAuth applications at the new callback (`https://your-app/auth/oauth/<provider>/callback`) and give the plugin the same client ids, so an imported account's `provider_account_id` matches what the provider returns.
2. Deploy with sign-in on the new routes. Every user signs in again: Auth0 sessions and tokens do not move, and the import creates none.
3. A user with an imported hash signs in with the old password and is re-hashed on the spot. A user without one (no password export, or a social-only account) signs in with their provider, or uses "Forgot password" to set one; the forgot mail goes to a verified address, which is why unverified addresses were imported unverified.
4. Grant the first admin from Go if step 5 imported none ([admin](../plugins/admin.md), step 2); blocked users are already banned and appear as such in the admin list.
5. Keep the Auth0 tenant for a while in case a row needs a second look, then delete it; the import is a copy, not a move.

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `FAILED … auth: identity taken` | Two Auth0 users hold the same verified address | Merge or drop one; see step 4 |
| `FAILED … password: … password.hash_unrecognized` | The `password_hash` is not bcrypt (a custom hash import into Auth0), so no configured verifier recognizes it | Add a `password.Verifier` for that format, or drop the hash and let the user reset |
| `note … account google not imported: provider not configured` | The oauth plugin has no provider under that name | Configure it, or accept that the user signs in another way |
| `note … two-factor not imported` | `AUTH_TOTP_KEY` is unset | Set it and re-run for those users after deleting them, or let them re-enrol |
| The user's first sign-in says `password.invalid_credentials` with the right password | The export's `password_hash` belongs to another connection of that user | Compare the `identities[].connection` the hash came from |
| `FAILED <org>: member …: auth.user_not_found` | That member's user import failed or was never run | Import the user (or drop the member from `orgs.json`) and run import-orgs again |
| `note … role X has no equivalent; imported as member` | An Auth0 organization role whose name is not owner, admin or member | Promote the member with `organization.SetRole`, or add the name to `auth0OrgRoles` before importing |
| A user signs in with Google and gets a new, empty account | The provider's account id differs from the one Auth0 stored, or the client id changed | Keep the same OAuth application; the plugin links by verified address when `oauth.TrustedProviders` names the provider |

## Next

- [Password plugin](../plugins/password.md) for the legacy-hash verifiers and `WithHasher`.
- [OAuth plugin](../plugins/oauth.md) for account linking rules.
- [Migrating](README.md) for the other sources.
