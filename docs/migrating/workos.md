# Migrate from WorkOS

You will have every WorkOS user in your own database with the same id, name, picture and address (verified when WorkOS had verified it), a plan for the one thing WorkOS does not hand over, passwords, and a plan for moving each enterprise customer's SSO connection and Directory Sync to [`plugin/sso`](../plugins/sso.md) and [`plugin/scim`](../plugins/scim.md). WorkOS exports no hashes, so every user sets a password through the forgot flow at their first sign-in, or signs in with a magic link or a social provider instead.

## Before you start

- [Migrating](README.md) for what every import has in common, and an app wired as in [your first app](../start/first-app.md).
- The example program is [`examples/import-users`](../../examples/import-users); `go test ./import-users` in `examples/` runs it against a WorkOS fixture.
- A WorkOS API key with User Management access.

## Step 1 — List the users

WorkOS has no export; page through the User Management API and save the pages. The reader accepts either a page as the API returns it (`{"data": [...]}`) or a bare array you concatenated:

```sh
curl -s "https://api.workos.com/user_management/users?limit=100" -H "Authorization: Bearer $WORKOS_API_KEY" > users.json
# repeat with &after=<list_metadata.after> until it is null, saving each page
```

Check: `jq '.data | length' users.json` is at most 100, and `jq '.list_metadata.after' users.json` is the cursor for the next page or `null`.

## Step 2 — What each field becomes

<!-- ds:block id=import-readworkos-8d3hq5tn -->
**readWorkOS** · [`examples/import-users/workos.go:39-67`](../../examples/import-users/workos.go#L39-L67)

```go
func readWorkOS(in input) ([]record, error) {
	var raw json.RawMessage
	if err := json.NewDecoder(in.Main).Decode(&raw); err != nil {
		return nil, fmt.Errorf("workos: %w", err)
	}
	var users []workosUser
	if err := json.Unmarshal(raw, &users); err != nil {
		var page workosPage
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("workos: neither an array nor a {\"data\": [...]} page: %w", err)
		}
		users = page.Data
	}
	out := make([]record, 0, len(users))
	for _, u := range users {
		r := record{
			ID:           u.ID,
			Name:         strings.TrimSpace(u.FirstName + " " + u.LastName),
			Image:        u.ProfilePictureURL,
			CreatedAt:    parseTime(u.CreatedAt),
			PasswordNote: workosNoPassword,
		}
		if u.Email != "" {
			r.Emails = []identifier{{Value: u.Email, Verified: u.EmailVerified, Primary: true}}
		}
		out = append(out, r)
	}
	return out, nil
}
```
<!-- /ds:block hash=1044e3 -->

| WorkOS | Here | Note |
|---|---|---|
| `id` (`user_01H…`) | `auth_user.id` | Kept |
| `email`, `email_verified` | an `email` identity, verified when WorkOS said so, primary | WorkOS verifies addresses at sign-up, so most are verified |
| `first_name` + `last_name` | `auth_user.name` | |
| `profile_picture_url` | `auth_user.image` | |
| `created_at` | `auth_user.created_at` | |
| password | none | WorkOS does not export hashes; every record carries the note `password not imported`, and step 4 says what the user does |
| social sign-ins | none | WorkOS keeps the provider link in its own account; the user signs in with the provider here and the plugin links by verified address (`oauth.TrustedProviders`) |
| SSO connections, Directory Sync | none | Re-created per customer with `plugin/sso` and `plugin/scim`, [step 5](#step-5--sso-connections-and-directory-sync) |
| organizations, memberships, roles | not imported by import-users | The [organization plugin](../plugins/organization.md)'s `CreateFor` and `AddMember` load them; [`examples/import-orgs`](../../examples/import-orgs) shows the pattern for Auth0 and Clerk exports |
| `metadata` | not imported | Your tables, joined on the kept id |

Check: `go run ./import-users -source workos -file users.json -dry-run` prints one `note` per user about the password.

## Step 3 — Import

```sh
go run ./import-users -source workos -file users.json -db app.db
```

```text
imported 2 user(s), 0 failed, 0 skipped
  note   ada@example.com: password not imported: WorkOS does not export password hashes; the user sets one through the forgot flow
  note   bob@example.com: password not imported: WorkOS does not export password hashes; the user sets one through the forgot flow
```

Run it once per saved page, or concatenate the pages' `data` arrays with `jq -s '[.[].data[]]'` into one file first.

## Step 4 — Decide how users get back in

Nobody has a password, so the sign-in page needs one of these on day one:

| Option | What the user does | Wire |
|---|---|---|
| Set a password | Clicks "Forgot password", receives the reset mail at their verified address, chooses a password, is signed in | `plugin/password` with `email.Recover()`; the default |
| Magic link | Types their address, clicks the mailed link | [`plugin/magiclink`](../plugins/magiclink.md); no password ever |
| Social sign-in | Signs in with Google or Microsoft as before | [`plugin/oauth`](../plugins/oauth.md) with `TrustedProviders`, which links the provider account to the imported user by verified address |
| Passkey | Registers one after any of the above | [`plugin/passkey`](../plugins/passkey.md) |

Tell users before the switch: a mail saying "sign in with 'Forgot password' the first time" removes most of the support load. An unverified address cannot receive the reset mail; those users need the social or magic-link path, or a verification mail you trigger from your own code with `email.Plugin.Add` for the address.

## Step 5 — SSO connections and Directory Sync

An organization whose people signed in through a WorkOS SSO connection keeps signing in through its IdP here: [`plugin/sso`](../plugins/sso.md) speaks SAML 2.0 and OpenID Connect to the same IdPs, and [`plugin/scim`](../plugins/scim.md) replaces Directory Sync. What does not move is the configuration: WorkOS holds each connection's IdP certificate and client secret and is the service provider the IdP knows, so each connection is set up again with the customer's IdP admin, one customer at a time. [`examples/sso`](../../examples/sso) and [`examples/scim`](../../examples/scim) run both end to end.

1. List what you have: `GET https://api.workos.com/connections` (type, state, organization) and `GET https://api.workos.com/organizations` (each with its `domains`) give each customer's protocol and email domains; `GET https://api.workos.com/directories` lists the Directory Sync directories.
2. Wire `sso.New(...)` with `auth.WithSecret` (provider secrets are sealed with it). With organizations, pass `sso.WithOrganizations` so a customer's admin can register the provider for their organization from your settings page.
3. Register each connection as a provider with the same domains (`POST /auth/sso/register`, or `RegisterProvider` from Go): for SAML, the IdP's metadata XML or SSO URL, certificate and entity id, which the customer's admin exports from the IdP; for OIDC, the issuer, client id and secret. The answer carries the new `acsURL` and `spMetadataURL` (SAML) or `redirectURI` (OIDC).
4. The customer's IdP admin replaces WorkOS's ACS URL and SP entity id (or redirect URI) with the new ones. Agree a moment: until they switch, the IdP keeps posting to WorkOS.
5. Imported users keep their accounts: name the providers in `sso.TrustProviders(...)` (WorkOS had verified those domains), or verify the domains with `sso.WithDomainVerification`. A trusted provider links a first SSO sign-in to the imported user holding that verified address in its domain; an untrusted one refuses it with `sso.account_exists` instead of linking.
6. Directory Sync: create one SCIM connection per directory (`scim.ManagedConnections()`, then `CreateManagedConnection` from your admin page, which shows the token once), and give the IdP admin the new base URL (`https://app.example.com/scim/v2`) and token in place of WorkOS's. The IdP then pushes its users again. A provisioned address already held by an imported user answers `409 uniqueness`, because the plugin never links by email on its own; decide it with `scim.ResolveUser`, linking only an address that is a verified identity in one of that customer's domains. `scim.WithGroupMapper` or `scim.ProjectRoles` carries the directory's groups into organizations or roles.

Check, per customer: one person signs in through the IdP and lands on their imported account (`/me` shows the imported id), and the IdP's provisioning log shows a successful push to the new SCIM URL.

## Step 6 — Cut over

1. Register your own OAuth applications at the providers WorkOS fronted (WorkOS's were WorkOS's) and configure the plugin with them.
2. Deploy; every user signs in again. WorkOS sessions and tokens do not move.
3. Switch each enterprise customer's IdP over (step 5) before WorkOS is turned off for them; a customer still pointing at WorkOS cannot sign in here.
4. Keep the WorkOS environment for a while, then remove it.

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `FAILED … auth: identity taken` | Two WorkOS users hold the same verified address (possible across environments) | Merge or drop one |
| The reset mail never arrives | The address was imported unverified | Verify it first, or use social or magic-link sign-in |
| An SSO sign-in answers `409 sso.account_exists` | The provider is not trusted, so the imported account with that address is not linked | Add it to `sso.TrustProviders`, or verify its domain |
| The IdP still sends people to WorkOS | Its ACS URL or redirect URI was not changed | Step 5, item 4 |
| A SCIM push answers `409 uniqueness` for an imported user | The address is already an identity and nothing decided to link it | `scim.ResolveUser`, step 5, item 6 |
| `workos: neither an array nor a {"data": [...]} page` | The file is a single user object or an error response | Save the list endpoint's response |

## Next

- [Email plugin](../plugins/email.md), [magic links](../plugins/magiclink.md), [OAuth](../plugins/oauth.md), [SSO](../plugins/sso.md), [SCIM](../plugins/scim.md).
- [Migrating](README.md) for the other sources.
