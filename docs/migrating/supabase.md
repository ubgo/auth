# Migrate from Supabase Auth

You will have every Supabase user in your own database with the same UUID, their confirmed address or number, their bcrypt password working until it is re-hashed at the first sign-in, their Google or GitHub identity linked, their verified authenticator factor still working, super admins granted, bans carried over with their end dates, anonymous and deleted rows left behind, and, if you used Supabase's SAML SSO, every SSO provider with its metadata, domains and attribute mapping, so your enterprise customers' people keep signing in through their IdP.

## Before you start

- [Migrating](README.md) for what every import has in common, and an app wired as in [your first app](../start/first-app.md).
- The example program is [`examples/import-users`](../../examples/import-users); `go test ./import-users` in `examples/` runs it against a Supabase fixture.
- `psql` with the project's direct connection string (Dashboard, **Project Settings**, **Database**); the `auth` schema is readable with the `postgres` role.

## Step 1 — Export the three tables

Supabase keeps users in its `auth` schema. Copy out the users, their identities and their verified TOTP factors as CSV; Postgres writes booleans as `t`/`f`, nulls as empty cells and JSON as text, which is what the reader expects:

```sh
psql "$SUPABASE_DB_URL" <<'SQL'
\copy (SELECT id, email, encrypted_password, email_confirmed_at, phone, phone_confirmed_at, raw_user_meta_data, created_at, is_super_admin, banned_until, is_anonymous, deleted_at FROM auth.users) TO 'users.csv' CSV HEADER
\copy (SELECT user_id, provider, provider_id, identity_data FROM auth.identities) TO 'identities.csv' CSV HEADER
\copy (SELECT user_id, factor_type, status, secret FROM auth.mfa_factors WHERE factor_type = 'totp' AND status = 'verified') TO 'factors.csv' CSV HEADER
SQL
```

Check: `head -1 users.csv` starts with `id,email,encrypted_password`.

## Step 2 — What each field becomes

<!-- ds:block id=import-supabaserecord-5w7rj2kc -->
**supabaseRecord** · [`examples/import-users/supabase.go:125-154`](../../examples/import-users/supabase.go#L125-L154)

```go
func supabaseRecord(get func(string) string) record {
	var meta sbMeta
	_ = json.Unmarshal([]byte(get(sbColMeta)), &meta) // odd metadata only loses name and picture
	r := record{
		ID:           get(sbColID),
		Name:         firstNonEmpty(meta.FullName, meta.Name),
		Image:        firstNonEmpty(meta.AvatarURL, meta.Picture),
		CreatedAt:    parseTime(get(sbColCreatedAt)),
		PasswordHash: get(sbColPassword),
		Admin:        get(sbColSuperAdmin) == pgTrue,
	}
	// A ban still in force comes along with its end; one that has lapsed is
	// history Supabase kept, not a ban.
	if until := parseTime(get(sbColBannedUntil)); !until.IsZero() && until.After(now()) {
		r.Banned, r.BannedUntil, r.BanReason = true, until, sbBannedReason
	}
	switch {
	case get(sbColDeletedAt) != "":
		r.Skip = "deleted in Supabase"
	case get(sbColAnonymous) == pgTrue:
		r.Skip = "anonymous user, nothing to sign in with"
	}
	if e := get(sbColEmail); e != "" {
		r.Emails = []identifier{{Value: e, Verified: get(sbColEmailConfirmed) != "", Primary: true}}
	}
	if p := get(sbColPhone); p != "" {
		r.Phones = []identifier{{Value: "+" + strings.TrimPrefix(p, "+"), Verified: get(sbColPhoneConfirmed) != "", Primary: true}}
	}
	return r
}
```
<!-- /ds:block hash=325a6e -->

| Supabase | Here | Note |
|---|---|---|
| `auth.users.id` | `auth_user.id` | The UUID is kept as text, so `public` tables that reference it keep working |
| `email`, `email_confirmed_at` | an `email` identity, verified when confirmed, primary | |
| `phone`, `phone_confirmed_at` | a `phone` identity | Supabase stores numbers without the `+`; the reader adds it |
| `raw_user_meta_data.full_name` or `.name` | `auth_user.name` | What the OAuth provider or your sign-up form wrote there |
| `raw_user_meta_data.avatar_url` or `.picture` | `auth_user.image` | |
| `created_at` | `auth_user.created_at` | |
| `encrypted_password` | `auth_password.hash`, unchanged | bcrypt `$2a$10$`; verified by `password.Bcrypt()` and replaced with argon2id at the first sign-in |
| `auth.identities` with `provider` other than `email`/`phone` | an `auth_account` row | `provider_id` is the provider's subject; `identity_data.email` is kept as the account's address. Supabase's provider names (`google`, `github`, `apple`, `azure`) match the plugin's defaults except `azure`, which you configure under the name you choose |
| `auth.mfa_factors` with `factor_type = 'totp'`, `status = 'verified'` | the user's authenticator factor | Sealed with your key; an unverified factor was never finished and is left behind |
| `is_super_admin = t` | `admin.Grant` | The admin plugin's flag |
| `banned_until` in the future | a ban until that moment (`admin.BanFor`) with the reason `banned in Supabase` | Sign-in answers `admin.banned` until then; a `banned_until` already in the past is history and is not imported |
| `is_anonymous = t` | skipped | An anonymous user has no identifier and no credential, nothing they could come back with; the [anonymous plugin](../plugins/anonymous.md) starts fresh guests here |
| `deleted_at` set | skipped | |
| `auth.identities` with `provider` `sso:<uuid>` | nothing; listed as `account sso:… not imported` | The SSO link is re-made at the user's first SSO sign-in, [step 5](#step-5--sso-providers) |
| `auth.sso_providers`, `auth.saml_providers`, `auth.sso_domains` | `plugin/sso` providers | [Step 5](#step-5--sso-providers) |
| `raw_app_meta_data`, `last_sign_in_at`, `invited_at` | not imported | Your tables, joined on the kept id |

Check: `go run ./import-users -source supabase -file users.csv -identities identities.csv -factors factors.csv -dry-run` prints the counts and a `skip` line per anonymous or deleted row.

## Step 3 — Wire the plugins

The same wiring as the [Auth0 guide](auth0.md#step-3--wire-the-plugins-the-export-needs), step 3: `password.AcceptLegacyHashes(password.Bcrypt())`, the oauth providers under Supabase's names, `plugin/phone` for numbers, `AUTH_TOTP_KEY` for the factors, `plugin/admin` for the super admins and the bans.

## Step 4 — Import

```sh
AUTH_TOTP_KEY=$(openssl rand -hex 32) go run ./import-users -source supabase \
  -file users.csv -identities identities.csv -factors factors.csv -db app.db
```

```text
imported 3 user(s), 0 failed, 2 skipped
  skip   0b1f1c1e-0000-4000-8000-000000000003: anonymous user, nothing to sign in with
  skip   erin@example.com: deleted in Supabase
```

Check: `select count(*) from auth_user` is the number of non-anonymous, non-deleted users; a super admin has `admin_granted_at` set, a banned user `admin_banned_at` and `admin_ban_expires_at`.

## Step 5 — SSO providers

Skip this step if the project never ran `supabase sso add`. Supabase keeps each SAML provider in three tables; copy them out too:

```sh
psql "$SUPABASE_DB_URL" <<'SQL'
\copy (SELECT id, resource_id FROM auth.sso_providers) TO 'sso_providers.csv' CSV HEADER
\copy (SELECT sso_provider_id, entity_id, metadata_xml, metadata_url, attribute_mapping, name_id_format FROM auth.saml_providers) TO 'saml_providers.csv' CSV HEADER
\copy (SELECT sso_provider_id, domain FROM auth.sso_domains) TO 'sso_domains.csv' CSV HEADER
SQL
```

[`examples/import-sso`](../../examples/import-sso) registers each one with [`plugin/sso`](../plugins/sso.md) through `RegisterProvider`, so the metadata is checked as it would be for a new registration, and owned by an imported administrator (`-owner`). It keeps Supabase's SP entity id (`https://<ref>.supabase.co/auth/v1/sso/saml/metadata`), so at the IdP only the ACS URL changes, and maps the attribute mapping onto the plugin's:

<!-- ds:block id=samlmapping-9t3pv6hd -->
**samlMapping** · [`examples/import-sso/main.go:203-240`](../../examples/import-sso/main.go#L203-L240)

```go
func samlMapping(raw string) (sso.SAMLMapping, []string, error) {
	var out sso.SAMLMapping
	var m supabaseMapping
	if raw == "" {
		return out, nil, nil
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return out, nil, fmt.Errorf("attribute_mapping: %w", err)
	}
	var notes []string
	keys := slices.Sorted(maps.Keys(m.Keys))
	for _, k := range keys {
		attr := m.Keys[k].Name
		if names := m.Keys[k].Names; attr == "" && len(names) > 0 {
			attr = names[0]
			if len(names) > 1 {
				notes = append(notes, fmt.Sprintf("%s: kept the first of %d attribute names (%s)", k, len(names), attr))
			}
		}
		switch {
		case attr == "":
		case k == "email":
			out.Email = attr
		case k == "name":
			out.Name = attr
		case k == "first_name" || k == "given_name":
			out.FirstName = attr
		case k == "last_name" || k == "family_name":
			out.LastName = attr
		default:
			if out.ExtraFields == nil {
				out.ExtraFields = map[string]string{}
			}
			out.ExtraFields[k] = attr
		}
	}
	return out, notes, nil
}
```
<!-- /ds:block hash=671122 -->

```sh
AUTH_SECRET=… go run ./import-sso -providers sso_providers.csv -saml saml_providers.csv -domains sso_domains.csv \
  -sp-entity-id https://<ref>.supabase.co/auth/v1/sso/saml/metadata -owner <admin user id> -base-url https://app.example.com -db app.db
```

```text
imported 1 provider(s), 1 failed
  ok     example-okta: example.com, example.org (IdP https://idp.example.com/saml)
  note   example-okta: department: kept the first of 2 attribute names (dept)
  FAILED supabase-5a1b2c3d-0000-4000-8000-00000000000b: no metadata_xml (metadata_url "https://login.globex.test/saml/metadata"): fetch the XML and put it in the CSV
```

`AUTH_SECRET` must be the one the app runs with, and `-base-url` its production URL, since the ACS URL is built from it. A provider keeps its `resource_id` as its id, else `supabase-<uuid>`.

Then name the imported providers in the app's `sso.TrustProviders(...)`. An imported provider is not domain-verified here, and without trust a user imported with a verified address in its domain is refused at their first SSO sign-in with `sso.account_exists` rather than linked; with it, that sign-in links the IdP account to the imported user. Supabase had already accepted those domains, so trusting them keeps the behaviour; [domain verification](../plugins/sso.md#domain-verification) is the alternative.

Check: `GET /auth/sso/providers` as the owner lists each provider with its `acsURL` and `spMetadataURL`, and a sign-in with an address in one of its domains (`POST /auth/sso/sign-in`) answers the IdP's URL.

## Step 6 — Cut over

1. Supabase's OAuth applications were registered to `https://<ref>.supabase.co/auth/v1/callback`; add your callback to the same applications (or create your own and keep the client ids where the provider lets you), so the subjects in `provider_id` match.
2. Deploy; every user signs in again. Supabase JWTs and refresh tokens do not move.
3. Row-level security policies keyed on `auth.uid()` are a database feature of Supabase's JWT; with the library your app enforces access in Go with `auth.CurrentUser(ctx)`, and your `public` tables keep the same user ids.
4. SSO, per provider: send the customer's IdP admin the new ACS URL (`https://app.example.com/auth/sso/saml2/sp/acs`) to replace `https://<ref>.supabase.co/auth/v1/sso/saml/acs`; the SP entity id stays, so nothing else changes at the IdP. Agree a moment, because between the IdP change and your deploy one side answers for the other. An IdP-initiated sign-in (a tile on the Okta dashboard), which Supabase accepted, is off by default here because an unsolicited response is bound to no browser: turn it on with `sso.WithSAMLOptions(sso.SAMLOptions{AllowIdPInitiated: true})` only if customers use it, and give the IdP the provider id as its default RelayState, or use `sso.PerProviderPaths()` ([one URL per provider](../plugins/sso.md#one-url-per-provider)).
5. SSO, after the switch: have one person per customer sign in through the IdP and check they land on their existing account (`created: false`), not a new one.
6. Retire the Supabase project once the first sign-ins have gone through.

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `FAILED … auth: identity taken` | Two users share a confirmed address (Supabase allows it when linking is manual) | Merge or drop one |
| `FAILED … account google: … already linked` | The same provider subject appears under two users | Decide which user owns it |
| `note … account azure not imported: provider not configured` | The plugin has no provider under Supabase's name | Configure the OIDC provider under that name |
| `FAILED <provider>: no metadata_xml (metadata_url …)` | Supabase fetched that IdP's metadata from a URL | Download the XML into the `metadata_xml` cell and run import-sso again |
| `FAILED <provider>: sso.provider_exists` | The provider was imported by an earlier run | Nothing to do; delete it (`POST /auth/sso/delete-provider`) first to re-import |
| An SSO sign-in answers `409 sso.account_exists` | The provider is not trusted, so an existing account is not linked by email | Add the provider id to `sso.TrustProviders`, or verify its domain |
| The IdP shows "invalid destination" or `sso.saml_*` errors after the switch | The IdP still posts to Supabase's ACS, or `-base-url` was not the production URL | Update the ACS at the IdP; re-import with the right `-base-url` |
| `note … account sso:… not imported` from import-users | Supabase's SSO identities are not OAuth accounts | Expected: the link is re-made at the first SSO sign-in |
| A phone-only user cannot recover | They have no address to mail a reset to | Wire `password.ResetByCode()` and the phone plugin's SMS sender ([password](../plugins/password.md)) |

## Next

- [Password plugin](../plugins/password.md), [phone plugin](../plugins/phone.md), [admin plugin](../plugins/admin.md), [SSO plugin](../plugins/sso.md).
- [Migrating](README.md) for the other sources.
