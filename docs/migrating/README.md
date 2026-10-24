# Migrating from another auth system

You have users somewhere else and want them here without asking every one of them to sign up again. Each guide below takes one source from its export to a tested import: the export command, what each field becomes, what happens to passwords, linked social accounts, phone numbers and authenticator apps, and the cutover checklist.

| Coming from | Guide | Passwords survive? |
|---|---|---|
| Auth0 | [auth0.md](auth0.md) | Yes, with the bcrypt export Auth0 provides on request |
| Clerk | [clerk.md](clerk.md) | Yes, the CSV export carries bcrypt digests |
| Supabase Auth | [supabase.md](supabase.md) | Yes, `auth.users.encrypted_password` is bcrypt |
| Auth.js / NextAuth | [authjs.md](authjs.md) | Auth.js stores none; your own credentials table can come along |
| WorkOS | [workos.md](workos.md) | No, WorkOS does not export hashes; users set one at first sign-in |

## How every import works

All five guides run the same program, [`examples/import-users`](../../examples/import-users), which reads one export format into a common shape and writes it through the library's own API, so the uniqueness rules, the plugins' data hooks and your column extensions apply to imported users exactly as they do to sign-ups, and nothing is written to an auth table by hand:

1. [`a.ImportUsers`](ds:block?id=core-importusers-9zk3wq6p) creates the user with its original id and sign-up time, its addresses, numbers and handle, each marked verified only when the source had verified it ([migrations and maintenance](../concepts/migrations-and-maintenance.md), step 8).
2. [`password.ImportHash`](ds:block?id=plugin-importhash-k2v7mq3x) stores the old hash string unchanged; the user signs in with the old password, which is re-hashed with argon2id in that same sign-in ([bringing passwords from another stack](../plugins/password.md#bringing-passwords-from-another-stack)).
3. `oauth.ImportAccount` links the social accounts the source had linked, so "Sign in with Google" lands on the same user.
4. [`twofactor.ImportTOTP`](ds:block?id=plugin-importtotp-h8n4rw2c) moves an authenticator secret when the source exports one; a secret that is not base32 is refused at import (`twofactor.secret_invalid`), never stored broken.
5. `admin.Grant` keeps who was an administrator, and [`admin.BanFor`](ds:block?id=plugin-banfor-m3x8vt5q) carries a ban over with its end date, so a user the old system had locked out stays locked out.

Each user is one transaction: a row whose address is taken, whose hash is in a format no verifier recognizes or whose linked account collides fails alone, leaves nothing behind and is listed in the summary; the rest land. No mail or text goes out during an import. Running the import twice refuses every user already imported (`auth.user_exists`) and changes nothing.

After the users, two more programs move what hangs off them: [`examples/import-orgs`](../../examples/import-orgs) loads Auth0 and Clerk organizations, members and roles into the [organization plugin](../plugins/organization.md) and Auth0's administrator roles into the [admin plugin](../plugins/admin.md) ([Auth0](auth0.md#step-5--organizations-and-roles), [Clerk](clerk.md#step-6--organizations)); [`examples/import-sso`](../../examples/import-sso) moves Supabase's SAML SSO providers into [`plugin/sso`](../plugins/sso.md) ([Supabase](supabase.md#step-5--sso-providers)). WorkOS SSO connections and Directory Sync are set up again per customer ([WorkOS](workos.md#step-5--sso-connections-and-directory-sync)), since WorkOS keeps their secrets.

What never moves: sessions (every user signs in again, as every migration guide of every provider says) and API tokens the old provider issued.

## Before any of them

- An app wired as in [your first app](../start/first-app.md), on the database the users will live in. The import program wires every plugin a user base may need; in your app, pass your own `auth.New` so your hooks and columns apply.
- The plugins for what the export carries: `plugin/password` with `AcceptLegacyHashes` for the hashes, `plugin/oauth` with the same providers configured (the import never calls a provider, but refuses to write an account for one you do not offer), `plugin/phone` for numbers, `plugin/username` for handles, `plugin/twofactor` with its key for authenticator secrets, `plugin/admin` for the flag.
- A dry run first (`-dry-run`): it reads and maps the whole export and prints the plan, including every password and account that would not be imported, without opening a transaction.
