# Migrate from Auth.js (NextAuth)

You will have every Auth.js user in your own database with the same id, their address (verified when Auth.js had verified it), their Google, GitHub or other OAuth accounts linked so the same sign-in lands on the same user, and a map from Auth.js's four tables to the library's. Sessions and verification tokens are not moved, and Auth.js has no passwords to move.

## Before you start

- [Migrating](README.md) for what every import has in common, and an app wired as in [your first app](../start/first-app.md).
- The example program is [`examples/import-users`](../../examples/import-users); `go test ./import-users` in `examples/` runs it against an Auth.js fixture.
- Auth.js's tables live wherever your adapter put them (Prisma, Drizzle, TypeORM, Kysely, a Postgres schema); the export below is `psql`, and any ORM's "dump table as JSON" gives the same two arrays.

## Step 1 — Export users and accounts

Two JSON arrays, one per table. The column names below are the Auth.js adapter defaults; a Prisma schema with `@map` names may differ, so check yours:

```sh
psql "$DATABASE_URL" -At -c 'select json_agg(u) from "users" u' > users.json
psql "$DATABASE_URL" -At -c 'select json_agg(a) from "accounts" a' > accounts.json
```

Sessions are not exported: every migration signs everyone out. Verification tokens are minutes old by design.

Check: `jq length users.json` is your user count; `jq '.[0] | keys' accounts.json` shows `provider`, `providerAccountId`, `type`, `userId`.

## Step 2 — What each table becomes

<!-- ds:block id=import-readauthjs-2p6zm9vt -->
**readAuthJS** · [`examples/import-users/authjs.go:45-72`](../../examples/import-users/authjs.go#L45-L72)

```go
func readAuthJS(in input) ([]record, error) {
	var users []authjsUser
	if err := json.NewDecoder(in.Main).Decode(&users); err != nil {
		return nil, fmt.Errorf("auth.js users: %w", err)
	}
	accounts := map[string][]account{}
	if in.Identities != nil {
		var accs []authjsAccount
		if err := json.NewDecoder(in.Identities).Decode(&accs); err != nil {
			return nil, fmt.Errorf("auth.js accounts: %w", err)
		}
		for _, a := range accs {
			if !authjsOAuthTypes[a.Type] {
				continue
			}
			accounts[a.UserID] = append(accounts[a.UserID], account{Provider: a.Provider, AccountID: a.ProviderAccountID})
		}
	}
	out := make([]record, 0, len(users))
	for _, u := range users {
		r := record{ID: u.ID, Name: u.Name, Image: u.Image, Accounts: accounts[u.ID]}
		if u.Email != "" {
			r.Emails = []identifier{{Value: u.Email, Verified: u.EmailVerified != "", Primary: true}}
		}
		out = append(out, r)
	}
	return out, nil
}
```
<!-- /ds:block hash=ab0fa3 -->

| Auth.js table and column | Here | Note |
|---|---|---|
| `users.id` | `auth_user.id` | Kept |
| `users.name`, `users.image` | `auth_user.name`, `auth_user.image` | |
| `users.email`, `users.emailVerified` (a timestamp or null) | an `email` identity, verified when the timestamp is set | Auth.js sets `emailVerified` when a magic link was used, and some providers set it at sign-in; null stays unverified |
| `accounts` with `type` `oauth` or `oidc` | an `auth_account` row: `provider`, `providerAccountId` | The provider ids (`google`, `github`) are the names the plugin's providers use by default |
| `accounts.access_token`, `refresh_token`, `expires_at`, `id_token` | not imported | They were issued to the Auth.js client id; the user re-consents at the first sign-in and the plugin stores fresh tokens if `oauth.StoreTokens` is on |
| `accounts` with `type` `email` or `credentials` | nothing | A magic-link "account" is the user's address, already imported; a credentials account points at your own password table |
| `sessions` (`sessionToken`, `expires`) | nothing | `auth_session` starts empty; every user signs in again |
| `verification_tokens` (`identifier`, `token`, `expires`) | nothing | `auth_verification` holds the library's own, hashed |

Passwords: Auth.js never stored them. If your Credentials provider checked a `password_hash` column of your own, export `(user_id, password_hash)` beside the users and call `password.ImportHash` for each, with `password.AcceptLegacyHashes` listing the format you used (`password.Bcrypt()` for `bcryptjs`, `password.Scrypt(...)` for a scrypt of your own); the import program's `record.PasswordHash` is where it goes.

Check: `go run ./import-users -source authjs -file users.json -identities accounts.json -dry-run` prints `would import N user(s)`.

## Step 3 — Sessions: database or stateless

Auth.js offered two session strategies. Both have an equivalent here, chosen at wiring, with the same routes either way:

| Auth.js | Here |
|---|---|
| `strategy: "database"` (a `sessions` row per sign-in) | the default: `auth_session` rows, listable and revocable (`GET /auth/sessions`, `POST /auth/sessions/revoke`) |
| `strategy: "jwt"` (a signed cookie, no table) | `auth.WithStatelessSessions(key)`: a sealed token, the user loaded per request, revoked for everyone at once through `sessions_valid_after` ([sessions](../concepts/sessions.md)) |

## Step 4 — Import

```sh
go run ./import-users -source authjs -file users.json -identities accounts.json -db app.db
```

```text
imported 2 user(s), 0 failed, 0 skipped
```

Check: a user with a `google` account row signs in with Google (same OAuth application, see below) and lands on their imported user, not a new one.

## Step 5 — Cut over

1. Add the library's callback, `https://your-app/auth/oauth/<provider>/callback`, to the same OAuth applications Auth.js used, so the `providerAccountId` values match what the provider returns. A new application at Google keeps the same subjects for the same project; at GitHub the user id is global.
2. Replace `signIn()` / `signOut()` / `useSession()` in the frontend with `fetch` against `POST /auth/oauth/<provider>/start`, `POST /auth/sign-out` and `GET /auth/session` ([SPA frontends](../integrations/spa-frontends.md)); replace `auth()` on the server with the Go handler's `authhttp.CurrentUser(r)` ([net/http](../integrations/net-http.md)).
3. Deploy; every user signs in again.

## What can go wrong

| You see | Why | Fix |
|---|---|---|
| `FAILED … account google: … already linked` | Two users rows share one `providerAccountId` (Auth.js's `allowDangerousEmailAccountLinking` off, a user signed up twice) | Decide which user owns it |
| Google sign-in creates a new user | A different OAuth application, so the subject changed; or the account row was `type: "oauth"` under a provider the plugin does not know | Reuse the application; configure the provider under Auth.js's id |
| An unverified address cannot receive the reset mail | `emailVerified` was null | The user signs in with their provider first, then verifies the address from settings |

## Next

- [OAuth plugin](../plugins/oauth.md), [sessions](../concepts/sessions.md), [databases](../concepts/databases.md) for the library's tables.
- [Migrating](README.md) for the other sources.
