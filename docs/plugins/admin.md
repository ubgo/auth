# Admin operations

You will have an app whose operators can find a user, see their identities and sessions, create a user, set a user's password or address, ban and unban them (with a message the banned user reads at sign-in), end their sessions, grant and remove admin rights, act as a user for support and come back to their own session, and read the audit log, all through routes the library serves and with limits a stolen admin session cannot cross.

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md). The admin plugin needs no other plugin.
- The example is [`examples/admin-ops`](../../examples/admin-ops): the admin and [audit](audit.md) plugins on the quick start, plus a `grant` subcommand and one page, `/me`, that says who a session belongs to. `go run ./admin-ops` in `examples/` serves it on `localhost:8081`; `go test ./admin-ops` runs the flow below. [`examples/admin-plan`](../../examples/admin-plan) is the companion: an admin page of the app's own that joins the plugin's columns to the app's tables.
- What an admin is: a user whose `admin_granted_at` column is set. There is one level, no roles. Every operation first refuses a caller who is not an admin with `403 admin.forbidden`, before it looks at the target, so a non-admin learns nothing about who exists.
- Several routes need a fresh sign-in: a session created within the last [ten minutes](ds:block?id=defaultfreshwindow-5mt8jqw7) (`auth.WithFreshWindow` changes it). An admin who has been signed in longer gets `403 auth.fresh_session_required` and signs in again.

## Step 1 — Wire the plugin

Who is an admin is data, not configuration; the options set defaults and messages. The example passes `admin.BannedMessage` (step 4). Keep the returned plugin; the first grant needs it. At `Init` the plugin finds the registered password plugin (to set passwords), email plugin (to set addresses) and audit log (to record Go-side bans and read the log: `admin.EventRecorder` and `admin.EventQuerier`, which `*audit.Plugin` satisfies and so does any audit backend of your own with the same two methods) by interface, so there is nothing to wire for `create-user`, `set-password`, `set-email` or `audit`.

<!-- ds:block id=newauth-tj6fup6p -->
**newAuth** · [`examples/admin-ops/main.go:125-133`](../../examples/admin-ops/main.go#L125-L133)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, *admin.Plugin, error) {
	ad := admin.New(admin.BannedMessage(bannedMessage))
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad, audit.New()),
	)
	return a, ad, err
}
```
<!-- /ds:block hash=19862c -->

Check: `a.Migrate` adds four columns to `auth_user`: `admin_granted_at`, `admin_banned_at`, `admin_ban_reason` and `admin_ban_expires_at`.

## Step 2 — Grant the first admin from Go

Nobody can grant admin rights over HTTP before an admin exists, so the first one comes from code: a subcommand, a seed, a one-off job. `Grant` takes a user id; the example resolves a verified address first, because granting admin to whoever typed an address at sign-up would be a takeover.

<!-- ds:block id=grantbyemail-2uubrheb -->
**grantByEmail** · [`examples/admin-ops/main.go:156-162`](../../examples/admin-ops/main.go#L156-L162)

```go
func grantByEmail(ctx context.Context, a *auth.Auth, ad *admin.Plugin, address string) (string, error) {
	idn, err := a.FindIdentity(ctx, email.KindEmail, address, true)
	if err != nil {
		return "", fmt.Errorf("find a verified %s: %w", address, err)
	}
	return idn.UserID, ad.Grant(ctx, idn.UserID)
}
```
<!-- /ds:block hash=d75539 -->

<!-- ds:block id=plugin-grant-x65z5qqa -->
**Plugin.Grant** · [`plugin/admin/admin.go:551-557`](../../plugin/admin/admin.go#L551-L557)

```go
func (p *Plugin) Grant(ctx context.Context, userID string) error {
	if _, err := p.core.User(ctx, userID); err != nil {
		return err
	}
	now := p.core.Now()
	return auth.SetUserColumn(ctx, p.core, PluginName, userID, GrantedAt, &now)
}
```
<!-- /ds:block hash=6909a2 -->

Alice signs up and runs the command before and after verifying her address:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
go run ./admin-ops grant alice@example.com
curl -s -b alice.txt -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"E7dg-fIBAeGJHCzp47QNRkP_mZ01I48tY3O0Bq87tv0"}'
go run ./admin-ops grant alice@example.com
```

```text
{"user":{"id":"usr_gejihnupfzjajqbl5xi6aguc","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
2026/10/01 10:49:12 find a verified alice@example.com: auth.identity_not_found
exit status 1
{"email":"alice@example.com"}
alice@example.com (usr_gejihnupfzjajqbl5xi6aguc) is an admin
```

Check: `Grant` of an unknown id is `auth.user_not_found`; the example's `grant` of an unverified address fails with `auth.identity_not_found`, as the first run above shows.

An app that routes a word of its command line to [`authcli`](../integrations/cli.md) (the example routes `auth`) has the same without writing it: `go run ./admin-ops auth admin grant --email alice@example.com` resolves the verified address and grants, and `echo "$ADMIN_PASSWORD" | go run ./admin-ops auth admin create --email root@example.com --name Root --password-stdin` creates the first admin outright, with a verified address and the password from stdin, in one transaction. Both take `--dry-run` and `--json`, exit 1 on failure and 2 on a usage error, and find this plugin, the email plugin and the password plugin by interface (`authcli.AdminGranter`, `AddressSetter`, `PasswordSetter`), so nothing is registered for them; the transcript is in the [CLI guide](../integrations/cli.md#step-7--make-the-first-admin).

## Step 3 — Find users

`GET /auth/admin/users` lists users newest first, [50](ds:block?id=defaultpagesize-k5wq5psj) a page by default (or the app's `auth.WithDefaultPageSize`, as for every list, and `all-sessions` too) and [200](ds:block?id=maxpagesize-9qpk2wp4) at most; a larger `limit` is clamped, not refused. `query` matches one thing exactly: a normalized identifier (an address, a phone number, a username) or a user id. It never matches a fragment; fragments go to `search-users` below, which has its own rate rule, because a search that lists every address starting with "a" turns one stolen admin session into an enumeration tool and deserves its own budget.

Bob, not an admin, is refused; Alice pages, searches by address and by id:

```sh
curl -s -b bob.txt localhost:8081/auth/admin/users
curl -s -b alice.txt 'localhost:8081/auth/admin/users?limit=1'
curl -s -b alice.txt 'localhost:8081/auth/admin/users?query=Bob@Example.com'
curl -s -b alice.txt 'localhost:8081/auth/admin/users?query=bob'
```

```json
{"error":{"code":"admin.forbidden","message":"Only an administrator can do this."}}
{"users":[{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","createdAt":"2026-10-01T05:19:13.766596Z","admin":false,"banned":false}],"total":2,"page":1,"limit":1}
{"users":[{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","createdAt":"2026-10-01T05:19:13.766596Z","admin":false,"banned":false}],"total":1,"page":1,"limit":50}
{"users":[],"total":0,"page":1,"limit":50}
```

`GET /auth/admin/user?userId=` shows one user with their identities and live session count:

```sh
curl -s -b alice.txt 'localhost:8081/auth/admin/user?userId=usr_u6zvrbzlaexjc5l3tfvcvpri'
```

```json
{"user":{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","createdAt":"2026-10-01T05:19:13.766596Z","admin":false,"banned":false},"banReason":"","identities":[{"kind":"email","value":"bob@example.com","verified":false,"primary":false}],"sessions":1}
```

From Go: `ad.Users(ctx, admin.UsersRequest{Query: "bob@example.com"})` and `ad.User(ctx, userID)`, with a `ctx` that carries the admin's request.

`GET /auth/admin/search-users?value=&field=&operator=` finds users by a fragment, with the same `page`, `limit`, `offset`, `sort`, `admin` and `banned` as the list and the same result:

- `field` is `email` (the default) or `name`; `operator` is `contains` (the default), `starts_with` or `ends_with`; `value` is 1 to [320](ds:block?id=maxsearchlength-r7d4kq2n) characters after trimming.
- An `email` search reads the user's email addresses, verified or not, and ignores case: addresses are stored folded, and the value is folded the same way in Go before an exact comparison, so `BOB` finds `bob@example.com` on every engine.
- A `name` search matches the name as stored, case included: names have no normalized form and the library never folds case in SQL, so `bo` does not find `Bob`. On SQLite, whose `LIKE` ignores ASCII case, it runs as `GLOB` so the answer is the same as on Postgres and MySQL.
- Every character of `value` is text: `%`, `_`, `!`, `*`, `?` and `[` match themselves, never "anything".
- It allows [30](ds:block?id=defaultsearchlimit-p3w8zn6c) searches a minute per IP by default (`admin.SearchRate(limit, window)` to change; a limit below one is refused at `auth.New`).

The example's test runs these against the server: `search-users?value=BOB` finds Bob, `field=name&operator=starts_with&value=bo` finds nobody, `value=%` finds nobody, and Bob, not an admin, is `admin.forbidden`. From Go: `ad.SearchUsers(ctx, admin.SearchUsersRequest{Value: "bob", Field: admin.SearchEmail, Operator: admin.SearchContains})`.

**Filter and sort by field.** `users` and `search-users` also take `filterField`, `filterOperator`, `filterValue`, `sortBy` and `sortDirection`:

- `filterField` is one of `email` (the default), `emailVerified`, `id`, `name`, `role`, `banned`, `banReason`, `banExpires`, `createdAt`, `updatedAt` (`admin.FilterFieldValues`). Each field takes the operators that mean something for it (`admin.FilterOperatorsOf`): text fields `eq` (the default), `ne`, `in`, `not_in`, `contains`, `starts_with`, `ends_with`; `id` and `role` `eq`, `ne`, `in`, `not_in`; flags `eq`, `ne`; times `eq`, `ne`, `lt`, `lte`, `gt`, `gte`.
- `filterValue` is the value: comma-joined for `in` and `not_in` (at most 200 values), `true` or `false` for a flag, RFC 3339 for a time. Without it nothing is filtered, but an unknown field or operator is still refused.
- `email` compares the user's addresses folded, as the search does; `ne` and `not_in` mean "holds no such address", which includes users with none. `name`, `id` and `banReason` keep case on every engine. `role` follows the roles a user holds: the stored ones, the `admin` role of a granted user or one in `AdminIDs`, and the default role only for a user with neither. `banExpires` never matches a ban with no end.
- `sortBy` is `createdAt`, `updatedAt`, `name` or `id`, ascending unless `sortDirection=desc`; it replaces `sort`, and naming both is `admin.bad_sort`. Email is not a sort field: a user may hold several addresses.

```sh
curl -s -b alice.txt 'localhost:8081/auth/admin/users?filterField=createdAt&filterOperator=gte&filterValue=2026-10-01T00:00:00Z&sortBy=name&sortDirection=desc'
curl -s -b alice.txt 'localhost:8081/auth/admin/users?filterField=role&filterOperator=in&filterValue=admin,support'
```

From Go: `ad.Users(ctx, admin.UsersRequest{FilterField: admin.FilterBanned, FilterValue: &yes, SortBy: admin.SortByUpdatedAt, SortDirection: admin.SortDesc})`.

**Address and roles.** Every user row also carries `email`, the user's primary email address (else their earliest email identity, verified or not, so a user awaiting verification still shows one; empty when they have none), and `roles`, every role they hold by the same rules the permission check uses (stored roles, the admin flag's role, else the default role). Both are loaded for the whole page with one query each, never per row, and the single-user read (`GET /auth/admin/user`) carries them too.

**Last active.** Every user row carries `lastActiveAt`, the last-active time: the latest `last_seen_at` among the user's sessions, refreshed by the session slide. It is derived from the session rows rather than written to a column on every request. With sessions in the database it reads every row the table still holds, expired and revoked ones included, so it reaches back as far as `auth sweep` (and `auth.WithSessionArchive`'s retention) allows; with another session store it reads the user's live sessions; in stateless mode only the caller's own row has one. `null` means no session record is left.

## Step 4 — Ban and unban

`POST /auth/admin/ban` sets `admin_banned_at`, the reason and, for a temporary ban, `admin_ban_expires_at`, and deletes every session of the user. The ban is also a session check: the plugin adds "not banned, or the ban has expired" to every session lookup, evaluated per lookup, so a session made later does not work either, on every instance, and a temporary ban stops blocking the moment it passes. Deleting the sessions also evicts the user's entries from a server-side session cache (memory, contrib/redis) after the commit, so a cached device is refused on its next request; a client-held cache copy (snapshot, compact, JWT) keeps working until it expires.

<!-- ds:block id=plugin-sessionpredicates-smtxeyuk -->
**Plugin.SessionPredicates** · [`plugin/admin/admin.go:508-510`](../../plugin/admin/admin.go#L508-L510)

```go
func (p *Plugin) SessionPredicates() []sqlb.Predicate {
	return []sqlb.Predicate{notBanned(p.core.Now())}
}
```
<!-- /ds:block hash=82df5f -->

From [`examples/admin-plan`](../../examples/admin-plan/README.md), Alice bans Bob, his session stops at once, and she lifts the ban:

```sh
O='Origin: http://localhost:8081'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/ban -H "$O" -d '{"userId":"usr_tldnrp5dzgjvjs3alrynvgtm","reason":"chargeback"}'
curl -s -b bob.txt localhost:8081/auth/session
curl -s -b alice.txt -X POST localhost:8081/auth/admin/unban -H "$O" -d '{"userId":"usr_tldnrp5dzgjvjs3alrynvgtm"}'
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"ok":true}
```

The reason is cut to [300](ds:block?id=maxreasonlength-s6upfze5) characters, so it fits the column on every engine. `unban` clears the ban and its reason; the sessions the ban ended stay ended, and Bob signs in again.

While banned, Bob is told so at sign-in — but only once he has proved his password. The refusal is a data hook on the session write, so it covers every sign-in method (password, emailed code, magic link, passkey, OAuth, a pending second-factor session) and fires after the method proved the credential: a stranger guessing at Bob's address gets the ordinary wrong-credential answer and learns nothing about the ban. `admin.BannedMessage` composes the text from the ban; the example says why and, for a temporary ban, until when:

<!-- ds:block id=bannedmessage-mz3a85wp -->
**bannedMessage** · [`examples/admin-ops/main.go:140-149`](../../examples/admin-ops/main.go#L140-L149)

```go
func bannedMessage(_ context.Context, b admin.Ban) string {
	msg := "Your account is suspended"
	if b.Reason != "" {
		msg += ": " + b.Reason
	}
	if b.ExpiresAt != nil {
		msg += " (until " + b.ExpiresAt.Format(time.RFC1123) + ")"
	}
	return msg + "."
}
```
<!-- /ds:block hash=9d7ea7 -->

```sh
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"not it"}'
```

```json
{"error":{"code":"admin.banned","message":"Your account is suspended: chargeback."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
```

Without the option the message is ["This account is banned."](ds:block?id=defaultbannedmessage-wjzk8uve); the code is `403 admin.banned` either way.

An admin cannot be banned. Remove their rights first (step 6), so one stolen admin session cannot lock every other admin out:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/ban -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","reason":"spam"}'
```

```json
{"error":{"code":"admin.admin_target","message":"Remove this user's admin rights first."}}
```

A ban that comes from code rather than from an admin's session, an import carrying another system's bans or a job acting on a fraud signal, is `ad.BanFor(ctx, userID, reason, until)` from Go, in the spirit of `Grant`: no signed-in admin, no route. A zero `until` is permanent; otherwise the ban lifts at `until`. It ends the user's sessions like the route, refuses an admin the same way, and when an audit log is registered (the [audit plugin](audit.md), or anything implementing `admin.EventRecorder`) it records an `admin.ban` event with no actor and the user as subject, in the same transaction, so the log still says the ban happened.

## Step 5 — End a user's sessions

For a suspected stolen session, `POST /auth/admin/revoke-sessions` ends every session of the user without banning them. Bob's cookie stops working and he signs in again:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/revoke-sessions -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri"}'
curl -s -b bob.txt localhost:8081/me
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"user":{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

**Every session at once.** `GET /auth/admin/all-sessions?page=&limit=&offset=&userId=` pages through every live session of every user, most recently used first, for a session monitor: each row has `id`, `userId`, `impersonated`, `ip`, `userAgent`, `createdAt`, `lastSeenAt` and `expiresAt`, and `total` counts them. `userId` narrows it to one user. End one with `revoke-session {userId, sessionId}` and all of a user's with `revoke-sessions`. It needs `session:list`. It reads the `auth_session` table, so it answers `409 admin.sessions_not_listable` when sessions live elsewhere (`auth.WithSessionStore` with memory, Redis, a mirror or a custom store, or stateless sessions) rather than an empty page that would read as "nobody is signed in". From Go: `ad.AllSessions(ctx, admin.AllSessionsRequest{Limit: 50})`.

## Step 6 — Grant and remove admin rights

`POST /auth/admin/set-admin` with `{"userId": …, "admin": true}` grants, `false` removes. Granting someone who is already an admin, or removing a non-admin, succeeds and changes nothing. The last admin cannot be removed, so the app is never left with nobody who can grant the rights back:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-admin -H "$O" -d '{"userId":"usr_gejihnupfzjajqbl5xi6aguc","admin":false}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-admin -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","admin":true}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-admin -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","admin":false}'
```

```json
{"error":{"code":"admin.last_admin","message":"Keep at least one administrator."}}
{"ok":true}
{"ok":true}
```


**Roles and permissions.** Every admin operation asks the plugin's `admin.Authorizer` for a permission of `admin.DefaultStatements`, passing the caller's roles: `users` and `search-users` need `user:list`, `user` `user:get`, `ban` and `unban` `user:ban`, `set-admin` and `set-role` `user:set-role`, `impersonate` `user:impersonate`, `create-user`, `update-user`, `remove-user`, `set-password` and `set-email` their `user:` action, `sessions` and `all-sessions` `session:list`, `revoke-session` and `revoke-sessions` `session:revoke`. Roles live in `auth_user.admin_role`, comma-joined. The staff flag is unchanged and is the default: an admin granted as above (or listed in `AdminIDs`) holds the `admin` role, which grants everything except `impersonate-admins`; everyone else holds `user`, which grants nothing (`admin.DefaultRole` changes it).

`POST /auth/admin/set-role {"userId": …, "role": "support"}` (or `["support","user"]`) stores roles and keeps the flag in step, so a role in `admin.AdminRoles` (default `admin`) makes an admin and taking the last admin's is `409 admin.last_admin`; an unknown role is `400 admin.bad_role`. `POST /auth/admin/has-permission {"permissions": {"user": ["ban"]}}` answers `{"success": …}` for the caller, or for `userId` when the caller has `user:get`. From Go: `SetRoleFor` (no caller), `RolesOf`, and `CheckRolePermission(ctx, role, perms)`, which needs no database. Roles of your own come from the `accessadmin` adapter of the [access](access.md) module, `admin.WithAuthorizer(accessadmin.MustNew(accessadmin.DefaultAccessControl, roles))`, built from `accessadmin.DefaultAccessControl` or your own vocabulary; any other model (a policy engine, a relationship store, attributes) plugs in through `admin.WithAuthorizer` the same way, and an error from it refuses ([bring your own authorization](../extending/11-authorization.md)). Impersonating an admin is allowed to a role with `user:impersonate-admins`, as well as by `AllowImpersonatingAdmins`. `TestR30_AdminRoles` runs a support role, an admin role of the app's and the flag on the three engines.

[`examples/authorizer`](../../examples/authorizer) adds that support role to an app: it may list and read users and their sessions, nothing else.

<!-- ds:block id=authz-adminauthorizer-2k7xv9pm -->
**adminAuthorizer** · [`examples/authorizer/main.go:100-107`](../../examples/authorizer/main.go#L100-L107)

```go
func adminAuthorizer() *accessadmin.Authorizer {
	ac := accessadmin.DefaultAccessControl
	support := ac.MustRole(access.Permissions{
		admin.ResourceUser:    {admin.ActionList, admin.ActionGet},
		admin.ResourceSession: {admin.ActionList},
	})
	return accessadmin.MustNew(ac, map[string]access.Role{roleSupport: support})
}
```
<!-- /ds:block hash=eba011 -->

The first admin is granted from Go, gives Sam the role with `set-role`, and Sam's `users` answers while his `ban` is `403 admin.forbidden`; `set-role` with a role nobody defined is `400 admin.bad_role`. Check: `TestAuthorizer_SupportRole`.

## Step 7 — Create a user, set a password, set an address

`POST /auth/admin/create-user` makes a user through the core and gives it the address through the email plugin and the password through the password plugin, so every rule those plugins enforce applies to an admin-created user too: address uniqueness, one address per user, password length and policies, the breached-password check. It is one transaction, so a refused password leaves no user. `verified: true` makes the address verified and primary at once, for an admin who knows it is the person's; without it the usual verify link goes out. `password` is optional; without one the user sets theirs through the forgot flow.

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/create-user -H "$O" -d '{"name":"Carol","email":"carol@example.com","password":"short"}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/create-user -H "$O" -d '{"name":"Carol","email":"carol@example.com","verified":true,"password":"correct horse battery staple"}'
curl -s -c carol.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"carol@example.com","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"password.too_short","message":"Choose a longer password."}}
{"user":{"id":"usr_rbowbyjbsbaupkb3tdktw6kh","name":"Carol","image":""}}
{"user":{"id":"usr_rbowbyjbsbaupkb3tdktw6kh","name":"Carol","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

`POST /auth/admin/set-password` sets a user's password with the same rules; every session of the user ends and open reset links are spent, because whoever holds them may not be the person the password is being set for. `POST /auth/admin/set-email` gives a user an address: it replaces the address when the email plugin allows one per user, adds one under `email.Multiple()`, and `verified` makes it primary at once. Neither works on an admin, for the same reason an admin cannot be banned: a stolen admin session must not be able to take over the other admins' accounts.

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-password -H "$O" -d '{"userId":"usr_bwvncybszuhpp4fx6bbudkky","password":"a brand new passphrase"}'
curl -s -b bob.txt localhost:8081/me
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-email -H "$O" -d '{"userId":"usr_bwvncybszuhpp4fx6bbudkky","email":"robert@example.com","verified":true}'
curl -s -b alice.txt -X POST localhost:8081/auth/admin/set-password -H "$O" -d '{"userId":"usr_62pz2ve5aawqz6kowwdreijn","password":"a brand new passphrase"}'
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
{"ok":true}
{"error":{"code":"admin.admin_target","message":"Remove this user's admin rights first."}}
```

From Go: `ad.CreateUser(ctx, admin.CreateUserRequest{...})`, `ad.SetUserPassword(ctx, userID, password)`, `ad.SetUserEmail(ctx, admin.SetEmailRequest{...})`. The plugin finds the password and email plugins at `Init` through the `PasswordSetter` and `EmailSetter` interfaces; without them the routes answer `409 admin.no_password_plugin` / `409 admin.no_email_plugin`.

## Step 8 — Act as a user for support

`POST /auth/admin/impersonate` with `{"userId": …, "minutes": …}` opens a session as the user and issues it in place of the admin's own: the cookie in the admin's browser now belongs to the impersonation. The admin's own session is kept aside for the way back (below). The limits are the library's, not the app's:

- It lasts at most [one hour](ds:block?id=maximpersonationttl-3f39wbus) (`auth.MaxImpersonationTTL`); a longer `minutes`, zero or a negative value become the cap.
- It cannot target an admin (`409 admin.admin_target`) or a banned user (`409 admin.banned_target`).
- It can look but not change what proves the user's identity: every `FreshSignIn` operation (change password, change address, enrol a factor, register a passkey) answers `403 auth.impersonation_refused`. The admin routes refuse it too: with `admin.forbidden` when the session's user is not an admin, and with `auth.impersonation_refused` when it is one (`AllowImpersonatingAdmins`), so acting as an admin never chains into a second impersonation.
- It refuses an admin target (`409 admin.admin_target`) unless the plugin was built with `admin.AllowImpersonatingAdmins()`, which is covered under Options below together with its risk.
- The user sees it: the session row records the admin (`Session.ImpersonatedBy`), and their own `GET /auth/sessions` shows it with `"impersonated": true`.
- Start and stop are logged at WARN with both user ids.

The example's `/me` route is an ordinary page behind `RequireUser`; whoever the session belongs to is who it names:

<!-- ds:block id=newhandler-vte4bmzn -->
**newHandler** · [`examples/admin-ops/main.go:169-174`](../../examples/admin-ops/main.go#L169-L174)

```go
func newHandler(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
	mux.Handle("GET /me", authhttp.Middleware(a)(authhttp.RequireUser(http.HandlerFunc(me))))
	return mux
}
```
<!-- /ds:block hash=9e15a2 -->

Alice impersonates Bob, sees his `/me`, cannot change his password, and Bob's session list shows the impersonation:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/admin/impersonate -H "$O" -d '{"userId":"usr_gejihnupfzjajqbl5xi6aguc"}'
curl -s -b alice.txt -c support.txt -X POST localhost:8081/auth/admin/impersonate -H "$O" -d '{"userId":"usr_u6zvrbzlaexjc5l3tfvcvpri","minutes":600}'
curl -s -b support.txt localhost:8081/me
curl -s -b support.txt -X POST localhost:8081/auth/password/change -H "$O" -d '{"current":"correct horse battery staple","new":"hijacked passphrase"}'
curl -s -b support.txt localhost:8081/auth/admin/users
curl -s -b bob.txt localhost:8081/auth/sessions
```

```json
{"error":{"code":"admin.admin_target","message":"Remove this user's admin rights first."}}
{"user":{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob","image":""},"expiresAt":"2026-10-01T06:19:14.498264Z"}
{"id":"usr_u6zvrbzlaexjc5l3tfvcvpri","name":"Bob"}
{"error":{"code":"auth.impersonation_refused","message":"This cannot be done while acting as another user."}}
{"error":{"code":"admin.forbidden","message":"Only an administrator can do this."}}
{"sessions":[{"id":"ses_q7ob3wylddxxr56flwoyrgy6","current":false,"impersonated":true,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-01T05:19:14.498264Z","lastSeenAt":"2026-10-01T05:19:14.498264Z"},{"id":"ses_d4425bkp5eboi7zd6zh5qh4v","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-01T05:19:14.254692Z","lastSeenAt":"2026-10-01T05:19:14.254692Z"}]}
```

Sixty minutes were asked for, not six hundred: `expiresAt` is one hour after the request. The server log records both ends:

```text
2026/10/01 10:49:14 WARN admin: impersonation started admin=usr_gejihnupfzjajqbl5xi6aguc user=usr_u6zvrbzlaexjc5l3tfvcvpri expires=2026-10-01T06:19:14.498Z
2026/10/01 10:49:14 WARN admin: impersonation ended admin=usr_gejihnupfzjajqbl5xi6aguc user=usr_u6zvrbzlaexjc5l3tfvcvpri
```

`POST /auth/admin/stop-impersonating` ends it from the impersonation session and gives the admin their own session back: `impersonate` rotated the admin's token (the old one stopped working) and bound the new one to the client in the flow cookie `__Host-auth_flow`, the same cookie an OAuth sign-in uses; `stop-impersonating` re-issues it. The admin's session keeps its own creation time, so no freshness is gained on the way back, and a stolen impersonation cookie alone gains nothing, because the admin's token lives in a separate cookie. When the flow value is gone (another flow replaced it, a bearer client that keeps no cookies, a Go caller) or the admin's session ended meanwhile, the client is simply signed out, as before. On an ordinary session the route is `409 admin.not_impersonating`:

```sh
curl -s -b support.txt -c support.txt -X POST localhost:8081/auth/admin/stop-impersonating -H "$O"
curl -s -b support.txt localhost:8081/me
curl -s -b bob.txt -X POST localhost:8081/auth/admin/stop-impersonating -H "$O"
```

```json
{"ok":true,"restored":true}
{"id":"usr_62pz2ve5aawqz6kowwdreijn","name":"Alice"}
{"error":{"code":"admin.not_impersonating","message":"This session is not an impersonation."}}
```

In this transcript the impersonation and the flow cookie were saved to their own jar (`-c support.txt`), so stopping restores Alice in that jar; in a browser the cookies replace hers and the restore lands where she is.

From Go: `ad.Impersonate(ctx, admin.ImpersonateRequest{UserID: id, Minutes: 30})` returns the user, `ExpiresAt` and the `Token`; `ad.StopImpersonating(ctx)` ends the session in `ctx` and, when `ctx` carries the flow value, re-issues the admin's session as an effect.

## Step 9 — Read the audit log

With the [audit plugin](audit.md) registered, `GET /auth/admin/audit?userId=&op=&page=&limit=` pages through every recorded operation about a user, as actor or subject, newest first; see that guide for the event shape and a transcript. Without the plugin the route is `409 admin.no_audit_plugin`. The route reads whatever `admin.EventQuerier` is registered, so an app that keeps its log elsewhere registers a plugin with `Events(ctx, audit.Query) (audit.Page, error)` instead; with `audit.To(sink)` and a sink that cannot be queried, the route is `501 audit.no_query_backend`.

## Step 10 — Manage another user's two-factor

With the [two-factor plugin](twofactor.md) registered too, four routes manage a user's second factor. Admin finds the factor plugin by its methods ([`admin.TwoFactorManager`](ds:block?id=admin-twofactormanager-c8v4nq2x): `FactorOf`, `DisableFor`, `EnableFor`, `Reset`), so it imports no second-factor package and another implementation with the same four methods works as well; without one, the routes answer `409 admin.no_two_factor_plugin`.

| Route | Does | Permission |
|---|---|---|
| `GET /auth/admin/two-factor?userId=` | Answers `{enrolled, enabled, method}`: a confirmed factor, whether sign-in asks for it, `totp` or `delivered` | `two-factor:get` |
| `POST /auth/admin/disable-two-factor` `{userId}` | Pauses the factor: sign-in stops asking; the factor, recovery codes and sessions stay; the user sees it off and may enrol a new one | `two-factor:disable`, fresh sign-in |
| `POST /auth/admin/enable-two-factor` `{userId}` | Switches a paused factor back on and ends the user's sessions, which never passed the factor | `two-factor:enable`, fresh sign-in |
| `POST /auth/admin/reset-two-factor` `{userId}` | Removes the factor, recovery codes and trusted devices; the user enrols again | `two-factor:reset`, fresh sign-in |

The built-in admin role holds the four `two-factor` permissions; with your own Authorizer a support role can hold `two-factor:get` alone. Pause and reset refuse an admin target (`409 admin.admin_target`), so a stolen admin session cannot strip the other admins' protection; enable does not. For an admin who lost their phone, call [`ad.ResetTwoFactorFor(ctx, userID)`](ds:block?id=admin-resettwofactorfor-w2k9pt4m) from trusted Go code (a recovery command): it accepts an admin and is recorded in the audit log with no actor, in the same transaction. A user with no confirmed factor is `409 twofactor.not_enrolled`. The routes are audited like every admin mutation.

From Go: `ad.TwoFactor(ctx, id)`, `ad.DisableTwoFactor(ctx, id)`, `ad.EnableTwoFactor(ctx, id)`, `ad.ResetTwoFactor(ctx, id)`. [`examples/two-factor-manage`](../../examples/two-factor-manage) wires both plugins; `TestTwoFactorManage_AdminRoutes` there walks pause, sign-in without the factor, enable, a recovery code, and reset.

## Options you may want

| Want | Do |
|---|---|
| A role that may only look users up, or any role of your own | `admin.WithAuthorizer(accessadmin.MustNew(ac, roles))`; Step 6 and [`examples/authorizer`](../../examples/authorizer) |
| An admin page of your own, with app data next to each user | Read the plugin's typed columns (`admin.GrantedAt`, `admin.BannedAt`, `admin.BanReason`) in your own query, and guard the route by loading `admin.AdminColumns` for the caller. [`examples/admin-plan`](../../examples/admin-plan) does both |
| A different fresh window for the admin routes | `auth.WithFreshWindow(d)`; it applies to every `FreshSignIn` operation, not only the admin's |
| Admins who sign in with a second factor | Add [two-factor](twofactor.md); the admin routes are ordinary operations and inherit it |
| Support that pauses or resets a user's second factor | Add [two-factor](twofactor.md); `GET /auth/admin/two-factor` and `POST /auth/admin/disable-two-factor`, `/enable-two-factor`, `/reset-two-factor` (step 10) |
| The first admin from the command line, no code of your own | Route a word to `authcli`: `myapp auth admin grant --email x` for an existing verified user, `echo "$PW" \| myapp auth admin create --email x --name y --password-stdin` for a new one ([CLI guide](../integrations/cli.md#step-7--make-the-first-admin)) |
| Operators fixed in configuration, no grant step | `admin.AdminIDs("usr_…", …)`: the listed users are admins and are protected like admins (no ban, impersonation or removal) |
| A ban that lifts itself | `{"userId": …, "minutes": 1440}` on `ban`, or `admin.DefaultBanDuration(d)` for bans that name no minutes; the session check is evaluated per lookup, so the user is back the moment it passes |
| A reason on every ban | `admin.DefaultBanReason("policy")` fills an empty reason |
| A message of your own for banned users | `admin.BannedMessage(func(ctx, b admin.Ban) string)`, with the reason and dates in hand; an empty result falls back to the default |
| Create users, set passwords and addresses from a back office | `POST /auth/admin/create-user`, `set-password`, `set-email` (step 7), or the Go methods; the password and email plugins' rules apply |
| An audit trail of what admins and users did | Register [`audit.New()`](audit.md) and read `GET /auth/admin/audit` |
| Shorter impersonations by default | `admin.ImpersonationTTL(15 * time.Minute)` for requests that name no `minutes`; the one-hour cap stays |
| Admins who may impersonate other admins | `admin.AllowImpersonatingAdmins()`. Everything else stays: a fresh sign-in, the one-hour cap, the audit record, the way back, no FreshSignIn operation and no admin operation from the impersonation session, and impersonating yourself is `409 admin.self_target`. **The risk:** one stolen admin session can then act as every other admin, so the least careful admin's compromise is everyone's. Turn it on only where every admin is equally trusted |
| Search users by part of an address or name | `GET /auth/admin/search-users?value=bob&field=email&operator=starts_with` (step 3); `admin.SearchRate(60, time.Minute)` for a looser budget |
| A sortable, filterable user list | `GET /auth/admin/users?sort=name_asc&admin=false&banned=true&offset=50&limit=50`: sort is `created_desc`, `created_asc`, `name_asc` or `name_desc`; `admin` and `banned` are `true` or `false`; `offset` replaces `page` |
| Let admins edit your own user columns | Register the column with `auth.WithUserColumns`, then `admin.EditableColumns(admin.Editable(planCol, checkPlan))`; `POST /auth/admin/update-user {"userId": …, "data": {"plan": "pro"}}` sets it. The value must decode into the column's Go type and pass the check; `name` and `image` are accepted in `data` too; any other key, including `password`, `email` and `role` (which have their own routes), is `400 admin.field_not_editable`, and every key is checked before the first write |
| Edit a user, see and end one session, delete a user | `POST /auth/admin/update-user {userId, name, image}`, `GET /auth/admin/sessions?userId=`, `POST /auth/admin/revoke-session {userId, sessionId}`, `POST /auth/admin/remove-user {userId}`; all but `sessions` need a fresh sign-in, and an admin cannot be removed |

The plugin rate-limits only `search-users` (`SearchRate`); its other routes are reachable by admins only.

## From TypeScript

Use this when the admin console is a frontend: a React or Vue back office, or a script in Node. The [typed client](../client/README.md) has every route of this guide on `client.admin`; list `admin()` in `plugins`. Every call answers `admin.forbidden` to a caller who is not an admin, before it looks at the target, so the console can call `admin.users` once to decide whether to show itself.

One page of users. Query inputs travel in the query string, so the paging and filter fields are strings, typed as the Go struct declares them:

<!-- ds:block id=tsp-admin-users-3wq8nk5x -->
**bannedUsers** · [`clients/ts/examples/plugin-account.ts:14-18`](../../clients/ts/examples/plugin-account.ts#L14-L18)

```typescript
export async function bannedUsers(page: number): Promise<string[]> {
  const { data, error } = await auth.admin.users({ banned: "true", limit: "50", page: String(page), sortBy: "createdAt", sortDirection: "desc" });
  if (error) return [];
  return (data.users ?? []).map((u) => `${u.name} (${u.id})`);
}
```
<!-- /ds:block hash=2b4296 -->

A ban, with the codes the button has to explain:

<!-- ds:block id=tsp-admin-ban-7mk2xq9w -->
**banForAWeek** · [`clients/ts/examples/plugin-account.ts:23-36`](../../clients/ts/examples/plugin-account.ts#L23-L36)

```typescript
export async function banForAWeek(userId: string, reason: string): Promise<string> {
  const { error } = await auth.admin.ban({ userId, reason, minutes: 7 * 24 * 60 });
  if (!error) return "banned";
  switch (error.code) {
    case "admin.self_target":
      return "You cannot ban yourself.";
    case "admin.admin_target":
      return "Remove this user's admin rights first.";
    case "auth.fresh_session_required":
      return "Confirm it is you, then try again.";
    default:
      return error.message;
  }
}
```
<!-- /ds:block hash=19b2f0 -->

Acting as a user for support, and coming back:

<!-- ds:block id=tsp-admin-impersonate-5nx9wk2m -->
**actAs** · [`clients/ts/examples/plugin-account.ts:41-51`](../../clients/ts/examples/plugin-account.ts#L41-L51)

```typescript
export async function actAs(userId: string, work: () => Promise<void>): Promise<boolean> {
  const started = await auth.admin.impersonate({ userId, minutes: 15 });
  if (started.error) return false;
  try {
    await work();
  } finally {
    const stopped = await auth.admin.stopImpersonating();
    if (!stopped.data?.restored) location.assign("/sign-in"); // the admin's own session ended meanwhile
  }
  return true;
}
```
<!-- /ds:block hash=fdf8a7 -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `admin.forbidden`, `auth.fresh_session_required` on every changing call (ban, impersonate, set a role or a password, remove a user: re-authenticate on the held session as [password's From TypeScript](password.md#from-typescript) shows, then retry), `admin.self_target`, `admin.admin_target`, `admin.last_admin`, `admin.banned_target`, `admin.not_impersonating`, the `admin.bad_filter*`, `admin.bad_search*` and `admin.bad_sort` family from list and search inputs, and `admin.no_*_plugin` when the server lacks the plugin a call needs.

There is no runnable TypeScript example for the admin plugin; the blocks above are type-checked by `task ts:check`, and Steps 3 to 8 show the same calls with curl.

Pitfalls:

- **Impersonation replaces this browser's session.** Until `stopImpersonating`, every call from the console runs as the user, including the next `admin.users` (which then answers `admin.forbidden`). Run support work in the flow the block shows, and reload the console's data after stopping.
- **`stopImpersonating` answers `restored: false`** when the admin's own session ended meanwhile; the browser is then signed out and goes to the sign-in page.
- **The console's checks are for display only.** Hide buttons with `admin.hasPermission`, but every call is checked again on the server.

Every method with its route and types: [TypeScript client reference › admin](../reference/ts-client.md#admin).

## What can go wrong

- `403 admin.forbidden` ("Only an administrator can do this.") — the caller is not an admin. Grant the first one from Go (step 2).
- `403 auth.fresh_session_required` ("Sign in again to continue.") — ban, unban, revoke, set-admin or impersonate on a session older than the fresh window. Sign in again.
- `404 auth.user_not_found` — the `userId` does not exist. The caller was already checked as an admin, so this is safe to show.
- `409 admin.admin_target` ("Remove this user's admin rights first.") — banning, impersonating (unless `AllowImpersonatingAdmins()`), removing, or pausing or resetting the second factor of an admin, granted or listed in `AdminIDs`.
- `400 admin.bad_sort` ("This sort order does not exist.") — `users` or `search-users` with a `sort` that is not one of the four.
- `400 admin.bad_filter` ("A filter is true, false or absent.") — `users` or `search-users` with `admin` or `banned` set to anything else.
- `400 admin.search_value` ("Search for one to 320 characters.") — `search-users` with an empty value or a longer one.
- `400 admin.bad_filter_field` / `400 admin.bad_filter_operator` / `400 admin.bad_filter_value` — a `filterField` outside the list, an operator the field does not take (`lt` on `email`), or a value it cannot hold (not `true`/`false`, not RFC 3339, empty, over 320 characters, or more than 200 values in `in`).
- `409 admin.sessions_not_listable` — `all-sessions` while sessions are not kept in the database.
- `400 admin.no_user_data` / `400 admin.field_not_editable` / `400 admin.bad_user_data` — `update-user` with an empty `data`, a key that is not `name`, `image` or an `EditableColumns` column, or a value of the wrong type. An `Editable` check's own error comes back as it is.
- `400 admin.bad_search_field` / `400 admin.bad_search_operator` — `search-users` with a `field` other than `email` or `name`, or an `operator` other than `contains`, `starts_with` or `ends_with`.
- `429 auth.rate_limited` on `search-users` — more searches from one IP than `SearchRate` allows. Wait for the window, or raise the limit.
- `409 admin.self_target` ("You cannot do this to yourself.") — impersonating yourself with `AllowImpersonatingAdmins()` on.
- `400 auth.profile_invalid` on `update-user` — the name is over the limit or the image is not an https URL; the same rule as the user's own profile update.
- `409 admin.banned_target` ("This user is banned.") — impersonating a banned user. Unban first if that is really wanted.
- `409 admin.last_admin` ("Keep at least one administrator.") — removing the last admin's rights. Grant another admin first.
- `409 admin.not_impersonating` ("This session is not an impersonation.") — `stop-impersonating` on an ordinary session.
- `403 auth.impersonation_refused` ("This cannot be done while acting as another user.") — a `FreshSignIn` operation during an impersonation, or an admin operation while acting as an admin. By design; stop impersonating.
- Signed out after `stop-impersonating` instead of back as the admin — the flow cookie is gone (another flow such as an OAuth sign-in replaced it, or the client keeps no cookies) or the admin's session ended meanwhile. Sign in again.
- `403 admin.banned` at sign-in — the user is banned; the message is `admin.BannedMessage`'s. Only a caller who proved the credential sees it.
- `400 admin.email_required` — `create-user` without an address.
- `409 admin.no_password_plugin` / `409 admin.no_email_plugin` / `409 admin.no_audit_plugin` / `409 admin.no_two_factor_plugin` — the operation needs a plugin that is not registered (an `email` search needs the email plugin, the two-factor routes a plugin with `admin.TwoFactorManager`'s methods).
- `409 twofactor.not_enrolled` on `disable-two-factor`, `enable-two-factor` or `reset-two-factor` — the user has no confirmed second factor.
- `409 auth.identity_taken` — `create-user` or `set-email` with an address another user holds.
- `400 password.too_short` and the password plugin's other refusals — `create-user` or `set-password` with a password its rules refuse.

## Next

- [Sessions](../concepts/sessions.md): what a session check is and why a ban reaches every instance.
- [Databases](../concepts/databases.md): joining the plugin's columns into your own admin queries.
- The plugin's [README](../../plugin/admin/README.md) is the reference for its routes, columns and errors.
