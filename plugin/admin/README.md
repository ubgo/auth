# github.com/ubgo/auth/plugin/admin

Gives an app's operators the user operations every product needs: find a user, see their identities and session count, create a user, set a password or an address, ban and unban, end their sessions, grant or remove admin rights, act as a user for support and come back to their own session, and read the audit log.

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module `github.com/ubgo/auth`, so it brings no extra dependency beyond `github.com/ubgo/sqlb`.

## Wire it

Taken from [`examples/admin-plan`](../../examples/admin-plan/main.go):

```go
ad := admin.New()
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad),
)
// then: a.Migrate(ctx), and mount authhttp.Handler(a, authhttp.Prefix("/auth"))
```

The first admin is granted from Go, because nobody can grant it over HTTP before an admin exists. The example does it from a subcommand, for a verified address only:

```go
idn, err := a.FindIdentity(ctx, email.KindEmail, address, true) // verified only
err = ad.Grant(ctx, idn.UserID)
```

The plugin depends on no other plugin and has no `Validate` refusals. At `Init` it looks for a registered plugin that can set a password (`PasswordSetter`, which `*password.Plugin` is), one that can give a user an address (`EmailSetter`, which `*email.Plugin` is) and an audit log (`EventRecorder` to record a Go-side ban, `EventQuerier` to serve the audit route; `*audit.Plugin` is both, and any other log with the same methods is used instead); `create-user`, `set-password`, `set-email` and `audit` answer with a `409` code when the plugin they need is absent, and everything else works without them. An app's own admin-only routes read the same column:

```go
var cols admin.AdminColumns
if err := a.LoadUserColumns(r.Context(), authhttp.MustUser(r).ID, admin.Bindings(&cols)...); err != nil {
	return err
}
if cols.AdminGrantedAt == nil {
	return admin.ErrForbidden
}
```

## Options

Who is an admin is data (`admin_granted_at`); the options add fixed admins and defaults.

| Option | What it does | Default |
|---|---|---|
| `admin.AdminIDs(ids...)` | The listed users are admins without a grant row, and are protected like admins (no ban, impersonation or removal) | none |
| `admin.DefaultBanReason(s)` | Stored when a ban names no reason | empty |
| `admin.DefaultBanDuration(d)` | A ban whose request names no `minutes` lifts itself after d | until unban |
| `admin.ImpersonationTTL(d)` | Length of an impersonation whose request names no `minutes`; the core cap of [one hour](ds:block?id=maximpersonationttl-3f39wbus) still applies | the cap |
| `admin.SearchRate(limit, window)` | The per-IP limit on `search-users`; `auth.New` refuses a limit below one, so the search can be loosened but never left unlimited | [30](ds:block?id=defaultsearchlimit-p3w8zn6c) per minute |
| `admin.AllowImpersonatingAdmins()` | An admin may impersonate another admin; everything else about impersonation stays (see the risk below) | refused, `admin.admin_target` |
| `admin.EditableColumns(admin.Editable(col, check), …)` | The app columns (`auth.WithUserColumns`) an admin may set through `update-user`'s `data`, typed by the column's Go type and checked by `check` (nil for none); written with `auth.SetUserColumn` under `auth.AppName` | none: `data` takes `name` and `image` only |
| `admin.BannedMessage(func(ctx, admin.Ban) string)` | The text a banned user reads at sign-in, from the ban's reason and dates; an empty result falls back to the default | ["This account is banned."](ds:block?id=defaultbannedmessage-wjzk8uve) |

## Routes and Go API

Routes are under the mount prefix (`/auth` below). A Query is served as GET with its input in the query string; a Mutation as POST with a JSON body. Every operation first refuses a caller whose roles lack its permission (`DefaultStatements`; see Roles below) with `ErrForbidden`. FreshSignIn means a session created within [`auth.DefaultFreshWindow`](ds:block?id=defaultfreshwindow-5mt8jqw7) (10 minutes, `auth.WithFreshWindow` to change); the core refuses every FreshSignIn operation on an impersonation session.

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /auth/admin/set-role` `{userId, role}` (a string or an array) | `SetRole(ctx, SetRoleRequest)` | FreshSignIn, `user:set-role` | none |
| `POST /auth/admin/has-permission` `{userId, permissions, connector}` | `HasPermission(ctx, PermissionRequest)` | SignedIn; another user's needs `user:get` | none |
| `GET /auth/admin/users?query=&page=&limit=&offset=&sort=&sortBy=&sortDirection=&admin=&banned=&filterField=&filterOperator=&filterValue=` | `Users(ctx, UsersRequest)` | SignedIn | none |
| `GET /auth/admin/search-users?value=&field=&operator=` plus every `users` parameter but `query` | `SearchUsers(ctx, SearchUsersRequest)` | SignedIn | `SearchRate`, per IP |
| `GET /auth/admin/user?userId=` | `User(ctx, userID)` | SignedIn | none |
| `POST /auth/admin/create-user` `{name, image, email, verified, password}` | `CreateUser(ctx, CreateUserRequest)` | FreshSignIn | none |
| `POST /auth/admin/update-user` `{userId, name, image, data}` | `UpdateUser(ctx, UpdateUserRequest)` | FreshSignIn | none |
| `POST /auth/admin/set-password` `{userId, password}` | `SetUserPassword(ctx, userID, password)` | FreshSignIn | none |
| `POST /auth/admin/set-email` `{userId, email, verified}` | `SetUserEmail(ctx, SetEmailRequest)` | FreshSignIn | none |
| `POST /auth/admin/ban` `{userId, reason, minutes}` | `Ban(ctx, userID, reason)` | FreshSignIn | none |
| `POST /auth/admin/unban` `{userId}` | `Unban(ctx, userID)` | FreshSignIn | none |
| `GET /auth/admin/sessions?userId=` | `Sessions(ctx, userID)` | SignedIn | none |
| `GET /auth/admin/all-sessions?userId=&page=&limit=&offset=` | `AllSessions(ctx, AllSessionsRequest)` | SignedIn, `session:list` | none |
| `POST /auth/admin/revoke-session` `{userId, sessionId}` | `RevokeSession(ctx, userID, sessionID)` | FreshSignIn | none |
| `POST /auth/admin/revoke-sessions` `{userId}` | `RevokeSessions(ctx, userID)` | FreshSignIn | none |
| `POST /auth/admin/remove-user` `{userId}` | `RemoveUser(ctx, userID)` | FreshSignIn | none |
| `POST /auth/admin/set-admin` `{userId, admin}` | `SetAdmin(ctx, userID, admin)` | FreshSignIn | none |
| `POST /auth/admin/impersonate` `{userId, minutes}` | `Impersonate(ctx, ImpersonateRequest)` | FreshSignIn | none |
| `POST /auth/admin/stop-impersonating` → `{ok, restored}` | `StopImpersonating(ctx) (StopResult, error)` | SignedIn, on an impersonation session | none |
| `GET /auth/admin/audit?userId=&op=&page=&limit=` | `Audit(ctx, audit.Query)` | SignedIn | none |
| `GET /auth/admin/two-factor?userId=` → `{enrolled, enabled, method}` | `TwoFactor(ctx, userID)` | SignedIn, `two-factor:get` | none |
| `POST /auth/admin/disable-two-factor` `{userId}` | `DisableTwoFactor(ctx, userID)` | FreshSignIn, `two-factor:disable` | none |
| `POST /auth/admin/enable-two-factor` `{userId}` | `EnableTwoFactor(ctx, userID)` | FreshSignIn, `two-factor:enable` | none |
| `POST /auth/admin/reset-two-factor` `{userId}` | `ResetTwoFactor(ctx, userID)` | FreshSignIn, `two-factor:reset` | none |
| (Go only) | `Grant(ctx, userID)` | none: call it from trusted code | none |
| (command line) | `myapp auth admin grant --email x`, `myapp auth admin create --email x --name y --password-stdin` | the operator's shell; [`authcli`](../../authcli/README.md) finds this plugin's `Grant` by interface | none |
| (Go only) | [`ResetTwoFactorFor(ctx, userID)`](ds:block?id=admin-resettwofactorfor-w2k9pt4m) resets a user's second factor with no signed-in admin (an operator's recovery command), an admin's included; recorded in the audit log with no actor when one is registered (`EventRecorder`), in the same transaction | none: call it from trusted code | none |
| (Go only) | [`BanFor(ctx, userID, reason, until)`](ds:block?id=plugin-banfor-m3x8vt5q) bans with no signed-in admin (an import, a job); a zero `until` is permanent; the user's sessions end; recorded in the audit log with no actor when one is registered (`EventRecorder`) | none: call it from trusted code | none |

Operation ids are the `Endpoint*` constants (`admin.users` and so on).

Behaviour worth knowing:

- `users`: `query` is matched exactly, as a normalized identifier (address, number, handle) or a user id, never as a fragment. Pages start at 1; `limit` defaults to `auth.WithDefaultPageSize` when the app set one, else 50 ([`DefaultPageSize`](ds:block?id=defaultpagesize-k5wq5psj)), and is clamped to 200 ([`MaxPageSize`](ds:block?id=maxpagesize-9qpk2wp4)); `offset`, when set, replaces `page`. `sort` is one of `created_desc` (default), `created_asc`, `name_asc`, `name_desc` (`UserSortValues`); anything else is `admin.bad_sort`. `admin` and `banned` filter with `true` or `false` (`FlagValues`); anything else is `admin.bad_filter`. `sortBy` (`createdAt`, `updatedAt`, `name`, `id`; `SortFieldValues`) with `sortDirection` (`asc`, the default, or `desc`) is a field sort and replaces `sort`; naming both is `admin.bad_sort`. `filterField`, `filterOperator` and `filterValue` are a single field filter: the field is one of `FilterFieldValues` (`email` by default), the operator one of `FilterOperatorsOf(field)` (`eq` by default), the value comma-joined for `in` and `not_in` (at most `MaxFilterValues`), `true`/`false` for a flag, RFC 3339 for a time; an absent value filters nothing, an unknown field or operator is refused regardless. Addresses compare folded and their negations include users with no address; names, ids and ban reasons keep case; `role` means a role the user holds by `RolesOf`'s rules (stored, the flag's admin role, `AdminIDs`, or the default for a user with none). The result carries `total`, and `page`, `limit` and `offset` as actually used. Every row carries `email` (the primary email address, else the earliest email identity, verified or not, else empty), `roles` (every role the user holds by `RolesOf`'s rules), both loaded for the whole page in one query rather than per row, and `lastActiveAt`, the latest `last_seen_at` among the user's sessions (every row `auth_session` still holds when sessions are in SQL, the live ones otherwise, only the caller's in stateless mode), or null.
- `search-users` finds users by a fragment: `field` is `email` (default) or `name` (`SearchFieldValues`), `operator` is `contains` (default), `starts_with` or `ends_with` (`SearchOperatorValues`), and `value` is 1 to [320](ds:block?id=maxsearchlength-r7d4kq2n) characters after trimming (`admin.search_value` otherwise). Every character of `value` is text: `%`, `_` and the escape character `!` match themselves, through sqlb's escaped `LIKE ... ESCAPE '!'`. An `email` search reads the user's email identities, verified or not, and ignores case: addresses are stored folded and the value is folded the same way in Go (trimmed, lowercased; a custom `email.WithNormalizer` is not applied to a fragment), then compared exactly. A `name` search matches the display name as stored, case included, on every engine: names have no normalized form and the library never folds case in SQL, so `ada` does not find `Ada`; on SQLite, whose `LIKE` ignores ASCII case, it is `GLOB` with the value's `*`, `?` and `[` escaped. It pages, sorts and filters exactly like `users` and returns the same result. Without the email plugin an `email` search is `409 admin.no_email_plugin`. It has its own rate rule, 30 searches a minute per IP by default (`SearchRate`), because a fragment search is the one admin read that can walk the user table.
- `ban` stores the reason cut to 300 characters ([`maxReasonLength`](ds:block?id=maxreasonlength-s6upfze5), so it fits the column on every engine), sets `admin_banned_at` and, when `minutes` or `DefaultBanDuration` says so, `admin_ban_expires_at`; then it deletes every session of the user. The ban is also a session check, evaluated per lookup, so a session made later does not work either, on any instance, and a ban with an expiry stops blocking the moment it passes. Deleting the sessions evicts the user's server-side session-cache entries too (`auth.EvictCachedSessions`); a client-held cache copy expires within the cache TTL.
- `unban` clears the ban, its expiry and its reason. `revoke-sessions` ends sessions without banning; `revoke-session` ends one, named by user and session id. `sessions` lists another user's sessions as `auth.SessionView` rows with `current` false. `all-sessions` pages through every live session of every user (`FleetSession` rows with the user id and expiry), most recently used first; it reads `auth_session`, so with sessions elsewhere (another `auth.WithSessionStore`, a mirror, stateless) it is `409 admin.sessions_not_listable`, never an empty page.
- `update-user` changes the display name or image through the core, with the same limits as the user's own profile update (`auth.ErrProfileInvalid`); its `data` object takes `name`, `image` and the `EditableColumns` columns, decodes and checks every key before the first write, and refuses any other key (`password`, `email`, `role` included, which have their own operations). The edit is one transaction. `remove-user` hard-deletes a user and everything that references them; an admin must lose the rights first.
- `set-admin` with the state the user already has is a no-op that succeeds.
- `create-user` creates the user through the core, gives it the address through the email plugin (`verified: true` makes it verified and primary at once; otherwise the usual verify link goes out) and, when `password` is set, the password through the password plugin, so every rule those plugins enforce (address uniqueness, one address per user, password length, policies, the breached-password check) applies to an admin-created user; it is one transaction, so a refused password leaves no user. `email` is required (`admin.email_required`); `password` is optional, and without one the user sets theirs through the forgot flow.
- `set-password` sets a user's password with the password plugin's rules; every session of the user ends and open reset links are spent, as `password.SetPassword` promises. `set-email` gives a user an address under the email plugin's rules (replacing the address without `email.Multiple()`, adding one with it). Neither works on an admin (`admin.admin_target`): a stolen admin session must not be able to take over the other admins' accounts, and a verified address recovers an account.
- A banned user who proves their credential is refused at sign-in with `403 admin.banned` and the configured message, on every sign-in method: the refusal is a data hook on the session write, so it covers password, code, link, passkey and OAuth sign-ins and a pending second-factor session alike. It fires only after the credential was proven, so a stranger without the password gets the ordinary wrong-credential answer and learns nothing about the ban.
- `audit` pages through the registered audit log (`EventQuerier`) for admins; see [plugin/audit](../audit/README.md) for the query and the event shape. Without one it is `409 admin.no_audit_plugin`; with the audit plugin sending events to a sink that cannot be read it is `501 audit.no_query_backend`.
- `impersonate` returns the user and `expiresAt`, and issues the new session as an effect (a cookie, or `Set-Auth-Token` in bearer mode), replacing the admin's own in the session cookie. The admin's own session survives for the way back: its token is rotated (`auth.RotateSessionToken`, so the value in the overwritten cookie dies) and the new one is bound to the client in the flow cookie `__Host-auth_flow` (`ImpersonateResult.AdminToken` for Go callers and bearer clients, which keep it themselves). `stop-impersonating` ends the impersonation and, when the client still presents that flow value and the session still belongs to the impersonating admin, re-issues it (`restored: true`); otherwise the client is signed out as before (`restored: false`). The admin session keeps its own creation time, so coming back never makes it fresh, and a stolen impersonation cookie alone holds a user session, never the admin's. `minutes` of 0, negative, or above the cap become [`auth.MaxImpersonationTTL`](ds:block?id=maximpersonationttl-3f39wbus) (1 hour). The session row records the admin (`Session.ImpersonatedBy`), the user sees it in their session list, and every FreshSignIn operation refuses it with `auth.impersonation_refused`. Start and stop are logged at WARN with both user ids. An admin target is refused (`admin.admin_target`) unless `AllowImpersonatingAdmins()`; with it, impersonating yourself is `409 admin.self_target`.
- The two-factor routes manage another user's second factor through whichever registered plugin has the four methods of [`TwoFactorManager`](ds:block?id=admin-twofactormanager-c8v4nq2x) (`FactorOf`, `DisableFor`, `EnableFor`, `Reset`; `plugin/twofactor` has them), found at `Init` by method set, so admin imports no second-factor package; without one they answer `409 admin.no_two_factor_plugin`, after the permission check. `two-factor` reports `enrolled` (a confirmed factor, on or paused), `enabled` (sign-in asks for it) and `method` (`totp` or `delivered`). `disable-two-factor` pauses the factor: sign-in stops asking, the factor and its recovery codes stay, and the user sees two-factor as off and may enrol a new one, which replaces it. `enable-two-factor` switches a paused factor back on and ends every session of the user, because sessions made during the pause never passed the factor; on a factor that is already on it changes nothing. `reset-two-factor` removes the factor, its recovery codes and its trusted devices so the user enrols again (`twofactor.Reset`). Pause and reset leave the user's sessions alone, as `twofactor.Reset` does: they were made with the factor, and `revoke-sessions` is the act for a suspected takeover. Pause and reset refuse an admin target (`admin.admin_target`), for the reason `set-password` does; enable does not, because raising an admin's protection helps nobody who stole a session; `ResetTwoFactorFor` from Go accepts an admin, as the way back for one who lost their phone. A user with no confirmed factor is the factor plugin's `409 twofactor.not_enrolled` on pause, enable and reset. Every route is recorded by the audit plugin's operation hook like any other mutation.
- Every admin operation refuses an impersonation session of an admin with `403 auth.impersonation_refused` (a non-admin still gets `admin.forbidden`), so acting as another admin grants none of their admin operations and never chains into a second impersonation.
- **The risk of `AllowImpersonatingAdmins()`.** With it, one stolen admin session (fresh within the window) can act as every other admin: read their account as they see it, use the app as them, and do whatever the app lets them do that is not a FreshSignIn operation. A compromise of the least careful admin becomes a compromise of all of them. Turn it on only where every admin is equally trusted and support work really needs to see another admin's account; the audit log and the WARN lines record every such impersonation with both ids.

## Roles

Every permission decision goes through one `admin.Authorizer`: the first check of every operation (before the target is looked up, so a refusal never reveals whether a user exists), the `impersonate-admins` check, `has-permission` and `CheckRolePermission`. The plugin never decides a permission itself, so you can answer with roles, attributes, a relationship store, a policy engine or rules of your own.

<!-- ds:block id=authorizer-yr8g745x -->
**Authorizer** · [`plugin/admin/authorizer.go:86-88`](authorizer.go#L86-L88)

```go
type Authorizer interface {
	Authorize(ctx context.Context, req AccessRequest) (bool, error)
}
```
<!-- /ds:block hash=571728 -->

`AccessRequest` carries `UserID` (whose permission), `Roles` (that user's roles as the plugin resolved them), `Permissions` and `Connector` (the permission object), `TargetUserID` (the user the operation acts on, as the request names it), `Operation` and `Call` (client IP, session, decoded input; nil outside an operation). It is a struct so it can grow without breaking an implementation. Any error refuses: the plugin never reads the boolean of a call that failed, so a policy engine that is down fails closed. `admin.AuthorizerFunc` adapts a function.

The default is two built-in roles: `admin` may do everything in `DefaultStatements` except `impersonate-admins`, `user` nothing (`DefaultRoles()`). `DefaultStatements` is the admin vocabulary (`user`: create, list, set-role, ban, impersonate, impersonate-admins, delete, set-password, set-email, get, update; `session`: list, revoke, delete) plus `two-factor`: get, disable, enable, reset (`ResourceTwoFactor`), its own resource so a support role can be granted it without ban or set-password. A user's roles are `auth_user.admin_role`, comma-joined; the staff flag (`admin_granted_at`, `AdminIDs`) counts as the first of `AdminRoles`, and a user with neither holds `DefaultRole`, so an app that never names a role behaves as before.

Fine-grained roles built from a statement vocabulary come from the [`accessadmin`](../access/accessadmin) adapter in the separate `plugin/access` module: `admin.WithAuthorizer(accessadmin.MustNew(accessadmin.DefaultAccessControl, map[string]access.Role{"support": support}))`. Any model of your own plugs in the same way; [Bring your own authorization](../../docs/extending/11-authorization.md) shows policy-table and relationship-store authorizers.

| Option | What it does | Default |
|---|---|---|
| `admin.WithAuthorizer(a)` | Decides every admin permission. Implement `admin.RoleCatalog` (`DefinesRole(name) bool`) too when `set-role` should accept roles other than `admin` and `user` | the built-in roles |
| `admin.AdminRoles(names...)` | Roles that make an admin: protected from ban, impersonation and removal, counted for the last-admin rule, kept in step with the flag | `admin` |
| `admin.DefaultRole(name)` | The role of a user with none | `user` |

`set-role` and `set-admin` keep the flag and the roles in step; `Grant` still sets the flag only. `ErrBadRole` (`admin.bad_role`, 400) is a role the authorizer does not define (`RoleCatalog`, or `admin` and `user` without one), or none. `auth.New` refuses a nil authorizer (`auth.ErrNilOption` naming `admin.WithAuthorizer`), an undefined default or admin role, a role name with a comma and no admin roles. `admin.Grants(granted, want, connector)` is the role check the built-in roles use, exported for an authorizer that keeps a role table of its own.

## Tables and columns

The plugin owns no table. It adds five columns to `auth_user`:

| Column | Type | Meaning |
|---|---|---|
| `admin_granted_at` | timestamp, nullable | Set when the user is an admin |
| `admin_banned_at` | timestamp, nullable | Set while the user is banned |
| `admin_ban_reason` | text, default `''` | The ban reason (VARCHAR(320) on MySQL) |
| `admin_ban_expires_at` | timestamp, nullable | When a temporary ban lifts itself; null for a ban that lasts until unban |
| `admin_role` | text, default `''` | The user's roles, comma-joined; empty means the flag and `DefaultRole` decide |

Typed columns: `admin.GrantedAt`, `admin.BannedAt`, `admin.BanReason`, `admin.BanExpiresAt`, `admin.UserRole`; `admin.AdminColumns` + `admin.Bindings` for a composite user or `LoadUserColumns`. These plugin columns are not in the stability contract (`stability_test.go` covers only the core's own columns).

## Errors

| Error variable | Code | HTTP | When |
|---|---|---|---|
| `ErrForbidden` | `admin.forbidden` | 403 | The caller is not an admin (checked before the target is looked up) |
| `ErrAdminTarget` | `admin.admin_target` | 409 | Banning (over HTTP or `BanFor`), impersonating, removing, or pausing or resetting the second factor of an admin (granted or listed) |
| `ErrBannedTarget` | `admin.banned_target` | 409 | Impersonating a banned user |
| `ErrSelfTarget` | `admin.self_target` | 409 | Impersonating yourself with `AllowImpersonatingAdmins()` on (without it, `admin.admin_target` answers first) |
| `ErrSearchValue` | `admin.search_value` | 400 | `search-users` with an empty value or one over 320 characters |
| `ErrBadSearchField` | `admin.bad_search_field` | 400 | `search-users` with a `field` outside `SearchFieldValues` |
| `ErrBadSearchOperator` | `admin.bad_search_operator` | 400 | `search-users` with an `operator` outside `SearchOperatorValues` |
| `auth.ErrImpersonationRefused` | `auth.impersonation_refused` | 403 | An admin operation called from an impersonation session of an admin |
| `auth.ErrRateLimited` | `auth.rate_limited` | 429 | More `search-users` calls from one IP than `SearchRate` allows |
| `ErrLastAdmin` | `admin.last_admin` | 409 | Removing the last admin's rights |
| `ErrNotImpersonating` | `admin.not_impersonating` | 409 | `stop-impersonating` on an ordinary session |
| `ErrBadSort` | `admin.bad_sort` | 400 | `users` or `search-users` with a `sort` outside `UserSortValues` |
| `ErrBadFilterField` | `admin.bad_filter_field` | 400 | `filterField` outside `FilterFieldValues` |
| `ErrBadFilterOperator` | `admin.bad_filter_operator` | 400 | `filterOperator` the field does not take (`FilterOperatorsOf`) |
| `ErrBadFilterValue` | `admin.bad_filter_value` | 400 | `filterValue` that is empty, over 320 characters, not a flag or an RFC 3339 time, or more than `MaxFilterValues` values |
| `ErrSessionsNotListable` | `admin.sessions_not_listable` | 409 | `all-sessions` while sessions are not in the `auth_session` table |
| `ErrNoUserData` | `admin.no_user_data` | 400 | `update-user` with an empty `data` |
| `ErrFieldNotEditable` | `admin.field_not_editable` | 400 | `update-user` `data` key that is not `name`, `image` or an `EditableColumns` column |
| `ErrBadUserData` | `admin.bad_user_data` | 400 | `update-user` `data` value of the wrong type |
| `ErrBadFilter` | `admin.bad_filter` | 400 | `users` or `search-users` with an `admin` or `banned` filter that is not `true`, `false` or absent |
| `ErrBanned` | `admin.banned` | 403 | A banned user proved their credential at sign-in; the message is `BannedMessage`'s |
| `ErrNoPasswordPlugin` | `admin.no_password_plugin` | 409 | `set-password`, or `create-user` with a password, with no plugin that can store one |
| `ErrNoEmailPlugin` | `admin.no_email_plugin` | 409 | `set-email`, `create-user` or an `email` search with no plugin that can give a user an address |
| `ErrEmailRequired` | `admin.email_required` | 400 | `create-user` without an address |
| `ErrNoAuditPlugin` | `admin.no_audit_plugin` | 409 | `audit` with no audit log with a read side (`EventQuerier`) registered |
| `ErrNoTwoFactorPlugin` | `admin.no_two_factor_plugin` | 409 | A two-factor route, or `ResetTwoFactorFor`, with no plugin that manages second factors (`TwoFactorManager`) registered |
| the factor plugin's `twofactor.not_enrolled` | | 409 | `disable-two-factor`, `enable-two-factor` or `reset-two-factor` for a user with no confirmed factor |
| `auth.ErrUserNotFound` | `auth.user_not_found` | 404 | The target user does not exist (also from `Grant` and `BanFor`) |
| `auth.ErrProfileInvalid` | `auth.profile_invalid` | 400 | `update-user` or `create-user` with a name over the limit or a non-https image |
| `auth.ErrIdentityTaken` | `auth.identity_taken` | 409 | `create-user` or `set-email` with an address another user holds |
| the password plugin's `password.too_short`, `password.weak`, `password.breached` and friends | | 400 | `create-user` or `set-password` with a password its rules refuse |

## Security notes

| Property | Pinned by |
|---|---|
| A non-admin is refused by every operation, and an unknown target is an error, not a silent success | `TestOrgCov_AdminRefusesNonAdminsAndUnknownUsers` |
| A ban ends the user's sessions and refuses new ones; unban restores sign-in | `TestAdmin_BanFindAndLastAdmin` |
| `users` matches `query` exactly, never a fragment; fragments go through `search-users`, which has its own rate rule | `TestAdmin_BanFindAndLastAdmin`, `TestAdmin_SearchUsersHasItsOwnRateRule` |
| A fragment search treats `%`, `_`, `!`, `*`, `?` and `[` as text, ignores case for addresses and keeps it for names, identically on SQLite, Postgres and MySQL | `TestAdmin_SearchUsersMatchesFragmentsAsText` |
| `search-users` refuses a non-admin before reading the input, and refuses an empty or over-long value, an unknown field, operator, sort or filter | `TestAdmin_SearchUsersRefusals` |
| Every database failure in a search, by email or name, reaches the caller | `TestAdmin_SearchUsersEveryDatabaseFailureSurfaces` |
| Impersonating an admin is refused by default; with `AllowImpersonatingAdmins()` it still needs a fresh sign-in, is capped, audited and stoppable, refuses self, and the impersonation session gets no admin operation | `TestAdmin_ImpersonatingAdminsIsOptIn` |
| An admin cannot be banned, and the last admin cannot be removed | `TestAdmin_BanFindAndLastAdmin` |
| Impersonation is capped at one hour, visible to the user, refused for FreshSignIn operations, refused for admin and banned targets, and stoppable | `TestAdmin_ImpersonationIsVisibleLimitedAndStoppable`, `TestOrgCov_AdminPagingNoOpsRevokeAndBannedTarget` |
| Stopping an impersonation restores the admin's own session, not fresh, only with the flow value and only for the impersonating admin; the admin's old token is dead; without the flow value the client is signed out | `TestAdmin_StopImpersonatingRestoresTheAdmin` |
| Every database failure reaches the caller; a failed identity lookup in search is an error, not an empty page | `TestOrgCov_AdminEveryDatabaseFailureSurfaces` |
| The ban check uses only `auth_user`, so `auth.New` accepts it as a session predicate | `TestNew_BanCheckPassesTheSessionCheckGuard` |
| A banned user is refused at sign-in with the configured message on the password and code methods alike, and only after proving the credential: a wrong password gets the ordinary answer | `TestAdmin_BannedUserIsRefusedAtSignInOnEveryMethod`, `TestAdmin_BannedMessageDefaultsAndTemporaryBanLifts` |
| An admin-created user signs in at once; a refused password leaves no user; a taken address stays taken; `set-password` ends the user's sessions; an admin's password and address cannot be set | `TestAdmin_CreateUserSetPasswordSetEmail` |
| Every filter field and operator answers the same on SQLite, Postgres and MySQL, plain and with prefixed tables; addresses fold, names keep case, a role is a whole element (`support` is not `support_x`), and `AdminIDs` count as admins | `TestP3Admin_FilterEveryField`, `TestP3Admin_FilterTimeAndTextOperators`, `TestP3Admin_RoleFilterFollowsRolesOf`, `TestP3Admin_RoleFilterCountsAdminIDs` |
| `sortBy` sorts by each field both ways; mixing it with `sort` is refused | `TestP3Admin_SortByEveryField` |
| `update-user` `data` sets declared app columns only, typed and checked, refuses `password`, `email`, `role` and unknown keys, and a failed write rolls the whole edit back | `TestP3Admin_UpdateUserData` |
| `all-sessions` is admin-only, pages and narrows, drops ended sessions, surfaces every database failure, and is refused (not empty) when sessions are not in SQL; last activity follows the sessions in every store mode | `TestP3Admin_AllSessionsAndLastActive`, `TestP3Admin_AllSessionsEveryDatabaseFailureSurfaces`, `TestP3Admin_SessionsInMemory`, `TestP3Admin_LastActiveOutsideSQL`, `TestP3Admin_HTTP` |
| Without the password or email plugin the operations answer with a code | `TestAdmin_WithoutPasswordOrEmailPluginTheOperationsSaySo` |
| Every database failure in the round-2 operations and in a banned user's sign-in reaches the caller | `TestAdmin_Round2EveryDatabaseFailureSurfaces` |

| Every operation checks its permission; a role without it is refused before the target is read; set-role keeps the flag in step and never removes the last admin; impersonating an admin needs `impersonate-admins` or the opt-in | `TestR30_AdminRoles`, `TestR30_AdminRolesValidate` |
| The two-factor routes refuse a caller without the permission before reading the target (an unknown id reads the same as a real one); pause keeps the factor, codes and sessions; enable ends the sessions and the kept codes work again; reset removes everything; an admin target cannot be paused or reset over HTTP but can from Go; every route and the Go reset are audited | `TestBatch1_AdminTwoFactor` |
| The routes ask the Authorizer for `two-factor` permissions, so a role with `two-factor:get` alone reads and cannot reset; the built-in admin role holds all four | `TestBatch1_AdminTwoFactorAuthorizer` |
| Without a second-factor plugin the routes answer `admin.no_two_factor_plugin` to an admin only; over HTTP an anonymous caller gets 401 and a non-admin 403 on all four | `TestBatch1_AdminTwoFactorWithoutThePlugin`, `TestBatch1_AdminTwoFactorOverHTTP` |
| Every database failure in the two-factor routes and `ResetTwoFactorFor` reaches the caller | `TestBatch1_AdminTwoFactorFaults` |

Limits: Only `search-users` has a plugin rate limit; the other operations are only reachable by admins. The audit log is the [audit plugin](../audit/README.md)'s.

## Example

- Runnable recipe: [`examples/admin-plan`](../../examples/admin-plan/) (`go run ./admin-plan` to serve, `go run ./admin-plan grant alice@example.com` to make the first admin, from `examples/`).
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/admin
