# github.com/ubgo/auth/plugin/sessiondata

Keeps per-session app data in a table of its own, keyed by session id, with the same typed API as the core's inline `Session.Data`: `Get` and `Set` on the request's session, encoded as JSON from the app's own Go type. For an app that wants the data out of the session record: a value the session store (Redis, memory) should not hold, a value that must never travel in a token or a cache entry, or a table the app joins and reports on.

The rows follow the sessions through the core's `auth.SessionLifecycle`: a sign-out, a revoke, "sign out everywhere" and a deleted user remove the row, a second-factor promotion moves it to the full session, and `a.Sweep` removes the rows of sessions that reached their hard stop. There is no foreign key and no cascade: the library creates none on any engine.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency.

## Wire it

From [examples/session-data](../../examples/session-data/main.go):

```go
sd := sessiondata.New(sessiondata.WithInitial(func(_ context.Context, s auth.Session) (any, error) {
	return device{UserAgent: s.UserAgent, SignedInAt: s.CreatedAt}, nil
}))
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		sd,
	),
)
```

The plugin has no route and no required option. `a.Migrate` creates its table with everything else.

## Inline or table?

| | `Session.Data` (core) | this plugin |
|---|---|---|
| Where it lives | with the session: the row, the Redis hash, the memory map, the stateless token, the client snapshot, every cache entry | a row in [`auth_session_data`](ds:block?id=tablenamesessiondata-5kq8mw2x), in SQL whatever the session store |
| Read cost | none: it came with the session | one query per `Get` |
| Bound | [`auth.MaxSessionDataSize`](ds:block?id=maxsessiondatasize-9wk3rq2d) | the same |
| In a token or a cookie | yes, in stateless mode and in a client snapshot | never |
| Read | `auth.SessionData[T](ctx)` | [`sessiondata.Get[T](ctx, p)`](ds:block?id=sessiondata-get-2nq7xk4m) |
| Write | `auth.SetSessionData(ctx, a, v)` | [`p.Set(ctx, v)`](ds:block?id=sessiondata-set-9rk3wq6t) |
| At sign-in | a `Session.BeforeCreate` data hook with `auth.EncodeSessionData` | `WithInitial(fn)` |

Both can be used at once, as the example does.

## Options

| Option | What it does | Default |
|---|---|---|
| `WithInitial(fn)` | Records `fn`'s value for every session the core creates, inside the transaction that creates it; `nil` records nothing, an error fails the sign-in. A pending second-factor session gets its row at the first factor and the promotion moves it, so `fn` runs once per sign-in ([`Initial`](ds:block?id=sessiondata-initial-7mw3kq9r)) | no row until `Set` |

## Go API

| Function | What it does |
|---|---|
| `Get[T](ctx, p)` | The request's session's data as `T`; `ok` false for a signed-out request, an API-key request or a session with no row; an error when the row is not a `T` or the database failed |
| `GetFor[T](ctx, p, sessionID)` | The same for any session id, for a hook or a list |
| `p.Set(ctx, v)` | Replaces the request's session's data with `v` as JSON; `nil` deletes the row. Last write wins |
| `p.SetFor(ctx, s, v)` | The same for any session, such as the one a hook is handed |

There is no HTTP route: the data is the app's, read and written by the app's own handlers, as [examples/session-data](../../examples/session-data/) does with `/me` and `/workspace`.

## Tables and columns

| Column | Type | Meaning |
|---|---|---|
| `session_id` | key, primary | the session the row belongs to; one row per session |
| `user_id` | key, indexed | the session's user, registered as an `auth.UserTable` so `DeleteUser` removes the rows |
| `data` | document | the app's JSON, compact |
| `expires_at` | timestamp | the session's hard stop (`MaxExpiresAt`, or its expiry when it has none); `a.Sweep` removes the row after it |
| `updated_at` | timestamp | when the data was last written |

Read it in your own queries through `sessiondata.TableData` and the typed columns `DataSessionID`, `DataUserID`, `DataValue`, `DataExpiresAt`, `DataUpdatedAt`. Rename it with `auth.RenameTable(sessiondata.TableData, …)` or `auth.WithTablePrefix`.

## When rows go

| Event | Rows |
|---|---|
| Sign-out, revoke by id, an admin ending a session, a device's other account ended | that session's row, before the store is told, in the same transaction |
| Sign-out everywhere, a password reset, a ban | every row of the user but the excepted session's |
| Second-factor promotion | the pending session's row moves to the full session; a row the full session already had gives way |
| The user is deleted | every row of the user (`auth.UserTable`) |
| The session expires | the row stays until `a.Sweep` runs after the session's hard stop plus the retention; the core sees no end for an expiry, in any store |
| Stateless mode: sign-out on one device | the row goes (the id is in the token); other ends are only the cookie being cleared, and the sweep covers them |

## Errors

| Error | When |
|---|---|
| `auth.ErrSignedOut` | `Set` on a signed-out request |
| `auth.ErrSessionDataUnavailable` (409 `auth.session_data_unavailable`) | `Set` on a request signed in with an API key: no session row |
| `auth.ErrSessionDataTooLarge` | the encoded value exceeds [`auth.MaxSessionDataSize`](ds:block?id=maxsessiondatasize-9wk3rq2d) |
| `auth.ErrSessionDataInvalid` | the value does not encode as JSON |
| `auth.ErrOperationNotWired` | `SetFor` or `GetFor` before the plugin was passed to `auth.New` |

## Security notes

| Property | Pinned by |
|---|---|
| A row is written at sign-in, read and replaced through the request, kept at a promotion under the new id, and removed by sign-out, sign-out everywhere, a deleted user and the sweep, in every store and stateless mode, on every engine | `integration/TestSessionDataPlugin_GetSetAndLifecycle`, `TestSessionDataPlugin_PromotionMovesTheRow` |
| A signed-out or API-key request can neither read nor write; a failing initial function fails the sign-in | `integration/TestSessionDataPlugin_Refusals` |
| Every database failure fails the operation, and a failing plugin keeps the session in every store | `integration/TestSessionDataFaults`, `TestSessionLifecycle_NoticesAndTheirErrors` |
| The table carries no foreign key, and its user column is registered for deletion | `plugin/sessiondata/TestPlugin_MigrationsPerEngine`, `integration/TestGuard_UserTablesAreDeleted` |

Limits:

- `Get` is one query; a page that reads it on every request pays that query. Data a request needs every time belongs inline (`Session.Data`), which comes with the session.
- The bound is the core's: a document does not fit. A large value belongs in a table of the app's own keyed by session id, cleaned through `auth.SessionLifecycle` the way this plugin does.

## Example

- [examples/session-data](../../examples/session-data/): the active workspace inline, the sign-in device in this plugin's table, `/me` showing both.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/sessiondata
