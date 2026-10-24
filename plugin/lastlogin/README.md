# github.com/ubgo/auth/plugin/lastlogin

Remembers how each user last signed in — password, a provider, a magic link, a code, a passkey — so a sign-in page can put the method the person used last in front, and so an app can see which methods its users actually use.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency.

## Wire it

From [examples/last-login](../../examples/last-login/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		magiclink.New(),
		lastlogin.New(),
	),
)
```

The plugin has no route (two under `WithCookie`) and no required option. It records on a data hook on session creation, which every sign-in method ends with, so a method added later is recorded without knowing this plugin exists.

## Options

| Option | What it does | Default |
|---|---|---|
| `WithResolver(fn)` | Names the method from the operation that created the session and the session itself; `""` records nothing for that sign-in ([`Resolver`](ds:block?id=resolver-3m9xk2wt)) | `DefaultResolver`: the plugin that ran the operation (`password`, `oauth`, `magiclink`, `email`, `phone`, `passkey`, `anonymous`, …) |
| [`WithCookie(name, maxAge)`](ds:block?id=lastlogin-withcookie-3vn9qk5t) | Also keeps the method in a cookie: every sign-in that records a method sets it (`""` takes [`DefaultCookieName`](ds:block?id=lastlogin-defaultcookiename-5qk8nw2v), `last_used_login_method`, sent by authhttp as `__Host-auth_last_used_login_method`; `0` takes [`DefaultCookieMaxAge`](ds:block?id=lastlogin-defaultcookiemaxage-8wr3mt6q), 30 days), and adds the routes below. The cookie has the core's fixed attributes, HttpOnly included, so a script reads it through `GET /lastlogin/method`. `auth.New` refuses a name outside `auth.CookieNamePattern` and a negative age (`ErrBadCookieAge`) | no cookie |
| `WithCookieConsent(fn)` | Asks `fn(ctx)` before each cookie; `false` skips the cookie for that sign-in, the database record is still written | always set under `WithCookie` |

## Go API

| Method | What it returns |
|---|---|
| `Of(ctx, userID)` | `LastLoginColumns{LastLoginMethod, LastLoginAt}`; the method is `""` and the time nil for a user who never signed in since the column existed |

Without `WithCookie` there is no HTTP route: the sign-in page reads the hint from the user row (`lastlogin.Bindings` in a composite user, or `Of`). With it, a page served before any session exists reads the cookie: server-side through `auth.RequestCookie(ctx, lastlogin.DefaultCookieName)`, or from a script:

| Route | Requirement | What it does |
|---|---|---|
| `GET /lastlogin/method` | Public | `{"method":"password"}` from this browser's cookie, `""` without one |
| `POST /lastlogin/clear` | Public | Deletes the cookie |

The cookie follows the database record's rules: none for the promotion after a second factor (the first step set it), none for an impersonation. It holds a method name, never an identifier, so it tells someone at this browser how it last signed in, not who.

## What is recorded

| Session | Recorded |
|---|---|
| Any sign-in or sign-up operation that creates a session | yes: the resolver's name and the session's creation time |
| A pending second-factor session | yes: the first factor was used; the promotion that follows (a `PendingSecondFactor` operation) is skipped so it does not overwrite it |
| An impersonation by an admin | no: not the user's own sign-in |
| A session made from Go outside any operation (`a.CreateSession`) | no: there is no operation to name |
| A hand-off exchange (`plugin/handoff`) | yes, as `handoff`; resolve it to `""` with `WithResolver` to keep the original method |

## Tables and columns

The plugin owns no table. It adds two columns to `auth_user`:

| Column | Type | Meaning |
|---|---|---|
| [`last_login_method`](ds:block?id=colmethod-7q2nv8kx) | text, default `''` | the method of the last sign-in |
| `last_login_at` | timestamp, null | when it happened |

Read them in a composite user through `lastlogin.LastLoginColumns` and `lastlogin.Bindings`, or in your own queries through `lastlogin.Method` and `lastlogin.At`.

## Errors

The plugin returns none of its own; `Of` returns `auth.ErrUserNotFound` for an unknown id and `auth.ErrOperationNotWired` when the plugin was not passed to `auth.New`.

## Security notes

| Property | Pinned by |
|---|---|
| Password, magic link and email code each record their method and time; a Go-made session records nothing; a user with no sign-in reads empty | `integration/TestLastLogin_RecordsTheMethodOfEverySignIn` |
| A pending session records the first factor, the promotion keeps it, an impersonation records nothing | `integration/TestLastLogin_PendingKeepsTheFirstFactorAndImpersonationIsSkipped` |
| `WithResolver` names the method or skips it | `integration/TestLastLogin_Resolver` |
| Every database failure fails the sign-in | `integration/TestIdentFaults_LastLogin` |

Limits:

- The method is a hint for the person who owns the account, read by the app after a session exists or from the user row. Shown to a visitor before sign-in it tells them which method an address uses; keep it behind the app's own rule, such as a consent check.

## Example

- [examples/last-login](../../examples/last-login/): a `/me` page that says how the user last signed in.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/lastlogin
