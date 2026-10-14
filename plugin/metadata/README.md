# github.com/ubgo/auth/plugin/metadata

Three JSON documents per user: `public` (the user reads it, only the backend writes it), `private` (the backend's alone, never in any answer a user can get) and `unsafe` (the user reads it and writes it with a JSON merge patch, size-capped and rate-limited). Optional admin routes read and patch all three, each call decided by an `Authorizer` you supply.

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module `github.com/ubgo/auth`, so it brings no extra dependency beyond `github.com/ubgo/sqlb`.

## Wire it

Taken from `examples/user-metadata`:

```go
ad := admin.New()
md := metadata.New(metadata.WithAdmin(adminAuthorizer(ad)))
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), ad, md),
	auth.WithSessionExtras(md.SessionExtras),
)
// then: a.Migrate(ctx), and mount authhttp.Handler(a, authhttp.Prefix("/auth"))

md.Merge(ctx, userID, metadata.Public, json.RawMessage(`{"plan":"pro"}`))
```

`metadata.New()` with no option serves `metadata.get` and `metadata.update` only; `WithAdmin` adds `metadata.admin-get` and `metadata.admin-update`. The plugin imports no other plugin: the example's `adminAuthorizer` bridges to the admin plugin's roles in a few lines.

## Storage

One table, `auth_user_metadata`, one row per user that was written, the documents in the engine's document type. A user with no row reads as `{}` three times; `DeleteUser` removes the row.

## Guide

[docs/plugins/metadata.md](../../docs/plugins/metadata.md)
