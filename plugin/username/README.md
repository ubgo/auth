# github.com/ubgo/auth/plugin/username

Adds handles (usernames) to accounts: a user claims or renames a handle, anyone can ask whether a handle is free, reserved names such as `admin` can never be claimed, and a handle can optionally sign in with the password.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency.

## Wire it

Adapted from the plugin list in [examples/poc](../../examples/poc/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		username.New(username.Login(), username.Reserved("khanakia", "ubgo")),
		password.New(),
	),
)
```

A handle is not a sign-in method on its own: pair it with `password` (or another method). A handle cannot receive messages, so it can never recover an account. Username plus password alone fails in `auth.New` with `password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()`.

The plugin has no `Validate` refusals of its own.

## Options

| Option | What it does | Default |
|---|---|---|
| `Login()` | The handle can sign in (e.g. with `password`) | off |
| `ScopedByTenant()` | Handles unique per tenant (`auth.WithScope`) | global |
| `Length(min, max)` | Replaces the length bounds; `auth.New` refuses `min` below 1 or `max` below `min` (`ErrBadLength`) | `MinLength` = 2, `MaxLength` = 39 |
| `WithValidator(fn)` | Replaces the character rule (`ValidateChars`) for the normalized handle; the length bounds still apply. Keep `@` and a leading `+` out, or one sign-in field can no longer tell a handle from an address or a number | `ValidateChars` |
| `WithNormalizer(fn)` | Replaces `Normalize` (trim and lowercase); the reserved list is still matched on the trimmed, lowercased form | `Normalize` |
| `Immutable()` | `set` refuses a rename once the user has a handle (`username.immutable`); the first handle can still be set | off |
| `WithoutAvailability()` | Leaves the public `available` route out | route on |
| `WithAvailableLimit(n, window)` | Replaces the `available` route's own per-IP limit; `auth.New` refuses a limit below 1 or a window of zero (`ErrBadAvailableLimit`) | [`DefaultAvailableLimit`](ds:block?id=username-availablelimit-6tq2nw8k) per [`DefaultAvailableWindow`](ds:block?id=username-availablewindow-3hv7mc5p) |
| [`DisplayValidator(fn)`](ds:block?id=username-displayvalidator-7nm3qx5k) | A rule for the display form a client sends as `displayUsername` (better-auth's `displayUsernameValidator`); an error refuses the call with `username.display_invalid` | no extra rule |
| [`DisplayNormalizer(fn)`](ds:block?id=username-displaynormalizer-2wq9kt6r) | Rewrites the display form before it is stored (better-auth's `displayUsernameNormalization`) | kept as sent |
| `ValidateDisplayAfterNormalization()` | `DisplayValidator` sees the rewritten form instead of the one sent (better-auth's `validationOrder.displayUsername: "post-normalization"`) | before normalization |
| `Reserved(names...)` | Adds names to the reserved set, on top of `DefaultReserved`; names are trimmed and lowercased | `DefaultReserved` (21 names: `admin`, `root`, `support`, `settings`, `api`, `login`, …) |

A handle is always unique over every row, verified or not, because a handle has no verification. It is stored verified. `Validate` allows [`MinLength`](ds:block?id=minlength-x3pjevmb) (2) to [`MaxLength`](ds:block?id=maxlength-xnr4ndys) (39) characters: lowercase letters, digits, `-` and `_`, starting with a letter. The leading letter keeps a handle from ever looking like a phone number, and the missing `@` keeps it from looking like an address, so one sign-in field can tell the three apart.

## Routes and Go API

The routes are under your mount prefix (for example `/auth`). The plugin declares no rate limits.

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /username/set` with `username` and optional `displayUsername` | `Set(ctx, handle)`, `SetWithDisplay(ctx, handle, display)` return `Result{Username}` | SignedIn | none |
| `GET /username/available?username=…` | `Available(ctx, handle)` returns `bool` | Public | 30 per minute per IP (`WithAvailableLimit`) |
| (no route) | `Claim(ctx, userID, handle)` and `ClaimWithDisplay(ctx, userID, handle, display)`: the same rules as `set`, from inside another plugin's operation, such as a password sign-up that takes a `username` in the same body ([`Claim`](ds:block?id=plugin-claim-2v8xk7qn)); `ClaimWithDisplay` is what makes this plugin the password plugin's `UsernameClaimer` | the caller's | the caller's |

- The display form is what `Data.Display` shows: the handle as typed, or the `displayUsername` the client sent (on `set`, or as `displayUsername` on a password sign-up beside `username`). It goes through `DisplayNormalizer` and `DisplayValidator`, and one rule always holds: it must normalize to the same handle, so `"AdaLovelace"` can be shown for `adalovelace` but `"admin"` cannot be shown for `joe`. better-auth checks nothing by default; a display free of the handle would get around the reserved list and the uniqueness the handle exists for ([`DisplayForm`](ds:block?id=username-displayform-6vk2mr8t)).
- `set` claims the new handle first, then deletes the old one. A taken handle fails before the old one is released, and after a rename the old one is free for anyone.
- `available` answers false for a reserved, malformed or taken handle. The answer can be stale by the time `set` runs; the unique index is the authority.
- `IsReserved(handle)` checks the reserved set in Go.

## Tables and columns

The plugin owns no table.

- **Handles:** each handle is a row of the core `auth_identity` table with `kind = 'username'`: `value` holds the normalized form, `value_raw` what the user typed. The core's `0000_identity_unique_username_all` migration (`…_all_scoped` under `ScopedByTenant()`) adds the unique index.
- **Queries:** the plugin reads `auth_identity` under the alias `uni` ([`TableAliasIdentity`](ds:block?id=tablealiasidentity-r7attc8r)).
  - `username.UserJoin()` with `username.UserBindings(&u.Handle)` fills a nested `username.Data` (`Handle`, `Display`) in a composite user query.
  - `username.Of(a, userID, &d)` builds the standalone lookup.
  - `username.ByHandleQuery(a, handle, &u)` resolves a user from a handle.

`stability_test.go` lists every `auth_identity` column these read (`user_id`, `kind`, `value`, `value_raw`, `is_primary`, `created_at`) as stable.

## Errors

| Error | Code | HTTP | When |
|---|---|---|---|
| `username.ErrReserved` | `username.reserved` | 409 | `set` of a reserved handle, however the identity is created (a data hook) |
| [`username.ErrDisplayInvalid`](ds:block?id=username-errdisplayinvalid-4kq8wz2m) | `username.display_invalid` | 400 | a `displayUsername` that `DisplayValidator` refused or that does not normalize to the handle |
| `username.ErrImmutable` | `username.immutable` | 409 | `set` of a new handle under `Immutable()` when the user already has one |
| `username.ErrBadLength` | (plain error, from `auth.New`) | – | `Length` with `min` below 1 or `max` below `min` |
| `auth.ErrIdentityTaken` | `auth.identity_taken` | 409 | `set` of a handle another user has |
| `auth.ErrIdentifierInvalid` | `auth.identifier_invalid` | 400 | `set` of a malformed handle |
| `auth.ErrPluginNotRegistered` | (plain error) | – | `Of` on an `*auth.Auth` without this plugin |

## Security notes

| Property | Pinned by |
|---|---|
| `available` stops one client at its own limit and lets it in again after the window | `integration/TestR23_UsernameAvailableHasItsOwnLimit`, `plugin/username/TestAvailableLimit` |
| Reserved names are refused on every path, whatever their case; the list is additive | `integration/TestUsername_SetAvailableReserved`, `plugin/username/TestIsReserved_CoversRouteCollisionsAndIsAdditive`, `TestReserved_FoldsLikeTheNormalizer` |
| A handle is unique over every row, not only verified ones | `plugin/username/TestKind_IsUniqueOverEveryRow` |
| Lookup normalizes in Go and compares exactly, never with SQL `lower()` | `plugin/username/TestByHandleQuery_ComparesTheNormalFormExactly` |
| `Claim` applies the reserved, taken and malformed rules and replaces an existing handle; under `Immutable()` a second claim is refused | `integration/TestIdentUsername_Claim`, `integration/TestIdentUsername_ClaimImmutable` |
| Every database failure fails the operation | `integration/TestIdentFaults_Username` |

Limits:

- `available` is public and has its own per-IP limit, counted apart from every other route, so one client cannot walk a dictionary of handles. Change it with `WithAvailableLimit`, replace it with an app rule for `EndpointAvailable`, or leave the route out with `WithoutAvailability()`.
- `DefaultReserved` is a minimum; add every route name of your app with `Reserved`.

## Example

- [examples/poc](../../examples/poc/): the plugin wired beside email, phone and password, plus the composite user query.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/username
