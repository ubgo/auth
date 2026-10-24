# Usernames

You will have handles in your app: a signed-in user claims one, anyone can ask whether a handle is free, names such as `admin` and your own route names can never be claimed, and the handle signs in with the user's password.

Use this plugin when people are shown to each other, or appear in URLs, and need a name that is not their email address. A handle is an identifier like an address or a number, so it lives in the same `auth_identity` table and follows the same rules, but it has no verification flow and cannot receive a message: it can sign in, never recover an account.

## Before you start

- An app running the quick start: email and password on `net/http`, as in [first app](../start/first-app.md). This guide adds the username plugin to that list.
- The whole program this guide is built from is [`examples/username`](../../examples/username/): `main.go`, a `main_test.go` that drives every step over HTTP, and a `README.md` with the same transcript.
- The reference for every option, route and error is the package's [README](../../plugin/username/README.md).

## Step 1 — Add the plugin

Pass `username.New` beside email and password. `username.Login()` lets the handle sign in; without it a handle is a display name the app can look up, and nothing more. `username.Reserved` adds your own route names to the built-in list, so a user can never claim `/pricing`.

<!-- ds:block id=newauth-x4adkhau -->
**newAuth** · [`examples/username/main.go:101-111`](../../examples/username/main.go#L101-L111)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			username.New(username.Login(), username.Reserved(reservedHandles...)),
			password.New(),
		),
	)
}
```
<!-- /ds:block hash=8740de -->

The plugin needs nothing else, and has no `Validate` refusals of its own. Two rules of the core apply to the list, though:

- A handle cannot recover an account (it receives no mail), so username and password alone fail in `auth.New` with `password: no identifier can recover an account; add one with Recover(), for example email.New(email.Recover()), or pass password.WithoutRecovery()`. Keep email with `Recover()` in the list, as above.
- Without `username.Login()` the handle is not a sign-in identifier, and the password plugin keeps accepting the address only.

Check: `go run ./username` prints `listening on http://localhost:8081`, and `GET /auth/username/available?username=anything` answers JSON instead of `auth.unknown_operation`.

## Step 2 — Claim a handle

Ada signs up with her address, asks whether `Ada_Lovelace` is free, and claims it. The handle is stored in its normal form, lowercase and trimmed, and the spelling she typed is kept for display.

```sh
O='Origin: http://localhost:8081'
curl -s -c ada.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'
curl -s 'localhost:8081/auth/username/available?username=Ada_Lovelace'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"Ada_Lovelace"}'
```

```json
{"user":{"id":"usr_onk5awmdb3rucs3y4spihacn","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"available":true}
{"username":"ada_lovelace"}
```

`available` is a `GET` with the handle in the query string, and needs no session: handles are public by nature, so saying whether one is free gives nothing away. `set` needs the session cookie (`-b ada.txt`) and the app's `Origin`, like every signed-in mutation.

From Go, the same two operations are methods on the plugin. `ctx` is the request's context, carrying the session:

<!-- ds:block id=plugin-set-chbnx53c -->
**Plugin.Set** · [`plugin/username/username.go:442-444`](../../plugin/username/username.go#L442-L444)

```go
func (p *Plugin) Set(ctx context.Context, handle string) (Result, error) {
	return p.set.Call(ctx, Request{Username: handle})
}
```
<!-- /ds:block hash=7e8a4f -->

<!-- ds:block id=plugin-available-ejr8ztwd -->
**Plugin.Available** · [`plugin/username/username.go:495-498`](../../plugin/username/username.go#L495-L498)

```go
func (p *Plugin) Available(ctx context.Context, handle string) (bool, error) {
	r, err := p.available.Call(ctx, Request{Username: handle})
	return r.Available, err
}
```
<!-- /ds:block hash=76a904 -->

Their answers are the JSON shapes above:

<!-- ds:block id=result-acs7f84u -->
**Result** · [`plugin/username/username.go:427-429`](../../plugin/username/username.go#L427-L429)

```go
type Result struct {
	Username string `json:"username"`
}
```
<!-- /ds:block hash=e3244a -->

<!-- ds:block id=availability-2u9y8jqf -->
**Availability** · [`plugin/username/username.go:435-437`](../../plugin/username/username.go#L435-L437)

```go
type Availability struct {
	Available bool `json:"available"`
}
```
<!-- /ds:block hash=9db188 -->

Check: the handle is taken now, in any spelling, and the app's `/me` shows both forms:

```sh
curl -s 'localhost:8081/auth/username/available?username=ADA_LOVELACE'
curl -s -b ada.txt localhost:8081/me
```

```json
{"available":false}
{"id":"usr_onk5awmdb3rucs3y4spihacn","handle":"ada_lovelace","display":"Ada_Lovelace"}
```

### Claim a handle from another operation

A sign-up form that asks for the handle on the same page does not want a second request. `Claim(ctx, userID, handle)` applies every rule `set` does, from inside another plugin's operation and its transaction, so the account and the handle commit or roll back together; a taken handle fails the whole sign-up and leaves no half account. The password plugin's sign-up calls it (as `ClaimWithDisplay`, with the body's `displayUsername`) when its body carries a `username`; it finds this plugin by that one method (`password.UsernameClaimer`), so a handle scheme of your own with the same method takes its place.

<!-- ds:block id=plugin-claim-2v8xk7qn -->
**Plugin.Claim** · [`plugin/username/username.go:512-514`](../../plugin/username/username.go#L512-L514)

```go
func (p *Plugin) Claim(ctx context.Context, userID, handle string) error {
	return p.ClaimWithDisplay(ctx, userID, handle, "")
}
```
<!-- /ds:block hash=abe243 -->

## Step 3 — Sign in with the handle

With `username.Login()`, the password plugin's one identifier field takes the handle as well as the address. The core tells them apart by shape: an address has an `@`, a number starts with `+`, a handle starts with a letter and has neither.

```sh
curl -s -c ada2.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"ADA_LOVELACE","password":"correct horse battery staple"}'
```

```json
{"user":{"id":"usr_onk5awmdb3rucs3y4spihacn","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Check: the user id is Ada's, and `curl -s -b ada2.txt localhost:8081/me` answers with her handle.

## Step 4 — Rename, and see what is refused

Reserved names, malformed handles and handles another user holds are refused, each with its own code. A rename frees the old handle at once.

```sh
curl -s 'localhost:8081/auth/username/available?username=pricing'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"pricing"}'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"1ada"}'
```

```json
{"available":false}
{"error":{"code":"username.reserved","message":"This username is not available."}}
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
```

Bob tries to take Ada's handle, then Ada renames herself and the old handle is free:

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"bob@example.com","password":"correct horse battery staple"}'
curl -s -b bob.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"ada_lovelace"}'
curl -s -b ada.txt -X POST localhost:8081/auth/username/set -H "$O" -d '{"username":"ada"}'
curl -s 'localhost:8081/auth/username/available?username=ada_lovelace'
```

```json
{"user":{"id":"usr_isxj6dge7gbgwqzjbg7ubsdz","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"auth.identity_taken","message":"This is already in use by another account."}}
{"username":"ada"}
{"available":true}
```

`set` claims the new handle first and deletes the old one after, inside one transaction, so a taken handle fails before anything is released. The reserved message says "not available" rather than "reserved" on purpose: it gives away nothing about the list.

Check the rows. One handle per user, as `is_primary`, with the display spelling in `value_raw`:

```sh
sqlite3 username.db "select kind, value, value_raw, is_primary from auth_identity order by created_at;"
```

```text
email|ada@example.com|ada@example.com|0
email|bob@example.com|bob@example.com|0
username|ada|ada|1
```

## Step 5 — Read the handle in your own queries

A handle lives in `auth_identity`, not in `auth_user`, so your user struct has it as a nested field filled by a join in the same statement. The example's `/me` loads it that way:

<!-- ds:block id=appuser-p3n55cug -->
**appUser** · [`examples/username/main.go:126-129`](../../examples/username/main.go#L126-L129)

```go
type appUser struct {
	auth.User
	Handle username.Data
}
```
<!-- /ds:block hash=faec7e -->

<!-- ds:block id=appuser-bindings-6s2x4es4 -->
**appUser.Bindings** · [`examples/username/main.go:134-136`](../../examples/username/main.go#L134-L136)

```go
func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), username.UserBindings(&u.Handle))
}
```
<!-- /ds:block hash=0437a2 -->

<!-- ds:block id=appuser-joins-5wvehw76 -->
**appUser.Joins** · [`examples/username/main.go:141`](../../examples/username/main.go#L141-L141)

```go
func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{username.UserJoin()} }
```
<!-- /ds:block hash=aadbf0 -->

`a.LoadUser(ctx, id, &u)` then fills `u.Handle.Handle` and `u.Handle.Display`; both are empty for a user without a handle, and `u.Handle.Exists()` says which. The `Data` struct is the plugin's part of a composite user:

<!-- ds:block id=data-te6h9jmx -->
**Data** · [`plugin/username/username.go:107-110`](../../plugin/username/username.go#L107-L110)

```go
type Data struct {
	Handle  string
	Display string
}
```
<!-- /ds:block hash=86cc86 -->

To go the other way, from a handle to its user, `ByHandleQuery` builds the statement. It normalizes the handle in Go and compares exactly, so the plain unique index is used and no engine's `lower()` rule is involved:

<!-- ds:block id=byhandlequery-avta9z5p -->
**ByHandleQuery** · [`plugin/username/username.go:645-659`](../../plugin/username/username.go#L645-L659)

```go
func ByHandleQuery(a *auth.Auth, rawHandle string, dst *auth.User) (sqlb.Query, error) {
	return a.Select().
		Columns(auth.UserBindings(dst)...).
		From(auth.TableUser).
		Join(sqlb.Join{
			Type:  sqlb.JoinInner,
			Table: TableIdentity,
			On: []sqlb.Predicate{
				sqlb.EqExpr(IdentityUserID, auth.UserID),
				sqlb.Eq(IdentityKind, KindUsername),
			},
		}).
		Where(sqlb.Eq(IdentityValue, fold(rawHandle))).
		Build()
}
```
<!-- /ds:block hash=858f59 -->

Check: `curl -s -b ada.txt localhost:8081/me` after the rename answers `{"id":"usr_onk5awmdb3rucs3y4spihacn","handle":"ada","display":"ada"}`.

## Options you may want

| Option | Use it when |
|---|---|
| `username.Login()` | The handle should sign in with the password. Without it, it is a public name only. |
| `username.Reserved(names...)` | You have route names or brand names nobody may claim. Additive to the built-in list, and names are lowercased and trimmed first. |
| `username.ScopedByTenant()` | Each tenant has its own namespace of handles; see [multi-tenancy](../concepts/multi-tenancy.md). |
| `username.Length(min, max)` | Other length bounds. `auth.New` refuses bounds nobody could satisfy. |
| `username.WithValidator(fn)` | Your own character rule for the normalized handle, in place of `ValidateChars`; the length bounds still apply. Keep `@` and a leading `+` out, or the sign-in field can no longer tell a handle from an address or a number. |
| `username.WithNormalizer(fn)` | Your own normal form, for an app that folds look-alike characters. The reserved list still matches the lowercased form. |
| `username.Immutable()` | A handle is set once; `set` of another answers `username.immutable`. For handles that appear in URLs other people have saved. |
| `username.WithoutAvailability()` | No public `available` route, when you would rather nobody probed which handles exist. |
| `username.WithAvailableLimit(n, window)` | Replaces the `available` route's own limit, [30](ds:block?id=username-availablelimit-6tq2nw8k) checks per IP per [minute](ds:block?id=username-availablewindow-3hv7mc5p) by default, counted apart from every other route. Raise it for a form that checks on every keystroke. |
| `username.DisplayValidator(fn)`, `username.DisplayNormalizer(fn)`, `username.ValidateDisplayAfterNormalization()` | Clients send a `displayUsername` beside `username` (on `set`, or on a password sign-up) and you want a rule for it or a rewrite of it. Whatever the rule, the display form must normalize to the handle, so `AdaLovelace` can be shown for `adalovelace` but `admin` cannot be shown for `joe`; anything else answers `username.display_invalid`. |

The built-in reserved list is the minimum: route names a handle would collide with the day it appears in a URL, and names a user could impersonate the operator with.

<!-- ds:block id=defaultreserved-d6zzfhmd -->
**DefaultReserved** · [`plugin/username/username.go:126-130`](../../plugin/username/username.go#L126-L130)

```go
var DefaultReserved = []string{
	"admin", "administrator", "root", "support", "help", "about", "api",
	"auth", "login", "logout", "signup", "register", "settings", "account",
	"billing", "security", "system", "static", "assets", "www", "mail",
}
```
<!-- /ds:block hash=6ea766 -->

By default a handle is [2](ds:block?id=minlength-x3pjevmb) to [39](ds:block?id=maxlength-xnr4ndys) characters, lowercase letters, digits, `-` and `_`, starting with a letter. The leading letter keeps a handle from ever looking like a phone number, and the missing `@` from looking like an address, so one sign-in field can tell the three apart; `Length` and `WithValidator` change the bounds and the characters, and a rule that lets those two characters in breaks that.

## From TypeScript

Use this when a sign-up form checks a handle as the user types, or a profile page claims or renames one. The [typed client](../client/README.md) has the two routes as `client.username.available` and `client.username.set`; list `username()` in `plugins`. Signing in by handle is `client.password.signIn` with the handle as the `identifier` (with `username.Login()` on the server).

A hint beside the field, before submit. `available` is a public `GET`, rate limited per IP, so debounce it:

<!-- ds:block id=tsp-username-available-2wn7kq4m -->
**handleHint** · [`clients/ts/examples/plugin-identifiers.ts:40-44`](../../clients/ts/examples/plugin-identifiers.ts#L40-L44)

```typescript
export async function handleHint(handle: string): Promise<string> {
  const { data, error } = await auth.username.available({ username: handle });
  if (error) return error.code === "auth.rate_limited" ? "" : error.message;
  return data.available ? "Available" : "Taken";
}
```
<!-- /ds:block hash=bfe621 -->

Claim or rename on the signed-in account; the answer is the stored lower-case form:

<!-- ds:block id=tsp-username-set-6qm2xw8k -->
**claimHandle** · [`clients/ts/examples/plugin-identifiers.ts:49-61`](../../clients/ts/examples/plugin-identifiers.ts#L49-L61)

```typescript
export async function claimHandle(handle: string): Promise<string> {
  const { data, error } = await auth.username.set({ username: handle });
  if (!error) return `You are @${data.username}.`;
  switch (error.code) {
    case "auth.identity_taken":
    case "username.reserved":
      return "This username is not available.";
    case "username.immutable":
      return "Your username cannot be changed.";
    default:
      return error.message;
  }
}
```
<!-- /ds:block hash=82f4cf -->

Or claim it in the sign-up call itself, so a taken handle leaves no half-made account:

<!-- ds:block id=tsp-username-signup-9vk4nw3q -->
**signUpWithHandle** · [`clients/ts/examples/plugin-identifiers.ts:66-69`](../../clients/ts/examples/plugin-identifiers.ts#L66-L69)

```typescript
export async function signUpWithHandle(address: string, secret: string, handle: string): Promise<boolean> {
  const { error } = await auth.password.signUp({ identifier: address, password: secret, name: handle, username: handle });
  return error === null;
}
```
<!-- /ds:block hash=4fd811 -->

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `auth.identity_taken` and `username.reserved` (show one "not available" message for both), `auth.identifier_invalid` (show the length and character rule), `username.display_invalid`, `username.immutable` under `Immutable()`, `auth.rate_limited` from `available`, and `password.no_usernames` when sign-up sends a `username` to a server without this plugin.

There is no runnable TypeScript example for usernames yet; the blocks above are type-checked by `task ts:check`, and Step 2's curl transcript shows the answers.

Pitfalls:

- **"Available" is a hint, not a reservation.** Another user can claim the handle between the check and the submit; `set` or the sign-up can still answer `auth.identity_taken`, and the form has to handle it.
- **Setting the handle you already have answers `auth.identity_taken`**, because the check is "held by any user"; compare with the current handle before calling `set`.

Every method with its route and types: [TypeScript client reference › username](../reference/ts-client.md#username).

## What can go wrong

| Error | When | Fix |
|---|---|---|
| `username.reserved` (409, "This username is not available.") | The handle is on the built-in list or in `Reserved`. Refused on every path, through a data hook, so a handle created by other code is refused too. | Pick another handle. |
| `auth.identifier_invalid` (400, "This does not look right. Check it and try again.") | Wrong length, a digit or symbol first, or a character outside letters, digits, `-` and `_`. | Show the rule in the form. |
| `auth.identity_taken` (409, "This is already in use by another account.") | Another user holds the handle, whatever its case. A user setting their own current handle again gets this too. | Ask for another handle; check `available` first. |
| `username.display_invalid` (400, "This display username is not valid for the username.") | A `displayUsername` your `DisplayValidator` refused, or one that names another handle. | Send a display form of the same handle, or none. |
| `username.immutable` (409, "Your username cannot be changed.") | `set` of another handle under `Immutable()`. | Expected; the first handle is the one that stays. |
| `username: Length needs 1 <= min <= max` from `auth.New` | `Length` with impossible bounds. | Fix the numbers. |
| `auth.signed_out` (401, "Sign in to continue.") | `set` without a session. | Send the session cookie, or the bearer token. |
| `password: no identifier can recover an account; …` from `auth.New` | Username and password without an identifier that can receive mail. | Keep `email.New(email.Recover(), …)` in the list, or pass `password.WithoutRecovery()`. |
| `password.invalid_credentials` (401) on sign-in by handle | `username.Login()` is missing, so the handle is not a sign-in identifier. | Add `username.Login()`. |

`available` is public and has a rate limit of its own: [30](ds:block?id=username-availablelimit-6tq2nw8k) checks per IP per [minute](ds:block?id=username-availablewindow-3hv7mc5p), after which it answers `auth.rate_limited` (429) until the window passes. Change it with `username.WithAvailableLimit`, replace it with an app rate rule for `username.EndpointAvailable` (see [rate limits](../concepts/rate-limits.md)), or leave the route out with `username.WithoutAvailability()`.

## Next

- [Email](email.md) is the identifier that recovers the account a handle signs in to.
- [Identifiers and verification](../concepts/identifiers-and-verification.md) explains why a handle is unique over every row while an address is unique among verified ones.
- [Databases](../concepts/databases.md) covers composite user queries and the stable columns of `auth_identity`.
- The package [README](../../plugin/username/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/username).
