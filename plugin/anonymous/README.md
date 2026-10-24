# github.com/ubgo/auth/plugin/anonymous

Gives a visitor an account before they have said who they are: a guest session for a cart, a trial or a draft. The moment the guest signs up or signs in with any method, the app's hook moves their data to the real account and the guest row is deleted.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency.

## Wire it

From [examples/guest-sessions](../../examples/guest-sessions/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		anonymous.New(anonymous.OnLink(moveCart)),
	),
)
```

A guest is an ordinary `auth_user` row with no identifier and the plugin's `is_anonymous` column set, so every app table that references a user works for a guest unchanged. The plugin is a sign-in method by itself; an app with guests and nothing else passes `auth.New`.

`auth.New` never fails for this plugin's sake: it has no required option.

## Options

| Option | What it does | Default |
|---|---|---|
| `OnLink(fn)` | The app's hook when a guest signs up or in: move the guest's rows to the account, inside the sign-in's transaction ([`LinkFunc`](ds:block?id=linkfunc-5r8nq3vd)) | nothing moves; the guest is deleted (or kept) |
| `KeepUsers()` | Keep the guest row after linking, and leave the delete route out | the guest is deleted once linked |
| `WithName(fn)` | How a guest's display name is made | [`DefaultName`](ds:block?id=defaultname-m3xc8t4e) (`Guest`) for everyone |
| `SweepStale()` | `a.Sweep` deletes guests older than the retention whose every session has expired | off: a sweep deletes no guest |
| `WithSignInLimit(n, window)` | Rate rule of `sign-in` per IP | 10 per hour (`signInIPLimit`, `signInIPWindow`) |

## Routes and Go API

The routes are under your mount prefix (for example `/auth`).

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /anonymous/sign-in` (optional `remember`) | `SignIn(ctx)` returns `SignInResult{User, Token}` | Public | 10 per hour per IP ([`signInIPLimit`](ds:block?id=signiniplimit-9v4bq2zp), [`signInIPWindow`](ds:block?id=signinipwindow-2k7xw8rt)) |
| `POST /anonymous/delete` | `Delete(ctx)` | SignedIn | none |

- `sign-in` creates a guest and starts a session. A caller who is already a guest is refused with `anonymous.already`, so a page that reloads cannot pile up guest rows. A signed-in real user who asks gets a guest session and their cookie is replaced; nothing links. `remember: false` makes the session transient, as for a password sign-in.
- `delete` removes the guest's own account and ends the session; a real account answers `anonymous.not_anonymous`. Not registered under `KeepUsers()`.
- `IsAnonymous(ctx, userID)` reports whether a user is a guest, for the app's own checks.

## Linking

Every sign-in method ends by creating a session, so the link is a data hook on session creation: the request's signed-in user is the guest, the new session's user is the account. It fires for a password sign-up or sign-in, a magic link, an email or SMS code, a social provider and a passkey alike, and for a method added later. The hook does not fire for a session of the same user, for an impersonation, or when the request carries no guest.

Inside the hook, in the sign-in's own transaction: the app's `OnLink` runs with the guest and the account, then the guest is deleted (with `KeepUsers()`, kept). An `OnLink` error fails the sign-in and leaves the guest as it was. A guest who adds and verifies an address or number of their own stops being a guest: the flag clears, and a later sign-in to another account no longer links them away.

## Tables and columns

The plugin owns no table. It adds one column to `auth_user`:

| Column | Type | Meaning |
|---|---|---|
| [`is_anonymous`](ds:block?id=colisanonymous-7h2kq9mw) | bool, default false | true for a guest; false for everyone else, including a guest who later verified an identifier |

Read it in a composite user through `anonymous.AnonymousColumns` and `anonymous.Bindings`, or filter guests out of your own queries with `anonymous.IsAnonymous`.

## Errors

| Error | Code | HTTP | When |
|---|---|---|---|
| `ErrAlreadyAnonymous` | `anonymous.already` | 409 | a guest asks for another guest session |
| `ErrNotAnonymous` | `anonymous.not_anonymous` | 403 | a real account calls `delete` |
| `auth.ErrRateLimited` | `auth.rate_limited` | 429 | the `sign-in` limit above |

## Security notes

| Property | Pinned by |
|---|---|
| A guest is linked and deleted on sign-up from the guest session; a second guest sign-in is refused; a real user's guest links nothing | `integration/TestAnonymous_GuestSignsUpAndIsLinked` |
| Password sign-in, a magic link and an email code all link; a sign-in without a guest session links nothing | `integration/TestAnonymous_LinksOnEverySignInPath` |
| An `OnLink` error rolls the sign-in back and keeps the guest | `integration/TestAnonymous_LinkErrorFailsTheSignIn` |
| `KeepUsers` keeps the row and hides the route | `integration/TestAnonymous_KeepUsers` |
| A guest deletes only their own account | `integration/TestAnonymous_DeleteOwnAccount` |
| A verified identifier ends guest status | `integration/TestAnonymous_VerifiedIdentifierEndsGuestStatus` |
| The sweep deletes only old guests with no live session, and only under `SweepStale` | `integration/TestAnonymous_SweepStale`, `integration/TestAnonymous_SweepOffByDefault` |
| A guest another instance's sweep deleted first is skipped, not counted; `WithName` names the guest | `integration/TestAnonymous_SweepSkipsAGuestAnotherSweepDeleted` |
| Guest creation is limited per IP | `integration/TestAnonymous_RateAndRemember` |
| Every database failure fails the operation | `integration/TestIdentFaults_Anonymous` |

Limits:

- A guest session is a cookie: whoever holds the device holds the cart. Nothing in it is worth more than that until the person signs in.
- Deleting a guest deletes the library's rows for it, and your `User.BeforeDelete` hook (`auth.WithDataHooks`) is where the app's rows that hold the guest's id go; there is no cascade. Move what matters in `OnLink` first; use `KeepUsers()` when guest rows have value of their own.

## Example

- [examples/guest-sessions](../../examples/guest-sessions/): a cart kept for a guest and handed to the account they sign up with.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/anonymous
