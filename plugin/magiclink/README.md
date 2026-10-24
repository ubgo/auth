# github.com/ubgo/auth/plugin/magiclink

Adds passwordless sign-in by a single-use link sent to a user's verified email address (or any identifier kind whose plugin can deliver), and optionally sign-up by the same link.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency. It sends nothing itself: it asks the core to deliver through whichever plugin owns the identifier's kind, such as `plugin/email`.

## Wire it

From [examples/magic-link](../../examples/magic-link/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		magiclink.New(magiclink.SignUp()),
	),
)
```

It needs at least one identifier kind that can sign in, has a verification flow, and whose plugin delivers messages. `email.New(email.Login(), …)` is one; a username is not. The plugin is a sign-in method by itself, so email plus magic links is a complete app.

The link opens a page of your app, [`DefaultPage`](ds:block?id=defaultpage-uke973qb) (`/magic-link`) unless you pass `Links`. The page must POST the token to `/magiclink/sign-in`; a GET that signed in would be spent by every mail scanner that previews links. The example serves such a page. `VerifyByGET()` is the opt-in exception, with its risk below.

`auth.New` fails with:

| Error | Text | Cause |
|---|---|---|
| `ErrNoBase` | `magiclink: links need auth.WithBaseURL or magiclink.Links` | neither set |
| `ErrNoKinds` | `magiclink: no identifier kind can receive a link; add a Verifiable kind whose plugin delivers, such as email` | no usable kind registered (checked in `Validate`, and again in `Init` for delivery) |
| `ErrBadKinds` | `magiclink: a kind given to Kinds must be registered, sign-in capable, verifiable and owned by a plugin that delivers` | a kind named in `Kinds` fails one of those |

## Options

| Option | What it does | Default |
|---|---|---|
| `Kinds(kinds...)` | Restrict links to these identifier kinds | every sign-in, verifiable kind whose plugin delivers |
| `SignUp()` | A link to an identifier nobody has verified creates the account on click | off: such a link is not sent at all |
| `WithTTL(d)` | Link lifetime | [`DefaultTTL`](ds:block?id=defaultttl-z8p2fp62) = 15 minutes |
| `Links(fn)` | Builds the URL from the token | `baseURL + DefaultPage + "?token=…"` |
| [`VerifyByGET()`](ds:block?id=magiclink-verifybyget-5kr8nw2q) | The link is `baseURL` + [`DefaultMountPrefix`](ds:block?id=magiclink-defaultmountprefix-3nw8kq6v) (`/auth`) + `/magiclink/verify?token=…` with the send request's `callbackURL`, `newUserCallbackURL` and `errorCallbackURL`; the GET signs in and redirects to `newUserCallbackURL` when it created the account, else `callbackURL`, and a bad link to `errorCallbackURL` (or `callbackURL`, or `auth.WithErrorURL`) with `?error=<code>`; with no `callbackURL` it answers JSON. Each page must pass `auth.Auth.TrustsReturnURL` ([`magiclink.callback_invalid`](ds:block?id=magiclink-errcallbackinvalid-7tq2mw5x)). Risk: a mail scanner that fetches the link signs in and spends it, and a GET sign-in cannot be origin-checked, so a link to an attacker's own account signs a victim into it (login CSRF); `auth.WithFetchMetadata` judges mutations only and does not cover this GET | off: the link opens your page, which POSTs |
| [`GenerateToken(fn)`](ds:block?id=magiclink-generatetoken-3vr7kx2m) | A plain override: `fn(ctx, identifier)` returns the link's token, used as is; an error or an empty token from `fn` fails the send. Risk: a link token is found by its hash alone with no attempt counter, so a guessable token signs in whoever guesses it | off: 256 random bits |
| `WithSendLimit(n, window)` | Rate rule of `send` per identifier | 3 per 15 minutes (`sendLimit`, `sendWindow`) |
| `WithIPLimit(n, window)` | Rate rule of `send` per IP | 20 per hour (`sendIPLimit`, `sendIPWindow`) |

## Routes and Go API

The routes are under your mount prefix (for example `/auth`).

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /magiclink/send` (`identifier`, optional `name` for the account a link creates, optional `metadata` for the sender) | `Send(ctx, identifier)`, `SendAs(ctx, identifier, name)`, `SendWithMetadata(ctx, identifier, metadata)`, `SendWith(ctx, SendRequest{…, CallbackURL, NewUserCallbackURL, ErrorCallbackURL})` | Public | 3 per 15 minutes per identifier ([`sendLimit`](ds:block?id=sendlimit-6v7fhkmf), [`sendWindow`](ds:block?id=sendwindow-d5jquxvk)); 20 per hour per IP ([`sendIPLimit`](ds:block?id=sendiplimit-f3us3sne), [`sendIPWindow`](ds:block?id=sendipwindow-usu2f57p)) |
| `GET /magiclink/verify?token=…&callbackURL=…&newUserCallbackURL=…&errorCallbackURL=…` | none: a browser follows the mailed link | Public | none; only with `VerifyByGET` |
| `POST /magiclink/sign-in` | `SignIn(ctx, token)` returns `SignInResult{User, Created, SecondFactorRequired, Token}` | Public | none (the token is single-use) |

- `send` answers OK for every input. It sends only to the verified owner's identifier, or, with `SignUp()`, to an identifier nobody has verified. It never sends to an unverified row's account, a kind outside `Kinds`, or a value that is no identifier.
- `sign-in` spends the token and starts a session. A user with two-factor gets a pending session (`SecondFactorRequired`) only under `twofactor.WithPolicy(twofactor.AskEverySignIn)`: the two-factor plugin's default does not ask after a magic link.
- `metadata` (an invite id, a page to return to) travels with the message to the delivering plugin's sender — `email.Mail.Metadata`, or `phone.MetadataSender` — and is never stored. At most `email.MaxMetadataEntries` entries of `email.MaxMetadataLength` bytes; over the bounds the request is refused with `auth.bad_request` ([`TestMetadata_ReachesTheSender`](https://github.com/ubgo/auth/blob/main/integration/metadata_test.go)).

## Tables and columns

The plugin owns no table and adds no column. A link is a core verification token (`auth_verification`) with purpose [`PurposeSignIn`](ds:block?id=purposesignin-9w1k7l0e) (`magiclink.sign-in`). Its identifier is `<kind>:<normalized value>` and its meta is the tenant it was sent in.

## Errors

| Error | Code | HTTP | When |
|---|---|---|---|
| `auth.ErrTokenInvalid` | `auth.token_invalid` | 400 | the token is bad, spent or expired; it was clicked in another tenant; or, without `SignUp()`, the identifier has no verified owner any more |
| `magiclink.ErrCallbackInvalid` | `magiclink.callback_invalid` | 400 | `send` or the GET `verify` with a `callbackURL`, `newUserCallbackURL` or `errorCallbackURL` that is not a site path or a URL on a trusted origin; judged on the input alone, and nothing is sent or spent |
| `auth.ErrRateLimited` | `auth.rate_limited` | 429 | a `send` limit above |

`ErrNoBase`, `ErrNoKinds` and `ErrBadKinds` are configuration errors from `auth.New`.

## Security notes

| Property | Pinned by |
|---|---|
| A link signs in only the verified owner, works once and expires; unknown and unverified identifiers get the same answer and no mail | `integration/TestMagicLink_SignsInTheVerifiedOwnerOnly` |
| With `SignUp()`, the clicked identifier is created verified | `integration/TestMagicLink_SignUpCreatesAVerifiedAccount` |
| A link is bound to its tenant and refused in another | `integration/TestMagicLink_BoundToItsTenant` |
| A kind whose plugin cannot deliver is refused at start. Otherwise `send` would fail only for identifiers that have an account, which reveals them | `plugin/magiclink/TestInit_RefusesAKindThatCannotDeliver` |
| `Kinds`, `WithTTL`, `Links`, and a link to an address removed since | `integration/TestIdentMagicLink_OptionsAndRefusals` |
| Every database failure fails the operation | `integration/TestIdentFaults_MagicLink` |
| `GenerateToken`'s token is the one linked and it signs in; a generator error fails the send and mails nothing | `integration/TestR21_MagicLinkGenerateToken`, `TestR21_GeneratorErrorsFailTheSend` |

Limits:

- Whoever reads the mailbox can sign in; the short [`DefaultTTL`](ds:block?id=defaultttl-z8p2fp62) and single use bound that window.
- Mail is delivered after the transaction commits, in the background. A delivery error is logged, not returned.

## Example

- [examples/magic-link](../../examples/magic-link/): email plus magic links, with sign-up and the POSTing link page.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/magiclink
