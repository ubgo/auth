# github.com/ubgo/auth/plugin/handoff

Moves a signed-in session to another client in one step: a web page asks for a short-lived, single-use token, hands it to a native app, a desktop helper, a CLI or a page on a second domain, and that client exchanges it for a session of its own.

## Install

```sh
go get github.com/ubgo/auth
```

The package is part of the core module, so it adds no dependency.

## Wire it

From [examples/handoff](../../examples/handoff/main.go):

```go
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		handoff.New(),
	),
)
```

The plugin is not a sign-in method: it needs one beside it, since a token is minted from an existing session.

`auth.New` fails with:

| Error | Text | Cause |
|---|---|---|
| `ErrBadTTL` | `handoff: WithTTL needs a positive duration` | `WithTTL(0)` or less |

## Options

| Option | What it does | Default |
|---|---|---|
| `WithTTL(d)` | How long a token can be exchanged | [`DefaultTTL`](ds:block?id=defaultttl-k8w2pn5q) = 3 minutes |
| `ServerOnly()` | The `generate` route answers `auth.unknown_operation` and is absent from the OpenAPI document and the generated TypeScript client; tokens are minted only by the app's own Go code through `Generate` | the route is served |
| `WithGenerateLimit(n, window)` | Rate rule of `generate` per IP | 10 per minute (`generateLimit`, `generateWindow`) |
| `WithVerifyLimit(n, window)` | Rate rule of `verify` per IP; the per-token rule is fixed | [10](ds:block?id=handoff-verifylimit-3xr8mq2w) per [minute](ds:block?id=handoff-verifywindow-7kp4nt9v) |
| [`IssueOnNewSession()`](ds:block?id=handoff-issueonnewsession-8qw3mz6k) | Every operation that starts a full session (sign-in, sign-up, the promotion after a second factor) also mints a token for it and hands it in the [`Set-OTT`](ds:block?id=handoff-setottheader-5wn8kq3v) header, better-auth's `setOttHeaderOnNewSession`; a Go caller reads it with [`handoff.NewSessionToken(ctx)`](ds:block?id=handoff-newsessiontoken-3kv9pw2n). None for a pending session, an impersonation, or `verify` itself. Risk: every sign-in answer then carries a second credential, so a proxy that logs or caches responses leaks a session; prefer calling `generate` when a hand-off is wanted | off |

## Routes and Go API

The routes are under your mount prefix (for example `/auth`).

| Route | Go method | Requirement | Rate limit |
|---|---|---|---|
| `POST /handoff/generate` (`challenge`, optional) | `Generate(ctx)`, `GenerateWith(ctx, GenerateRequest{Challenge})` return `GenerateResult{Token, ExpiresAt}` | SignedIn | 10 per minute per IP ([`generateLimit`](ds:block?id=generatelimit-3c7vx9ht), [`generateWindow`](ds:block?id=generatewindow-5m2zq8rk)) |
| `POST /handoff/verify` (`token`, `verifier` when the token was bound) | `Verify(ctx, token)`, `VerifyWith(ctx, VerifyRequest{Token, Verifier})` return `VerifyResult{User, Token}` | Public | 10 per minute per IP (`WithVerifyLimit`) and [5](ds:block?id=handoff-verifytokenlimit-5qw2zn8k) per minute per token, keyed by the token's hash: a refused exchange leaves a bound token unspent, so this is what bounds guessing its verifier |

- `generate` mints a token for the request's own session. The token is in the response body in the clear: handing it to the client is the point, and it is a hand-off token, not the session's. An admin acting as the user is refused (`auth.impersonation_refused`): an impersonation must not outlive its short life on another client.
- `verify` spends the token and starts a NEW session for its user, recorded on the call's effects, so a cookie client gets the cookie and a bearer client (`Auth-Token-Mode: bearer`) gets `Set-Auth-Token`. The source session must still be live; a token minted before a sign-out is refused. The new session skips the second factor, which the source session already passed. In stateless session mode the source cannot be checked, and the token's short life is the bound.
- **Binding the token to the receiving client** (RFC 7636 PKCE, method [`S256`](ds:block?id=handoff-challengemethod-4k7xp2nm) only). When the token will travel on a channel another program could also receive it on, such as a custom URL scheme any app on the machine can register, the client makes a verifier and sends its challenge with `generate`; `verify` then needs the verifier, which never left the client. `handoff.NewVerifier()` returns a verifier of [32](ds:block?id=handoff-verifierbytes-8q2mt5rw) random bytes as 43 base64url characters and its challenge; `handoff.ChallengeOf(verifier)` is the base64url SHA-256 for a client written in another language. A challenge that is not a base64url SHA-256 is `handoff.challenge_invalid`; a verifier outside [43](ds:block?id=handoff-minverifierlen-6n9wq3kt) to [128](ds:block?id=handoff-maxverifierlen-2m5zr8vp) unreserved characters is `handoff.verifier_invalid`; both are shape errors that touch no token. A wrong verifier, a missing one for a bound token or one sent for an unbound token answer `auth.token_invalid`, like a wrong token, and the token stays unspent (the operation's transaction rolls back), so the program that caught the token can neither use nor burn it, and the holder of the verifier still exchanges it within the token's life. A token minted without a challenge works as before.

## Tables and columns

The plugin owns no table and adds no column. A token is a core verification token (`auth_verification`) with purpose [`PurposeHandoff`](ds:block?id=purposehandoff-6y9kr3mt) (`handoff.token`); its identifier is the user id and its meta the id of the session that minted it, followed, for a bound token, by a newline and the challenge.

## Errors

| Error | Code | HTTP | When |
|---|---|---|---|
| `auth.ErrTokenInvalid` | `auth.token_invalid` | 400 | the token is bad, spent or expired; its source session ended; its user was deleted; or the verifier is wrong, missing for a bound token, or sent for an unbound one |
| `ErrChallengeInvalid` | `handoff.challenge_invalid` | 400 | `generate` with a challenge that is not a base64url SHA-256 |
| `ErrVerifierInvalid` | `handoff.verifier_invalid` | 400 | `verify` with a verifier outside 43 to 128 unreserved characters |
| `auth.ErrImpersonationRefused` | `auth.impersonation_refused` | 403 | `generate` from an impersonation session |
| `auth.ErrUnknownOperation` | `auth.unknown_operation` | 404 | `generate` over a transport under `ServerOnly()` |
| `auth.ErrRateLimited` | `auth.rate_limited` | 429 | the `generate` and `verify` limits above |

## Security notes

| Property | Pinned by |
|---|---|
| A token is exchanged once for a new session of the same user; a reused, expired or made-up token, and one whose source session ended, are refused alike; nobody signed out can mint one | `integration/TestHandoff_ExchangeStartsANewSessionOnce` |
| The new session is full, not pending; a token of a deleted user answers like a spent one | `integration/TestHandoff_NewSessionIsFullAndUserMayBeGone` |
| An impersonation cannot be handed off | `integration/TestHandoff_ImpersonationRefused` |
| `ServerOnly` refuses the transport and keeps the Go call | `integration/TestHandoff_ServerOnly` |
| The exchange works in stateless session mode, and a deleted user's token answers like a spent one | `integration/TestHandoff_Stateless` |
| A token minted with a challenge is exchanged only with its verifier; a wrong or missing verifier, or one for an unbound token, answers like a bad token and leaves the token unspent; a malformed challenge or verifier is refused before any token is touched | `integration/TestHandoff_ChallengeBindsTheToken` |
| `ChallengeOf` is RFC 7636's S256 (appendix B's example); `NewVerifier` draws 32 bytes | `plugin/handoff/TestChallengeOf` |
| Exchanges are bounded per token (five a minute, on the token's hash) and per IP (ten a minute), so a verifier cannot be guessed at volume while the token lives; the right one still works after the window | `integration/TestHandoff_VerifyIsRateLimited`, `plugin/handoff/TestGenerateLimitOption` |
| Every database failure fails the operation, bound or not | `integration/TestIdentFaults_Handoff` |

Limits:

- Whoever holds the token for its three minutes can sign in as the user, unless it was bound to a verifier. Pass it over a channel the user controls (a deep link, a QR code, a localhost redirect), never a log line or a referrer, and bind it when the channel may have another listener.
- The two sessions are independent: signing out of one leaves the other; "sign out everywhere" ends both.

## Example

- [examples/handoff](../../examples/handoff/): a web session handed to a second client that signs in with a bearer token.
- [examples/desktop-sign-in](../../examples/desktop-sign-in/): a desktop app signing in through the system browser, its token bound to a verifier.
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/handoff
