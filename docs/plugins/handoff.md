# Hand a session to another client

You will move a signed-in session to a second client in one step: a web page hands a native app a short-lived, single-use token, and the app exchanges it for a session of its own. The same works for a second domain, a desktop helper, or a CLI the user authorized in the browser.

Use this plugin when a person who is signed in on one client should not type their password again on another they also hold.

## Before you start

- An app with a sign-in method wired, as in [your first app](../start/first-app.md): a token is minted from an existing session.
- The example program this guide is built from, with a `main_test.go` that drives the same steps and a `README.md` with the same transcript: [`examples/handoff`](../../examples/handoff/).
- The reference for every option, route and error is the package's [README](../../plugin/handoff/README.md).

## Step 1 — Wire the plugin

The example wires email, passwords and the hand-off plugin, with no options:

<!-- ds:block id=newauth-5h2vq7mr -->
**newAuth** · [`examples/handoff/main.go:90-100`](../../examples/handoff/main.go#L90-L100)

```go
func newAuth(db *sql.DB, m email.Mailer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
			handoff.New(),
		),
	)
}
```
<!-- /ds:block hash=194a5b -->

The plugin owns no table and adds no column: a token is a core verification token with purpose [`handoff.token`](ds:block?id=purposehandoff-6y9kr3mt), stored hashed, expired after [three minutes](ds:block?id=defaultttl-k8w2pn5q) (`WithTTL`), spent by exactly one exchange.

Check: `go run ./handoff` prints `listening on http://localhost:8081`.

## Step 2 — Mint a token from the signed-in session

Sign up on the web, then ask for a token. The token is in the body in the clear: handing it to the other client is the point, and it is a hand-off token, not the session's:

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/handoff/generate -H "$O" -d '{}'
```

```json
{"user":{"id":"usr_dgdffrxo4lcj4vt5qodbgggn","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"token":"9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA","expiresAt":"2026-10-02T15:47:35.188082Z"}
```

From Go, and the result:

<!-- ds:block id=plugin-generate-2q6vh4nd -->
**Plugin.Generate** · [`plugin/handoff/handoff.go:389-391`](../../plugin/handoff/handoff.go#L389-L391)

```go
func (p *Plugin) Generate(ctx context.Context) (GenerateResult, error) {
	return p.GenerateWith(ctx, GenerateRequest{})
}
```
<!-- /ds:block hash=ce7643 -->

<!-- ds:block id=generateresult-7r4tk2wq -->
**GenerateResult** · [`plugin/handoff/handoff.go:354-357`](../../plugin/handoff/handoff.go#L354-L357)

```go
type GenerateResult struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
}
```
<!-- /ds:block hash=843018 -->

Check: minting is limited to [10](ds:block?id=generatelimit-3c7vx9ht) tokens per IP per [minute](ds:block?id=generatewindow-5m2zq8rk) (`WithGenerateLimit`). An admin acting as the user is refused with `auth.impersonation_refused`: an impersonation must not outlive its short life on another client.

## Step 3 — Exchange it on the other client

The app has no cookies. It posts the token with `Auth-Token-Mode: bearer` and receives a session token of its own in `Set-Auth-Token`; a client that wanted a cookie leaves the header off and gets `Set-Cookie`:

```sh
curl -s -i -X POST localhost:8081/auth/handoff/verify -H "$O" -H 'Auth-Token-Mode: bearer' \
  -d '{"token":"9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA"}'
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Set-Auth-Token: -y3ORvQ1LHBjFsZ3mhwDkeXd0Sy6-A0JIkzv2C5vSp4
Set-Auth-Token-Expires: 2026-10-09T15:44:35Z
Content-Length: 68

{"user":{"id":"usr_dgdffrxo4lcj4vt5qodbgggn","name":"","image":""}}
```

The exchange creates a new session rather than copying the web one: the web session's raw token is never stored, and two clients sharing one session would let either end the other's. The new session is full even for a user with two-factor, because the web session already passed it.

From Go, and the result:

<!-- ds:block id=plugin-verify-8k5tz3fp -->
**Plugin.Verify** · [`plugin/handoff/handoff.go:409-411`](../../plugin/handoff/handoff.go#L409-L411)

```go
func (p *Plugin) Verify(ctx context.Context, t auth.Token) (VerifyResult, error) {
	return p.VerifyWith(ctx, VerifyRequest{Token: t.Wire()})
}
```
<!-- /ds:block hash=c9e54d -->

<!-- ds:block id=verifyresult-9n3mw8xs -->
**VerifyResult** · [`plugin/handoff/handoff.go:380-383`](../../plugin/handoff/handoff.go#L380-L383)

```go
type VerifyResult struct {
	User  auth.UserView `json:"user"`
	Token auth.Token    `json:"-"`
}
```
<!-- /ds:block hash=792385 -->

**Binding the token to the client that will receive it.** When the token travels on a channel another program could also receive it on, a custom URL scheme that any app on the machine can register, say, the receiving client makes a verifier first and sends its S256 challenge with `generate`; `verify` then needs the verifier, which never left the client (RFC 7636 PKCE, as RFC 8252 asks of every native app). From Go, `handoff.NewVerifier()` gives both, and `handoff.ChallengeOf` is the hash for a client in another language:

```sh
V=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
C=$(printf %s "$V" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
curl -s -b cookies.txt -X POST localhost:8081/auth/handoff/generate -H "$O" -d "{\"challenge\":\"$C\"}"
curl -s -X POST localhost:8081/auth/handoff/verify -H "$O" -H 'Auth-Token-Mode: bearer' -d '{"token":"<token>"}'
curl -s -i -X POST localhost:8081/auth/handoff/verify -H "$O" -H 'Auth-Token-Mode: bearer' -d "{\"token\":\"<token>\",\"verifier\":\"$V\"}"
```

The second call, without the verifier, answers `auth.token_invalid` and leaves the token unspent; the third signs the client in. A wrong verifier answers the same, so nothing tells an eavesdropper whether the token was bound. The Go side is `hp.GenerateWith(ctx, handoff.GenerateRequest{Challenge: c})` and `hp.VerifyWith(ctx, handoff.VerifyRequest{Token: t, Verifier: v})`; the [desktop guide](../integrations/desktop-apps.md) uses them.

Check: a token works once, and a token of a session that has since signed out is refused:

```sh
curl -s -X POST localhost:8081/auth/handoff/verify -H "$O" -H 'Auth-Token-Mode: bearer' \
  -d '{"token":"9OsDfF24MIreUqcQNGliyGJaBU1WxDL-qFkJiAxCYDA"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
{"id":"usr_dgdffrxo4lcj4vt5qodbgggn"}
```

## Options you may want

| Option | Use it when |
|---|---|
| `handoff.ServerOnly()` | Only your own Go code may mint tokens, after a check of its own. The `generate` route answers `auth.unknown_operation` and is left out of the OpenAPI document and the generated TypeScript client; `hp.Generate(ctx)` from your handler still works. |
| `handoff.WithTTL(d)` | Another lifetime. Shorter is safer; three minutes already covers a tap on a deep link. |
| `handoff.WithGenerateLimit(n, window)` | Another limit on minting per IP. |
| `handoff.WithVerifyLimit(n, window)` | Another limit on exchanges per IP (ten a minute by default). Exchanges are also bounded to [5](ds:block?id=handoff-verifytokenlimit-5qw2zn8k) a minute per token, which is not configurable: a refused exchange leaves a bound token unspent, and that rule is what stops a verifier being guessed at volume. |
| `handoff.IssueOnNewSession()` | A client that wants a hand-off token after every sign-in without asking for it, as better-auth's `setOttHeaderOnNewSession`. Each operation that starts a full session answers a token for it in the `Set-OTT` header (`handoff.NewSessionToken(ctx)` from Go), with the same life and rules as one from `generate`. A pending session (second factor still owed), an impersonation and the exchange itself get none. Off by default because every sign-in answer then carries a second credential: a proxy or a log that keeps responses keeps a way into the account. |

## From TypeScript

Use this when a signed-in web page hands its user to another client (a desktop app, a mobile app, a CLI), and that client is written in TypeScript. The [typed client](../client/README.md) has the two routes as `client.handoff.generate` and `client.handoff.verify`; list `handoff()` in `plugins` on both sides. The receiving client usually runs in [bearer mode](../client/bearer-and-mobile.md), so its new session token lands in its token store.

On the web page, mint the token, bound to the receiving client's challenge:

<!-- ds:block id=tsp-handoff-generate-8wk3mq5n -->
**handOffTo** · [`clients/ts/examples/plugin-signin.ts:132-135`](../../clients/ts/examples/plugin-signin.ts#L132-L135)

```typescript
export async function handOffTo(challenge: string): Promise<string | null> {
  const { data } = await auth.handoff.generate({ challenge });
  return data?.token ?? null;
}
```
<!-- /ds:block hash=4e3ce3 -->

On the receiving client, make a verifier and its S256 challenge before asking, then exchange the token with the verifier:

<!-- ds:block id=tsp-handoff-verify-2mx7wk4q -->
**receiveHandOff** · [`clients/ts/examples/plugin-signin.ts:141-153`](../../clients/ts/examples/plugin-signin.ts#L141-L153)

```typescript
export async function receiveHandOff(receive: (challenge: string) => Promise<string>): Promise<string | null> {
  const app = createAuthClient({
    baseURL: "https://app.example.com/auth",
    tokenMode: "bearer",
    tokenStore: memoryTokenStore(),
    plugins: [handoff()],
  });
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const token = await receive(challenge); // the web page ran handOffTo(challenge) and passed the token back
  const { data } = await app.handoff.verify({ token, verifier });
  return data?.user.id ?? null;
}
```
<!-- /ds:block hash=3ff7b7 -->

How the challenge reaches the web page and the token comes back (a deep link, a localhost redirect, a QR code) is the app's choice, as Step 3 explains. Without a channel another program could listen on, `generate()` with no challenge and `verify({ token })` without a verifier work too.

The codes a frontend handles, explained in [What can go wrong](#what-can-go-wrong): `auth.token_invalid` (spent, expired, its source session ended, or the verifier is wrong or missing; mint a new one), `handoff.challenge_invalid` (the challenge is not 43 base64url characters), `handoff.verifier_invalid`, `auth.impersonation_refused` when an admin acting as the user tries to mint one, `auth.rate_limited`.

There is no runnable TypeScript example for hand-off; the blocks above are type-checked by `task ts:check`, and Steps 2 and 3 show the same calls with curl and openssl.

Pitfalls:

- **The token lasts three minutes and works once.** Mint it when the user clicks "open in the app", not when the page loads.
- **The exchange creates a new session**, separate from the web one: signing out on the web does not sign the app out, and the app shows in the sessions list as its own device.
- **The verifier must never leave the receiving client.** Only the challenge travels to the web page; a verifier sent along with the token defeats the binding.

Every method with its route and types: [TypeScript client reference › handoff](../reference/ts-client.md#handoff).

## What can go wrong

| Error | When | Fix |
|---|---|---|
| `auth.token_invalid` (400) | The token is bad, spent or expired; its source session ended; its user was deleted; or the verifier is wrong, missing for a bound token, or sent for an unbound one. | Mint a new one from a live session; send the verifier whose challenge minted it. |
| `handoff.challenge_invalid` (400) on `generate` | The challenge is not 43 base64url characters (an S256 hash). | Hash the verifier with SHA-256 and encode it base64url without padding; `handoff.ChallengeOf` does. |
| `handoff.verifier_invalid` (400) on `verify` | The verifier is shorter than 43 or longer than 128 characters, or uses characters outside `A-Z a-z 0-9 - . _ ~`. | Use `handoff.NewVerifier`, or 32 random bytes base64url-encoded. |
| `auth.signed_out` (401) on `generate` | No session on the request. | Sign in first; `generate` needs a session. |
| `auth.rate_limited` (429) on `verify` | More than five exchanges of one token, or ten from one address, in a minute. | Wait for `Retry-After`; a client needs one exchange. |
| `auth.impersonation_refused` (403) | An admin impersonating the user called `generate`. | Expected: impersonation stays on one client. |
| `auth.unknown_operation` (404) on `generate` | `ServerOnly()` is set. | Mint from Go. |
| The new session is pending a second factor | It cannot be: the exchange creates a full session. If you see one, the token came from `hp.Generate` on a pending session, which the pipeline refuses. | Nothing; `generate` needs a full session. |

Known limits:

- Whoever holds the token for its three minutes can sign in as the user, unless it was bound to a verifier. Pass it over a channel the user controls (a deep link, a QR code, a localhost redirect), never a log line or a referrer, and bind it when the channel may have another listener.
- In stateless session mode the server keeps no session list, so "the source session still exists" cannot be checked; the token's short life is the bound.
- The two sessions are independent: signing out of one leaves the other; "sign out everywhere" ends both.

## Next

- [Desktop apps](../integrations/desktop-apps.md) and [`examples/desktop-sign-in`](../../examples/desktop-sign-in/): the whole desktop flow built on this plugin, through the system browser and back over a loopback address, an app URL scheme or a pasted code.
- [Mobile apps](../integrations/mobile-apps.md): the bearer mode the app used, and app-length sessions.
- [Sessions](../concepts/sessions.md): what the new session is, and how it is ended.
- The package [README](../../plugin/handoff/README.md) is the full reference; the Go reference is on [pkg.go.dev](https://pkg.go.dev/github.com/ubgo/auth/plugin/handoff).
