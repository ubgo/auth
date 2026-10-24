# Captcha

You will have an app whose sign-up, sign-in and password-reset request are refused unless the page solved a captcha, with Cloudflare Turnstile, Google reCAPTCHA, hCaptcha or CaptchaFox checking the token, and the same check on every transport: HTTP, GraphQL and the framework adapters.

## Before you start

- An app with sign-in, as in [your first app](../start/first-app.md). The plugin works with every sign-in method, because it is an operation hook rather than part of any one form.
- The example is [`examples/captcha`](../../examples/captcha): email and password sign-in behind Turnstile. `CAPTCHA_SECRET=… go run ./captcha` in `examples/` serves it on `localhost:8081`; `go test ./captcha` runs the flow below against a fake provider.
- What the plugin stores: nothing. It adds no table and no column, and it registers no route; it refuses calls before they run.
- What it does not replace: the rate rules and the per-account lockout. The captcha check runs after the rate limit and the origin check in the pipeline, so a flood is still stopped by the cheaper brakes first; the captcha is for the bot that stays under them.

## Step 1 — Pick a provider and wire the plugin

Each built-in provider takes the site's secret key and returns a `Verifier`:

<!-- ds:block id=newverifier-captcha-ex-8kq2mv7p -->
**newVerifier** · [`examples/captcha/main.go:114-120`](../../examples/captcha/main.go#L114-L120)

```go
func newVerifier(secret, siteVerifyURL string) *captcha.SiteVerify {
	opts := []captcha.ProviderOption{captcha.WithExpectedAction(expectedAction)}
	if siteVerifyURL != "" {
		opts = append(opts, captcha.WithEndpoint(siteVerifyURL))
	}
	return captcha.Turnstile(secret, opts...)
}
```
<!-- /ds:block hash=f374b7 -->

`WithExpectedAction` refuses a token the widget minted for another action of the same site (reCAPTCHA v3 and Turnstile report it); `WithAllowedHostnames`, `WithSiteKey` and `WithMinScore` are the other checks on the verdict, listed in the [README](../../plugin/captcha/README.md#options). `WithEndpoint` points at a mirror or, as in the test, a fake server. The secret is checked at `auth.New`: an empty one fails with `captcha.ErrNoSecret`.

The plugin is one entry in the plugin list:

<!-- ds:block id=newauth-captcha-ex-5tn8rw3c -->
**newAuth** · [`examples/captcha/main.go:127-133`](../../examples/captcha/main.go#L127-L133)

```go
func newAuth(db *sql.DB, m email.Mailer, v captcha.Verifier) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), captcha.New(v)),
	)
}
```
<!-- /ds:block hash=e08c00 -->

Check: `auth.New` fails with `captcha.ErrNothingProtected` when none of the operations in the default list is registered, so a plugin set that forgot the password plugin is refused at start rather than guarding nothing.

## Step 2 — Decide which operations are protected

With no option the plugin guards [this list](ds:block?id=defaultprotected-captcha-9vx4tn2c), narrowed to the operations the registered plugins provide. The list is every way an anonymous request can create an account, prove a password, or make the app send a message. In the example only the password plugin's four are present.

To guard a different set, name the ids:

```go
captcha.New(v, captcha.Protect(password.EndpointSignUp, password.EndpointForgot))
```

Every id in [`Protect`](ds:block?id=protect-captcha-6bn3zf8k) must be registered; a typo fails `auth.New` with `auth.ErrUnknownHookTarget`, because a guard aimed at nothing leaves the real operation open. An operation switched off with `auth.WithDisabledOperations` may stay in the list.

To name routes rather than ids, use `captcha.ProtectPaths` with wildcards: `*` matches within one path segment and `**` across segments, so `captcha.ProtectPaths("/password/*")` guards sign-in, sign-up, forgot and the rest of the password routes, and `"/oauth/**"` every OAuth route. Patterns name the operation's own route, without your mount prefix, and add up with `Protect`. The typo check stays: a pattern that matches no registered operation fails `auth.New` with `auth.ErrUnknownHookTarget` and the pattern in the message, so a route renamed in a later release fails your start-up instead of leaving the form open.

To use the captcha only as the answer to a busy address, not on every call, pass [`captcha.ChallengeOnly()`](ds:block?id=challengeonly-captcha-3wn8qk5v): the plugin then guards no operation always and serves as the core's rate challenger, so a [`RateChallenge`](../concepts/rate-limits.md#step-5--choose-what-a-rule-does-over-its-limit) rule asks for the token only once its limit is passed. It cannot be combined with `Protect` or `ProtectPaths`, which would say the opposite. With both, a token the challenge accepted is not sent to the guard a second time, because providers accept a token once. Registered at all, with or without `ChallengeOnly`, the plugin is the app's rate challenger, so it cannot be registered beside [`plugin/pow`](pow.md), the proof-of-work challenger: `auth.New` refuses two challengers, since a client could not tell which proof to send.

A direct Go call (`pw.SignIn(ctx, …)` from the app's own code) is never checked: it has no browser and no header, and the app's own code is not the bot the captcha is for. Every transport call is.

## Step 3 — Send the token from the page

The widget hands the page a token when solved. The page sends it in the [`X-Captcha-Response`](ds:block?id=tokenheader-captcha-2k9fq3xa) header of the protected request (`captcha.TokenHeader`; `WithHeader` renames it).

Without the header the call is refused before it runs and the provider is not asked:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"error":{"code":"captcha.missing","message":"Complete the captcha and try again."}}
```

With a token the provider rejects, the client gets one code whatever the reason, so a bot cannot learn which check it tripped; the provider's reason is in the server log:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Captcha-Response: token-a-bot-made-up' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"error":{"code":"captcha.failed","message":"The captcha could not be verified. Try again."}}
```

With an accepted token the operation runs as if the plugin were not there:

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Captcha-Response: token-from-a-solved-widget' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_zgw7ra2tmmtcs3ho6gu2yae5","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

A page that uses the ready-made pages of `authui` or a GraphQL client sends the same header: the check is the hook below, which every transport runs.

<!-- ds:block id=plugin-operationhooks-captcha-4qt7mw9n -->
**Plugin.OperationHooks** · [`plugin/captcha/captcha.go:340-363`](../../plugin/captcha/captcha.go#L340-L363)

```go
func (p *Plugin) OperationHooks() []auth.OperationHook {
	if p.challengeOnly {
		return nil
	}
	if len(p.patterns) > 0 {
		p.protected = append(p.protected, p.resolvePatterns()...)
	}
	if !p.explicit {
		known := map[auth.EndpointID]bool{}
		for _, id := range p.core.DisabledOperations() {
			known[id] = true
		}
		narrowed := make([]auth.EndpointID, 0, len(p.protected))
		for _, id := range p.protected {
			if _, ok := p.core.Operation(id); ok || known[id] {
				narrowed = append(narrowed, id)
			}
		}
		if len(narrowed) > 0 {
			p.protected = narrowed
		}
	}
	return []auth.OperationHook{{Match: slices.Clone(p.protected), Before: p.before}}
}
```
<!-- /ds:block hash=13bac1 -->

## Step 4 — Know what happens when the provider is down

Each verification is bounded by [10 seconds](ds:block?id=defaulttimeout-captcha-7mz2hq4e) (`WithTimeout` changes it). When the provider cannot be reached, times out, answers a status other than 200 or returns something that is not a verdict, the call is refused with `503 captcha.unavailable`. That is deliberate: an unreachable provider must not become an open door. The plugin logs a warning naming the operation and the cause, so an outage is visible in the log rather than as a quiet rise in sign-ups.

## Step 5 — Another provider

Anything that can say "human" or "bot" for a request is a `Verifier`:

<!-- ds:block id=verifier-captcha-5hw8rd7b -->
**Verifier** · [`plugin/captcha/captcha.go:119-121`](../../plugin/captcha/captcha.go#L119-L121)

```go
type Verifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}
```
<!-- /ds:block hash=a19203 -->

Return `nil` to let the call through, `captcha.ErrFailed` (or an error wrapping it) to refuse the token, and any other error when no verdict could be had, which the plugin reports as `captcha.unavailable`. `captcha.VerifierFunc` adapts a function, and the built-in `*captcha.SiteVerify` can be used on its own in a custom flow with `Verify(ctx, token, remoteIP)`.

## From TypeScript

The captcha plugin adds no route, so it has no factory in the [typed client](../client/README.md): a call it protects is another plugin's method, and the page sends the widget's token in the `X-Captcha-Response` header of that one call, with the per-call `headers` option every method takes ([Reference › Per-call headers](../client/reference.md#per-call-headers)):

<!-- ds:block id=tsp-captcha-header-7kx2wq9m -->
**signUpWithCaptcha** · [`clients/ts/examples/plugin-headers.ts:16-23`](../../clients/ts/examples/plugin-headers.ts#L16-L23)

```typescript
export async function signUpWithCaptcha(address: string, secret: string, widgetToken: string): Promise<string> {
  const { error } = await auth.password.signUp(
    { identifier: address, password: secret },
    { headers: { "X-Captcha-Response": widgetToken } },
  );
  if (!error) return "signed-up";
  return error.code === "captcha.failed" || error.code === "captcha.missing" ? "Solve the captcha again." : error.message;
}
```
<!-- /ds:block hash=ab2aa0 -->

The codes a frontend handles: `captcha.missing` (the header was not sent; the call never ran), `captcha.failed` (the provider refused the token, one code whatever the reason: reset the widget and ask again), `captcha.unavailable` when the provider cannot be reached and the plugin fails closed (Step 4). The rest is in [What can go wrong](#what-can-go-wrong). Narrow on `error.code` as for any other plugin; the codes are in the client's `AuthErrorCode` union.

There is no runnable TypeScript example for captcha; the block is type-checked by `task ts:check`, and Step 3 shows the same three answers with curl.

Pitfalls:

- **Send the header on the protected call, not as a client-wide `headers` option.** A token is single use at the provider, so a token kept on the client works for the first protected call and every later one answers `captcha.failed`.
- **A token expires at the provider within minutes.** Get it from the widget when the user submits, not when the page loads.
- **A protected call retried after `auth.rate_limited` needs a new token**, because the first one was spent or refused.

Related: [proof of work](pow.md) is the same header pattern without a third-party widget.

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `auth: plugin "captcha": captcha: none of the protected operations is registered` | No plugin in the default list is wired, or `Protect()` was given no id | Register the password or code plugin, or name the ids in `captcha.Protect` |
| `auth: hook names an operation that is not registered: plugin "captcha" hooks "…"` | A typo in `Protect`, a `ProtectPaths` pattern that matches no route, or a registered plugin that provides none of the default ids | Use the plugin's `Endpoint…` constants |
| Every protected call answers `captcha.failed` in production | The secret belongs to another site, or `WithExpectedAction` names an action the widget does not set | Check the provider dashboard; the log line carries the provider's reason |
| `captcha.unavailable` on every call | The server cannot reach the provider, or `WithEndpoint` points at the wrong URL | Check egress and the endpoint; the log names the cause |
| Your own Go code calling `pw.SignIn` is not checked | By design: Go calls skip the hook | Protect the transport, not the Go API |

## Next

- [Rate limits](../concepts/rate-limits.md): the brakes the captcha sits behind.
- [Proof of work](pow.md): the other rate challenger, with no third party in the loop; an app registers one of the two, never both.
- [Password policies](password.md): the per-account lockout.
- [Hooks](../extending/03-hooks.md): the mechanism this plugin is built on, for a check of your own.
