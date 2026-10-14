# github.com/ubgo/auth/plugin/captcha

Refuses chosen operations unless the request carries a captcha token the provider accepts: a bot cannot sign up, sign in or ask for reset links at the rate the rate rules allow a human to. Cloudflare Turnstile, Google reCAPTCHA (v2 and v3), hCaptcha and CaptchaFox are built in; any other provider is a `Verifier`.

## Install

```sh
go get github.com/ubgo/auth
```

The package is in the core module `github.com/ubgo/auth`, so it brings no extra dependency beyond `github.com/ubgo/sqlb`; the providers are called with `net/http`.

## Wire it

Taken from [`examples/captcha`](../../examples/captcha/):

```go
v := captcha.Turnstile(os.Getenv("CAPTCHA_SECRET"), captcha.WithExpectedAction("auth"))
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), captcha.New(v)),
)
```

The page solves the widget and sends the token in the [`X-Captcha-Response`](ds:block?id=tokenheader-captcha-2k9fq3xa) header (`captcha.TokenHeader`, the header better-auth's clients send, so a frontend written for one works against the other). On every transport (HTTP, GraphQL, an adapter) the plugin reads it before a protected operation runs and asks the provider once; the call is refused when the token is missing, rejected, or could not be checked. A direct Go call (`pw.SignIn(ctx, …)` from the app's own code) has no browser and is never checked.

`captcha.ChallengeOnly()` makes the plugin guard nothing always and serve only as the core's rate challenger: an `auth.RateChallenge` rule asks for the token once its limit is passed, and never before (it cannot be combined with `Protect` or `ProtectPaths`). Without it the plugin does both, and a token the challenge accepted is not sent to the guard again.

With no `Protect` option the plugin guards [this list](ds:block?id=defaultprotected-captcha-9vx4tn2c), narrowed at `auth.New` to the operations the registered plugins provide. `auth.New` fails with `ErrNothingProtected` when none of them is registered, and with `auth.ErrUnknownHookTarget` when an id in `Protect` is a typo, so a captcha that guards nothing is never wired silently.

## Options

| Option | What it does | Default |
|---|---|---|
| `captcha.New(v, opts...)` | The plugin around a `Verifier` | required |
| [`captcha.Protect(ids...)`](ds:block?id=protect-captcha-6bn3zf8k) | Replace the default list with these operation ids; every id must be registered | the default list |
| [`captcha.ProtectPaths(patterns...)`](ds:block?id=protectpaths-captcha-5wq8kz3n) | Guard every operation whose route matches a pattern, better-auth's `endpoints` with wildcards: `*` within one path segment, `**` across segments, no wildcard for one exact route (`"/password/*"`, `"/oauth/**"`). Routes are the operation's own, without the mount prefix. Replaces the default list and adds up with `Protect`; a pattern matching no registered operation fails `auth.New` with `auth.ErrUnknownHookTarget` naming the pattern. [`captcha.MatchPath(pattern, route)`](ds:block?id=matchpath-captcha-8nr2vx6q) tests one | the default list |
| `captcha.WithHeader(name)` | Read the token from another header | `X-Captcha-Response` |
| `captcha.WithTimeout(d)` | Bound each verification; zero or negative keeps the default | [10 s](ds:block?id=defaulttimeout-captcha-7mz2hq4e) |

Providers, each returning a `*SiteVerify` that is a `Verifier`:

| Constructor | Verifies | Siteverify endpoint |
|---|---|---|
| `captcha.Turnstile(secret, opts...)` | Cloudflare Turnstile | `challenges.cloudflare.com/turnstile/v0/siteverify` |
| `captcha.ReCAPTCHA(secret, opts...)` | Google reCAPTCHA v2 and v3; a v3 token carries a score and must reach the threshold, a v2 token is judged by success | `www.google.com/recaptcha/api/siteverify` |
| `captcha.HCaptcha(secret, opts...)` | hCaptcha | `api.hcaptcha.com/siteverify` |
| `captcha.CaptchaFox(secret, opts...)` | CaptchaFox (hCaptcha-compatible verdict, no score) | `api.captchafox.com/siteverify` |

| Provider option | What it does | Default |
|---|---|---|
| `captcha.WithExpectedAction(action)` | Refuse a token the widget minted for another action (reCAPTCHA v3, Turnstile report it) | accept any |
| `captcha.WithAllowedHostnames(hosts...)` | Refuse a token solved on another site, by the hostname the provider reports | accept any |
| `captcha.WithSiteKey(key)` | Send the site key so the provider rejects a token solved under another key (hCaptcha, CaptchaFox) | not sent |
| `captcha.WithMinScore(score)` | The reCAPTCHA v3 score a token must reach, 0 to 1; out of range keeps the default | [0.5](ds:block?id=defaultminscore-captcha-3rp8wq5d) |
| `captcha.WithEndpoint(url)` | A mirror, or a fake server in a test; must be absolute | the provider's |
| `captcha.WithHTTPClient(c)` | The client the verification uses | `http.DefaultClient` |

The client address (`Call.Client.IP`, as `authhttp` derives it) is sent as `remoteip`, and the secret is checked at `auth.New`: an empty one fails with `ErrNoSecret`.

Another provider, or a bot verdict without a token, is a `Verifier`:

<!-- ds:block id=verifier-captcha-5hw8rd7b -->
**Verifier** · [`plugin/captcha/captcha.go:120-122`](captcha.go#L120-L122)

```go
type Verifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}
```
<!-- /ds:block hash=a19203 -->

Return `nil` to let the call through, `captcha.ErrFailed` (or an error wrapping it) to refuse the token, and any other error when no verdict could be had. `captcha.VerifierFunc` adapts a function.

## Routes and Go API

The plugin registers no operation; it is one `auth.OperationHook`:

<!-- ds:block id=plugin-operationhooks-captcha-4qt7mw9n -->
**Plugin.OperationHooks** · [`plugin/captcha/captcha.go:342-365`](captcha.go#L342-L365)

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

| Function | Use |
|---|---|
| `(*Plugin).Protected()` | The operation ids guarded, settled at `auth.New` |
| `(*SiteVerify).Verify(ctx, token, remoteIP)` | Verify one token outside the pipeline, in a custom flow |
| `(*SiteVerify).Provider()` | `turnstile`, `recaptcha`, `hcaptcha` or `captchafox`, for logs |

## Tables and columns

None. The plugin stores nothing.

## Errors

| Error variable | Code | HTTP | When |
|---|---|---|---|
| `ErrMissing` | `captcha.missing` | 400 | A protected transport call sent no token |
| `ErrFailed` | `captcha.failed` | 403 | The provider rejected the token: expired, used, solved elsewhere, another action, or a score below the threshold. One code for every reason, so a bot cannot learn which check it tripped; the reason is in the log |
| `ErrUnavailable` | `captcha.unavailable` | 503 | The provider could not be reached, answered a non-200 status, timed out, or returned something that is not a verdict. The call is refused: a provider outage must not be an open door |
| `ErrNoVerifier` | (plain error, no code) | n/a | `auth.New` with `captcha.New(nil)` |
| `ErrNothingProtected` | (plain error, no code) | n/a | `auth.New` when none of the default operations' plugins is registered, or `Protect()` / `ProtectPaths()` was given nothing |
| `ErrNoSecret` | (plain error, no code) | n/a | `auth.New` with a built-in provider and an empty secret |

## Security notes

| Property | Pinned by |
|---|---|
| A protected call without a token is refused before the operation runs and before any provider call | `TestHook_HTTP`, `TestCaptcha_GuardsSignUpAndSignIn` |
| A rejected token, a wrong action, a wrong hostname and a low score are one error for the client | `TestSiteVerify_Judgement` |
| A provider outage, a bad status, a non-JSON answer and a timeout fail closed | `TestHook_HTTP`, `TestHook_Timeout` |
| The default list guards only operations that exist, and `auth.New` refuses a plugin that would guard nothing or an empty `Match` (which would guard everything) | `TestInit_DefaultListNarrowsToRegisteredPlugins`, `TestInit_RegisteredPluginWithoutDefaultOperations`, `TestNew_Refusals` |
| The real password routes are refused without a token on every engine | `TestCaptcha_GuardsPasswordRoutes` (integration) |
| Tests never call a real provider: every verdict comes from a fake siteverify server | every test in the package and the example |

Limits: a direct Go call is never checked, by design; the check is a hook, so it costs one provider round-trip per protected call and sits after the rate limit and origin check in the pipeline, which means a flood is still stopped by the rate rules first.

## Example

- [`examples/captcha`](../../examples/captcha/): Turnstile in front of email-and-password sign-up, sign-in and the reset request, with a fake provider in the test.
- Guide: [docs/plugins/captcha.md](../../docs/plugins/captcha.md)
- API reference: https://pkg.go.dev/github.com/ubgo/auth/plugin/captcha
