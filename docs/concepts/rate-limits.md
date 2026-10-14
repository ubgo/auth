# Rate limits

Sign-in, sign-up and "forgot password" are the operations an attacker hammers. This page explains the rules the plugins ship with, where the counters live, how a limited client is told what to do, and how to share counters across instances.

## Before you start

- [Plugins and the pipeline](plugins-and-pipeline.md): the per-address limit is step 1 of the pipeline and the per-account limit step 5, both before any transaction, so a failed call cannot roll its own count back.
- Rate limits are declared by plugins for their own operations; the app chooses only where the counters live.

## Step 1 — Know what is counted

A rule names an operation, a key and a budget: so many calls per window. Three keys exist. `ByIP` counts per client address and stops one machine from trying many accounts; `ByIdentifier` counts per normalized identifier in the input and stops many machines from trying one account; [`ByFunc`](ds:block?id=core-ratekey-byfunc-7nq4wz2k) counts per whatever the rule's `KeyFunc` returns (the signed-in user, a tenant, an API key, a device header), for every budget the first two cannot express. A rule may also `Derive` a group from the value — the first digits of a phone number, the domain of an address — so a whole range or provider shares one counter.

<!-- ds:block id=core-raterule-m3gp9xc5 -->
**RateRule** · [`ratelimit.go:61-79`](../../ratelimit.go#L61-L79)

```go
type RateRule struct {
	Match  EndpointID
	Key    RateKey
	Limit  int
	Window time.Duration
	// Derive, when set, maps the key's value before counting, so a rule can
	// count a group rather than one value: the first digits of a phone number
	// count every number in a range, the domain of an address counts a whole
	// provider. Optional; a rule without it counts the value itself.
	Derive func(value string) string
	// KeyFunc is what a ByFunc rule counts by, and is required by one; any
	// other key must leave it nil, or New refuses the rule.
	KeyFunc RateKeyFunc
	// Action is what the rule does with a call over Limit: RateBlock (the
	// default, also for ""), RateLog or RateChallenge. New refuses an
	// unknown action, and a RateChallenge rule when no RateChallenger is
	// registered.
	Action RateAction
}
```
<!-- /ds:block hash=399386 -->

<!-- ds:block id=core-ratekeys-n636dm3p -->
**ByIP** · [`ratelimit.go:22`](../../ratelimit.go#L22-L22)

```go
"ip"
```
<!-- /ds:block hash=49d5c7 -->

The password plugin's rules are the model: sign-in by address and by account, the password check by address, the re-authentication of a signed-in session by address and by account (`auth.UserRateKey`), sign-up by address and by identifier, "forgot" by identifier so a stranger cannot flood someone's inbox, and, with `password.ResetByCode()`, the reset-code route by address and by identifier, and, with `password.ExpireAfter(d)`, the change-expired route by address and by account. A rule for a route the plugin does not serve is left out, so `password.WithoutSignUp()` drops the two sign-up rules:

<!-- ds:block id=password-ratelimits-k2sm7ztg -->
**Plugin.RateLimits** · [`plugin/password/password.go:604-635`](../../plugin/password/password.go#L604-L635)

```go
func (p *Plugin) RateLimits() []auth.RateRule {
	rules := []auth.RateRule{
		{Match: EndpointSignIn, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
		{Match: EndpointSignIn, Key: auth.ByIdentifier, Limit: signInAccountLimit, Window: signInAccountWindow},
		{Match: EndpointVerify, Key: auth.ByIP, Limit: verifyIPLimit, Window: verifyIPWindow},
		{Match: EndpointReauthenticate, Key: auth.ByIP, Limit: reauthIPLimit, Window: reauthIPWindow},
		{Match: EndpointReauthenticate, Key: auth.ByFunc, Limit: reauthAccountLimit, Window: reauthAccountWindow, KeyFunc: auth.UserRateKey},
	}
	if !p.noSignUp {
		rules = append(rules,
			auth.RateRule{Match: EndpointSignUp, Key: auth.ByIP, Limit: signUpIPLimit, Window: signUpIPWindow},
			auth.RateRule{Match: EndpointSignUp, Key: auth.ByIdentifier, Limit: signUpIDLimit, Window: signUpIDWindow},
		)
	}
	if p.expireAfter > 0 {
		// change-expired checks a password, so it is bounded like sign-in.
		rules = append(rules,
			auth.RateRule{Match: EndpointChangeExpired, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
			auth.RateRule{Match: EndpointChangeExpired, Key: auth.ByIdentifier, Limit: signInAccountLimit, Window: signInAccountWindow},
		)
	}
	if !p.noRecovery {
		rules = append(rules, auth.RateRule{Match: EndpointForgot, Key: auth.ByIdentifier, Limit: forgotLimit, Window: forgotWindow})
	}
	if !p.noRecovery && p.byCode {
		rules = append(rules,
			auth.RateRule{Match: EndpointResetCode, Key: auth.ByIP, Limit: signInIPLimit, Window: signInIPWindow},
			auth.RateRule{Match: EndpointResetCode, Key: auth.ByIdentifier, Limit: resetCodeLimit, Window: resetCodeWindow},
		)
	}
	return rules
}
```
<!-- /ds:block hash=54042f -->

Each plugin's README lists its rules and numbers. A Go API call has no address, so `ByIP` rules do not count it; `ByIdentifier` rules do.

Check: five wrong passwords for one account answer `auth.rate_limited` on the sixth, whichever address they came from (`examples/multi-instance`).

## Step 2 — Tell the client what to do

A refused call is `auth.rate_limited` (429). The error carries the rule's window, an upper bound on the wait because a fixed window may reopen sooner; `auth.RetryAfter` reads it, and `authhttp` sets `Retry-After` in whole seconds on the response. A plugin with a limit of its own (an API key's quota) answers the same error with `auth.RateLimitedFor(retry)`, so clients meet one code.

<!-- ds:block id=core-retryafter-c4y8e9t7 -->
**RetryAfter** · [`ratelimit.go:456-462`](../../ratelimit.go#L456-L462)

```go
func RetryAfter(err error) (time.Duration, bool) {
	var rl rateLimited
	if errors.As(err, &rl) {
		return rl.retry, true
	}
	return 0, false
}
```
<!-- /ds:block hash=459211 -->

```text
HTTP/1.1 429 Too Many Requests
Retry-After: 900
Content-Type: application/json

{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

Check: your front end reads the `Retry-After` header and disables the form for that long, rather than letting the user retry into the same window.

## Step 3 — Choose where the counters live

By default counters live in this process's memory. That is correct for one instance and wrong for two: each instance counts on its own, so an attacker gets every instance's budget. The first counted call logs `auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance` until the app passes a shared store.

Whichever store you pick, it never sees an email, a phone number or an IP: the key it gets is the rule's operation and kind in clear, then a SHA-256 hash of the value (shaped `<operation>|identifier|<rule index>|9f2c…`). A dump of the rate table or of Redis therefore lists no addresses.

<!-- ds:block id=core-ratestore-fwswxsb9 -->
**RateStore** · [`ratelimit.go:108-110`](../../ratelimit.go#L108-L110)

```go
type RateStore interface {
	Hit(ctx context.Context, key string, window time.Duration) (int, error)
}
```
<!-- /ds:block hash=c0e5e5 -->

<!-- ds:block id=core-newmemoryratestore-zegx546n -->
**NewMemoryRateStore** · [`ratelimit.go:488-490`](../../ratelimit.go#L488-L490)

```go
func NewMemoryRateStore(now func() time.Time) RateStore {
	return &memoryStore{now: now, m: map[string]*memoryWindow{}}
}
```
<!-- /ds:block hash=a75a9b -->

| Store | Option | When |
| --- | --- | --- |
| Memory (default) | none | one instance |
| The auth database, table `auth_rate_limit` | `auth.WithDBRateStore()` | several instances and no shared cache; `Migrate` creates the table, `Sweep` clears finished windows |
| Redis | `auth.WithRateStore(redis.New(client))` from `contrib/redis` | several instances with Redis already there |
| Your own | `auth.WithRateStore(s)` | a store that implements `Hit` |
| Your own algorithm | `auth.WithRateStore(s)` | a store that also implements [`RateDecider`](ds:block?id=core-ratedecider-8hx2mv4q): a token bucket, GCRA, or an external limiter's verdict |

A store that implements `RateDecider` decides each rule itself: `Allow(ctx, key, rule)` gets the same hashed key `Hit` would and the rule's `Limit` and `Window` to interpret, and answers whether the call may pass and how long to wait if not (zero means the rule's window). The core then never compares a count, and `Hit` serves only `RateHit`. An error from `Allow`, like one from `Hit`, fails the call rather than letting it through.

The multi-instance example chooses between the database and Redis from the environment:

<!-- ds:block id=ratestore-7z8zumcj -->
**rateStore** · [`examples/multi-instance/main.go:136-147`](../../examples/multi-instance/main.go#L136-L147)

```go
func rateStore(redisAddr string) (auth.Option, error) {
	if redisAddr == "" {
		log.Printf("rate limits: counted in the database table %s", auth.TableNameRateLimit)
		return auth.WithDBRateStore(), nil
	}
	client := redis.NewClient(&redis.Options{Addr: redisAddr})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis at %s does not answer: %w", redisAddr, err)
	}
	log.Printf("rate limits: counted in Redis at %s", redisAddr)
	return auth.WithRateStore(redisrate.New(client)), nil
}
```
<!-- /ds:block hash=b1815c -->

Check: two instances on one database, five wrong passwords spread across both, and the sixth is refused on either instance.

## Step 4 — Add rules of your own

A plugin of yours declares rules with `RateLimiter`; the input names its account with `Identified` for `ByIdentifier` rules. See [Operations](../extending/02-operations.md), step 6.

An app sets rules from outside too. `auth.WithRateRules(rules...)` takes rules in the same shape: a rule for an operation a plugin already limits replaces that plugin's rules for the operation, so a budget that is too tight or too loose for your users becomes the one you state; a rule for an operation with none adds the first. What an app cannot do is remove a limit: every rule needs a `Limit` of one or more, and `auth.WithDisabledOperations` is the way to switch an operation off entirely.

<!-- ds:block id=opt-withraterules-3pxw7hgf -->
**WithRateRules** · [`ratelimit.go:137-139`](../../ratelimit.go#L137-L139)

```go
func WithRateRules(rules ...RateRule) Option {
	return func(s *settings) { s.appRules = append(s.appRules, rules...) }
}
```
<!-- /ds:block hash=5698af -->

`auth.WithRateLimit(limit, window)` is the floor: one `ByIP` limit on every operation, counted per operation and per address, on top of whatever the plugins declare. The plugins' rules stay the ceiling on the sensitive operations; the blanket one catches a flood of requests to an operation nobody thought to limit. It is off by default, because the right number depends on what sits in front of the app.

<!-- ds:block id=opt-withratelimit-6kq2mz4d -->
**WithRateLimit** · [`ratelimit.go:149-151`](../../ratelimit.go#L149-L151)

```go
func WithRateLimit(limit int, window time.Duration) Option {
	return func(s *settings) { s.globalRate = &RateRule{Key: ByIP, Limit: limit, Window: window} }
}
```
<!-- /ds:block hash=e851cc -->

A `ByFunc` rule counts by what its [`KeyFunc`](ds:block?id=core-ratekeyfunc-3vd8kq6m) returns for the call. It runs with the `ByIdentifier` rules, after the input is decoded and the caller resolved, so `c.User`, `c.Session`, `c.Input` and `c.Header` are all there; `""` leaves the call uncounted by that rule, and an error fails the call, because a limiter that cannot tell who is calling must not wave the call through. The value is stored only as a hash, like every other key. Per-user writes, per-tenant quotas and per-key API budgets are each one rule:

```go
perUser := auth.RateRule{Match: "org.create", Key: auth.ByFunc, Limit: 10, Window: time.Hour,
	KeyFunc: func(_ context.Context, c *auth.Call) (string, error) {
		if c.User == nil {
			return "", nil
		}
		return c.User.ID, nil
	}}
```

The per-user one is common enough to ship: [`auth.UserRateKey`](ds:block?id=core-userratekey-6tq2wm8n) is exactly that function, and the re-authentication operations of `plugin/password`, `plugin/passkey` and `plugin/twofactor` use it for their per-account rules (`KeyFunc: auth.UserRateKey`).

`auth.New` refuses a `ByFunc` rule without a `KeyFunc`, and a `KeyFunc` on any other key, since it would never be called.

`auth.WithRateExempt(fn)` is the one exemption function: asked once per call, before the input is decoded, whether this client is exempt from every `ByIP` rule, the blanket one included. It is for a health checker, an internal range or a partner's gateway that nothing in front of the app can be told about. `ByIdentifier` rules are never exempt, because they count guesses at one account from whatever address, and an exemption there would hand anyone behind the exempt address unlimited attempts at every user. The function must be fast and answer `false` on its own failure.

A plugin with a limit that is not a per-operation rule (failed attempts across many accounts, a quota) counts on the same configured store with [`a.RateHit(ctx, key, window)`](ds:block?id=core-ratehit-7wn3kq5x), which namespaces and hashes the key and returns the new count, and reads a count without adding to it with [`a.RatePeek`](ds:block?id=core-ratepeek-2pv8nq4k), for a guard that must refuse before it checks. `RatePeek` needs a [`RatePeeker`](ds:block?id=core-ratepeeker-4kq8wn2x) store: every store the library ships is one, a custom store answers `auth.ErrRatePeekUnsupported`, and `a.CanPeekRates()` lets a plugin refuse that at start; it answers during a plugin's Init too, while `RateHit` and `RatePeek` called there answer `auth.ErrRatesNotReady`, because the counters exist only once `auth.New` returns.

Direct Go calls (no transport attached a request) carry no address, so `ByIP` rules never count them; `ByIdentifier` and `ByFunc` rules do, so an app route that takes a password and calls the operation from Go cannot become an unlimited guess channel against one account. better-auth skips every server call instead; `auth.WithoutServerCallRateLimits()` is that rule, as an escape hatch `auth.New` [warns about](ds:block?id=core-warnservercalllimitsoff-4nd8qw2k) at every start. Turn it on only when every Go call site is a trusted job (an import, a seed, a back-office tool); calls through `authhttp` and the adapters are still counted.

<!-- ds:block id=opt-withoutservercallratelimits-7hq2xm5n -->
**WithoutServerCallRateLimits** · [`escapes.go:86`](../../escapes.go#L86-L86)

```go
func WithoutServerCallRateLimits() Option { return func(s *settings) { s.noServerCallLimits = true } }
```
<!-- /ds:block hash=2b2acf -->

<!-- ds:block id=opt-withrateexempt-4qz8vn7m -->
**WithRateExempt** · [`ratelimit.go:169-176`](../../ratelimit.go#L169-L176)

```go
func WithRateExempt(fn RateExemptFunc) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithRateExempt", fn) {
			return
		}
		s.rateExempt = fn
	}
}
```
<!-- /ds:block hash=d95004 -->

Addresses are canonicalized before counting (`::1` and `0:0:0:0:0:0:0:1` are one counter, an IPv4-mapped address is its IPv4 address), and `auth.WithIPv6Prefix(64)` counts an IPv6 allocation as one client, so an attacker rotating through the 2^64 addresses of a /64 hits one counter.

<!-- ds:block id=opt-withipv6prefix-8cfh3b2a -->
**WithIPv6Prefix** · [`ratelimit.go:196`](../../ratelimit.go#L196-L196)

```go
func WithIPv6Prefix(bits int) Option { return func(s *settings) { s.ipv6Prefix = bits } }
```
<!-- /ds:block hash=1981b7 -->

Check: `auth.New` refuses a rule for an unknown operation (`auth: hook names an operation that is not registered: plugin "x" limits "y.op"`, or `WithRateRules limits "y.op"`) and a rule with no limit, no window or an unknown key (`auth: operation description is not valid: rate rule for "y.op" is not valid`). With `WithRateLimit(2, time.Minute)`, the third `GET /auth/session` from one address in a minute answers `429` with `Retry-After: 60`.

## Step 5 — Choose what a rule does over its limit

A rule that is over its limit does not have to refuse the call. `RateRule.Action` (a [`RateAction`](ds:block?id=core-rateaction-4kz8wq2n)) says what happens, per rule, as better-auth Sentinel's per-feature actions do:

| Action | Over the limit | Use it for |
|---|---|---|
| `auth.RateBlock` (also `""`, the default) | The call is refused with `429 auth.rate_limited` and `Retry-After`, as every rule did before actions existed | Most rules |
| `auth.RateLog` | The call goes through and the event is recorded | Trying a limit in production before enforcing it, or watching a route you do not want to break |
| `auth.RateChallenge` | The call goes through only with a proof, else `428 auth.challenge_required`; a proof the challenger rejects is refused with the challenger's own error (`captcha.failed`, 403; `pow.proof_invalid`, 403, or `pow.challenge_invalid`, 400) | A busy shared address (an office, a school) where a human should be asked to prove it rather than shut out |

A challenge is passed by a [`RateChallenger`](ds:block?id=core-ratechallenger-5qt8nw3x). Registering the [captcha plugin](../plugins/captcha.md) is enough: it checks the same `X-Captcha-Response` header with the verifier you gave it, and `captcha.ChallengeOnly()` makes it guard nothing on its own, so a visitor under the limit never sees a captcha. Registering the [proof-of-work plugin](../plugins/pow.md) instead asks the client to spend CPU time on a hashcash puzzle (`POST /auth/pow/challenge`, then the solution in the `X-Pow-Proof` header), with no third party in the loop. Anything else, such as a fresh second factor, is a challenger of your own passed with `auth.WithRateChallenger`. `auth.New` refuses an unknown action, a challenge rule with no challenger, and two challengers (so `plugin/captcha` and `plugin/pow` cannot be registered together), since a client could not tell which to satisfy:

<!-- ds:block id=rateactions-example-rule-6k2q8w4n -->
**signInRule** · [`examples/rate-actions/main.go:95-97`](../../examples/rate-actions/main.go#L95-L97)

```go
func signInRule(action auth.RateAction) auth.RateRule {
	return auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: freeSignIns, Window: time.Minute, Action: action}
}
```
<!-- /ds:block hash=cd0a70 -->

<!-- ds:block id=rateactions-example-plugins-4v9m3x7q -->
**plugins** · [`examples/rate-actions/main.go:105-117`](../../examples/rate-actions/main.go#L105-L117)

```go
func plugins() []auth.Plugin {
	human := captcha.VerifierFunc(func(_ context.Context, token, _ string) error {
		if token == humanToken {
			return nil
		}
		return captcha.ErrFailed
	})
	return []auth.Plugin{
		email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
		password.New(),
		captcha.New(human, captcha.ChallengeOnly()),
	}
}
```
<!-- /ds:block hash=664e79 -->

Every call over a limit, whatever the action did with it, is reported once to each of: the logger (`rate rule exceeded` with `op`, `key`, `limit`, `window`, `action` and `outcome`), the `Observer` when it also implements [`RateObserver`](ds:block?id=core-rateobserver-9wd4kn7t), and the [audit log](../plugins/audit.md) as `rate_limit_exceeded` with the outcome in the code, and the [security event stream](security-events.md) as a `rate.limit` event. The outcomes are `blocked`, `logged`, `challenged` and `challenge_passed`. The logger, the audit log and the security stream take only the first event of each window, so a flood against one key writes one line and one row; the observer sees every one to count them. Counters held by a `RateDecider` store carry no count, so each of their events is reported.

The tested example is [`examples/rate-actions`](../../examples/rate-actions/): three sign-ins a minute, the fourth asked for a captcha.

<!-- ds:block id=rateactions-example-test-challenge-8d5n2r6c -->
**TestRateActions_ChallengeAsksForACaptchaOnlyOverTheLimit** · [`examples/rate-actions/main_test.go:50-65`](../../examples/rate-actions/main_test.go#L50-L65)

```go
func TestRateActions_ChallengeAsksForACaptchaOnlyOverTheLimit(t *testing.T) {
	_, b := world(t, auth.RateChallenge)
	for i := range freeSignIns {
		if r := signIn(t, b, ""); r.Status != http.StatusOK {
			t.Fatalf("sign-in %d under the limit: %d %s", i+1, r.Status, r.Body)
		}
	}
	over := signIn(t, b, "").Expect(http.StatusPreconditionRequired)
	if over.ErrorCode() != auth.ErrChallengeRequired.Code {
		t.Fatalf("over the limit: %s", over.Body)
	}
	if code := signIn(t, b, "forged").Expect(http.StatusForbidden).ErrorCode(); code != captcha.ErrFailed.Code {
		t.Fatalf("a rejected token: %s", code)
	}
	signIn(t, b, humanToken).Expect(http.StatusOK)
}
```
<!-- /ds:block hash=adfd18 -->

## What can go wrong

- `auth.rate_limited` during development — your tests or your own retries exhausted a budget. Memory counters reset with the process; the database store's reset when the window ends or `auth sweep` runs.
- Limits that do not hold behind a load balancer — the default memory store, one per instance. Pass `auth.WithDBRateStore()` or a Redis store.
- `auth: operation description is not valid: WithRateStore and WithDBRateStore both set` — choose one.
- `auth: no database configured; pass auth.WithDB: WithDBRateStore needs WithDB` — the database store has nowhere to count.
- A `ByIP` rule that never fires from Go — Go calls have no address; only HTTP requests are counted by address.
- Every client limited at once — the app sits behind a proxy and the library sees the proxy's address. `authhttp` reads `RemoteAddr`; terminate the proxy so that the real address reaches it, or put the limit at the proxy.
- One client escapes a `ByIP` rule by changing IPv6 addresses — it owns a /64; pass `auth.WithIPv6Prefix(64)`.
- `428 auth.challenge_required` — a `RateChallenge` rule is over its limit and the call carried no proof; send the captcha token (or the proof of work) and call again. `auth.New` fails with a challenge rule and no challenger: register `plugin/captcha` or `plugin/pow`, or pass `auth.WithRateChallenger`.
- `auth: operation description is not valid: two rate challengers: plugin "captcha" and plugin "pow"; keep one` — both challengers are registered; a client could not tell which proof to send.
- A `RateLog` rule that never refuses — by design; change the action to `auth.RateBlock` when the log shows the limit is right.
- `auth: hook names an operation that is not registered: WithRateRules limits "password.signin"` — the id in an app rule is a plugin's exported `Endpoint…` constant, here `password.EndpointSignIn`.

## Next

- [Security](security.md): the other defences around sign-in.
- [Proof of work](../plugins/pow.md): the challenger with no third party.
- [Security events](security-events.md): every call over a limit, on your own log drain.
- [Configuration](configuration.md): `WithRateStore` and `WithDBRateStore` among the rest.
