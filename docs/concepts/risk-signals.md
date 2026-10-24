# Risk signals

You will have a suspicious address, a script, or a repeat free-trial sign-up refused (or logged, or challenged) by a check you supply. The library ships no detector and no vendor client: it asks three small interfaces, and what answers them is yours (a denylist, a reputation service, your own billing table).

## Before you start

- [Rate limits](rate-limits.md), Step 5: a flag applies the same three actions (block, log, challenge), and a challenge is answered by the same `auth.RateChallenger`.
- [Security events](security-events.md): every flag is exactly one event on the stream, of kind `ip.suspicious`, `bot` or `trial.abuse`, with the cause under `reason`.
- The example is [`examples/risk-signals`](../../examples/risk-signals/): a denylisted address, a script's user agent and a repeat trial address, over email and password sign-in. `go run ./risk-signals` in `examples/` serves it on `localhost:8081`; `go test ./risk-signals` runs the checks below.
- Everything here is off until you pass a check.

## Step 1 — Judge an address

An [`IPReputation`](ds:block?id=core-ipreputation-8wt4nq6k) answers one question about a client address. `WithIPReputation(check, auth.RiskPolicy{})` runs it before the credentials are read, for every signed-out mutation (sign-in, sign-up, a reset or code request) and every operation marked `OpInfo.SignIn`, so a flagged address gets the same answer for a right and a wrong password. A Go call, a query and a signed-in operation are not judged, and neither is a call with no client address.

<!-- ds:block id=core-ipreputation-8wt4nq6k -->
**IPReputation** · [`risk.go:84-86`](../../risk.go#L84-L86)

```go
type IPReputation interface {
	CheckIP(ctx context.Context, ip netip.Addr) (RiskVerdict, error)
}
```
<!-- /ds:block hash=8069d0 -->

The answer is a [`RiskVerdict`](ds:block?id=core-riskverdict-7qk3xv8m): whether to flag, and a short machine-readable `Reason` (cut to `MaxRiskReasonLen` bytes) that lands on the event. Keep the reason a category such as `tor-exit`, never an address or a name.

<!-- ds:block id=core-riskverdict-7qk3xv8m -->
**RiskVerdict** · [`risk.go:32-39`](../../risk.go#L32-L39)

```go
type RiskVerdict struct {
	// Flagged is true when the check wants the policy's action applied.
	Flagged bool
	// Reason is a short machine-readable cause ("tor-exit", "datacenter",
	// "headless-ua") recorded on the event as AttrReason. It is cut to
	// MaxRiskReasonLen bytes, and must carry nothing secret or personal.
	Reason string
}
```
<!-- /ds:block hash=b6fc1c -->

The check runs on the request's goroutine, so keep it fast and local: a list in memory, or a cache in front of a lookup service with a tight timeout.

## Step 2 — Judge a request

A [`BotChecker`](ds:block?id=core-botchecker-6hv2xn4t) sees the [`BotSignals`](ds:block?id=core-botsignals-3mx7kq9v) of the request: the operation, the transport, the client address, user agent, origin and fetch site, and any header through `Header(name)`. It never sees a credential or the input, so nothing secret can reach a third-party service. `WithBotCheck(check, policy)` runs at the same point as the address check, after it.

<!-- ds:block id=core-botchecker-6hv2xn4t -->
**BotChecker** · [`risk.go:126-128`](../../risk.go#L126-L128)

```go
type BotChecker interface {
	CheckBot(ctx context.Context, s BotSignals) (RiskVerdict, error)
}
```
<!-- /ds:block hash=f79a84 -->

<!-- ds:block id=core-botsignals-3mx7kq9v -->
**BotSignals** · [`risk.go:101-111`](../../risk.go#L101-L111)

```go
type BotSignals struct {
	// Op is the operation being called.
	Op OpInfo
	// Transport is how it arrived.
	Transport Transport
	// Client is the caller's address, user agent, origin and fetch site; IP
	// is "" when the transport did not supply one.
	Client Client

	header func(name string) string
}
```
<!-- /ds:block hash=99f42c -->

## Step 3 — Judge a sign-up

A [`TrialAbuseChecker`](ds:block?id=core-trialabusechecker-4tq8vk7m) sees the new account as a [`SignUpInfo`](ds:block?id=core-signupinfo-9rk5wq2n): the user's id, the normalized identifier and the client. `WithTrialAbuseCheck(check, policy)` runs when a user's first identifier is stored, which is the moment a sign-up has said who it is, so it covers every plugin that creates an identity for a new user. The value is normalized by its identifier kind; folding the rest (dots and `+tag` in a mail address, a phone's formatting) is your rule, because it differs by product. An account made with no identifier (a pure provider link) is not judged, and adding a second identifier to an existing user is not a sign-up.

<!-- ds:block id=core-trialabusechecker-4tq8vk7m -->
**TrialAbuseChecker** · [`risk.go:162-164`](../../risk.go#L162-L164)

```go
type TrialAbuseChecker interface {
	CheckSignUp(ctx context.Context, s SignUpInfo) (RiskVerdict, error)
}
```
<!-- /ds:block hash=801b97 -->

<!-- ds:block id=core-signupinfo-9rk5wq2n -->
**SignUpInfo** · [`risk.go:147-155`](../../risk.go#L147-L155)

```go
type SignUpInfo struct {
	// UserID is the new user's id.
	UserID string
	// Identifiers are the account's first identifier, normalized (the
	// address a "+tag" or dot-trick checker compares).
	Identifiers []SignUpIdentifier
	// Client is the caller's address and user agent; empty for a Go call.
	Client Client
}
```
<!-- /ds:block hash=10433e -->

A block returns the error from the identifier write, so the sign-up that called it fails; the operation runs in a transaction, so the user it created is rolled back with it.

## Step 4 — Choose what a flag and a failure do

Each option takes a [`RiskPolicy`](ds:block?id=core-riskpolicy-5kz9wm3x). The zero value blocks a flagged call and fails open.

<!-- ds:block id=core-riskpolicy-5kz9wm3x -->
**RiskPolicy** · [`risk.go:68-76`](../../risk.go#L68-L76)

```go
type RiskPolicy struct {
	// Action is what a flag does: RateBlock (the default, 403), RateLog
	// (record only, to measure a detector before enforcing it) or
	// RateChallenge (the RateChallenger decides). A challenge needs a
	// challenger, as for a rate rule.
	Action RateAction
	// OnError is what a check that returns an error does; see RiskErrorMode.
	OnError RiskErrorMode
}
```
<!-- /ds:block hash=d43071 -->

| Action | What a flag does | Answer |
|---|---|---|
| `RateBlock` (default) | Refuses the call | `403`: `auth.ip_blocked`, `auth.bot_blocked` or `auth.signup_blocked` |
| `RateLog` | Lets it through and records the event; use it to measure a detector before enforcing it | the operation's own |
| `RateChallenge` | Asks the registered `RateChallenger` (a captcha, [pow](../plugins/pow.md)); `New` refuses it when there is none | `428 auth.challenge_required`, or the challenger's error |

`OnError` says what a check that returns an error does. `RiskFailOpen` (the default) lets the call through and logs a warning, because a vendor outage must not be a sign-in outage. `RiskFailClosed` refuses with `503 auth.risk_check_unavailable`, for an app that would rather turn people away than let an unchecked sign-up through. A failed check emits no event: nothing was flagged. Both modes are tested.

Every option refuses a nil check, an unknown action or error mode, and a challenge with no challenger, at `New`, naming the option.

## Step 5 — Read the events

A flag is one `SecurityEvent`: kind `ip.suspicious`, `bot` or `trial.abuse`, severity `warn` (`info` when a challenge was passed), the outcome, the operation, the client address (empty under `WithoutIPTracking`), the user id for a sign-up, and `reason`. It never carries the identifier, the user agent or a header. See [security events](security-events.md).

## What to remember

- The library decides nothing about what is suspicious; a check that flags too much locks people out, so start with `RateLog`.
- The address a check sees is the one the transport resolved. Behind a proxy, configure `authhttp.TrustedProxies`, or every client looks like the proxy.
- A bot check on a plain script is easy to evade; pair it with a challenge, which a script cannot answer cheaply.
