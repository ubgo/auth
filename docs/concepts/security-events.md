# Security events

You will have every refusal and alert the library makes on the way in (a rate rule over its limit, one password sprayed across many accounts, a second factor locked against guessing, a sign-in from a denied country, an impossible journey) arrive at your own log drain, SIEM client or alerting hook as one typed record, off the request path, without the library shipping any vendor client.

## Before you start

- [Rate limits](rate-limits.md): the rules whose excess is the most common event.
- The example is [`examples/security-events`](../../examples/security-events/): email and password sign-in, an app rate rule and the spraying guard, feeding a JSON-lines drain and the logger sink. `AUTH_SECRET=$(openssl rand -base64 32) go run ./security-events` in `examples/` serves it on `localhost:8081`; `go test ./security-events` runs the checks below.
- The stream is off by default. With no sink registered nothing is built, queued or started, and `a.SecurityStats()` is nil.
- The stream is not the audit log. [`plugin/audit`](../plugins/audit.md) is the durable record in your database and never loses a row; the stream is a live feed for outside systems and is allowed to lose events under pressure, so a gap in the feed never becomes a slow or failed sign-in.

## Step 1 — Know what an event is

Every event is one [`auth.SecurityEvent`](ds:block?id=core-securityevent-9hn4wq7v):

<!-- ds:block id=core-securityevent-9hn4wq7v -->
**SecurityEvent** · [`secevent.go:197-222`](../../secevent.go#L197-L222)

```go
type SecurityEvent struct {
	// ID is unique per event ("sev_" and 24 hex digits), for a sink that
	// de-duplicates retries.
	ID   string
	At   time.Time
	Kind SecurityKind
	// Severity is set by the emitter; EmitSecurity fills SeverityInfo when
	// it is empty.
	Severity SecuritySeverity
	// Outcome is what the library did: blocked, logged (recorded only),
	// challenged or challenge_passed. The same four values as RateOutcome.
	Outcome RateOutcome
	// Op, Plugin and Transport name the operation the event happened in;
	// "" for an event outside one.
	Op        EndpointID
	Plugin    string
	Transport Transport
	// UserID is the account concerned, "" when the event is about a call that
	// named none (a rate rule by address).
	UserID string
	// IP is the client address, "" under WithoutIPTracking or outside a
	// request.
	IP string
	// Attrs holds the kind's details under the Attr* keys.
	Attrs map[string]string
}
```
<!-- /ds:block hash=08cc44 -->

It carries no password, token, code or input, and the client address only while sessions track it (not under `auth.WithoutIPTracking`), so a sink can ship it to a third party as it stands. `Outcome` uses the same four values as a rate event: `blocked`, `logged`, `challenged` and `challenge_passed`.

The library emits thirteen [kinds](ds:block?id=core-securitykind-3vq8nw5k); `auth.SecurityKindValues` lists them for a sink that routes by kind:

| Kind | Emitted when | Severity | Attrs |
|---|---|---|---|
| `rate.limit` (`auth.SecurityRateLimit`) | A call goes over a rate rule's limit, once per rule window, as the logger and the audit log report it, whatever the rule's action did | `warn`; `info` when the rule only logs or the challenge was passed | `rule_key`, `limit`, `window`, `count` |
| `credential.stuffing` (`auth.SecurityCredentialStuffing`) | `plugin/password`'s `GuardCredentialStuffing` reaches its limit: once per window and scope, at the crossing, not on each refusal that follows | `alert` | `scope` (`password` or `global`), `failures`, `window` |
| `lockout` (`auth.SecurityLockout`) | `plugin/twofactor` locks a factor after too many wrong codes: once per lock, not on each refused code while it lasts | `warn` | `failures`, `window` (the lock's duration) |
| `geo.country` (`auth.SecurityGeoCountry`) | A sign-in from a country [`WithGeoRules`](geo-rules.md) denies, outside the ones it allows, or (with `DenyUnknown`) from an address the locator does not know | `warn`; `info` when a challenge was passed | `country` (empty for an unknown address) |
| `account.stale` (`auth.SecurityStaleAccount`) | [`plugin/stale`](../plugins/stale.md) warned a dormant account or deleted it after the grace period, once per account, none on a dry run | `info` (warned), `warn` (deleted) | the outcome says which |
| `password.compromised` (`auth.SecurityCompromisedPassword`) | A `BreachChecker` such as `hibp` refused a password, once per check; never carries the password or a hash prefix | `warn` | none |
| `ip.suspicious` (`auth.SecuritySuspiciousIP`) | The [`IPReputation`](risk-signals.md) the app passed flagged the caller's address | `warn`; `info` when a challenge was passed | `reason` |
| `bot` (`auth.SecurityBot`) | The [`BotChecker`](risk-signals.md) flagged the request | `warn`; `info` when a challenge was passed | `reason` |
| `trial.abuse` (`auth.SecurityTrialAbuse`) | The [`TrialAbuseChecker`](risk-signals.md) flagged a new account as it stored its first identifier | `warn`; `info` when a challenge was passed | `reason`; the event carries the new user id |
| `session.reauthenticated` (`auth.SecurityReauthentication`) | A signed-in user [re-authenticated](sessions.md#prove-it-is-still-you-re-authentication): the session became fresh, the first factor passed and the second is due, or a password, code or passkey was refused | `info` (outcome `logged`); `warn` (outcome `blocked`) for a refusal | `reauth_step` (`fresh`, `second_factor` or `failed`; `auth.ReauthStepValues`) |
| `token.replay` (`auth.SecurityTokenReplay`) | A proof that is good only once was presented again: an ID token [plugin/oauth](../plugins/oauth.md#replay-protection) had already accepted, refused by its replay guard, once per refusal | `alert` (outcome `blocked`) | `provider` |
| `session.token_reuse` (`auth.SecuritySessionTokenReuse`) | A session token that [`WithTokenRotation`](sessions.md#catch-a-copied-token-withtokenrotation) had replaced was presented after its grace window; the session was revoked, once per revocation | `alert` (outcome `blocked`) | `session_id`; the event carries the user id |
| `session.end_hook_failed` (`auth.SecuritySessionEndHookFailed`) | A `DataHooks.SessionEnded` hook returned an error; the session ended anyway, without that hook's work (for example a lost webhook) | `warn` (outcome `logged`) | `session_id` (empty for a user-wide end in stateless mode), `reason` (a `SessionEndReason`), `error`; the event carries the user id |
| `geo.impossible_travel` (`auth.SecurityImpossibleTravel`) | A sign-in too far from the user's previous one for the time between them ([`WithImpossibleTravel`](geo-rules.md)) | `alert`; `info` when a challenge was passed | `country`, `previous_country`, `distance_km`, `speed_kmh`, `elapsed` |

The [severities](ds:block?id=core-securityseverity-6kz2mx9t) are `info`, `warn` and `alert`, lowest first (`auth.SecuritySeverityValues`), for a sink that pages someone on alerts and only stores the rest. A plugin or an app may emit kinds of its own (Step 4), so a sink must tolerate a kind it does not know.

Check: `auth.SecurityKindValues` and the table above name the same thirteen kinds.

## Step 2 — Register a sink

A sink is one method that receives a batch:

<!-- ds:block id=core-securitysink-4cw7xk2m -->
**SecuritySink** · [`secevent.go:233-235`](../../secevent.go#L233-L235)

```go
type SecuritySink interface {
	WriteSecurity(ctx context.Context, batch []SecurityEvent) error
}
```
<!-- /ds:block hash=5ca9e5 -->

`auth.SecuritySinkFunc` adapts a function. The example's drain writes one JSON line per event, standing in for a SIEM client or a log shipper, and registers the library's logger sink beside it:

<!-- ds:block id=securityevents-example-sinks-8vk3qw2n -->
**securitySinks** · [`examples/security-events/main.go:139-144`](../../examples/security-events/main.go#L139-L144)

```go
func securitySinks(w io.Writer) []auth.Option {
	return []auth.Option{
		auth.WithSecuritySink(jsonDrain(w), drainQueue),
		auth.WithSecurityLog(auth.SecurityQueue{}),
	}
}
```
<!-- /ds:block hash=c625cb -->

[`auth.WithSecuritySink(sink, queue)`](ds:block?id=opt-withsecuritysink-7pm3vz8q) is called once per sink. [`auth.WithSecurityLog(queue)`](ds:block?id=opt-withsecuritylog-2tq9kn4x) is the zero-setup sink: one structured line per event on the Auth's logger (`auth.WithLogger`), at Info, Warn or Error for the severities info, warn and alert. [`auth.MemorySecuritySink`](ds:block?id=core-memorysecuritysink-8nx5kq3w) keeps events in memory for tests, with `Events`, `OfKind` and `Reset`.

`WriteSecurity` runs on the sink's own goroutine, never a request's, with a context bounded by `auth.SecurityWriteTimeout` (10 seconds), so it may block, retry and talk to the network. An error, or a panic (which is recovered), is logged as `auth: security sink failed` and counted; that batch is not offered again. A sink that must not lose events retries inside `WriteSecurity` or writes to a durable queue of its own. The slice is reused after the call returns, so keep a copy of anything you hold on to.

Check: `auth.New` refuses `WithSecuritySink(nil, …)` naming the option.

## Step 3 — Shape the queue

Each sink has its own bounded queue and goroutine, started by `auth.New` and stopped by `a.Close`, so a slow sink delays only itself. The [`auth.SecurityQueue`](ds:block?id=core-securityqueue-5nq2wx8k) passed with it shapes that queue, and its zero value takes every default:

| Field | Default | What it does |
|---|---|---|
| `Name` | `sink1`, `sink2`, … in registration order (`log` for `WithSecurityLog`) | Labels the sink in `SecurityStats` and in log lines about it |
| `Buffer` | `auth.DefaultSecurityBuffer`, 1024 | How many events may wait for the sink |
| `BatchSize` | `auth.DefaultSecurityBatch`, 100 | The most events handed to the sink in one call |
| `FlushEvery` | `auth.DefaultSecurityFlush`, 2s | The longest an event waits for its batch to fill |

A negative number is refused at `auth.New`. The example gives its drain a name, batches of 10 and a one-second flush, so a quiet stream still ships promptly.

Emitting never blocks a request: it is a non-blocking send into each queue. When a queue is full the new event is dropped and counted, because blocking the sign-in that triggered it, or growing without bound under the very flood being reported, is worse than a gap in the feed. The sink's goroutine logs how many it dropped, at most once per interval (`auth: security events dropped, the sink cannot keep up`).

[`a.SecurityStats()`](ds:block?id=core-securitysinkstats-5vk8wn2q) reports, per sink in registration order, how many events were `Queued`, `Delivered`, `Dropped` and `Failed`; queued minus delivered minus failed is what is still waiting. Export those numbers to your metrics: a rising `Dropped` means the sink cannot keep up.

`a.Close()` stops accepting events and lets each queue drain into its sink, bounded so a stuck sink cannot hang a shutdown; events emitted after it are dropped. Events are not durable: a process that dies loses what was queued. `a.FlushSecurity(ctx)` returns once everything emitted before it has been handed to its sink, for tests and for a handler that must see its events delivered; the stream needs no flushing in normal operation.

Check: `TestSecurityStream_DropsNewEventsWhenFullAndNeverBlocks` and `TestSecurityStream_CloseDrainsThenDrops` in `secevent_test.go` pin both halves.

## Step 4 — Watch an attack become two lines

Seven failed sign-ins from one address against the example's rule of five a minute per address:

<!-- ds:block id=securityevents-example-rule-5qw8nk3v -->
**signInRule** · [`examples/security-events/main.go:102-104`](../../examples/security-events/main.go#L102-L104)

```go
func signInRule() auth.RateRule {
	return auth.RateRule{Match: password.EndpointSignIn, Key: auth.ByIP, Limit: signInsPerMinute, Window: time.Minute}
}
```
<!-- /ds:block hash=11b9e9 -->

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
for i in 1 2 3 4 5 6 7; do curl -s -o /dev/null -w '%{http_code} ' -X POST localhost:8081/auth/password/sign-in -H "$O" -d "{\"identifier\":\"guess-$i@example.com\",\"password\":\"guess-$i-password\"}"; done
```

```text
401 401 401 401 401 429 429
```

Two calls went over the limit, and the drain received one event for the window, not one per refused call:

```json
{"ID":"sev_7baa539cb3f0834491d19c94","At":"2026-10-10T04:07:40.045914Z","Kind":"rate.limit","Severity":"warn","Outcome":"blocked","Op":"password.sign-in","Plugin":"password","Transport":"http","UserID":"","IP":"127.0.0.1","Attrs":{"count":"6","limit":"5","rule_key":"ip","window":"1m0s"}}
```

A minute later, one password sprayed across three accounts (two of them do not exist; the guard counts those too) and then tried on Ada's:

```sh
for who in a b c ada; do curl -s -w ' %{http_code}\n' -X POST localhost:8081/auth/password/sign-in -H "$O" -d "{\"identifier\":\"$who@example.com\",\"password\":\"Summer2026!\"}"; done
```

The first three answer `401 password.invalid_credentials`; the fourth is refused with `429 auth.rate_limited` before the password is checked. The crossing is one event, with the count and the scope and no password:

```json
{"ID":"sev_16a81b52886592aea8f91dc0","At":"2026-10-10T04:08:41.334059Z","Kind":"credential.stuffing","Severity":"alert","Outcome":"blocked","Op":"password.sign-in","Plugin":"","Transport":"","UserID":"","IP":"","Attrs":{"failures":"3","scope":"password","window":"15m0s"}}
```

The logger sink wrote the same two events at Warn and Error:

```text
WARN auth: security event id=sev_7baa539cb3f0834491d19c94 kind=rate.limit outcome=blocked op=password.sign-in user="" ip=127.0.0.1 rule_key=ip limit=5 window=1m0s count=6
ERROR auth: security event id=sev_16a81b52886592aea8f91dc0 kind=credential.stuffing outcome=blocked op=password.sign-in user="" ip="" scope=password failures=3 window=15m0s
```

The test pins the one-event-per-window rule:

<!-- ds:block id=securityevents-example-test-rate-3nw7kq5x lines=1-12 -->
**TestSecurityEvents_OneRateEventPerWindow** · [`examples/security-events/main_test.go:116-143`](../../examples/security-events/main_test.go#L116-L143)

```go
func TestSecurityEvents_OneRateEventPerWindow(t *testing.T) {
	e, b, buf := world(t, true)
	const refusedPerWindow = 3
	overTheLimit(t, b, 0, refusedPerWindow)
	got := ofKind(drain(t, e, buf), auth.SecurityRateLimit)
	if len(got) != 1 {
		t.Fatalf("%d rate.limit events for one window, want 1: %+v", len(got), got)
	}
	ev := got[0]
	want := map[string]string{
		auth.AttrRuleKey: string(auth.ByIP), auth.AttrLimit: strconv.Itoa(signInsPerMinute),
		auth.AttrWindow: time.Minute.String(), auth.AttrCount: strconv.Itoa(signInsPerMinute + 1),
```
<!-- /ds:block hash=59d396 -->

Check: `go test ./security-events` in `examples/` passes, and [`TestSecurityEvents_SprayIsOneEventWithoutThePassword`](ds:block?id=securityevents-example-test-spray-7xq2wn4k&assert=true) finds no password in anything the drain wrote.

## Step 5 — Emit events of your own

A plugin or an app with something worth reporting (an admin action from an unusual place, a webhook signature that failed) calls [`a.EmitSecurity(e)`](ds:block?id=core-emitsecurity-3rw6kx9n) with a kind of its own:

```go
a.EmitSecurity(auth.SecurityEvent{Kind: "billing.card_declined_burst", Severity: auth.SeverityAlert, UserID: userID})
```

It never blocks and never fails; with no sink registered it does nothing. `At`, `ID` (`sev_` and 24 hex digits, for a sink that de-duplicates retries) and `Severity` (`info`) are filled when empty, and `IP` is cleared under `auth.WithoutIPTracking`, so the promise in Step 1 holds for events a plugin builds too.

Check: `TestSecurityStream_FillsDefaultsAndHonoursNoIPTracking` in `secevent_test.go`.

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `auth: operation description is not valid: auth.WithSecuritySink "drain": Buffer -1, BatchSize 0 and FlushEvery 0s cannot be negative` | A negative field in the `SecurityQueue` | Use 0 for the default |
| `auth: security events dropped, the sink cannot keep up` in the log | The sink is slower than the events arrive and its queue filled | Raise `Buffer` or `BatchSize`, make `WriteSecurity` faster, or hand the batch to a local queue and return |
| `auth: security sink failed` in the log | `WriteSecurity` returned an error or panicked; that batch is counted in `Failed` and not offered again | Retry inside the sink if every event matters, or rely on `plugin/audit` for the durable record |
| No `rate.limit` event for the second refused call of a window | By design: one event per rule window | Count every refusal with an `Observer` that implements `auth.RateObserver` |
| No event at all in a test | The sink's goroutine has not run yet | Call `a.FlushSecurity(ctx)` before reading |
| `IP` is always empty | `auth.WithoutIPTracking` is on, or the event happened outside a request (the stuffing guard's crossing is reported without the call's address) | Expected |

## Next

- [Geo rules](geo-rules.md): country rules and impossible travel, two of the event kinds.
- [Risk signals](risk-signals.md): the IP, bot and trial-abuse checks, three more.
- [Rate limits](rate-limits.md): the rules and actions behind `rate.limit`.
- [Audit log](../plugins/audit.md): the durable record of the same refusals.
- [Production](../start/production.md): logging and monitoring.
