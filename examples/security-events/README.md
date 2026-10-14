# Feed security events to your log drain

The library reports what it refuses, challenges or notices on the way in as one typed record, `auth.SecurityEvent`, handed in batches to the sinks the app registers. Here a rate rule on password sign-in and the guard against one password sprayed across many accounts feed two sinks: the app's own drain (a small `auth.SecuritySinkFunc` that writes one JSON line per event, standing in for a SIEM client or a log shipper) and the library's logger sink, `auth.WithSecurityLog`. Each sink has its own bounded queue and goroutine, so a slow drain never delays a sign-in; a full queue drops the new event and counts it rather than block. The stream is off until a sink is registered, and it is a live feed that may lose events under pressure: `plugin/audit` stays the durable record. The reference is the doc comments in [secevent.go](../../secevent.go).

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) go run ./security-events
```

It creates `security-events.db` (SQLite) and listens on `http://localhost:8081`. The spraying guard counts each failed password under a keyed hash, so `AUTH_SECRET` is required. Events go to standard output as JSON lines, and to the log on standard error. Run the tests with `go test ./security-events`.

## Walkthrough

Sign up, then make seven failed sign-ins from one address, each against a different account with a different password, so only the app's rule (five a minute per address) counts them:

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

A minute later, spray one password across three accounts (two of them do not exist; the guard counts those too), then try it on Ada's:

```sh
for who in a b c ada; do curl -s -w ' %{http_code}\n' -X POST localhost:8081/auth/password/sign-in -H "$O" -d "{\"identifier\":\"$who@example.com\",\"password\":\"Summer2026!\"}"; done
```

The first three answer `401 password.invalid_credentials`; the fourth is refused with `429 auth.rate_limited` before the password is checked. The crossing is one event, and it carries the count and the scope but no password:

```json
{"ID":"sev_16a81b52886592aea8f91dc0","At":"2026-10-10T04:08:41.334059Z","Kind":"credential.stuffing","Severity":"alert","Outcome":"blocked","Op":"password.sign-in","Plugin":"","Transport":"","UserID":"","IP":"","Attrs":{"failures":"3","scope":"password","window":"15m0s"}}
```

The logger sink wrote the same two events as log lines, at Warn and Error by severity:

```text
WARN auth: security event id=sev_7baa539cb3f0834491d19c94 kind=rate.limit outcome=blocked op=password.sign-in user="" ip=127.0.0.1 rule_key=ip limit=5 window=1m0s count=6
ERROR auth: security event id=sev_16a81b52886592aea8f91dc0 kind=credential.stuffing outcome=blocked op=password.sign-in user="" ip="" scope=password failures=3 window=15m0s
```

## What the tests prove

`main_test.go`: three calls over the rate limit in one window are exactly one `rate.limit` event with the rule's key, limit, window and count, and the next window's excess is one more; the drain is called with batches of at most its `BatchSize`, every event arrives once and `SecurityStats` counts them per sink; a spray that crosses the guard's limit is one `credential.stuffing` event, the sprayed password is refused afterwards even on the account it was never tried on, and no password reaches the drain; with no sink registered `SecurityStats` is nil before and after calls over the limit, and `EmitSecurity` and `FlushSecurity` do nothing. The stuffing event, the two-factor lockout event and the geo events are checked on every engine in [integration/secgeo_test.go](../../integration/secgeo_test.go).
