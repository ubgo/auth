# Refuse a suspicious address, a script and a repeat trial sign-up

Three risk checks of your own, each a small function the app passes. The library ships no detector and no vendor client: it asks `auth.IPReputation`, `auth.BotChecker` and `auth.TrialAbuseChecker`, applies the answer with the same block, log or challenge actions a rate rule has, and puts exactly one event on the security stream. Here the IP check is a denylist of one documentation address, the bot check flags a scripting library's user agent, and the trial-abuse check folds a sign-up's address (no dots, no `+tag`) and compares it with the accounts that already used the trial. A real app wraps its own list, reputation service or billing table in the same functions. The reference is the doc comments in [risk.go](../../risk.go).

## Run it

```sh
cd examples
go run ./risk-signals
```

It creates `risk-signals.db` (SQLite) and listens on `http://localhost:8081`. The app trusts a reverse proxy on this machine (`authhttp.TrustedProxies`), so the client address is the one in `X-Forwarded-For`: `203.0.113.66` is on the denylist, `203.0.113.67` is clean, and `trial@example.com` already had the trial. Security events are logged by `auth.WithSecurityLog`. Run the tests with `go test ./risk-signals`.

## Walkthrough

Sign in from the denylisted address, sign up with a script's user agent, then sign up with a dotted, tagged variant of the used trial address:

```sh
O='Origin: http://localhost:8081'
J='{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.66' -d "$J"
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Forwarded-For: 203.0.113.67' -A python-requests/2.32 -d "$J"
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Forwarded-For: 203.0.113.67' -d '{"identifier":"T.rial+again@example.com","password":"correct horse battery staple","name":"T"}'
```

Each is refused with `403` and its own code:

```json
{"error":{"code":"auth.ip_blocked","message":"This request cannot be completed from your network."}}
{"error":{"code":"auth.bot_blocked","message":"This request looks automated. Try again from a browser."}}
{"error":{"code":"auth.signup_blocked","message":"We could not create this account. Contact support if you think this is a mistake."}}
```

Every refusal is one security event; the log shows them, with the cause under `reason` and never the address that was typed:

```text
WARN auth: security event id=sev_41a280ac73e47847f5c931a1 kind=ip.suspicious outcome=blocked op=password.sign-in user="" ip=203.0.113.66 reason=denylist
WARN auth: security event id=sev_9c36ef1144cba40b59da3908 kind=bot outcome=blocked op=password.sign-up user="" ip=203.0.113.67 reason=script-agent
WARN auth: security event id=sev_6a7149eda0abce539eda3ca8 kind=trial.abuse outcome=blocked op=password.sign-up user=usr_fzntnwn7l5qu6n3ovnk7pitz ip=203.0.113.67 reason=repeat-address
```

The address and bot checks run before the credentials are read, so the answer is the same for a right and a wrong password. The trial check runs when the new user's first identifier is stored; the refused sign-up leaves no user behind. `auth.RiskPolicy{Action: auth.RateLog}` records a flag without refusing it, which is how to measure a detector before enforcing it, and `auth.RateChallenge` asks the app's rate challenger. `OnError: auth.RiskFailClosed` refuses with `503 auth.risk_check_unavailable` when a check cannot answer; the default lets the call through and logs a warning.

## What the tests prove

`main_test.go`: from the denylisted address the right and the wrong password both get `403 auth.ip_blocked` and each is one `ip.suspicious` event with the reason, while a clean address signs in; a script's user agent is `403 auth.bot_blocked` with one `bot` event and a browser's is accepted; a variant of the used trial address is `403 auth.signup_blocked` with one `trial.abuse` event naming the new user and not the address, and a fresh address signs up. The same checks with the log and challenge actions, the fail-open and fail-closed switch, and the rolled-back user, are checked in [risk_test.go](../../risk_test.go) and, on every engine, [integration/risk_test.go](../../integration/risk_test.go).
