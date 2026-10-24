# Refuse sign-ins by country and impossible travel

Two checks on where a sign-in comes from. A country rule refuses sign-in from a denied country with `403 auth.geo_blocked`, and it runs before the credentials are read, so the answer is the same for the right and the wrong password. Impossible travel compares a sign-in's location with the user's previous sign-in and refuses with `403 auth.impossible_travel` when no flight could have made the journey in the time between them (900 km/h by default, hops under 100 km ignored); the refused sign-in leaves no session. Both report to the security event stream. The library has no GeoIP database and no vendor client: the app passes an `auth.GeoLocator`. Here it is a table of three documentation addresses standing in for a MaxMind reader, which a real app wraps in the same `auth.GeoLocatorFunc`. The reference is the doc comments in [geo.go](../../geo.go).

## Run it

```sh
cd examples
go run ./geo-rules
```

It creates `geo-rules.db` (SQLite) and listens on `http://localhost:8081`. The app trusts a reverse proxy on this machine (`authhttp.TrustedProxies`), so the client address is the one in `X-Forwarded-For`, which is how the walkthrough pretends to be in three cities: `203.0.113.7` is Berlin, `203.0.113.8` New York and `203.0.113.9` Moscow, and Russia is the denied country. A header from any untrusted address is ignored. Security events are logged by `auth.WithSecurityLog`. Run the tests with `go test ./geo-rules`.

## Walkthrough

Sign up from Berlin, then sign in from Moscow with the right password and with a wrong one:

```sh
O='Origin: http://localhost:8081'
B='{"identifier":"ada@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Forwarded-For: 203.0.113.7' -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.9' -d "$B"
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.9' -d '{"identifier":"ada@example.com","password":"wrong"}'
```

Both answer `403` with the same body:

```json
{"error":{"code":"auth.geo_blocked","message":"Sign-in is not available from your location."}}
```

Now sign in from New York, seconds after the sign-up in Berlin, and then from Berlin again:

```sh
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.8' -d "$B"
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.7' -d "$B"
```

New York is refused with `403`, Berlin is the same place and signs in:

```json
{"error":{"code":"auth.impossible_travel","message":"This sign-in looks unusual. Try again later or contact support."}}
```

Every refusal is one security event; the log shows them:

```text
WARN auth: security event id=sev_f3db67dcd50228c06cc1aba9 kind=geo.country outcome=blocked op=password.sign-in user="" ip=203.0.113.9 country=RU
WARN auth: security event id=sev_f1b361aa941b3502e9a8eb11 kind=geo.country outcome=blocked op=password.sign-in user="" ip=203.0.113.9 country=RU
ERROR auth: security event id=sev_882f80f69656abb6fbe5d3a6 kind=geo.impossible_travel outcome=blocked op=password.sign-in user=usr_zwtx22n6uq6r7ti2s637gupf ip=203.0.113.8 previous_country=DE distance_km=6385 speed_kmh=234150076 elapsed=0s country=US
```

The impossible-travel check runs after the password was accepted, because it needs the user, so its refusal does tell a caller holding the right password that it is right. `ImpossibleTravelRule{Action: auth.RateLog}` records the journey without refusing, and `auth.RateChallenge` asks the app's rate challenger (a captcha, for example) instead.

## What the tests prove

`main_test.go`, on a clock the test moves: from the denied country the right and the wrong password both get `403 auth.geo_blocked`, while from Berlin the wrong password is `password.invalid_credentials` and the right one signs in, and the two refusals reach a `MemorySecuritySink` as `geo.country` events naming the country and the address; New York an hour after Berlin is `403 auth.impossible_travel` and leaves the session count unchanged, the same sign-in eight hours after Berlin goes through, and the stream holds one `geo.impossible_travel` event with the user, both countries and the elapsed hour. The same rules, and a second factor judged once under the log action, are checked on every engine in [integration/secgeo_test.go](../../integration/secgeo_test.go).
