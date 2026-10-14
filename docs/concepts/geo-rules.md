# Geo rules

You will have sign-ins refused (or logged, or challenged) by the country they come from, and a sign-in flagged when it is too far from the user's previous one for any flight to have made the journey, over a GeoIP source you choose. The library ships no GeoIP database and no vendor client; it asks one small interface where an address is.

## Before you start

- [Rate limits](rate-limits.md), Step 5: the same three actions (block, log, challenge) apply here, and a challenge is answered by the same `auth.RateChallenger`.
- [Security events](security-events.md): every geo refusal or record is one event on the stream.
- The example is [`examples/geo-rules`](../../examples/geo-rules/): email and password sign-in, Russia denied, impossible travel at the defaults, over a table of three documentation addresses. `go run ./geo-rules` in `examples/` serves it on `localhost:8081`; `go test ./geo-rules` runs the checks below on a clock the test moves.
- A source of locations: a MaxMind or IP2Location reader in memory, a header your CDN sets, a lookup table. It runs on the sign-in request, so it must be fast and local.
- Everything here is off until `auth.WithGeoLocator` and at least one rule are given.

## Step 1 — Say where an address is

A [`GeoLocator`](ds:block?id=core-geolocator-2nw7kq5x) turns a client address into a [`GeoLocation`](ds:block?id=core-geolocation-6xk3wq8n):

<!-- ds:block id=core-geolocator-2nw7kq5x -->
**GeoLocator** · [`geo.go:52-54`](../../geo.go#L52-L54)

```go
type GeoLocator interface {
	Locate(ctx context.Context, ip netip.Addr) (loc GeoLocation, found bool, err error)
}
```
<!-- /ds:block hash=8d38b2 -->

<!-- ds:block id=core-geolocation-6xk3wq8n -->
**GeoLocation** · [`geo.go:32-41`](../../geo.go#L32-L41)

```go
type GeoLocation struct {
	// Country is the ISO 3166-1 alpha-2 code ("DE"), upper-case, or "" when
	// only coordinates are known.
	Country string
	// Latitude and Longitude are degrees, valid only when HasCoordinates.
	Latitude, Longitude float64
	// HasCoordinates is whether Latitude and Longitude mean anything; a
	// country-only database leaves it false and so cannot judge travel.
	HasCoordinates bool
}
```
<!-- /ds:block hash=dd985c -->

`found` false is an address the source does not know (a private range, a gap in the database); an error is a source that failed (a database that cannot be read). The two are treated differently: an unknown address is refused only under `DenyUnknown`, while a failing source never refuses anyone. The check fails open and logs (`auth: geo locator failed; the sign-in is not judged by country`), because a GeoIP outage must not become a sign-in outage. A country-only database leaves `HasCoordinates` false, which is enough for country rules and not for travel.

The example's locator is a map lookup; a real app wraps its database reader in the same `auth.GeoLocatorFunc`:

<!-- ds:block id=georules-example-locator-6nq2kw8x -->
**locator** · [`examples/geo-rules/main.go:118-121`](../../examples/geo-rules/main.go#L118-L121)

```go
var locator = auth.GeoLocatorFunc(func(_ context.Context, ip netip.Addr) (auth.GeoLocation, bool, error) {
	loc, found := geoTable[ip]
	return loc, found, nil
})
```
<!-- /ds:block hash=c827f9 -->

The address the locator gets is the one the transport resolved for the request. Behind a load balancer that is the balancer's address unless you name it with `authhttp.TrustedProxies` ([net/http, Step 8](../integrations/net-http.md#step-8--run-behind-a-reverse-proxy)); the example trusts a proxy on this machine, which is how its walkthrough pretends to be in three cities with `X-Forwarded-For`.

Check: [`auth.WithGeoLocator`](ds:block?id=opt-withgeolocator-4nz8kw2m) alone fails `auth.New` (`auth.WithGeoLocator needs auth.WithGeoRules or auth.WithImpossibleTravel, or it checks nothing`), and either rule without it fails too.

## Step 2 — Allow or deny countries

[`auth.WithGeoRules`](ds:block?id=opt-withgeorules-8cq3vx5t) takes the [`GeoRules`](ds:block?id=core-georules-9tm4vk2w):

<!-- ds:block id=core-georules-9tm4vk2w -->
**GeoRules** · [`geo.go:69-84`](../../geo.go#L69-L84)

```go
type GeoRules struct {
	// Allow, when not empty, lists the only countries that may sign in (ISO
	// 3166-1 alpha-2, any case). Deny lists countries that may not; a country
	// in both is denied.
	Allow, Deny []string
	// DenyUnknown applies Action to an address the locator does not know
	// (found false). Off by default: private networks, a development machine
	// and gaps in the database would otherwise lock people out. A locator
	// that returns an error is never denied for it: the check fails open and
	// logs, because a GeoIP outage must not be a sign-in outage.
	DenyUnknown bool
	// Action is what a violation does: RateBlock (the default, 403
	// auth.geo_blocked), RateLog (record only) or RateChallenge (the
	// RateChallenger decides, as for a rate rule).
	Action RateAction
}
```
<!-- /ds:block hash=2c78a0 -->

Codes are ISO 3166-1 alpha-2 in any case; `auth.New` upper-cases them and refuses anything that is not two letters, so a typo (`"GER"`) fails at start-up instead of allowing or denying nobody. A rule with no `Allow`, no `Deny` and no `DenyUnknown` is refused for checking nothing.

The rules apply to every operation marked `OpInfo.SignIn` (password and code sign-in, magic links, provider callbacks, passkeys, the second-factor step, and the other sign-in methods), called from the wire. They run in the pipeline after the per-address rate rules and the origin check and before the credentials are read, so a refusal looks the same whether the password was right. A direct Go call is the app's own code and has no client address, so it is not judged, and neither is an operation that is not a sign-in: a sign-up is not marked `SignIn`, so to keep a country from creating accounts, refuse it in an operation hook of your own.

The example denies Russia and turns on impossible travel at the defaults:

<!-- ds:block id=georules-example-options-3vw9qk5n -->
**geoOptions** · [`examples/geo-rules/main.go:133-139`](../../examples/geo-rules/main.go#L133-L139)

```go
func geoOptions() []auth.Option {
	return []auth.Option{
		auth.WithGeoLocator(locator),
		auth.WithGeoRules(auth.GeoRules{Deny: deniedCountries}),
		auth.WithImpossibleTravel(auth.ImpossibleTravelRule{}),
	}
}
```
<!-- /ds:block hash=63681d -->

From Moscow the right and the wrong password get the same answer:

```sh
O='Origin: http://localhost:8081'
B='{"identifier":"ada@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Forwarded-For: 203.0.113.7' -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.9' -d "$B"
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.9' -d '{"identifier":"ada@example.com","password":"wrong"}'
```

```json
{"error":{"code":"auth.geo_blocked","message":"Sign-in is not available from your location."}}
```

<!-- ds:block id=georules-example-test-country-8kq3wn5v lines=1-14 -->
**TestGeoRules_DeniedCountryIsRefusedBeforeThePassword** · [`examples/geo-rules/main_test.go:91-111`](../../examples/geo-rules/main_test.go#L91-L111)

```go
func TestGeoRules_DeniedCountryIsRefusedBeforeThePassword(t *testing.T) {
	e, b, mem, _ := world(t)
	for _, pass := range []string{adaPass, wrongPass} {
		if code := signIn(t, b, moscowIP, pass).Expect(auth.ErrGeoBlocked.Status).ErrorCode(); code != auth.ErrGeoBlocked.Code {
			t.Fatalf("denied country, password %q: %s", pass, code)
		}
	}
	if code := signIn(t, b, berlinIP, wrongPass).Expect(password.ErrInvalidCredentials.Status).ErrorCode(); code != password.ErrInvalidCredentials.Code {
		t.Fatalf("allowed country, wrong password: %s", code)
	}
	signIn(t, b, berlinIP, adaPass).Expect(http.StatusOK)
	got := events(t, e, mem, auth.SecurityGeoCountry)
	if len(got) != 2 {
		t.Fatalf("%d geo.country events, want 2: %+v", len(got), got)
```
<!-- /ds:block hash=03cfe5 -->

Check: from the denied country both passwords answer `403 auth.geo_blocked`; from Berlin the wrong one is `password.invalid_credentials`.

## Step 3 — Catch impossible travel

[`auth.WithImpossibleTravel`](ds:block?id=opt-withimpossibletravel-6km2wq9v) compares each new sign-in's location with the user's previous sign-in and acts when no journey could connect them:

<!-- ds:block id=core-impossibletravelrule-5qk8wn3v -->
**ImpossibleTravelRule** · [`geo.go:91-103`](../../geo.go#L91-L103)

```go
type ImpossibleTravelRule struct {
	// MaxSpeedKmh is the fastest believable journey in km/h; 0 takes
	// DefaultTravelSpeedKmh. A negative or non-finite value is refused.
	MaxSpeedKmh float64
	// MinDistanceKm is the distance below which two locations count as the
	// same place, whatever the time: GeoIP is accurate to tens or hundreds of
	// kilometres, and a carrier's address can resolve to another city. 0 takes
	// DefaultTravelMinDistanceKm.
	MinDistanceKm float64
	// Action is what an impossible journey does: RateBlock (the default, 403
	// auth.impossible_travel), RateLog or RateChallenge.
	Action RateAction
}
```
<!-- /ds:block hash=045495 -->

The distance is the great-circle distance between the two locations; the speed is that distance over the time since the previous sign-in. A sign-in is flagged when the distance is at least `MinDistanceKm` (default 100 km, below typical GeoIP error) and the speed is above `MaxSpeedKmh` (default 900 km/h, a little above an airliner's cruise). A first sign-in, or one where either location has no coordinates or is unknown, is not judged, and a failing locator or history is logged and lets the sign-in through.

This check needs the user, so it runs where the session is created, after the credentials were accepted. Its refusal therefore tells someone holding the right password that the password is right; that is inherent in any risk-based sign-in check, and `auth.RateLog` or `auth.RateChallenge` avoid showing it. A refused sign-in leaves no session. Promoting a pending session after the second factor is not judged again (the sign-in was judged when the pending session was made), and neither is an admin's impersonation or an import.

Sign in from New York seconds after Berlin, then from Berlin again:

```sh
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.8' -d "$B"
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Forwarded-For: 203.0.113.7' -d "$B"
```

New York is refused; Berlin is the same place and signs in:

```json
{"error":{"code":"auth.impossible_travel","message":"This sign-in looks unusual. Try again later or contact support."}}
```

<!-- ds:block id=georules-example-test-travel-4wn8qk2x lines=1-14 -->
**TestGeoRules_ImpossibleTravelIsRefusedAndLeavesNoSession** · [`examples/geo-rules/main_test.go:118-146`](../../examples/geo-rules/main_test.go#L118-L146)

```go
func TestGeoRules_ImpossibleTravelIsRefusedAndLeavesNoSession(t *testing.T) {
	e, b, mem, userID := world(t)
	signIn(t, b, berlinIP, adaPass).Expect(http.StatusOK)
	before := sessions(t, e, userID)

	e.Clock.Advance(tooSoon)
	if code := signIn(t, b, newYorkIP, adaPass).Expect(auth.ErrImpossibleTravel.Status).ErrorCode(); code != auth.ErrImpossibleTravel.Code {
		t.Fatalf("New York an hour after Berlin: %s", code)
	}
	if n := sessions(t, e, userID); n != before {
		t.Fatalf("%d sessions after the refused sign-in, want %d", n, before)
	}

	e.Clock.Advance(longEnough - tooSoon)
```
<!-- /ds:block hash=403105 -->

Check: New York an hour after Berlin is refused and leaves the session count unchanged; the same sign-in eight hours later goes through.

## Step 4 — Choose where the previous sign-in comes from

The previous sign-in is read through a [`SignInHistory`](ds:block?id=core-signinhistory-3wx9qn6k). The default, [`auth.SessionSignInHistory()`](ds:block?id=core-sessionsigninhistory-7hv2xm4q), takes the newest of the user's sessions that carries an address, among the live ones and, under `auth.WithSessionArchive`, the revoked ones; pending, impersonation and API-key sessions are not the user's own sign-ins. A user whose sessions all expired and were swept has no history, so keep the archive for a longer memory.

[`auth.WithTravelHistory(h)`](ds:block?id=opt-withtravelhistory-3xt7nk4w) replaces it, for an app that keeps a login table of its own or runs stateless sessions:

```go
auth.WithTravelHistory(auth.SignInHistoryFunc(func(ctx context.Context, a *auth.Auth, userID string) (auth.PriorSignIn, bool, error) {
	return logins.Last(ctx, userID) // your own table: address and time of the last sign-in
}))
```

Check: `auth.New` refuses `WithImpossibleTravel` under `auth.WithoutIPTracking` (sessions keep no address) and, with the default history, under `auth.WithStatelessSessions` (there is no session list); both messages name `auth.WithTravelHistory` as the way out.

## Step 5 — Block, log or challenge

`GeoRules.Action` and `ImpossibleTravelRule.Action` take the rate rules' actions:

| Action | A violation | Error |
|---|---|---|
| `auth.RateBlock` (also `""`, the default) | Refused | `403 auth.geo_blocked` or `403 auth.impossible_travel` |
| `auth.RateLog` | Goes through and is recorded on the security stream | none |
| `auth.RateChallenge` | Goes through only with a proof the registered `auth.RateChallenger` accepts, else `428 auth.challenge_required` | the challenger's own on a bad proof (`captcha.failed`, `pow.proof_invalid`) |

A challenge needs a challenger: [`plugin/captcha`](../plugins/captcha.md), [`plugin/pow`](../plugins/pow.md) or `auth.WithRateChallenger`; `auth.New` refuses a challenge action without one. One proof serves a call that a rate rule and a geo rule both challenge. A travel challenge outside an operation (a session created from Go) has nobody to ask and refuses like a block.

Every violation, whatever the action, is one [security event](security-events.md): `geo.country` (severity `warn`) or `geo.impossible_travel` (`alert`), with the outcome `blocked`, `logged`, `challenged` or `challenge_passed`:

```text
WARN auth: security event id=sev_f3db67dcd50228c06cc1aba9 kind=geo.country outcome=blocked op=password.sign-in user="" ip=203.0.113.9 country=RU
ERROR auth: security event id=sev_882f80f69656abb6fbe5d3a6 kind=geo.impossible_travel outcome=blocked op=password.sign-in user=usr_zwtx22n6uq6r7ti2s637gupf ip=203.0.113.8 previous_country=DE distance_km=6385 speed_kmh=234150076 elapsed=0s country=US
```

Check: `TestGeoRules_LogAndChallengeActions` in `geo_test.go`: the log action lets the call through with a `logged` event; the challenge action asks for a proof, and a passed one is a `challenge_passed` event at `info`.

## What can go wrong

| Symptom | Cause | Fix |
|---|---|---|
| `auth: … auth.WithGeoRules and auth.WithImpossibleTravel need auth.WithGeoLocator` | A rule without a source | Pass `auth.WithGeoLocator` |
| `auth: … auth.WithGeoRules Deny: "GER" is not an ISO 3166-1 alpha-2 country code` | A three-letter or misspelt code | Use the two-letter code (`DE`) |
| `auth: … auth.WithGeoRules challenges, and no challenger is registered` | `Action: auth.RateChallenge` with no challenger | Register `plugin/captcha` or `plugin/pow`, or pass `auth.WithRateChallenger` |
| Everyone passes the country rule in production | The locator sees the load balancer's address, which it does not know | `authhttp.TrustedProxies` with the balancer's network |
| `auth: geo locator failed; …` in the log, and nobody is refused | The source returned an error; the checks fail open by design | Fix the source; watch for the log line |
| A mobile user is flagged for travel between two nearby cities | A carrier's address resolved far away | Raise `MinDistanceKm`, or use `auth.RateLog` or `auth.RateChallenge` |
| Sign-ups from a denied country still go through | Sign-up is not a sign-in operation and is not judged by country | Refuse it in an operation hook of your own |

## Next

- [Security events](security-events.md): where the geo events go.
- [Rate limits](rate-limits.md): the actions and the challenger.
- [pow](../plugins/pow.md) and [captcha](../plugins/captcha.md): the two challengers the library ships.
- [Sessions](sessions.md): the session list and archive the default history reads.
