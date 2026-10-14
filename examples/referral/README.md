# Referrals that pay out on a first purchase

Every user has a referral code. A sign-up that brings one records who referred whom; the app's purchase handler records the `first_purchase` step, which completes the referral, and the referrer is credited once, however many purchases follow.

## Run it

```sh
cd examples
go run ./referral
```

It creates `referral.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./referral`.

## Walkthrough

Alice signs up and reads her code from the dashboard:

```sh
O='Origin: http://localhost:8081'
P='"password":"correct horse battery staple"'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"alice@example.com\",$P,\"name\":\"Alice\"}"
curl -s -b alice.txt localhost:8081/auth/referral/dashboard
```

```json
{"code":"WIDCY3VM","stats":{"total":0,"completed":0,"pending":0,"joinedToday":0}}
```

Bob brings the code in the `Referral-Code` header. Carol's page remembers it first, the way a page does before an OAuth sign-up whose callback carries no header, and her sign-up reads it from the `__Host-auth_referral` cookie. A code that names nobody refuses Dave's sign-up:

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Referral-Code: WIDCY3VM' -d "{\"identifier\":\"bob@example.com\",$P,\"name\":\"Bob\"}"
curl -s -c carol.txt -b carol.txt -X POST localhost:8081/auth/referral/remember -H "$O" -d '{"code":"WIDCY3VM"}'
curl -s -c carol.txt -b carol.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d "{\"identifier\":\"carol@example.com\",$P,\"name\":\"Carol\"}"
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Referral-Code: ZZZZZZZZ' -d "{\"identifier\":\"dave@example.com\",$P,\"name\":\"Dave\"}"
curl -s -b alice.txt localhost:8081/auth/referral/dashboard
```

```json
{"user":{"id":"usr_5atbm7kou77jizlsosyp7xfy","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"ok":true}
{"error":{"code":"referral.invalid_code","message":"This referral code is not valid."}}
{"code":"WIDCY3VM","stats":{"total":2,"completed":0,"pending":2,"joinedToday":2}}
```

(Carol's sign-up answer is left out above.) Bob buys twice. The first purchase completes his referral and credits Alice; the second changes nothing:

```sh
curl -s -b bob.txt -X POST localhost:8081/purchase -H "$O" -d '{"item":"book"}'
curl -s -b bob.txt -X POST localhost:8081/purchase -H "$O" -d '{"item":"pen"}'
curl -s -b alice.txt localhost:8081/credit
```

```json
{"orderId":1,"referralCompleted":true,"referralStatus":"completed"}
{"orderId":2,"referralCompleted":false,"referralStatus":"completed"}
{"cents":1000}
```

Alice's list shows both referrals, newest first, with each one's progress and the referred addresses masked:

```sh
curl -s -b alice.txt localhost:8081/auth/referral/list
```

```json
{"code":"WIDCY3VM","referrals":[{"id":"rfl_s6x6hlbvlgyc2ihtjxg4i7ro","status":"pending","completedAt":null,"createdAt":"2026-10-09T03:10:53.740006Z","progress":{"requiredSteps":["sign_up","first_purchase"],"completedSteps":["sign_up"],"remainingSteps":["first_purchase"],"completed":1,"total":2,"isCompleted":false},"referredUser":{"id":"usr_ctrz74ie5pj2eh23e77hni2s","name":"Carol","email":"c***@example.com"}},{"id":"rfl_56miyovkjeoj67n7qsbyy3gn","status":"completed","completedAt":"2026-10-09T03:10:53.917931Z","createdAt":"2026-10-09T03:10:53.601388Z","progress":{"requiredSteps":["sign_up","first_purchase"],"completedSteps":["sign_up","first_purchase"],"remainingSteps":[],"completed":2,"total":2,"isCompleted":true},"referredUser":{"id":"usr_5atbm7kou77jizlsosyp7xfy","name":"Bob","email":"b***@example.com"}}],"total":2,"limit":20,"offset":0}
```

## The code

- `newApp` wires `referral.Steps(StepFirstPurchase)` and `referral.AfterCompleted(x.reward)`. The plugin is its own module, `github.com/ubgo/auth/plugin/referral`.
- `purchase` records the order, then calls `MarkStep` from Go. A step is the app's statement that a reward was earned, so no route lets a client record one. A buyer nobody referred answers `referral.ErrNotFound`, which the handler ignores.
- `reward` runs once per referral, after the commit of the step that completed it, so adding to the balance there cannot pay twice. It cannot fail the referral either: a failed credit is logged for a retry.

`main_test.go` drives the flow over HTTPS and checks `MarkStep`'s refusals of an unknown step and an unreferred user.

Limits of this example: the credit is a number in the app's table, with no ledger, and `reward` has no retry job behind its log line.

## What this used

- [`plugin/referral`](https://pkg.go.dev/github.com/ubgo/auth/plugin/referral): `New`, `Steps`, `AfterCompleted`, `MarkStep`, `ReferralHeader`, `ErrNotFound`, `Event`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Middleware`, `RequireUser`, `MustUser`
- Guide: [docs/plugins/referral.md](../../docs/plugins/referral.md). Related: [custom-plugin](../custom-plugin) builds a smaller referral plugin of its own, as a lesson in writing plugins.
