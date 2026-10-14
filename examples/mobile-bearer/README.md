# A native app's backend: bearer mode

The [quick start](../quickstart) app as the backend of a phone app. The app cannot keep cookies, so it asks for its session as a bearer token, keeps it in the device's secure storage and sends it in `Authorization`. Its sessions live a year while a browser's live a month, and a sealed copy of the session rides along in a header so a request that presents it costs no session lookup.

## Run it

```sh
cd examples
go run ./mobile-bearer
```

It creates `mobile-bearer.db` (SQLite), listens on `http://localhost:8081`, and prints mail to the log. Set `AUTH_SESSION_KEY` (64 hex characters) to keep the sealing key across restarts; unset, the log says a key was made for this run. Run the tests with `go test ./mobile-bearer`.

## Walkthrough

Sign up as the app does, with `Auth-Token-Mode: bearer`. The session arrives in headers, never as a cookie and never in the body; the expiry is ninety days ahead, the app lifetime:

```sh
curl -si -X POST localhost:8081/auth/password/sign-up -H 'Auth-Token-Mode: bearer' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```text
HTTP/1.1 200 OK
Set-Auth-Token: m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o
Set-Auth-Token-Expires: 2026-12-30T05:17:42Z

{"user":{"id":"usr_u52646iiyonxgopmb4ylxi3x","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The first request with the token is looked up and answers a sealed copy of the session in `Set-Auth-Session-Cache` (959 characters; shortened here). Sent back, the next request costs no lookup and gets no new copy; the copy with another token is worthless:

```sh
curl -si localhost:8081/me -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o'
curl -si localhost:8081/me -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o' -H "Auth-Session-Cache: $SNAPSHOT"
curl -si localhost:8081/me -H 'Authorization: Bearer not-the-token' -H "Auth-Session-Cache: $SNAPSHOT"
```

```text
HTTP/1.1 200 OK
Set-Auth-Session-Cache: LKIRjQfl9H4zX4QyDNOzXYBgoBNCN5PxrRWlm7-zekwWB9WnZLf9MwANbUIuBJ7RBSze-pNRA1xBoGR2YKXSrnOPf1kII99q7DQZoPpP2xB9mTFrXVvvw5OnMH0A1I7RK5ezWEfMMVQmYAu71aS7ywEBUxX2VTfVh-dPkfCUHUpvv4ym2hUZsGcDMgyIXSzkoRuDqfrvJVMrj5d3M6g5gQ9s1HLge7BToxaVIt2J1GMopc2S5l3R5ohhFTd5WJjifl1jbQa4O0e-aDraFpRU2c2SzWBPB_trgKAqbGwXip5EyS2WxsD3PmbMZD4MdPicteojDwDQvAsh969hyXWIwK6V1hFHgNL-9-m1a-fPzIhWK8UFwaY15pRXPv8VhwIt6bdK_6LaFzvsoE9h4vUZVvEDbTozRKbaYgtl_N-Lbl9LqXWiYLSD9HQDidE_h9kAVEtbrQGuyAaV0QCGiEg1k2JTPEFbISSMar1qM27Vh8uxMO6pARhtTLgHsr6zKgkk7o4j5495QLabGqwpEvKpsVGvr5mPFylG506VzEv-CJ9RN4IC7As3TuZo68ovrc8VpP8ObeCI_OH_FLJZKMXANeVN8JBXh1cyo3j-N-b0jo3SBmlueN01d7BM4SldiTSpxKrCIJHQqdV212BnA9rrlZVNirocZtzpVaNaJs_Ms0myjV9Ly60HdAEMsEgScr6BAceLe_gs1VvsvYzW805aGaa9zWfceCDmQAjf7PFfEfa2VN9bqezDLm0y_s-Qkpg11wI8iG8o5faQUf6CyJ3M_B5vdoD2VEIp3Xykrr0L_mGUgYcOrbAxRL_ieLtCSevPeKQxVkjppsqTMwH1k9fgSWgZMQ-bFBB3xMsrdllKqiCiSrtweGrzaIg4hYgupFm9olShqRli_LmQUzhX2fIosdVpy8Bkv7y4X_hSPEAGfaUlVMq0BPpceUZlcfGo_ss

{"id":"usr_u52646iiyonxgopmb4ylxi3x","credential":"bearer","expiresAt":"2026-12-30T05:17:42.857457Z"}
HTTP/1.1 200 OK
{"id":"usr_u52646iiyonxgopmb4ylxi3x","credential":"bearer","expiresAt":"2026-12-30T05:17:42.857457Z"}
HTTP/1.1 401 Unauthorized
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A browser signing in to the same account gets a cookie and the web lifetime, seven days idle:

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
```

```text
HTTP/1.1 200 OK
Set-Cookie: __Host-auth_session=UWueilo6eBQQTCQe4sVox9DfJlJH82u53XR-W5Us3Dw; Path=/; Expires=Thu, 08 Oct 2026 05:17:43 GMT; HttpOnly; Secure; SameSite=Lax

{"id":"usr_u52646iiyonxgopmb4ylxi3x","credential":"cookie","expiresAt":"2026-10-08T05:17:43.26301Z"}
```

A wrong password answers the same JSON as in a browser, and a bearer sign-out needs no `Origin`; afterwards the token is dead:

```sh
curl -si -X POST localhost:8081/auth/password/sign-in -H 'Auth-Token-Mode: bearer' -d '{"identifier":"alice@example.com","password":"wrong"}'
curl -si -X POST localhost:8081/auth/sign-out -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o'
curl -s localhost:8081/me -H 'Authorization: Bearer m7gVGPn9an0pm4yrgJ_pFeEJ_g8l36DLZDzAxTP7V6o'
```

```text
HTTP/1.1 401 Unauthorized
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
HTTP/1.1 200 OK
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Only the status line, the auth headers and the body are shown. The sign-out answer also carried a new `Set-Auth-Session-Cache`, because that request did not send the copy; the app discards it with the token.

## The code

Lifetimes are chosen by how the client presents its token, and the snapshot cache seals the copy the app carries:

```go
webLifetime = auth.SessionLifetime{Idle: 7 * day, Max: 30 * day}
appLifetime = auth.SessionLifetime{Idle: 90 * day, Max: 365 * day}
```

```go
auth.WithSessionPolicy(auth.ByCredential(webLifetime, appLifetime)),
auth.WithSessionCache(auth.NewSnapshotCache(key), cacheTTL),
```

Nothing in the handler is specific to bearer clients; `authhttp` reads whichever credential the request carries. `main_test.go` drives the app's whole life (bearer sign-up, the copy, a stolen copy refused, sign-out without `Origin`), checks that a browser gets the shorter lifetime, and that a malformed `AUTH_SESSION_KEY` is refused.

## What this used

- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): bearer mode (`Auth-Token-Mode`, `Set-Auth-Token`, `Set-Auth-Token-Expires`), the session cache headers (`Auth-Session-Cache`, `Set-Auth-Session-Cache`)
- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithSessionPolicy`, `ByCredential`, `SessionLifetime`, `WithSessionCache`, `NewSnapshotCache`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- The guide is [docs/integrations/mobile-apps.md](../../docs/integrations/mobile-apps.md); every store and cache is in [session-strategies](../session-strategies).
