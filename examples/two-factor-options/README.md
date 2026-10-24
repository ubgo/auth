# Two-factor options: mailed codes, trusted devices, lockout, step-up and the sign-in policy

Every second-factor choice beyond an authenticator app, in one app: a code mailed at each sign-in for users who will not install an app, "remember this device" for 30 days, a lock after three wrong codes, a step-up check before a sensitive action, and a policy that asks for the factor after every sign-in method, a mailed sign-in code included.

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) go run ./two-factor-options
```

It creates `two-factor-options.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. `AUTH_SECRET` (at least 32 bytes) seals the factor's data; keep it the same across restarts or enrolled factors stop working. Mail is printed to the log instead of sent. Run the tests with `go test ./two-factor-options`.

## Walkthrough

Sign up, verify the address from the mailed link, enrol a mailed code and confirm it with the first code (the answer is the recovery codes, shown this once):

```sh
O='Origin: http://localhost:8081'
curl -s -c a.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b a.txt -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"NbeXesgGdukU1laSpSiJ4gjeI6hbwED9Q2kacrLf14Y"}'
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/enroll -H "$O" -d '{"method":"delivered"}'
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/confirm -H "$O" -d '{"code":"007639"}'
```

```json
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"alice@example.com"}
{"method":"delivered","enabled":false}
{"codes":["G2D2-YSZC-B6FS-ESA5","IRK7-OI3H-A6YF-3MLU","34KS-LEKN-RAFD-U66Q","T7FC-2YVX-UTHR-7QS4","GGYI-NLMQ-PS5D-7RLK","BXVI-TZEH-O55N-QIY7","2GIU-O5EV-JQGU-LCYR","JSJN-7ET3-KDTO-HKS5","6CJC-7EJ4-UOGO-RNKP","D7KK-GBGL-DRY7-OD6S"]}
```

Sign out and in: pending until the mailed code, sent with "remember this device". The next sign-in from this browser skips the step:

```sh
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/sign-out -H "$O"
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/send -H "$O"
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"199135","trustDevice":true}'
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/sign-out -H "$O"
curl -s -b a.txt -c a.txt -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"ok":true}
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"ok":true}
{"ok":true}
{"ok":true}
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

`GET /auth/twofactor/devices` lists the trusted device; `send` then `POST /auth/twofactor/check` with a fresh code is the step-up check, which changes no session. A second browser that signs in with a mailed sign-in code is asked too, and three wrong codes lock the factor, the right code included:

```sh
curl -s -c p.txt -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
curl -s -b p.txt -c p.txt -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"146869"}'
curl -s -b p.txt -c p.txt -X POST localhost:8081/auth/twofactor/send -H "$O"
for i in 1 2 3; do curl -s -b p.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"000000"}'; done
curl -s -b p.txt -X POST localhost:8081/auth/twofactor/verify -H "$O" -d '{"code":"397638"}'
```

```json
{"ok":true}
{"user":{"id":"usr_ausgm32c7dwxdzqs355bi6dv","name":"","image":""},"created":false,"secondFactorRequired":true}
{"ok":true}
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"error":{"code":"twofactor.locked","message":"Too many wrong codes. Wait and try again."}}
```

## The code

```go
twofactor.New(
	twofactor.DeliveredCodes(),
	twofactor.TrustDevices(trustAge),          // 30 days
	twofactor.Lockout(maxWrongCodes, lockFor), // 3 wrong codes, 15 minutes
	twofactor.WithPolicy(signInPolicy),        // ask after every sign-in method
)
```

`signInPolicy` calls `twofactor.AskEverySignIn`; it is the place to add the app's own rule (always ask an admin, skip on the office network) and hand the rest to `twofactor.DefaultPolicy`.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: mailed code and trusted device (and that a second browser is still asked), the policy after a mailed sign-in code (and `DefaultPolicy`'s answers for that sign-in and for a passkey that did not verify the user), the lockout, and the step-up check.

## What this used

- [`plugin/twofactor`](https://pkg.go.dev/github.com/ubgo/auth/plugin/twofactor): `DeliveredCodes`, `TrustDevices`, `Lockout`, `WithPolicy`, `AskEverySignIn`, `DefaultPolicy`, the `send`, `verify`, `check` and `devices` routes
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): the channel the codes go to, and `SignInWithCode`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): the first factor
- Related: [two-factor](../two-factor) for the authenticator app and recovery codes; [passkey-first](../passkey-first) for the passkey that did not verify the user.
