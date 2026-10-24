# Password lifecycle: reset by code, history, expiry and the spraying guard

The policies a compliance regime asks of passwords, on top of sign-up and sign-in: `forgot` mails a code instead of a link, a change back to one of the last three passwords is refused, a password stops signing in after 90 days and is changed through `change-expired`, and one password that failed on five accounts is refused for everyone.

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) go run ./password-lifecycle
```

It creates `password-lifecycle.db` (SQLite) in the current directory, creates the tables (with `auth_password_history`), and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. `AUTH_SECRET` (at least 32 bytes) keys the spraying guard's counters; without it the program stops at start. Run the tests with `go test ./password-lifecycle`.

## Walkthrough

Sign up and verify the address from the mailed link (recovery codes go only to a verified address). Change the password, then try to change it back:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"first-long-password"}'
curl -s -b alice.txt -X POST localhost:8081/auth/email/verify -H "$O" -d '{"token":"<token from the mail>"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/change -H "$O" -d '{"current":"first-long-password","new":"second-long-password"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/password/change -H "$O" -d '{"current":"second-long-password","new":"first-long-password"}'
```

```json
{"user":{"id":"usr_qujt2ldv6owniofkywnggihr","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"email":"alice@example.com"}
{"ok":true}
{"error":{"code":"password.reused","message":"Choose a password you have not used recently."}}
```

Forgot the password: the mail carries a code, and the code resets once:

```sh
curl -s -X POST localhost:8081/auth/password/forgot -H "$O" -d '{"identifier":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/password/reset-code -H "$O" -d '{"identifier":"alice@example.com","code":"584616","password":"third-long-password"}'
curl -s -X POST localhost:8081/auth/password/reset-code -H "$O" -d '{"identifier":"alice@example.com","code":"584616","password":"fourth-long-password"}'
```

```text
{"status":"check_your_inbox"}
2026/10/09 08:39:20 mail to=alice@example.com subject="Your password reset code"
Your password reset code is 584616.

If you did not ask for this, ignore this email. Your password has not changed.
{"ok":true}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
```

An attacker sprays one common password at five accounts. The sixth try is refused before the password is checked, for every account, for 15 minutes:

```sh
for i in 0 1 2 3 4; do curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d "{\"identifier\":\"user$i@example.com\",\"password\":\"Winter2026!\"}"; done
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"alice@example.com","password":"Winter2026!"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

Expiry cannot be shown live without waiting 90 days. The test moves the clock past `maxPasswordAge` and checks that the right password answers `password.expired` (403), a wrong one still answers `password.invalid_credentials`, `POST /auth/password/change-expired` with the same password answers `password.reused`, and with a new one signs in.

## The code

```go
password.New(
	password.ResetByCode(),
	password.History(historySize),          // 3
	password.ExpireAfter(maxPasswordAge),   // 90 days
	password.GuardCredentialStuffing(password.StuffingPolicy{PasswordFailures: sprayFailures}), // 5
)
```

`auth.WithClock(now)` lets the test age a password; `main` passes `time.Now`. `auth.WithSecret` is required by the spraying guard.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: `TestPasswordLifecycle_HistoryResetAndExpiry` walks one password through change, history, reset by code and expiry, and `TestPasswordLifecycle_SprayedPasswordIsRefused` sprays one password and checks a second user still signs in with their own.

## What this used

- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): `ResetByCode`, `History`, `ExpireAfter`, `GuardCredentialStuffing`, the `reset-code` and `change-expired` routes
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): the address and the mail delivery
- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithSecret`, `WithClock`
- Related: [password-policies](../password-policies) for the rules every new password passes (length, classes, breached passwords).
