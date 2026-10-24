# Email verify code: verify an address with a typed code

An email-and-password app whose verify mail carries a six-digit code instead of a link: the person types the code into the app. Changing the address works the same way, with a code mailed to the new address. A code suits a mobile app, where a link would open the browser, and survives mail scanners, which open every link. It is one option, `email.VerifyByCode()`.

## Run it

```sh
cd examples
go run ./email-verify-code
```

It creates `email-verify-code.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./email-verify-code`.

## Walkthrough

Alice signs up. The verify mail has a code and no link, and `/me` shows no address until it is verified, because only a verified primary address is copied onto `auth_user`:

```sh
O='Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_5l66tgytup77osqo3w5nzhsq","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_5l66tgytup77osqo3w5nzhsq","email":""}
```

```text
2026/10/09 15:50:05 mail to=alice@example.com subject="Your verification code"
Your verification code is 704074.

If you did not ask for this, ignore this email.
```

A wrong code is refused; the right one verifies the address:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/email/verify-code -H "$O" -d '{"email":"alice@example.com","code":"000000"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/email/verify-code -H "$O" -d '{"email":"alice@example.com","code":"704074"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"email":"alice@example.com"}
{"id":"usr_5l66tgytup77osqo3w5nzhsq","email":"alice@example.com"}
```

The route also works signed out, for the address as typed, so the person can type the code on another device. An unknown address answers exactly as a wrong code, so the route tells nobody which addresses have accounts.

Alice changes her address. `change` needs a fresh sign-in and mails a code to the new address; nothing changes until the signed-in user confirms it:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/email/change -H "$O" -d '{"email":"alice@work.example"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/email/confirm-change-code -H "$O" -d '{"email":"alice@work.example","code":"328327"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"email":"alice@work.example"}
{"id":"usr_5l66tgytup77osqo3w5nzhsq","email":"alice@work.example"}
```

The old address then gets "Your email address was changed" with an undo link, not a code: its reader may be anywhere, and the link must work after the sessions it ends are gone.

## The code

The one option, with a shorter code lifetime and a guess limit:

```go
email.New(
	email.Login(), email.Recover(),
	email.VerifyByCode(), // POST /auth/email/verify-code and confirm-change-code
	email.WithCodeTTL(codeTTL), email.WithMaxAttempts(maxAttempts),
	email.WithMailer(m),
),
```

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: the mail has no link, the wrong code, verify, change and confirm by code, the undo link to the old address; verifying signed out, the unknown address that answers as a wrong code; and `maxAttempts` wrong guesses that spend the code so the right one is refused.

## What this used

- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): `VerifyByCode`, `WithCodeTTL`, `WithMaxAttempts`, `VerifyCode`, `ConfirmChangeCode`, `EmailColumns`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp)
- Guide: [docs/plugins/email.md](../../docs/plugins/email.md#codes-instead-of-links). Related: [email-codes](../email-codes) signs in with a mailed code.
