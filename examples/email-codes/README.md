# Email codes: sign in with a mailed six-digit code

Passwordless sign-in by code. A person types their address, receives a six-digit code, and the code signs them in. The first code to a new address creates the account, with the address verified by the code, and a welcome mail follows. No password plugin is in the list.

## Run it

```sh
cd examples
go run ./email-codes
```

It creates `email-codes.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent, so you copy each code from the log. Run the tests with `go test ./email-codes`.

## Walkthrough

Ask for a code. The address may be typed any way; it is normalized to `alice@example.com`. The answer is the same for every input:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":" Alice@Example.com"}'
```

```json
{"ok":true}
```

The server log shows the mail:

```text
2026/10/01 10:36:27 mail to=alice@example.com subject="Your sign-in code"
Your sign-in code is 962352
```

A wrong code is refused. The right one creates the account and sets the session cookie, and the welcome mail follows:

```sh
curl -s -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"000000"}'
curl -si -c alice.txt -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"962352"}'
curl -s -b alice.txt localhost:8081/me
```

```text
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=OUrvUKzB1HMolH233xwXhYDugmAxzKZrmtVcUclkSVQ; Path=/; Expires=Thu, 08 Oct 2026 05:06:27 GMT; HttpOnly; Secure; SameSite=Lax
Date: Thu, 01 Oct 2026 05:06:27 GMT
Content-Length: 112

{"user":{"id":"usr_3zzpxiiexdjxo5hsxtzh5rkr","name":"","image":""},"created":true,"secondFactorRequired":false}
{"id":"usr_3zzpxiiexdjxo5hsxtzh5rkr","email":"alice@example.com"}
```

```text
2026/10/01 10:36:27 mail to=alice@example.com subject="Welcome"
Your account is ready. You can sign in with this address from now on.
```

A code works once. Sign out, ask for a new code, and sign in again: the same user, `"created":false`, and no second welcome:

```sh
curl -s -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"962352"}'
curl -s -b alice.txt -c alice.txt -X POST localhost:8081/auth/sign-out -H "$O"
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
curl -s -c alice.txt -X POST localhost:8081/auth/email/sign-in-code -H "$O" -d '{"email":"alice@example.com","code":"496761"}'
```

```json
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
{"ok":true}
{"user":{"id":"usr_3zzpxiiexdjxo5hsxtzh5rkr","name":"","image":""},"created":false,"secondFactorRequired":false}
```

A value that is no address gets the same answer and no mail, and the fourth code to one address in 15 minutes is refused:

```sh
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"not an address"}'
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/email/send-code -H "$O" -d '{"email":"alice@example.com"}'
```

```json
{"ok":true}
{"ok":true}
{"error":{"code":"auth.rate_limited","message":"Too many attempts. Wait a moment and try again."}}
```

## The code

One plugin is the whole sign-in story. `SignUpWithCode` is what makes it a sign-in method and lets a code create the account; without a code option `auth.New` returns `auth: no sign-in method; add a plugin such as password or oauth` at start-up (pinned by `TestEmailCodes_WithoutCodesNobodyCanSignIn`). `Welcome` mails each new user once, to the address the code just proved:

```go
email.New(email.Login(), email.Recover(), email.SignUpWithCode(), email.Welcome(), email.WithMailer(m))
```

The verified primary address is copied to `auth_user`, so the app's user struct reads it flat, with no join:

```go
type appUser struct {
	auth.User
	email.EmailColumns
}

func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), email.Bindings(&u.EmailColumns))
}
```

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: created then found, one welcome mail, the wrong code, the reused code, the non-address, and the start-up refusal.

## What this used

- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): `SignUpWithCode`, `Welcome`, `SendCode`, `SignInCode`, `EmailColumns`, `Bindings`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `auth.New`, `a.LoadUser`
- Guide: [docs/plugins/email.md](../../docs/plugins/email.md). Related: [magic-link](../magic-link) signs in with a link instead of a code; [phone-only](../phone-only) does the same by SMS.
