# Phone only: sign in with an SMS code

A consumer app with no email and no password. People type a phone number, receive a six-digit code by SMS, and the code signs them in. The first code creates the account; every later code signs in to the same one.

## Run it

```sh
cd examples
go run ./phone-only
```

It creates `phone-only.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Texts are printed to the log instead of sent. Run the tests with `go test ./phone-only`.

## Walkthrough

Ask for a code. The number may be typed any way a person types it; it is normalized to `+15550100100`. The answer is the same whether or not the number has an account.

```sh
curl -s -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"+1 (555) 010-0100"}'
```

```json
{"ok":true}
```

The server log shows the text:

```text
2026/09/29 13:43:23 sms to=+15550100100 "Your code is 419031. It expires in 10 minutes."
```

A wrong code is refused (each code allows five attempts, then it is spent):

```sh
curl -s -X POST localhost:8081/auth/phone/sign-in -H 'Origin: http://localhost:8081' -d '{"phone":"+15550100100","code":"12345"}'
```

```json
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
```

The right code creates the account, with the number already verified by that code, and sets the session cookie:

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/phone/sign-in -H 'Origin: http://localhost:8081' -d '{"phone":"+15550100100","code":"419031"}'
```

```text
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=kZ_0j6Q-2vPSYDfZIPq2fWkZ5oSo90_U9D3xf5bGRXE; Path=/; Expires=Tue, 06 Oct 2026 08:13:24 GMT; HttpOnly; Secure; SameSite=Lax

{"user":{"id":"usr_vnlifsn6yqpl66kzabzhv5vq","name":"","image":""},"created":true,"secondFactorRequired":false}
```

The app's `/me` loads the user and their number in one query:

```sh
curl -s -b cookies.txt localhost:8081/me
```

```json
{"id":"usr_vnlifsn6yqpl66kzabzhv5vq","phone":"+15550100100","phoneVerified":true}
```

Sign out, ask for a new code, and sign in again: the same user, `"created":false`.

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"+15550100100"}'
curl -s -c cookies.txt -X POST localhost:8081/auth/phone/sign-in -H 'Origin: http://localhost:8081' -d '{"phone":"+15550100100","code":"352973"}'
```

```json
{"ok":true}
{"ok":true}
{"user":{"id":"usr_vnlifsn6yqpl66kzabzhv5vq","name":"","image":""},"created":false,"secondFactorRequired":false}
```

A number outside the countries the app serves is refused before any text is sent:

```sh
curl -s -X POST localhost:8081/auth/phone/send-code -H 'Origin: http://localhost:8081' -d '{"phone":"+49 30 1234567"}'
```

```json
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
```

## The code

One plugin is the whole sign-in story. `SignInWithCode` is what makes it a sign-in method; without it, `auth.New` returns `auth: no sign-in method; add a plugin such as password or oauth` at start-up (pinned by `TestPhoneOnly_WithoutCodesNobodyCanSignIn`):

```go
phone.New(phone.Login(), phone.Recover(), phone.SignInWithCode(), phone.WithSMS(sms), phone.AllowPrefixes(allowedPrefixes...))
```

Every SMS costs money, and attackers trigger floods of codes to premium numbers they own (SMS pumping). The plugin already limits `send-code` to 3 per number in 10 minutes and 20 per IP an hour; `AllowPrefixes("+1", "+44")` refuses every other country, and `phone.LimitRange` caps a whole number range.

There is no phone column on `auth_user`: a number lives in `auth_identity`, so the app's user struct has it as a nested field, filled by a join in the same statement:

```go
type appUser struct {
	auth.User
	Phone phone.Data
}

func (u *appUser) Bindings() []sqlb.Binding {
	return sqlb.Bindings(auth.UserBindings(&u.User), phone.UserBindings(&u.Phone))
}

func (u *appUser) Joins() []sqlb.Join { return []sqlb.Join{phone.UserJoin()} }
```

`a.LoadUser(ctx, id, &u)` then fills both. The normalizer wants numbers in international form (`+` and the country code); for numbers typed without one, see [`contrib/phonenumbers`](https://pkg.go.dev/github.com/ubgo/auth/contrib/phonenumbers).

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: created then found, the wrong code, the refused country, and the start-up refusal.

## What this used

- [`plugin/phone`](https://pkg.go.dev/github.com/ubgo/auth/plugin/phone): `SignInWithCode`, `AllowPrefixes`, `UserJoin`, `UserBindings`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `auth.New`, `a.LoadUser`, `auth.UserBindings`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`, `WriteError`
- Related: [magic-link](../magic-link) signs in with a link instead of a code; [quickstart](../quickstart) is the email and password version.
