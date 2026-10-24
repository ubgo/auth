# Phone account: add and verify a number

An email-and-password account gets a phone number: the signed-in user adds it, receives a code by SMS, verifies it, can ask for a new code, and can remove the number. The number does not sign in here; it is a verified contact the app can text.

## Run it

```sh
cd examples
go run ./phone-account
```

It creates `phone-account.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail and texts are printed to the log instead of sent. Run the tests with `go test ./phone-account`.

## Walkthrough

Alice signs up and adds her number. A number needs the country code; any spacing is fine, and it is stored as `+15550100100`. A code is texted the moment the number is added:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"555 0100"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"+1 (555) 010-0100"}'
```

```json
{"user":{"id":"usr_una2t4lzyyu24knmaehvsj75","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"auth.identifier_invalid","message":"This does not look right. Check it and try again."}}
{"ok":true}
```

```text
2026/10/01 10:41:09 sms to=+15550100100 "Your code is 994241. It expires in 5 minutes."
```

Until it is verified the number is not primary, so `/me` shows none; and one number per account:

```sh
curl -s -b alice.txt localhost:8081/me
curl -s -b alice.txt -X POST localhost:8081/auth/phone/add -H "$O" -d '{"phone":"+15550100199"}'
```

```json
{"id":"usr_una2t4lzyyu24knmaehvsj75","phone":"","phoneVerified":false}
{"error":{"code":"phone.has_number","message":"This account already has a phone number. Remove it first."}}
```

A wrong code is refused. A resend issues a new code, and the earlier one stops working:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+15550100100","code":"000000"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/resend -H "$O" -d '{"phone":"+15550100100"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+15550100100","code":"994241"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/verify -H "$O" -d '{"phone":"+15550100100","code":"845969"}'
curl -s -b alice.txt localhost:8081/me
```

```json
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"ok":true}
{"id":"usr_una2t4lzyyu24knmaehvsj75","phone":"+15550100100","phoneVerified":true}
```

```text
2026/10/01 10:41:09 sms to=+15550100100 "Your code is 845969. It expires in 5 minutes."
```

A resend for a verified number texts nothing and is not an error. Remove takes the number away:

```sh
curl -s -b alice.txt -X POST localhost:8081/auth/phone/resend -H "$O" -d '{"phone":"+15550100100"}'
curl -s -b alice.txt -X POST localhost:8081/auth/phone/remove -H "$O" -d '{"phone":"+15550100100"}'
curl -s -b alice.txt localhost:8081/me
sqlite3 phone-account.db "select kind, value, value_raw, verified_at is not null as verified, is_primary from auth_identity order by created_at;"
```

```json
{"ok":true}
{"ok":true}
{"id":"usr_una2t4lzyyu24knmaehvsj75","phone":"","phoneVerified":false}
```

```text
email|alice@example.com|alice@example.com|0|0
```

## The code

The phone plugin with no sign-in option, and a shorter code lifetime, which the text states:

```go
phone.New(phone.WithSMS(sms), phone.WithCodeTTL(codeTTL))
```

There is no phone column on `auth_user`: a number lives in `auth_identity`, so the app's user struct has it as a nested field, filled by a join on kind and primary in the same statement. A user without a verified number gets an empty `phone.Data`, not a missing row:

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

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: add, the unverified number absent from `/me`, the wrong code, verify, the quiet resend, remove; and one number per account, the resend that replaces a code, the malformed number.

## What this used

- [`plugin/phone`](https://pkg.go.dev/github.com/ubgo/auth/plugin/phone): `WithSMS`, `WithCodeTTL`, `Add`, `Verify`, `Resend`, `Remove`, `UserJoin`, `UserBindings`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email), [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password), [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp)
- Guide: [docs/plugins/phone.md](../../docs/plugins/phone.md). Related: [phone-only](../phone-only) signs in with a code alone.
