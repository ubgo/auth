# Last sign-in method: remember how the user got in

A user signs in with a password one day and a magic link the next. The app remembers which, and when, so its sign-in page can put the method the person used last in front. Here `/me` just says it.

## Run it

```sh
cd examples
go run ./last-login
```

It creates `last-login.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./last-login`.

## Walkthrough

Sign up with a password. The sign-up starts a session, so it is the first sign-in, and `/me` says so:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_rfnko74ozlcywipmvo6yuwhp","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_rfnko74ozlcywipmvo6yuwhp","lastMethod":"password","lastAt":"2026-10-02T16:20:43.480739Z"}
```

A magic link goes only to a verified address, so open the verify link from the log first, then ask for a link and use it:

```sh
curl -s -X POST localhost:8081/auth/email/verify -H 'Origin: http://localhost:8081' -d '{"token":"8xgMm1FomRJPGRgAfB4mTygngcgiP0ILojVAJD48GDk"}'
curl -s -X POST localhost:8081/auth/magiclink/send -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com"}'
curl -s -c cookies.txt -X POST localhost:8081/auth/magiclink/sign-in -H 'Origin: http://localhost:8081' -d '{"token":"wYAhueFCQDkDcHvlIyFoXSu0iHaWdLtiu2bKV0tDn0U"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"email":"alice@example.com"}
{"ok":true}
{"user":{"id":"usr_rfnko74ozlcywipmvo6yuwhp","name":"","image":""},"created":false,"secondFactorRequired":false}
{"id":"usr_rfnko74ozlcywipmvo6yuwhp","lastMethod":"magiclink","lastAt":"2026-10-02T16:20:45.562417Z"}
```

## The code

Email, passwords, magic links and the record. The plugin value is kept because `/me` reads through it:

```go
ll := lastlogin.New()
a, err := auth.New(
	auth.WithDB(db, sqlb.SQLiteDialect{}),
	auth.WithBaseURL(baseURL),
	auth.WithPlugins(
		email.New(email.Login(), email.Recover(), email.WithMailer(m)),
		password.New(),
		magiclink.New(),
		ll,
	),
)
```

The record is written by a data hook on session creation, which every sign-in method ends with, so a method added later is recorded without knowing the plugin exists. The method is the plugin that ran the operation; `lastlogin.WithResolver` names it differently (the provider rather than `oauth`, say) or answers `""` to leave the record alone. A pending second-factor session records the first factor and the promotion keeps it; an impersonation records nothing.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: it signs up, reads `password` from `/me`, verifies the address, signs in by link and reads `magiclink` with a later time.

## What this used

- [`plugin/lastlogin`](https://pkg.go.dev/github.com/ubgo/auth/plugin/lastlogin): `New`, `Of`, `WithResolver`
- [`plugin/magiclink`](https://pkg.go.dev/github.com/ubgo/auth/plugin/magiclink) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password): the two methods recorded
- Related: [magic-link](../magic-link) is the passwordless method on its own; [plugin-hooks](../plugin-hooks) shows data hooks written by an app.
