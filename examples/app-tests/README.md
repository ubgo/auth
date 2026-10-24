# Testing an app with authtest

A small app — email and password sign-in, a phone number as a contact, one protected page — whose tests are written with [`github.com/ubgo/auth/authtest`](../../authtest): the library on SQLite in memory, recorders in place of the mail and SMS senders, a clock the test moves, a signed-in session as a cookie or a Go context, and a browser with a cookie jar over the app's handler. The program is ordinary; `main_test.go` is the recipe.

## Run it

```sh
cd examples
go test ./app-tests
go run ./app-tests
```

The tests need no server and no file: each builds its own in-memory database and leaves nothing behind. The program listens on `http://localhost:8081` and prints mail and texts to the log.

## What the tests show

| Test | What it proves | Harness pieces |
|---|---|---|
| `TestSignUpVerifyAndProtectedPage` | Sign-up sets the cookie, `/me` answers, the verify link's token comes out of the recorded mail, sign-out clears, a wrong password answers `password.invalid_credentials` | `Env.Browser`, `Response.Expect`/`Decode`/`ErrorCode`, `Mailbox.LastToken`, `Browser.Cookie` |
| `TestFixturesAndFreshSession` | A user and a session as fixtures, an SMS code read from the recorder, and a fresh-sign-in refusal after the clock moves past the window | `Env.CreateUser`, `Env.SignIn`, `Browser.SetSession`, `SMSBox.LastCode`, `Clock.Advance` |
| `TestGoAPIWithASessionContext` | The Go API called as the signed-in user, and the effects it recorded | `Session.Context`, `auth.RequestEffects` |

## How the app is shaped for it

`plugins(mailer, sms)` returns the plugin list with the senders as parameters, and `main` passes loggers while the test passes `e.Mail` and `e.SMS`. That one function is the seam: the test wires exactly what production runs, with the recorders in the two places that reach outside the process. The test also swaps the password plugin for one with fast Argon2 parameters, because a test checks behaviour, not hashing cost.

Everything else — opening the database, the base URL, the clock, the rate store, migrating, closing — is the harness's, so a new test is three lines before its first request.
