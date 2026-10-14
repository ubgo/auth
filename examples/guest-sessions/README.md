# Guest sessions: a cart before the account

A visitor fills a cart before they have an account. A guest session holds it; the moment the guest signs up, the cart moves to the real account in the same transaction and the guest row is deleted. Nothing in the cart code knows about guests: a guest is a user.

## Run it

```sh
cd examples
go run ./guest-sessions
```

It creates `guest-sessions.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./guest-sessions`.

## Walkthrough

The cart needs a signed-in user, and a visitor has none:

```sh
curl -s -i localhost:8081/cart | head -1
```

```text
HTTP/1.1 401 Unauthorized
```

A guest session takes one request and no identifier. The answer is a user like any other, named `Guest`, and the session cookie is set:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/anonymous/sign-in -H 'Origin: http://localhost:8081' -d '{}'
```

```json
{"user":{"id":"usr_jvptwzit6fqupar25t5yklu5","name":"Guest","image":""}}
```

The cart works for the guest, because the cart handler asks only for a signed-in user:

```sh
curl -s -b cookies.txt -X POST localhost:8081/cart -H 'Origin: http://localhost:8081' -d '{"item":"lamp"}'
curl -s -b cookies.txt -X POST localhost:8081/cart -H 'Origin: http://localhost:8081' -d '{"item":"chair"}'
```

```json
{"userId":"usr_jvptwzit6fqupar25t5yklu5","items":["lamp"]}
{"userId":"usr_jvptwzit6fqupar25t5yklu5","items":["lamp","chair"]}
```

A guest asking for another guest session is refused, so a page that reloads cannot pile up guest rows:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/anonymous/sign-in -H 'Origin: http://localhost:8081' -d '{}'
```

```json
{"error":{"code":"anonymous.already","message":"You already have a guest session."}}
```

The guest signs up. The sign-up runs with the guest's cookie, so the plugin sees a guest becoming an account: it calls the app's `OnLink` hook (which moves the cart rows), deletes the guest, and the new session replaces the cookie:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/cart
```

```json
{"user":{"id":"usr_uaheceq3wu6wxfh4hsayj2sd","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"userId":"usr_uaheceq3wu6wxfh4hsayj2sd","items":["lamp","chair"]}
```

The same happens for a guest who signs in to an existing account with a password, a magic link, a code, a provider or a passkey: every sign-in method ends by creating a session, and that is where the link runs.

## The code

Email, passwords and the anonymous plugin, with the one line the app adds:

```go
auth.WithPlugins(
	email.New(email.Login(), email.Recover(), email.WithMailer(m)),
	password.New(),
	anonymous.New(anonymous.OnLink(moveCart)),
)
```

The hook runs inside the sign-in's transaction, through `tx`, right before the guest row is deleted; an error fails the sign-in and leaves the guest as it was:

```go
func moveCart(ctx context.Context, tx sqlb.DBTX, guest, user auth.User) error {
	_, err := tx.ExecContext(ctx, "UPDATE app_cart_item SET user_id = ? WHERE user_id = ?", user.ID, guest.ID)
	return err
}
```

The cart table holds a user id with no foreign key, like any app table under this library, and the app's `User.BeforeDelete` hook deletes a user's cart with the user. That is why the move runs first: a guest deleted without one would take the cart with it. `anonymous.KeepUsers()` keeps guest rows instead; `anonymous.SweepStale()` lets `a.Sweep` delete guests who never signed up once their sessions have expired.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: it starts a guest, fills the cart, is refused a second guest session, signs up, and checks the cart belongs to the account and the guest row is gone.

## What this used

- [`plugin/anonymous`](https://pkg.go.dev/github.com/ubgo/auth/plugin/anonymous): `OnLink`, `ErrAlreadyAnonymous`, `DefaultName`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password) and [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): the account the guest becomes
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`, `MustUser`
- Related: [quickstart](../quickstart) is the same app without guests; [plugin-tables](../plugin-tables) shows app tables that reference users.
