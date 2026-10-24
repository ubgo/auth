# Magic link: sign in with a mailed link

Passwordless sign-in. A person types their email address, receives a single-use link, and the link signs them in. The first link to a new address creates the account, with the address verified by the click. There is no password to leak, reuse or reset.

## Run it

```sh
cd examples
go run ./magic-link
```

It creates `magic-link.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./magic-link`.

## Walkthrough

Ask for a link. The answer is the same for every address, so it tells nobody which addresses have accounts:

```sh
curl -s -X POST localhost:8081/auth/magiclink/send -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com"}'
```

```json
{"ok":true}
```

The server log shows the mail:

```text
2026/09/29 13:45:05 mail to=alice@example.com subject="Your sign-in link"
Open this link to sign in. It works once, for a few minutes:

http://localhost:8081/magic-link?token=AHrOgFWRw4-3BWQACg7p9ulkIx3E3Sk4sjgoaxwPV6A

If you did not ask for this, ignore this email.
```

Opening the link does not sign in. It serves a page with a button, because mail scanners open every link to preview it, and a GET that signed in would spend the link before its owner clicked:

```sh
curl -s 'localhost:8081/magic-link?token=AHrOgFWRw4-3BWQACg7p9ulkIx3E3Sk4sjgoaxwPV6A' | head -3
```

```html
<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
```

The button POSTs the token from the address bar. That creates the account and sets the session cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/magiclink/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"token":"AHrOgFWRw4-3BWQACg7p9ulkIx3E3Sk4sjgoaxwPV6A"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_taagwwhie3px5yzafkjifi7h","name":"","image":""},"created":true,"secondFactorRequired":false}
{"id":"usr_taagwwhie3px5yzafkjifi7h"}
```

A link works once:

```sh
curl -s -X POST localhost:8081/auth/magiclink/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"token":"AHrOgFWRw4-3BWQACg7p9ulkIx3E3Sk4sjgoaxwPV6A"}'
```

```json
{"error":{"code":"auth.token_invalid","message":"This link or code is not valid any more."}}
```

The next link to the same address signs in to the same account, `"created":false`:

```sh
curl -s -X POST localhost:8081/auth/magiclink/send -H 'Origin: http://localhost:8081' -d '{"identifier":"alice@example.com"}'
curl -s -X POST localhost:8081/auth/magiclink/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"token":"k2aASyyef86FylqLQUlXXfNhW74MlBsHrc0ji5HB-zs"}'
```

```json
{"ok":true}
{"user":{"id":"usr_taagwwhie3px5yzafkjifi7h","name":"","image":""},"created":false,"secondFactorRequired":false}
```

## The code

Email addresses plus magic links, and no password plugin at all. `magiclink.SignUp()` lets a link create an account; without it, a link to an unknown address is simply not sent, and the answer is the same:

```go
auth.WithPlugins(
	email.New(email.Login(), email.Recover(), email.WithMailer(m)),
	magiclink.New(magiclink.SignUp()),
)
```

The link points at `magiclink.DefaultPage` (`/magic-link`) on the base URL; `magiclink.Links(fn)` points it anywhere else. The app serves that page, and its script posts the token:

```js
const token = new URLSearchParams(location.search).get("token");
const res = await fetch("/auth/magiclink/sign-in", {
  method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({token}),
});
```

Links live 15 minutes (`magiclink.WithTTL` changes it). A link signs in only the verified owner of the address: if some other account merely claims the address without having verified it, the click creates a new account (with `SignUp`) instead of entering that one. Sending is limited to 3 links per address in 15 minutes and 20 per IP an hour.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: it opens the link page and checks no cookie was set, signs in, replays the spent link, and signs in again with a new one.

## What this used

- [`plugin/magiclink`](https://pkg.go.dev/github.com/ubgo/auth/plugin/magiclink): `SignUp`, `DefaultPage`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): the identifier kind and the mail delivery
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`
- Related: [phone-only](../phone-only) signs in with an SMS code; [quickstart](../quickstart) uses a password; [passkeys](../passkeys) is the other passwordless option.
