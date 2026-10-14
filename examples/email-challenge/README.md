# Email challenge: passwordless sign-in that lands in the browser that asked

Passwordless sign-in across devices. A person types their address on a laptop; one mail carries a link and a code. Opening the link on a phone and pressing Confirm signs in the laptop, never the phone; typing the code on the laptop signs it in at once. The first completed challenge creates the account.

## Run it

```sh
cd examples
go run ./email-challenge
```

It creates `email-challenge.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./email-challenge`.

## Walkthrough

The laptop starts a challenge. The answer sets the cookie `__Host-auth_email_challenge`, which holds the poll token; it is the only thing that can complete this challenge:

```sh
O='Origin: http://localhost:8081'
curl -s -c laptop.txt -X POST localhost:8081/auth/emailchallenge/start -H "$O" -H 'User-Agent: Firefox on a laptop' -d '{"identifier":"ada@example.com"}'
```

```json
{"state":"pending","pollToken":"4Vt9-2YZSRbL0zu03mJiIR-wHlFRdBz7FBStCqdBciU","expiresAt":"2026-10-09T04:55:58.957929Z"}
```

The server log shows the mail, with the link, the code, and who asked:

```text
2026/10/09 08:35:24 mail to=ada@example.com subject="Your sign-in request"
To sign in, open this link and confirm:
http://localhost:8081/email-challenge?token=giwgvy5xdIkNOji0rkFZpi_dNMZbGShE2_D6rygnx3Y

Or type this code in the page that asked: 505527

The request came from Firefox on a laptop (127.0.0.1). If you did not ask to sign in, ignore this message.
```

The phone opens the link. The page asks the context route what to show; on another device that changes nothing, so a mail scanner that fetches the link approves nothing. The laptop's poll is still pending:

```sh
curl -s 'localhost:8081/auth/emailchallenge/context?token=giwgvy5xdIkNOji0rkFZpi_dNMZbGShE2_D6rygnx3Y'
curl -s -b laptop.txt -X POST localhost:8081/auth/emailchallenge/poll -H "$O"
```

```json
{"state":"needs-confirmation","identifier":"ada@example.com","ipAddress":"127.0.0.1","userAgent":"Firefox on a laptop","expiresAt":"2026-10-09T03:10:24.87951Z"}
{"state":"pending"}
```

The phone presses Confirm. That approves and signs nobody in; the laptop's next poll completes, creates the account and sets the session cookie on the laptop:

```sh
curl -s -X POST localhost:8081/auth/emailchallenge/approve -H "$O" -d '{"token":"giwgvy5xdIkNOji0rkFZpi_dNMZbGShE2_D6rygnx3Y"}'
curl -si -b laptop.txt -c laptop.txt -X POST localhost:8081/auth/emailchallenge/poll -H "$O"
curl -s -b laptop.txt localhost:8081/me
```

```text
{"state":"approved"}
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: __Host-auth_session=f41UG8mo_ezknf2EzSstlXMYjRNQ9_IVX5XdSsi23ps; Path=/; Expires=Fri, 16 Oct 2026 03:05:25 GMT; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-auth_email_challenge=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
Date: Fri, 09 Oct 2026 03:05:25 GMT
Content-Length: 103

{"state":"completed","user":{"id":"usr_ofbntffetaakxkcx3iuaf7v4","name":"","image":""},"created":true}
{"id":"usr_ofbntffetaakxkcx3iuaf7v4"}
```

The code is the other way to finish. A wrong code is refused; the right one signs in the browser that started; the same code from any other browser is refused, because the code is checked against the poll token's challenge only:

```sh
curl -s -c l2.txt -X POST localhost:8081/auth/emailchallenge/start -H "$O" -d '{"identifier":"ada@example.com"}'
curl -s -b l2.txt -X POST localhost:8081/auth/emailchallenge/verify-otp -H "$O" -d '{"otp":"000000"}'
curl -s -b l2.txt -c l2.txt -X POST localhost:8081/auth/emailchallenge/verify-otp -H "$O" -d '{"otp":"520611"}'
curl -s -X POST localhost:8081/auth/emailchallenge/verify-otp -H "$O" -d '{"otp":"520611"}'
```

```json
{"state":"pending","pollToken":"15UZwXO0TCEhgME5c7fGi5TcYFtge2vFgKPhYprXXtw","expiresAt":"2026-10-09T04:55:58.977647Z"}
{"error":{"code":"auth.code_invalid","message":"This code is not right, or it has expired."}}
{"state":"completed","user":{"id":"usr_ofbntffetaakxkcx3iuaf7v4","name":"","image":""}}
{"error":{"code":"emailchallenge.invalid","message":"This sign-in request is not valid or has expired."}}
```

## The code

Email addresses plus the challenge, and no password plugin at all. `emailchallenge.SignUp()` lets a completed challenge create the account:

```go
auth.WithPlugins(
	email.New(email.Login(), email.Recover(), email.WithMailer(m)),
	emailchallenge.New(emailchallenge.SignUp()),
)
```

The link points at `emailchallenge.DefaultPage` (`/email-challenge`) on the base URL. The app serves that page: it calls `GET /auth/emailchallenge/context?token=…`, shows who asked, and its Confirm button POSTs the token to `/auth/emailchallenge/approve`. The page that started the challenge polls `POST /auth/emailchallenge/poll` every second or two, or posts the typed code to `verify-otp`.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server with two cookie jars, a laptop and a phone: it checks that opening the link approves nothing, that approval gives the phone no session, that the laptop's poll signs it in exactly once, that wrong codes spend a challenge after `DefaultMaxAttempts`, and that a code without the poll token is refused.

## What this used

- [`plugin/emailchallenge`](https://pkg.go.dev/github.com/ubgo/auth/plugin/emailchallenge): `SignUp`, `DefaultPage`, the five routes
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): the identifier kind and the mail delivery
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`
- Related: [magic-link](../magic-link) signs in whichever browser opens the link; [email-codes](../email-codes) signs in with a mailed code only.
