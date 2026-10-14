# Device login: a CLI signs in with a code

A CLI, a TV app or anything without a browser signs in with the device authorization grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)), the Go version of better-auth's `npx auth login` demo. The CLI asks the web app for a code, prints it with the page to open, and polls. The person opens that page on a phone or laptop, signs in there however the web app allows, and approves the code. The CLI's next poll gets a session of that person, which it then sends as a bearer token. The server side is the [deviceauth plugin](../../plugin/deviceauth); the CLI side is its `deviceauth.Client`, standard library only.

## Run it

Two processes. The web app:

```sh
cd examples
go run ./device-login
```

It creates `device-login.db` (SQLite), creates the tables and listens on `http://localhost:8081`; mail is printed to the log. Sign up once with curl (below). Then the CLI, in a second terminal:

```sh
go run ./device-login -login
```

It prints the code and the page, polls every 5 seconds until the code is approved or denied, and prints who it is signed in as. Run the tests with `go test ./device-login`.

## Walkthrough

Sign up on the web app, as a browser with a cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' -H 'Content-Type: application/json' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery","name":"Alice"}'
```

```text
{"user":{"id":"usr_edhj3cnxyzsfcemqyvolw3le","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Start the CLI. It prints:

```text
open http://localhost:8081/device and enter the code EKYS5XWU
(or open http://localhost:8081/device?user_code=EKYS5XWU)
waiting for approval...
```

A real app serves its approval page at `/device` (the plugin's default verification URI). That page makes two calls, shown here with curl as the signed-in browser. The lookup claims the code for the signed-in person, and only that person sees which client asked:

```sh
curl -s -b cookies.txt 'localhost:8081/auth/device/verify?user_code=EKYS5XWU'
```

```text
{"user_code":"EKYS5XWU","status":"pending","client_id":"example-cli","owned":true}
```

The approval is a cookie-authenticated POST, so it carries the app's `Origin`:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/device/approve -H 'Origin: http://localhost:8081' -H 'Content-Type: application/json' -d '{"userCode":"EKYS5XWU"}'
```

```text
{"success":true}
```

The CLI's next poll gets the session, and `/me` answers it as a bearer credential:

```text
signed in as usr_edhj3cnxyzsfcemqyvolw3le (Alice), /me answered with credential "bearer"
```

`POST /auth/device/deny` instead ends the CLI with `deviceauth: access_denied`. A client id the app does not accept gets no code:

```sh
curl -s -X POST localhost:8081/auth/device/code -d client_id=someone-else
```

```text
{"error":"invalid_client","error_description":"The client is not allowed to use device authorization.","auth_error":{"code":"device.invalid_client","message":"The client is not allowed to use device authorization."}}
```

## The code

The web app accepts one client and mounts the plugin's RFC handlers on the two endpoints the CLI calls, so the errors come back in the RFC's shape (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`) that any device client understands:

```go
dp := deviceauth.New(
	deviceauth.ValidateClient(func(_ context.Context, id string) (bool, error) { return id == clientID, nil }),
)
...
mux.Handle("POST "+codePath, dp.CodeHandler())
mux.Handle("POST "+tokenPath, dp.TokenHandler())
mux.Handle(authPrefix+"/", authhttp.Handler(a, authhttp.Prefix(authPrefix)))
```

The CLI is `deviceauth.Client`: `RequestCode` gets the code to show, and `Poll` waits the interval, keeps going on `authorization_pending`, adds 5 seconds on `slow_down`, and ends with the token or a `*deviceauth.ClientError` (its `ErrorName` is the RFC error):

```go
c := &deviceauth.Client{CodeURL: server + codePath, TokenURL: server + tokenPath, ClientID: clientID}
code, err := c.RequestCode(ctx, "")
// print code.UserCode and code.VerificationURI
tok, err := c.Poll(ctx, code)
// tok.AccessToken is the session; send it as "Authorization: Bearer …"
```

The token is a session of the person who approved, with the same lifetime and revocation as a browser session: signing out everywhere ends it too. The new session skips the second factor, because the approving session already passed it.

## Tests

`main_test.go` runs the web app on a TLS test server and drives both sides: the CLI's wait before its first poll is where the test's browser looks the code up and approves (or denies) it. It covers an approval that signs the CLI in and reaches `/me` as a bearer credential, a denial that ends with `access_denied`, an unknown client refused with `invalid_client`, and `/me` refusing a bad token.
