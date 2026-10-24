# Passkeys: sign in with Face ID, Touch ID or a security key

A user creates an account, adds a passkey, and from then on signs in with it alone: no password and no code. A passkey is a key pair kept by the device (or synced by the platform's password manager); the server stores only the public key, so there is nothing to phish and nothing worth stealing from the database.

## Run it

```sh
cd examples
go run ./passkeys
```

It creates `passkeys.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Open that address in a browser: the page signs you up, adds a passkey and signs in with it. Browsers allow passkeys on `http://localhost`; anywhere else the app must be served over HTTPS. Run the tests with `go test ./passkeys`.

## Walkthrough

A passkey ceremony is two requests around one browser call: `begin` returns options, the page passes them to `navigator.credentials.create` (register) or `.get` (sign in), the device asks for a fingerprint, face or PIN, and `finish` sends the device's answer back. curl can play the two server steps; the middle one needs a browser or a device, so this walkthrough shows the server side for real and the test plays the device.

The page that runs the ceremonies:

```sh
curl -s localhost:8081/ | head -3
```

```html
<!doctype html>
<meta charset="utf-8">
<title>Passkeys</title>
```

Adding a passkey needs an account and a fresh session, so sign up first:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"user":{"id":"usr_775q23ep6kboiqkbi4ix7phq","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Begin registration. `options.publicKey` goes to `navigator.credentials.create`; `ceremony` is a single-use handle that comes back with the answer. The relying party id is `localhost`, the host of the base URL, and user verification (the fingerprint, face or PIN) is required:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/passkey/register-begin -H 'Origin: http://localhost:8081'
```

```json
{"ceremony":"rATOvvJpuZ9wvPBOr_ue2ktK6dSlT1InNlnT4OZlJFQ","options":{"publicKey":{"rp":{"name":"Acme","id":"localhost"},"user":{"name":"usr_775q23ep6kboiqkbi4ix7phq","displayName":"Alice","id":"dXNyXzc3NXEyM2VwNmtib2lxa2JpNGl4N3BocQ"},"challenge":"jjgMr-5m4ub9iFrW9dwsVyqZUCECbBlDojH53k4kXtc","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-8}],"timeout":300000,"authenticatorSelection":{"requireResidentKey":true,"residentKey":"required","userVerification":"required"}}}}
```

Signing in asks for no identifier at all: the device offers the passkeys it holds for this site.

```sh
curl -s -X POST localhost:8081/auth/passkey/login-begin -H 'Origin: http://localhost:8081'
```

```json
{"ceremony":"irYtEo6jCrTted086ZGBUI_fQO5QCDf9_YqnP_sjOpw","options":{"publicKey":{"challenge":"li2qgLi6Dz3ye3gN3yZbC43CuXTzNsCzd9ttE9XS7L8","timeout":300000,"rpId":"localhost","userVerification":"required"}}}
```

A finish with a ceremony the server never began is refused (so is one used twice, or older than five minutes):

```sh
curl -s -X POST localhost:8081/auth/passkey/login-finish -H 'Origin: http://localhost:8081' -d '{"ceremony":"made-up","credential":{}}'
```

```json
{"error":{"code":"passkey.ceremony_invalid","message":"This passkey request has expired. Try again."}}
```

In the browser, the page then shows the passkey `register-finish` stored and, after signing in, the user `login-finish` returned; `GET /auth/passkey/list` lists the user's passkeys for a settings page. Those steps are what `main_test.go` runs, with a software authenticator in place of the device.

## The code

One more plugin. The relying party comes from `auth.WithBaseURL`: its host is the id every passkey is bound to for good (changing the domain strands them; `passkey.RelyingParty` sets it explicitly), and its origin is the only one a ceremony is accepted from.

```go
auth.WithPlugins(
	email.New(email.Login(), email.Recover(), email.WithMailer(m)),
	password.New(),
	passkey.New(passkey.DisplayName(appName)),
)
```

The browser side is a few lines with the WebAuthn JSON helpers of current browsers (older ones need a base64url shim):

```js
const begin = await post("/passkey/register-begin");
const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(begin.options.publicKey)});
return post("/passkey/register-finish", {ceremony: begin.ceremony, credential: cred.toJSON(), name: navigator.platform});
```

`main_test.go` includes a software authenticator: a P-256 key that builds the exact attestation and assertion bytes a browser hands over (CBOR, COSE key, signed client data), so the real WebAuthn verifier checks real ceremonies. The test registers a passkey, finds the ceremony refused a second time, signs out, signs in with the passkey alone, sees it in the list with a last-used time, and has a signature from another key refused with `passkey.invalid`.

Limits worth knowing:

- The page was written against the WebAuthn JSON helpers and exercised through the test's software authenticator, not clicked through in every browser.
- A passkey sign-in is a full session even when the user has [two-factor](../two-factor) on: user verification on the device already makes it two factors.
- The account name the device stores is the user id (the plugin does not know which identifier the app shows), so the chooser relies on the display name: sign up with a name, or the chooser shows the id.
- `POST /auth/passkey/remove` refuses to remove a user's last way in.

## What this used

- [`plugin/passkey`](https://pkg.go.dev/github.com/ubgo/auth/plugin/passkey): `DisplayName`, `RelyingParty`, the register, login, list and remove routes; a separate module, because it brings `go-webauthn`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password) and [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) to create the account
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`
- Related: [magic-link](../magic-link) could create the account instead of a password; [two-factor](../two-factor) is the code-based second factor.
