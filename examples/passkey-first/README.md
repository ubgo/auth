# Passkey-first: accounts with a passkey and no password

Accounts whose first and only credential is a passkey. Sign-up is one passkey ceremony that creates the user, their address and the passkey together; no password ever exists. The app also accepts security keys that cannot verify the user (no PIN, no biometric), turns one authenticator model away, and asks users who turned on a second factor for it after a key that did not verify them, because such a key proves only that it is present.

## Run it

```sh
cd examples
AUTH_SECRET=$(openssl rand -base64 32) go run ./passkey-first
```

It creates `passkey-first.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Open that page in a browser with a passkey (a phone, a laptop's platform authenticator, a password manager or a security key), type an address and a name, and press "Create account with a passkey". `AUTH_SECRET` (at least 32 bytes) seals the second factor's data. Mail is printed to the log instead of sent. Run the tests with `go test ./passkey-first`.

## Walkthrough

The sign-up starts with the address and the name, and answers the options the browser hands to `navigator.credentials.create`. `userVerification` is `preferred`, so a key without a PIN can register:

```sh
curl -s -X POST localhost:8081/auth/passkey/sign-up-begin -H 'Origin: http://localhost:8081' -d '{"identifier":"ada@example.com","name":"Ada"}'
```

```json
{"ceremony":"O9bRaDVUEgfsqi1516CgYVqnVhdcod6cI832Jt-fCFY","options":{"publicKey":{"rp":{"name":"Acme","id":"localhost"},"user":{"name":"ada@example.com","displayName":"Ada","id":"dXNyX2hmcm90c2ZkY3ltaGRnZTdiY2Vjd3R6aQ"},"challenge":"LW2J3F3o52fqu7JxZfV0eq621Npd3m-oiKmgR05w5_c","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-8}],"timeout":300000,"authenticatorSelection":{"requireResidentKey":true,"residentKey":"required","userVerification":"preferred"},"attestation":"none"}}}
```

The page's script creates the passkey and posts it to `/auth/passkey/sign-up-finish` with the ceremony; that creates the account and signs in. The finish step needs a real authenticator, so the rest of the flow is shown by the tests, which run real ceremonies against a software authenticator.

## The code

```go
passkey.New(
	passkey.DisplayName(appName),
	passkey.WithSignUp(),
	passkey.AuthenticatorSelection(passkey.Selection{UserVerification: passkey.RequirementPreferred}),
	passkey.DenyAuthenticators(deniedModel),
),
twofactor.New(twofactor.DeliveredCodes()),
```

`deniedModel` is a made-up AAGUID standing for a model the product does not support. A deny list steers honest clients; to take only some models (a company's issued keys) use `passkey.AllowAuthenticators` with `passkey.WithMetadata`, which checks the attestation.

`main_test.go` drives a software authenticator (one P-256 key, "none" attestation, user verification on or off, a chosen AAGUID) through the real verifier: `TestPasskeyFirst_SignUpWithAPasskeyAlone` signs up, signs out and signs in with the passkey; `TestPasskeyFirst_DeniedModelIsRefused` gets `passkey.authenticator_not_allowed` from the denied model; `TestPasskeyFirst_KeyWithoutUserVerificationAsksForTheFactor` enrols a mailed second factor and shows that a sign-in with user verification is a full session while one without is pending until the mailed code.

## What this used

- [`plugin/passkey`](https://pkg.go.dev/github.com/ubgo/auth/plugin/passkey): `WithSignUp`, `AuthenticatorSelection`, `DenyAuthenticators`, the `sign-up-begin`, `sign-up-finish`, `login-begin` and `login-finish` routes
- [`plugin/twofactor`](https://pkg.go.dev/github.com/ubgo/auth/plugin/twofactor): `DeliveredCodes`, and the default policy that asks after a single-factor passkey
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email): the address every account has
- Related: [passkeys](../passkeys) adds a passkey to a password account; [two-factor-options](../two-factor-options) for the second factor's other choices.
