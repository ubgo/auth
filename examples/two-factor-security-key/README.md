# Two-factor: several factors, and security keys

An email and password app where a user can hold more than one second factor at once (an authenticator app and one or more security keys) and pick one at each sign-in. A security key is a WebAuthn authenticator (a USB or NFC key, or the laptop's Touch ID or Windows Hello) used after the password, never instead of it. The passkey plugin stores and verifies the keys; the two-factor plugin decides which factors a user has, keeps the lockout and the recovery codes, and promotes the session.

## Run it

```sh
cd examples
go run ./two-factor-security-key
```

It creates `two-factor-security-key.db` (SQLite) in the current directory and listens on `http://localhost:8081` (`PORT` changes it). Set `AUTH_SECRET` to at least 32 characters so enrolled factors survive a restart; without it a random secret is used for this run. Open the page in a browser: the WebAuthn ceremonies run there (`navigator.credentials`), so curl can show only the steps around them.

Run the tests with `go test ./two-factor-security-key`.

## Walkthrough

Sign up, then ask which methods exist. With `twofactor.WithSecurityKeys` the list has `security_key`, and `factors` is empty while two-factor is off:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/auth/twofactor/status
```

```json
{"user":{"id":"usr_yfe2dattuzonwwsgzdgdd7il","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"enabled":false,"methods":["totp","security_key"],"trustDevices":false,"factors":[]}
```

`POST /auth/twofactor/security-key/register-begin` answers `{ceremony, options}`; the page passes `options.publicKey` to `navigator.credentials.create` and sends the result to `register-finish`. As the first factor the key turns two-factor on and the answer carries the recovery codes. Adding a key beside an authenticator app needs a current code as `proof`, or the finish is `twofactor.proof_required`. A challenge before any key exists is refused, and so is one without a session:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/security-key/challenge -H 'Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/twofactor/security-key/challenge -H 'Origin: http://localhost:8081'
```

```json
{"error":{"code":"twofactor.not_enrolled","message":"Start two-factor setup first."}}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

At sign-in the password leaves the session pending; `status` lists the factors for the picker, and the user answers with one of them: `{"method":"totp","code":"…"}` or, after `security-key/challenge`, `{"method":"security_key","securityKey":{"ceremony":"…","credential":{…}}}` to `POST /auth/twofactor/verify`.

## What the test proves

`TestSecurityKey_SeveralFactorsPickOne` drives every route through `authhttp.Handler` over HTTPS with a software security key making real P-256 signatures: an authenticator app enrolled the way every existing user enrolled, a key added beside it (refused without proof), sign-in with either factor, and the refusals: a method the user does not have, a forged signature, another user's genuine key, a replayed assertion, and a key removed after its assertion was signed. Removing the last factor turns two-factor off. `TestSecurityKey_KeyIsNotAPasskey` checks that a key registered as a second factor cannot sign in through passkey sign-in.

The full guide is [two-factor › Several factors, and security keys](../../docs/plugins/twofactor.md#several-factors-and-security-keys).
