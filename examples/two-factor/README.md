# Two-factor: TOTP codes and recovery codes

An email and password app where a user can turn on a second factor: a six-digit code from an authenticator app (Google Authenticator, 1Password, Authy and the rest). After that, the password alone opens only a pending session that signs nobody in, until the code or a single-use recovery code is given.

## Run it

```sh
cd examples
go run ./two-factor
```

It creates `two-factor.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. TOTP secrets are sealed with AES-256 at rest; set `AUTH_TWO_FACTOR_KEY` to 64 hex characters (`openssl rand -hex 32`) so enrolled factors survive a restart. Without it the program uses a random key for this run and says so:

```text
2026/09/29 13:47:55 WARN AUTH_TWO_FACTOR_KEY is not set: using a random key, so factors enrolled now stop working at the next start
```

Run the tests with `go test ./two-factor`.

## Walkthrough

Sign up as in the [quick start](../quickstart), then start enrolment. The session must be fresh (created in the last few minutes), so a stolen laptop with an old session cannot turn the factor on or off.

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/enroll -H 'Origin: http://localhost:8081'
```

```json
{"user":{"id":"usr_fywmdzbrm35uf46lg5biymrj","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"secret":"HMIX4E2LHAZ4VFBEJDYCG2EPCQVIBWIL","url":"otpauth://totp/Acme:alice@example.com?digits=6&issuer=Acme&period=30&secret=HMIX4E2LHAZ4VFBEJDYCG2EPCQVIBWIL"}
```

Show `url` as a QR code and `secret` as text to type. The factor stays off until the first code proves the app has it. Confirming returns the recovery codes, the only time they are shown (only their hashes are stored):

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/twofactor/confirm -H 'Origin: http://localhost:8081' -d '{"code":"325753"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"codes":["JRRP-QJEK-IWB7-PPLL","SAEO-UQ7E-ULF5-VQOX","FGFK-CSTA-VROW-LOSA","D7B4-CQNB-RAWQ-TALW","6TWJ-F3ZB-5OPK-K7CM","7R6L-CJD2-MLFY-TSV5","6WEQ-O3QM-LKAM-FADJ","LMDG-W3LJ-5HGW-XNBM","73PA-KYJD-XAJY-2TGB","I3HU-5UW5-OSDO-DLKI"]}
{"id":"usr_fywmdzbrm35uf46lg5biymrj","twoFactorEnabled":true}
```

Sign out and sign in with the password. The answer says a second factor is required, and the session it created signs nobody in:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"user":{"id":"usr_fywmdzbrm35uf46lg5biymrj","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

A code works once: the one that confirmed enrolment is refused even inside its 30 seconds, so a code read over someone's shoulder cannot be replayed. The next code is accepted, the pending session is replaced by a full one with a new token, and the app's page opens:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/twofactor/verify -H 'Origin: http://localhost:8081' -d '{"code":"325753"}'
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/twofactor/verify -H 'Origin: http://localhost:8081' -d '{"code":"811988"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
{"ok":true}
{"id":"usr_fywmdzbrm35uf46lg5biymrj","twoFactorEnabled":true}
```

A lost phone: sign in with the password and give a recovery code instead (dashes and case do not matter). It works once:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/twofactor/verify -H 'Origin: http://localhost:8081' -d '{"code":"JRRP-QJEK-IWB7-PPLL"}'
```

```json
{"user":{"id":"usr_fywmdzbrm35uf46lg5biymrj","name":"","image":""},"verificationRequired":false,"secondFactorRequired":true}
{"ok":true}
```

The same recovery code on the next sign-in:

```json
{"error":{"code":"twofactor.code_invalid","message":"This code is not right."}}
```

The codes in this transcript were computed from the secret by a 20-line RFC 6238 program, the same function `main_test.go` uses (`totp`), which is what an authenticator app does.

## The code

One more plugin in the list. The key is required; `auth.New` refuses the plugin without a 32-byte one:

```go
twofactor.New(twofactor.WithEncryptionKey(key), twofactor.Issuer(appName), twofactor.AccountLabel(accountLabel))
```

Nothing else in the app changes. Every sign-in method (password here, but also magic links, OAuth and SMS codes) consults the plugin, and for a user with the factor on it creates a pending session. Only an operation that requires `auth.PendingSecondFactor`, `twofactor.verify` here, can see that session; `RequireUser`, `/auth/session` and every other route treat it as signed out.

`AccountLabel` sets the name the authenticator app shows under the issuer. The plugin does not depend on the email plugin, so the app looks the address up; the callback receives the `*auth.Auth` to do it with:

```go
func accountLabel(ctx context.Context, a *auth.Auth, u auth.User) string {
	ids, err := a.Identities(ctx, u.ID)
	...
		if id.Kind == email.KindEmail {
			return id.Value
		}
```

Whether a user has the factor on is a flat column the plugin adds to `auth_user`, so reading it costs no join:

```go
var cols twofactor.TwoFactorColumns
a.LoadUserColumns(r.Context(), u.ID, twofactor.Bindings(&cols)...)
```

Five wrong codes lock the factor for 15 minutes, from any number of IPs. Turning the factor off (`POST /auth/twofactor/disable`) needs a fresh session and a current code or a recovery code.

`main_test.go` runs the same `newAuth` and `newHandler` behind an `httptest` TLS server: a wrong confirm code, enrolment, the pending session refused by `/me`, verify with the next step's code, a recovery code that works once, and the key rules of `sealKey`.

## What this used

- [`plugin/twofactor`](https://pkg.go.dev/github.com/ubgo/auth/plugin/twofactor): `WithEncryptionKey`, `Issuer`, `AccountLabel`, `TwoFactorColumns`
- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): pending sessions (`auth.PendingSecondFactor`), `a.Identities`, `a.LoadUserColumns`
- [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password) and [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email)
- Related: [quickstart](../quickstart) is this app without the factor; [ready-made-pages](../ready-made-pages) includes the two-factor step as a page; [passkeys](../passkeys) replaces the password and the code with one gesture.
