# KMS sealer: secrets at rest encrypted by a key service

Some of what the library stores must be read back, so it is encrypted rather than hashed: the TOTP secrets and encrypted recovery codes of two-factor sign-in, and the provider tokens the OAuth plugin keeps. By default they are sealed with an AES-256-GCM key ring in the app's memory. An app whose keys must never sit in process memory (Vault transit, AWS KMS, Google Cloud KMS, an HSM) supplies an `auth.Sealer` with `auth.WithSealer`, and every plugin that was given no key of its own seals through it.

The key service here is a fake in the same process, [`kms.go`](kms.go), with the shape of Vault transit: the app sends a plaintext and a context and stores the text it gets back, `kms:v1:…`, where `v1` names the key version so a rotated service knows which key opens it. A real implementation replaces the bodies of `Seal` and `Open` with a call to the service.

## Run it

```sh
cd examples
go run ./kms-sealer
```

It creates `kms-sealer.db` (SQLite) and listens on `http://localhost:8081` (`PORT` moves it). The fake service's keys live only in the process, so factors enrolled in one run do not open in the next; a real service keeps its keys. Run the tests with `go test ./kms-sealer`.

The transcript below was captured with `PORT=18432`, because 8081 was taken on the machine that ran it.

```text
2026/10/09 15:59:04 listening on http://localhost:18432; secrets at rest sealed by the key service
```

## Walkthrough

Sign up and enrol a TOTP factor. The answer carries the secret once, for the authenticator app:

```sh
curl -s -c c.txt -X POST localhost:18432/auth/password/sign-up -H 'Origin: http://localhost:18432' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b c.txt -X POST localhost:18432/auth/twofactor/enroll -H 'Origin: http://localhost:18432'
```

```json
{"user":{"id":"usr_itcwhv2twtqtakxbqbhdaq2f","name":"","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"method":"totp","secret":"O53N75TY2DT2V6JVE7QUTBTBKYIYEDZL","url":"otpauth://totp/Acme:usr_itcwhv2twtqtakxbqbhdaq2f?digits=6&issuer=Acme&period=30&secret=O53N75TY2DT2V6JVE7QUTBTBKYIYEDZL","enabled":false}
```

What the database holds is the key service's text, which nobody with read access to the database can turn back into the secret:

```sh
sqlite3 kms-sealer.db 'select secret_sealed from auth_two_factor'
```

```text
kms:v1:vmKWGXQo4xXoec4v4ZMf5PBSghbvfesUm8LOca3bhCIzpJXTfab8-d9jkVJAEUsr
```

Confirming with the current code from an authenticator app works, because the plugin opens the secret through the same service, and answers the recovery codes:

```sh
curl -s -b c.txt -X POST localhost:18432/auth/twofactor/confirm -H 'Origin: http://localhost:18432' -d '{"code":"968501"}'
```

```text
{"codes":["V5FA-KI4D-TDAB-XN5N","6UAM-DO3B-TI3L-4VAE","4KGT-TGHL-NDF7-RYRU",…
```

## The code

<!-- ds:block id=kmssealer-newauth-6pw3xr9k -->
**newAuth** · [`examples/kms-sealer/main.go:98-109`](main.go#L98-L109)

```go
func newAuth(db *sql.DB, s auth.Sealer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithSealer(s),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(logMail))),
			password.New(),
			twofactor.New(twofactor.Issuer(appName)),
		),
	)
}
```
<!-- /ds:block hash=f3926b -->

The fake service seals under its newest key version and binds the value to the `aad` the plugin passes, which names the row, so a sealed secret copied into another user's row does not open there:

<!-- ds:block id=fakekms-seal-sx8hws4z -->
**fakeKMS.Seal** · [`examples/kms-sealer/kms.go:80-94`](kms.go#L80-L94)

```go
func (k *fakeKMS) Seal(_ context.Context, plain []byte, aad string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.down {
		return "", errKMSUnavailable
	}
	k.seals++
	gcm := k.versions[len(k.versions)-1]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plain, []byte(aad))
	return kmsPrefix + strconv.Itoa(len(k.versions)) + ":" + base64.RawURLEncoding.EncodeToString(out), nil
}
```
<!-- /ds:block hash=017ba6 -->

`main_test.go` runs the same wiring behind an `httptest` TLS server: the stored secret is `kms:v1:…` and holds neither the base32 secret nor its bytes, and a password sign-in completes with the code; after `Rotate`, a new enrolment is sealed `kms:v2:…` while the first user's v1 secret still opens; a secret copied into another user's row fails that user's sign-in (`503 twofactor.secret_unreadable`) instead of opening; during an outage enrolment answers 500 and stores nothing; and the fake answers `auth.ErrSealedCorrupt` for another aad, a foreign value and an unknown version.

## What this used

- [`github.com/ubgo/auth`](https://pkg.go.dev/github.com/ubgo/auth): `Sealer`, `WithSealer`, `ErrSealedCorrupt`
- [`plugin/twofactor`](https://pkg.go.dev/github.com/ubgo/auth/plugin/twofactor): the plugin that seals through it; `twofactor.WithSealer(s)` sets one for this plugin alone, and `oauth.StoreTokensWith(s)` for the OAuth plugin
- Related: [two-factor](../two-factor) seals with a key of its own; the guide is [docs/concepts/security.md](../../docs/concepts/security.md), "Keys in a KMS".
