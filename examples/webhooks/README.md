# Send signed webhooks to another service

`plugin/webhook` tells other services, by a signed HTTP POST, whenever a user signs up, signs in or out, changes or is deleted, an identity is added or verified, or a security event fires. This program is both sides at once so it runs on its own: it registers an endpoint pointing at its own `/receiver` route, which verifies every request with `signature.Verify` and prints the event. A real receiver lives in another service and needs only the `signature` package (or any Standard Webhooks library) and the endpoint's secret.

## Run it

```sh
cd examples
export AUTH_SECRET=$(openssl rand -base64 32)
go run ./webhooks
```

It creates `webhooks.db` (SQLite) and listens on `http://localhost:8081` (`PORT` overrides it). Run the tests with `go test ./webhooks`: a real sign-up over the HTTP handler reaches a real local receiver as verified requests; a receiver answering 500 is retried by `auth.Maintain` on the backoff schedule and dead-lettered, then replayed once it is fixed; a 410 disables the endpoint; a rolled-back transaction sends nothing; secret rotation signs with both secrets; the SSRF guard refuses local URLs; and the endpoint secret appears in no log, stored error or returned value.

The wiring, in `main.go`:

- `webhook.New(webhook.AllowPrivateNetworks())`: the receiver is this program on `localhost`, which the SSRF guard refuses by default. Leave the option out in production.
- `auth.WithSecret`: endpoint secrets are sealed at rest under a key derived from it.
- `auth.WithSecuritySink(hooks.SecuritySink(), …)`: forwards the security event stream as `security.*` webhooks.
- A ticker calls `auth.Maintain` every minute, which retries failed deliveries; the library has no scheduler of its own.

## Walkthrough

Sign up:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -H 'Content-Type: application/json' -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
```

The receiver prints one line per verified webhook (ids shortened):

```text
{"data":{"id":"idn_aathvdwjja7h…","isPrimary":false,"kind":"email","userId":"usr_yvb3gc5hhscb…","value":"ada@example.com","verified":false},"id":"msg_ebf509f056a7…","type":"identity.created"}
{"data":{"createdAt":"2026-10-13T12:45:23.478762Z","expiresAt":"2026-10-20T12:45:23.478762Z","id":"ses_nviiwihlqqtb…","ip":"127.0.0.1","userAgent":"curl/8.7.1","userId":"usr_yvb3gc5hhscb…"},"id":"msg_aa8a4b9b68dc…","type":"session.created"}
{"data":{"createdAt":"2026-10-13T12:45:23.478031Z","id":"usr_yvb3gc5hhscb…","image":"","name":"Ada","updatedAt":"2026-10-13T12:45:23.478031Z"},"id":"msg_6ff7665c7b06…","type":"user.created"}
```

A forged request is refused before it is decoded:

```sh
curl -s -X POST localhost:8081/receiver -d '{}'   # bad signature (401)
```

The guide is [docs/plugins/webhook.md](../../docs/plugins/webhook.md).
