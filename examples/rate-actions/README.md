# Ask for a captcha instead of blocking

A rate rule can do three things with a call over its limit: block it (429, the default), let it through and record it, or ask for a captcha. Here password sign-in is limited to three calls a minute per address and the fourth must carry a captcha token, so a person behind a busy office address is asked to prove they are one rather than shut out. The guide is the "Actions" section of [docs/concepts/rate-limits.md](../../docs/concepts/rate-limits.md).

## Run it

```sh
cd examples
go run ./rate-actions
```

It creates `rate-actions.db` (SQLite) and listens on `http://localhost:8081`. The captcha is a fake verifier that accepts the token `human`; a real app passes `captcha.Turnstile` or another provider. Run the tests with `go test ./rate-actions`.

## Walkthrough

Sign up, then sign in four times:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple","name":"Ada"}'
for i in 1 2 3 4; do curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8081/auth/password/sign-in -H "$O" -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'; done
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Captcha-Response: human' -d '{"identifier":"ada@example.com","password":"correct horse battery staple"}'
```

The first three answer 200 and the fourth `428 auth.challenge_required`; the same call with the token goes through:

```json
{"error":{"code":"auth.challenge_required","message":"Complete the challenge and try again."}}
```

## What the tests prove

`main_test.go`: under the limit no token is needed; over it a call without a token is `428`, a rejected token is refused as the captcha refuses it, an accepted token goes through; an empty action still blocks with 429 and `Retry-After`, and a log action never refuses. The same actions are walked on the HTTP path, with the observer, the audit log and the logger checked, in [integration/rateaction_test.go](../../integration/rateaction_test.go).
