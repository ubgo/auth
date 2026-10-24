# Captcha: Turnstile in front of sign-up, sign-in and reset

A Cloudflare Turnstile check before the password operations an anonymous visitor can call. The page solves the widget and sends the token in a header; the plugin asks Cloudflare once and refuses the call before the operation runs when the token is missing or rejected.

## Run it

```sh
cd examples
CAPTCHA_SECRET=0x4AAAAAAA... go run ./captcha
```

`CAPTCHA_SECRET` is the secret key of your Turnstile site. It creates `captcha.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./captcha`; they use a fake siteverify server through `CAPTCHA_SITEVERIFY_URL` and never call Cloudflare.

## Walkthrough

The transcript below was captured against a fake provider (`CAPTCHA_SITEVERIFY_URL=http://localhost:8082`) that accepts the token `token-from-a-solved-widget`; against the real one, the token is what the Turnstile widget hands your page.

Without a token the sign-up is refused before it runs, and nothing is asked of the provider:

```sh
O='Origin: http://localhost:8081'
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"error":{"code":"captcha.missing","message":"Complete the captcha and try again."}}
```

With a token the provider rejects, the answer is one code whatever the reason (expired, used, another site, another action, low score); the reason goes to the log:

```sh
curl -s -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Captcha-Response: token-a-bot-made-up' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
```

```json
{"error":{"code":"captcha.failed","message":"The captcha could not be verified. Try again."}}
```

With a token the provider accepts, Alice is signed up and in. The dashboard needs no captcha: it is a signed-in route, not a protected operation:

```sh
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'X-Captcha-Response: token-from-a-solved-widget' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt localhost:8081/dashboard
```

```json
{"user":{"id":"usr_zgw7ra2tmmtcs3ho6gu2yae5","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"hello":"Alice"}
```

Sign-in and the reset request are guarded the same way:

```sh
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/password/sign-in -H "$O" -H 'X-Captcha-Response: token-from-a-solved-widget' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -X POST localhost:8081/auth/password/forgot -H "$O" -d '{"identifier":"alice@example.com"}'
```

```json
{"error":{"code":"captcha.missing","message":"Complete the captcha and try again."}}
{"user":{"id":"usr_zgw7ra2tmmtcs3ho6gu2yae5","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"captcha.missing","message":"Complete the captcha and try again."}}
```

## The code

The verifier is Turnstile with the widget's action, so a token minted for another widget of the same site is refused; the test swaps the endpoint for a fake:

```go
v := captcha.Turnstile(secret, captcha.WithExpectedAction("auth"))
```

The plugin is one line in the plugin list and guards its default list, narrowed to what is registered: here `password.sign-up`, `password.sign-in`, `password.forgot` and `password.reset`:

```go
auth.WithPlugins(email.New(email.Login(), email.Recover(), email.WithMailer(m)), password.New(), captcha.New(v))
```

`main_test.go` drives the fake provider through every outcome, including a token for another action and the provider being down (`503 captcha.unavailable`: the plugin fails closed).

## What this used

- [`plugin/captcha`](https://pkg.go.dev/github.com/ubgo/auth/plugin/captcha): `New`, `Turnstile`, `WithExpectedAction`, `WithEndpoint`, `TokenHeader`, `ErrMissing`, `ErrFailed`, `ErrUnavailable`
- Related: [quickstart](../quickstart), [password-policies](../password-policies) (the per-account lockout the captcha sits in front of).
