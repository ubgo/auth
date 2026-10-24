# Behind a proxy: client IP, error shape, OpenAPI, forms and language

The quick start as it runs in production behind a load balancer. The client's address comes from the proxy's forwarded headers, only when the request really came from the proxy, or from a header an edge function signs. Errors are RFC 9457 `application/problem+json`. The platform gets a health route and an OpenAPI document. Plain HTML forms post without JavaScript, and messages come in the language the visitor picked. Every one of these is an `authhttp` option, and every option is off by default.

## Run it

```sh
cd examples
go run ./behind-proxy
```

It creates `behind-proxy.db` (SQLite), creates the tables, and listens on `http://localhost:8081`. Set `EDGE_SECRET` to believe the signed edge header. Mail is printed to the log instead of sent. Run the tests with `go test ./behind-proxy`; they send requests from a chosen connection address, the way a request through a proxy arrives.

## Walkthrough

The health route and the OpenAPI document are there for the platform:

```sh
curl -s localhost:8081/auth/ok
curl -s localhost:8081/auth/openapi.json | jq -r '.openapi, .info.title, (.paths | length)'
```

```text
{"ok":true}
3.1.0
Example auth API
22
```

An error is a problem document under the library's status, in the language of the `auth_locale` cookie:

```sh
curl -si localhost:8081/me -H 'Cookie: auth_locale=fr'
```

```text
HTTP/1.1 401 Unauthorized
Content-Type: application/problem+json

{"type":"https://example.com/problems/auth.signed_out","title":"Connectez-vous pour continuer.","status":401,"code":"auth.signed_out"}
```

A form-encoded sign-up works, because of `AcceptForms`. The request comes straight from this machine, not from `10.0.0.0/8`, so the `X-Forwarded-For` it carries is ignored, and the session records the connection's address:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -H 'X-Forwarded-For: 192.0.2.66' \
  --data-urlencode identifier=alice@example.com --data-urlencode 'password=correct horse battery staple'
curl -s -b cookies.txt localhost:8081/auth/sessions
```

```json
{"sessions":[{"id":"ses_yljmbeorqwane4zgkty4qhz2","current":true,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:06:15.339288Z","lastSeenAt":"2026-10-09T03:06:15.339288Z"}]}
```

With `EDGE_SECRET=s3cret`, a request whose address is signed by the edge is recorded with that address:

```sh
SIG=$(printf %s 203.0.113.7 | openssl dgst -sha256 -hmac s3cret -hex | awk '{print $NF}')
curl -s -c edge.txt -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:8081' \
  -H 'X-Edge-Client-IP: 203.0.113.7' -H "X-Edge-Signature: $SIG" \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
curl -s -b edge.txt localhost:8081/auth/sessions
```

```json
{"sessions":[{"id":"ses_pnslin3774amt4b3uiay67s4","current":true,"impersonated":false,"ip":"203.0.113.7","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:06:15.473054Z","lastSeenAt":"2026-10-09T03:06:15.473054Z"},{"id":"ses_yljmbeorqwane4zgkty4qhz2","current":false,"impersonated":false,"ip":"127.0.0.1","userAgent":"curl/8.7.1","createdAt":"2026-10-09T03:06:15.339288Z","lastSeenAt":"2026-10-09T03:06:15.339288Z"}]}
```

`SkipTrailingSlash` routes `/auth/sign-out/` as `/auth/sign-out`:

```sh
curl -s -X POST localhost:8081/auth/sign-out/ -b edge.txt -H 'Origin: http://localhost:8081'
```

```json
{"ok":true}
```

## The code

`transportOptions` is the whole deployment, one option per concern. `Handler` and `Middleware` get the same list, because each one reads the client address, the locale and the error shape itself:

```go
authhttp.ClientIPFunc(edgeClientIP(secret)),
authhttp.TrustedProxies(proxyNetwork),
authhttp.ClientIPHeaders(authhttp.HeaderForwarded, forwardedForHeader),
authhttp.EncodeErrors(writeProblem),
authhttp.Health(),
authhttp.OpenAPI(authhttp.OpenAPIInfo{Title: apiTitle, Version: apiVersion, Servers: []string{baseURL}}),
authhttp.AcceptForms(),
authhttp.SkipTrailingSlash(),
authhttp.LocaleCookie(""),
```

`edgeClientIP` returns the edge's address only when its HMAC checks out, compared in constant time. Any other request gets `""`, which is not an address, so `authhttp` falls back to the `TrustedProxies` rule. `writeProblem` shapes only the body. The library has already decided the status, the `Retry-After` header and what the client may learn, and a database failure has already become the generic 500.

`main_test.go` signs up from inside the proxy network with `Forwarded: for=203.0.113.7` and finds that address on the session. It sends the same headers from outside the network and finds the connection's address. It checks that a signed edge header is believed and that a forged one falls back. It also checks the problem body in French, the health route, the OpenAPI paths and a sign-out with a trailing slash.

## What this used

- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `TrustedProxies`, `ClientIPHeaders`, `HeaderForwarded`, `ClientIPFunc`, `EncodeErrors`, `ErrorEncoder`, `Health`, `OpenAPI`, `AcceptForms`, `SkipTrailingSlash`, `LocaleCookie`
- [`i18n`](https://pkg.go.dev/github.com/ubgo/auth/i18n): `Messages`, every shipped translation
- Guide: [net/http, chi and gorilla](../../docs/integrations/net-http.md), Steps 7 to 9.
- Related: [quickstart](../quickstart) is the same app with no options; [spa-cross-origin](../spa-cross-origin) adds a frontend on another origin.
