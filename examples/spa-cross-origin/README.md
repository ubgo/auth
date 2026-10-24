# The API behind a single-page app on another origin

The [quick start](../quickstart) app as the API of a React, Vue or Svelte app served from somewhere else, here a Vite dev server on `localhost:5173`. The API answers CORS preflights for that origin only, lets it send the session cookie with its requests, and refuses every other origin, so the browser's cookie cannot be used by a page the app did not publish.

## Run it

```sh
cd examples
go run ./spa-cross-origin
```

It creates `spa-cross-origin.db` (SQLite) and listens on `http://localhost:8081`, allowing the frontend at `http://localhost:5173`. Mail is printed to the log. Run the tests with `go test ./spa-cross-origin`.

## Walkthrough

The browser's preflight for the frontend's origin is answered with that origin, credentials allowed, and the headers bearer mode and the session cache use:

```sh
curl -si -X OPTIONS localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:5173' \
  -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type'
```

```text
HTTP/1.1 204 No Content
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: Content-Type, Authorization, Auth-Token-Mode, Auth-Session-Cache
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Origin: http://localhost:5173
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After
Access-Control-Max-Age: 3600
Vary: Origin
```

A sign-up from the frontend (`fetch` with `credentials: "include"`) sets the cookie and is readable; the cookie then authenticates `/me`:

```sh
curl -si -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:5173' \
  -H 'Content-Type: application/json' -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -si -b cookies.txt localhost:8081/me -H 'Origin: http://localhost:5173'
```

```text
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://localhost:5173
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After
Set-Cookie: __Host-auth_session=Xn8j-btGU6UOvY40LhWJ0Zs1MLPBnqCut1F8_l7u7Bc; Path=/; Expires=Thu, 08 Oct 2026 05:17:46 GMT; HttpOnly; Secure; SameSite=Lax

{"user":{"id":"usr_nj5n5bhcrzipa5ptjfa35jaw","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
HTTP/1.1 200 OK
Access-Control-Allow-Credentials: true
Access-Control-Allow-Origin: http://localhost:5173
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After

{"id":"usr_nj5n5bhcrzipa5ptjfa35jaw","hello":"Alice"}
```

A page on another origin gets no CORS headers (its preflight reaches the library, which answers an `OPTIONS` like any unknown method), and a cookie-authenticated POST from it is refused by the core as well:

```sh
curl -si -X OPTIONS localhost:8081/auth/sign-out -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST'
curl -si -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```text
HTTP/1.1 405 Method Not Allowed
HTTP/1.1 403 Forbidden
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

A frontend on another site, where the browser would not send the cookie, asks for a bearer token instead and reads it from an exposed header:

```sh
curl -si -X POST localhost:8081/auth/password/sign-in -H 'Origin: http://localhost:5173' -H 'Auth-Token-Mode: bearer' \
  -H 'Content-Type: application/json' -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```text
HTTP/1.1 200 OK
Access-Control-Expose-Headers: Set-Auth-Token, Set-Auth-Token-Expires, Set-Auth-Session-Cache, Retry-After
Set-Auth-Token: LB3o3hZJSzAMhWYHcnBY8YCOuToTAWn9Ik4tt_QxQAg

{"user":{"id":"usr_nj5n5bhcrzipa5ptjfa35jaw","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

Only the status line, the CORS and auth headers and the body are shown.

## The code

The frontend's origin is trusted by the core, or every cookie-authenticated POST from it would be refused as cross-site, which to the core it is:

```go
auth.WithTrustedOrigins(spaOrigin),
```

The CORS middleware echoes an origin the core trusts, never `*`, and marks the answer readable with credentials; the core's own origin check still runs on every cookie-authenticated POST:

```go
if origin != "" && a.TrustsOrigin(auth.OriginOf(origin)) {
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", strings.Join(corsExposeHeaders, ", "))
	h.Add("Vary", "Origin")
	if r.Method == http.MethodOptions {
		// ... Allow-Methods, Allow-Headers, Max-Age, 204
	}
}
```

Preview deployments come and go while the API runs, so no list at start-up can name them. `auth.WithTrustedOriginFunc(previews.Trusted)` asks a set the deploy pipeline fills (`Add` when a preview of a branch goes up, `Remove` when it is merged), held in memory under a read lock because the core asks on every cookie-authenticated POST:

```go
func (p *previewOrigins) Trusted(origin string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.set[origin]
}
```

`main_test.go` plays the browser on the frontend's origin (preflight, credentialed sign-up, `/me`, sign-out), a hostile origin getting nothing and refused, bearer mode with the exposed header, and a preview origin refused, trusted once added and refused again once removed.

## What this used

- [`auth`](https://pkg.go.dev/github.com/ubgo/auth): `WithTrustedOrigins`, `WithTrustedOriginFunc`, `Auth.TrustsOrigin`, `OriginOf`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Middleware`, `RequireUser`, the header constants
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- The guide is [docs/integrations/spa-frontends.md](../../docs/integrations/spa-frontends.md); bearer mode in full is [mobile-bearer](../mobile-bearer).
