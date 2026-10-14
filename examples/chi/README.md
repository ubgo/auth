# The quick start on chi

The [quick start](../quickstart) app, email and password sign-in, served by a [chi](https://github.com/go-chi/chi) router instead of the standard mux. chi routes `http.Handler`s and takes `func(http.Handler) http.Handler` middleware, so the library's own net/http transport is used as it is: nothing is adapted, and the library keeps answering its own routes' misses.

## Run it

```sh
cd examples
go run ./chi
```

It creates `chi.db` (SQLite) in the current directory, creates the tables, and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./chi`.

## Walkthrough

Sign up, then call the app's own route with the session cookie:

```sh
curl -s -c cookies.txt -X POST localhost:8081/auth/password/sign-up -H 'Origin: http://localhost:8081' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"user":{"id":"usr_jhsqe2w4y2espwz5qtvwufad","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"id":"usr_jhsqe2w4y2espwz5qtvwufad","hello":"Alice"}
```

Under the mount the library owns the subtree, so an unknown path and a wrong method get its JSON errors; outside it, chi answers:

```sh
curl -si localhost:8081/auth/nope
curl -si localhost:8081/auth/password/sign-in
curl -si localhost:8081/nope
```

```text
HTTP/1.1 404 Not Found
{"error":{"code":"auth.unknown_operation","message":"Not found."}}
HTTP/1.1 405 Method Not Allowed
Allow: POST
{"error":{"code":"auth.method_not_allowed","message":"This method is not allowed here."}}
HTTP/1.1 404 Not Found
```

The origin check runs inside the operation, so a cross-site POST with the cookie is refused:

```sh
curl -s -b cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: https://evil.example'
```

```json
{"error":{"code":"auth.origin_not_trusted","message":"This request came from a site that is not trusted."}}
```

Sign out, and the route refuses the old cookie:

```sh
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8081/auth/sign-out -H 'Origin: http://localhost:8081'
curl -s -b cookies.txt localhost:8081/me
```

```json
{"ok":true}
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

Only the status line, the `Allow` header and the body are shown above.

## The code

`Mount` hands the library's handler the whole `/auth` subtree; a `Group` carries the two middlewares for the app's routes:

```go
r := chi.NewRouter()
r.Use(middleware.Recoverer)
r.Mount(authPrefix, authhttp.Handler(a, authhttp.Prefix(authPrefix)))
r.Group(func(r chi.Router) {
	r.Use(authhttp.Middleware(a), authhttp.RequireUser)
	r.Get("/me", me)
})
```

`main_test.go` builds the same router behind an `httptest` TLS server and walks sign-up, the protected route, email verification from the recorded mail, sign-out, a wrong password and sign-in again, the refused cross-site POST, and the library's own 404 and 405 under the mount.

## What this used

- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Handler`, `Prefix`, `Middleware`, `RequireUser`, `MustUser`
- [`plugin/email`](https://pkg.go.dev/github.com/ubgo/auth/plugin/email) and [`plugin/password`](https://pkg.go.dev/github.com/ubgo/auth/plugin/password)
- The same app on [net/http](../quickstart), [gin](../gin), [echo](../echo) and [fiber](../fiber); the guide is [docs/integrations/net-http.md](../../docs/integrations/net-http.md).
