# Terms of service: versions and acceptance

Which version of the terms each user accepted, and when. A sign-up form sends the version it showed in a header and the plugin records it with the new user; a user who signed up under older terms is refused the dashboard until they accept the current version through one route.

## Run it

```sh
cd examples
go run ./terms
```

It creates `terms.db` (SQLite) and listens on `http://localhost:8081`. Mail is printed to the log instead of sent. Run the tests with `go test ./terms`.

## Walkthrough

The form asks which version is in force and which header to send it back in:

```sh
curl -s localhost:8081/terms
```

```json
{"version":"2026-09","header":"Terms-Version"}
```

Alice's form showed the current version and sends it with the sign-up. She reaches the dashboard at once:

```sh
O='Origin: http://localhost:8081'
curl -s -c alice.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Terms-Version: 2026-09' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -b alice.txt localhost:8081/dashboard
```

```json
{"user":{"id":"usr_nrmkocl77dsmozgzrgovkydp","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"hello":"Alice"}
```

Bob's form was deployed before the terms changed and still sends `2025-01`. The stale acceptance is not recorded, so the dashboard refuses him, and accepting the stale version is refused too. He accepts the current one and is let in:

```sh
curl -s -c bob.txt -X POST localhost:8081/auth/password/sign-up -H "$O" -H 'Terms-Version: 2025-01' \
  -d '{"identifier":"bob@example.com","password":"correct horse battery staple","name":"Bob"}'
curl -s -b bob.txt localhost:8081/dashboard
curl -s -b bob.txt -X POST localhost:8081/auth/terms/accept -H "$O" -d '{"version":"2025-01"}'
curl -s -b bob.txt -X POST localhost:8081/auth/terms/accept -H "$O" -d '{"version":"2026-09"}'
curl -s -b bob.txt localhost:8081/dashboard
```

```json
{"user":{"id":"usr_vo4z4bgr4zgzoczkrywx7fmm","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"error":{"code":"terms.not_accepted","message":"Accept the current terms to continue."}}
{"error":{"code":"terms.stale_version","message":"The terms changed. Read the current version and accept again."}}
{"ok":true}
{"hello":"Bob"}
```

Signed out, the dashboard is refused before the terms are considered:

```sh
curl -s localhost:8081/dashboard
```

```json
{"error":{"code":"auth.signed_out","message":"Sign in to continue."}}
```

## The code

The plugin takes one option, the current version, and `auth.New` fails without it:

```go
tm := terms.New(terms.Current(currentTerms))
```

The dashboard is guarded by `RequireCurrent`, inside the library's middleware and after `RequireUser`:

```go
mux.Handle("GET /dashboard", authhttp.Middleware(a)(authhttp.RequireUser(tm.RequireCurrent()(http.HandlerFunc(dashboard)))))
```

Acceptance at sign-up is a data hook on user creation inside the plugin: it reads the `Terms-Version` header of the request that created the user, so every sign-up method records it and the sign-up code knows nothing about terms. `tm.Accepted(ctx, userID)` answers from Go; `main_test.go` checks it for both users.

Limits of this example: only the latest acceptance is kept, not a history, and the terms text itself is the app's to serve.

## What this used

- [`plugin/terms`](https://pkg.go.dev/github.com/ubgo/auth/plugin/terms): `New`, `Current`, `TermsHeader`, `RequireCurrent`, `Accepted`, `Version`
- [`authhttp`](https://pkg.go.dev/github.com/ubgo/auth/authhttp): `Middleware`, `RequireUser`, `MustUser`
- Related: [quickstart](../quickstart), [ready-made-pages](../ready-made-pages) (a sign-up page that sets the header from a checkbox).
