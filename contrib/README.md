# Contrib modules

Everything here depends on a third-party module, so each folder is its own Go module. An app downloads gin, Redis or libphonenumber only if it imports the adapter that needs it; the core module `github.com/ubgo/auth` depends on nothing but the standard library and sqlb, and a test fails the build if that changes.

Each folder has a README with its API, options and tests.

## Framework adapters

Every adapter mounts the same operations the core defines and calls them through the same pipeline, so a route served through gin behaves exactly like the net/http one: same rate limits, origin check, cookies and error codes. net/http and chi need no adapter: use [`authhttp`](../authhttp) from the core module.

| Module | Package | For | Gives you |
|---|---|---|---|
| [`contrib/gin`](gin) | `authgin` | gin | `Mount`, `Middleware`, `RequireUser`, `CurrentUser`, `MustUser` |
| [`contrib/echo`](echo) | `authecho` | echo v4 | the same five, for echo |
| [`contrib/fiber`](fiber) | `authfiber` | fiber v3 | the same five, for fiber |
| [`contrib/gqlgen`](gqlgen) | `authgql` | gqlgen | `ErrorPresenter` (stable codes in `extensions.code`), the `@signedIn` directive (`SignedIn`), `Code`, and a schema file; [`gqlgen/example`](gqlgen/example) is a generated server that signs a user in |

## Backends and helpers

| Module | Package | What it adds |
|---|---|---|
| [`contrib/redis`](redis) | `redisrate` | State shared by every instance of an app, in Redis: `New` (a rate store, for `auth.WithRateStore`), `NewSessionStore` (sessions, for `auth.WithSessionStore`) and `NewSessionCache` (a session cache, for `auth.WithSessionCache`) |
| [`contrib/otel`](otel) | `authotel` | OpenTelemetry for every operation: `Tracer` (a span per call and per hook, for `auth.WithTracer`), `Observer` (a call counter by outcome and a duration histogram, for `auth.WithObserver`) and `Options` for both; the standard otel API only |
| [`contrib/phonenumbers`](phonenumbers) | `phonenums` | Phone numbers typed the local way, such as "0412 345 678": `Normalizer(region)` and `Validator()`, plugged into the phone plugin through libphonenumber |
| [`contrib/goth`](goth) | `authgoth` | Any [goth](https://github.com/markbates/goth) provider as an `oauth.Provider`: `Wrap(gothProvider)`, for the OAuth plugin; no PKCE, declared and tested with `oauthtest` |

## Install

```sh
go get github.com/ubgo/auth/contrib/gin      # or echo, fiber, gqlgen
go get github.com/ubgo/auth/contrib/redis
go get github.com/ubgo/auth/contrib/phonenumbers
go get github.com/ubgo/auth/contrib/otel
go get github.com/ubgo/auth/contrib/goth
```

Runnable programs: [examples/gin](../examples/gin), [examples/echo](../examples/echo), [examples/fiber](../examples/fiber), [examples/multi-instance](../examples/multi-instance) and [examples/session-strategies](../examples/session-strategies) for Redis; [`phonenumbers`](phonenumbers)' own README shows it wired into the phone plugin.

## Adding a module

A new adapter or backend goes in its own folder with its own `go.mod` and a `replace github.com/ubgo/auth => ../..` line for development, and is added to the `contrib` task's list in the root `Taskfile.yml`, so `task check` vets and tests it. An adapter reuses `authhttp`'s building blocks (`OperationHandler`, `RequestOf`, `ApplyEffects`, `WriteError`) rather than reimplementing them, so cookies and error answers stay identical across frameworks.
