# Choose a transport

This guide answers one question: how does your app reach the library? Every feature is one typed operation (`auth.Define`), and every entry point (a Go call, the net/http handler, the gin, echo and fiber adapters, a GraphQL resolver) runs that same operation through the same pipeline, so the choice below changes how requests arrive, never which rules apply. Rate limits, hooks, the origin check and uniform answers hold on every path. The pipeline itself is explained in [Plugins and the pipeline](../concepts/plugins-and-pipeline.md#step-3--know-the-pipeline-order).

## The decision table

| Your app is built on | Use | Why | Guide | Example |
|---|---|---|---|---|
| `net/http`, `http.ServeMux`, gorilla | `authhttp.Handler` and `authhttp.Middleware` | In the core module, standard library only; every adapter below is built from it | [net/http](../integrations/net-http.md#step-1--mount-the-handler) | [quickstart](../../examples/quickstart/) |
| chi | `authhttp` as it is | chi routes are `http.Handler`s, so no adapter is needed | [net/http](../integrations/net-http.md#step-1--mount-the-handler) | [chi](../../examples/chi/) |
| gin | `contrib/gin` (`authgin.Mount`, `Middleware`, `RequireUser`, `CurrentUser`) | Mounts the routes on a gin group and gives gin handlers the user; its own module, so gin never reaches an app that does not use it | [gin](../integrations/gin.md#step-1--mount-the-routes-on-a-group) | [gin](../../examples/gin/) |
| echo | `contrib/echo` (`authecho.Mount`, …) | The same shape for echo | [echo](../integrations/echo.md#step-1--mount-the-routes-on-a-group) | [echo](../../examples/echo/) |
| fiber v3 | `contrib/fiber` (`authfiber.Mount`, …) | The same shape for fiber's own request type | [fiber](../integrations/fiber.md#step-1--mount-the-routes-on-a-group) | [fiber](../../examples/fiber/) |
| GraphQL with gqlgen | `contrib/gqlgen` behind `authhttp.Middleware` | Resolvers call the plugins' typed Go API; errors keep their codes in `extensions.code`; a `@signedIn` directive guards fields | [GraphQL](../integrations/graphql.md#step-2--wire-the-server-behind-authhttpmiddleware) | [gqlgen](../../contrib/gqlgen/example/) |
| No HTTP at all: a job, a CLI, an admin script, your own RPC | The Go API: each plugin's methods and `Op.Call` | The same operation with no transport; nothing is skipped | [Call operations from Go](../concepts/plugins-and-pipeline.md#step-4--call-operations-from-go) | [saas-workspace](../../examples/saas-workspace/) |
| You want sign-in pages without writing any UI | `authui.Handler` beside `authhttp.Handler` | Server-rendered pages that follow your plugin list; replaceable templates and texts | [ready-made pages](../integrations/ready-made-pages.md#step-1--mount-the-pages-at-the-root) | [ready-made-pages](../../examples/ready-made-pages/), [custom-pages](../../examples/custom-pages/) |
| Only "who is this" for an internal tool, with no database | `authgate` | A provider sign-in kept in a sealed cookie; no `auth.New`, no tables | [login gate](../integrations/login-gate.md#when-to-use-it-and-when-not-to) | [login-gate](../../examples/login-gate/) |
| A single-page app on another origin | `authhttp` plus CORS for that origin | The origin check replaces CSRF tokens; only the origins you trust may post | [SPA frontends](../integrations/spa-frontends.md#step-1--decide-same-site-or-another-one) | [spa-cross-origin](../../examples/spa-cross-origin/) |
| A native app, a CLI or a desktop app | `authhttp` in bearer mode | The token travels in a header instead of a cookie | [mobile apps](../integrations/mobile-apps.md#step-1--ask-for-the-token-as-a-bearer) | [mobile-bearer](../../examples/mobile-bearer/) |

These combine: one app can mount `authhttp.Handler` for its JSON routes, `authui.Handler` for its pages, a gqlgen server behind `authhttp.Middleware`, and call the Go API from a background job, all over one `*auth.Auth`.

## If X, then Y

- If your router accepts an `http.Handler`, use `authhttp` directly; an adapter exists only where the framework has its own handler type (gin, echo, fiber).
- If you use an adapter, pass the same `authhttp` options (`CookieDomain`, `Logger`, `EncodeErrors`, `TrustedProxies`) to `Mount` and to `Middleware`: each reads the request itself, so options given to one only change that one. Building the option list once, as [behind-proxy](../../examples/behind-proxy/) does, avoids the mismatch.
- If you serve GraphQL, put the GraphQL handler inside `authhttp.Middleware`: the middleware is what turns a sign-in's recorded effects into a cookie.
- If you want pages but your own look, start from `authui` and replace its templates and texts ([Step 6](../integrations/ready-made-pages.md#step-6--make-the-pages-yours)) rather than writing the forms; the pages already carry the origin check that stops login CSRF.
- If you need users, sessions you can revoke per device, passwords or second factors, use `auth.New`, not `authgate`: the gate has none of them by design.
- If the app sits behind a load balancer, name it with `authhttp.TrustedProxies` ([Step 8](../integrations/net-http.md#step-8--run-behind-a-reverse-proxy)), or every session shows the balancer's address and one office shares one rate limit.
- If your API clients want errors in another shape (RFC 9457 problem details, say), pass `authhttp.EncodeErrors` ([Step 7](../integrations/net-http.md#step-7--know-the-error-json)); status codes and `Retry-After` stay the library's.

## Pitfalls

- A cookie set from your handler never arrives: the handler wrote the body before calling the operation, and effects recorded after the first byte cannot become headers. Call the operation first. A streamed GraphQL response has the same problem, so sign in over a plain POST.
- `auth.origin_not_trusted` (403) on a POST from your own frontend: its origin is neither `auth.WithBaseURL`'s nor one of `auth.WithTrustedOrigins`. curl sends no `Origin` unless told to.
- Signed out right after signing in over plain HTTP: the session cookie is `Secure`, which browsers relax only for `localhost`. Serve HTTPS everywhere else.
- `auth.internal` (500) from a route behind `Middleware`: the session lookup failed (a database that is down). Every transport refuses to run the handler as if nobody were signed in; the detail is in the log.
- `panic: … MustUser called on a request without a user`: `MustUser` on a route with no `RequireUser` in front. Add the guard, or use `CurrentUser`.
- gin answers an unknown method with 404 unless `HandleMethodNotAllowed` is set; the adapter's example sets it.
- gqlgen `@signedIn` fields refuse a signed-in user: the directive was not wired in `graph.Config`, so no check ran.

## Next

- [Choose sign-in methods](sign-in-methods.md)
- [Choose a session strategy](sessions.md)
- [Choose by kind of app](app-types.md)
