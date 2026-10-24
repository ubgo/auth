# github.com/ubgo/auth/contrib/otel

OpenTelemetry spans and metrics for every auth operation: one span per call and per hook, a counter of calls by outcome and a duration histogram. The core knows nothing about OpenTelemetry; it describes spans through `auth.Tracer` and call endings through `auth.Observer`, and this package gives them their OpenTelemetry shape.

## Install

```sh
go get github.com/ubgo/auth/contrib/otel
```

Its own module, so the OpenTelemetry API reaches only the apps that use it. The package name is `authotel`. It needs the API only (`go.opentelemetry.io/otel`); the SDK and exporters are the app's choice.

## Wire it

```go
import authotel "github.com/ubgo/auth/contrib/otel"

opts, err := authotel.Options(otel.GetTracerProvider(), otel.GetMeterProvider())
if err != nil {
	log.Fatal(err)
}
a, err := auth.New(append(opts, auth.WithDB(db, dialect), auth.WithBaseURL(baseURL), auth.WithPlugins(/* … */))...)
```

`Options` is `auth.WithTracer(authotel.Tracer(tp))` and `auth.WithObserver(authotel.Observer(mp))`; pass `nil` for the provider you do not have. Wrap `authhttp.Handler` with `otelhttp.NewHandler` so each operation span is a child of the request's, The core already adds one `auth.db` span per statement it or a plugin runs through `Exec`, `One` or `Each` (the database row below), without the SQL; open the database through an instrumented driver (`otelsql`) as well if you want driver-level spans that carry the statement text, or that cover your own queries.

## What is recorded

| Span | Name | Attributes |
|---|---|---|
| operation | `auth.operation <id>` (`auth.operation core.session`) | `auth.operation`, `auth.plugin`, `auth.transport` |
| hook | `auth.hook <before\|after> <id> <plugin or app>` | the above plus `auth.hook.stage`, `auth.hook.source` |
| plugin middleware | `auth.middleware <plugin> <route>` | `auth.plugin`, `auth.transport`, `auth.route` (no operation): one per `authhttp.HTTPMiddlewarer` middleware run around a request |
| database | `auth.db <verb> <table>` (`auth.db select auth_user`) | the operation's attributes when a call is running, plus `db.operation.name` (`select`, `insert`, `update`, `delete`, `query`) and `db.collection.name` (the real table): one per statement the core or a plugin runs through `Exec`, `One` or `Each`; never the SQL or its arguments |
| data hook | `auth.db_hook <stage> <model>` (`auth.db_hook before_create user`) | the same keys, holding the stage and the core model: one per `auth.DataHooks` function |

A span that ends with an error has status `Error` with the error code as its description and in `auth.error.code`. The error text is never recorded: an internal error's text may hold SQL or a value, and it stays out of the trace the way it stays out of the response (`auth.internal`). No event is added either.

| Metric | Kind | Attributes |
|---|---|---|
| `auth.operations` | counter | `auth.operation`, `auth.plugin`, `auth.transport`, `auth.error.code` (`ok` for success) |
| `auth.operation.duration` | histogram, seconds | the same |

Durations are measured on the clock `auth.New` was given, from the pipeline's first check to the result, so a rate-limited or signed-out refusal is counted with its code and a duration near zero.

## Errors

`Observer` and `Options` fail only when the meter cannot create an instrument, or when `Options` is given neither provider.
