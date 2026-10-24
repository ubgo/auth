# Observability: observer, tracer and logger

The library reports what it does through three seams, each for a different question. `auth.WithObserver` answers "how many sign-ins failed, and why?": it sees every operation end with its outcome and duration. `auth.WithTracer` answers "what happened inside that slow sign-in?": it gets a span per operation, per hook and per database statement, and `contrib/otel` turns them into OpenTelemetry spans. `auth.WithLogger` answers "what went wrong that no response could report?": a mail that could not be delivered after the sign-up committed, a warning about the configuration. This program wires all three on an email and password app and writes everything to stderr as JSON lines.

## Run it

```sh
cd examples
go run ./observability
```

It creates `observability.db` (SQLite) in the current directory and listens on `http://localhost:8081` (`PORT=8093 go run ./observability` to pick another port; the walkthrough below used 8093). Mail to any address at `@bounce.example` fails on purpose, standing in for a provider that rejects a message. Run the tests with `go test ./observability`.

## The wiring

`newAuth` passes the three options next to the plugins. The tracer is `authotel.Tracer` over any OpenTelemetry `TracerProvider`; the observer is a small type of the app's own; the logger is a `*slog.Logger`.

<!-- ds:block id=obs-newauth-z6v7v9tm -->
**newAuth** · [`examples/observability/main.go:130-142`](main.go#L130-L142)

```go
func newAuth(db *sql.DB, m email.Mailer, logger *slog.Logger, tp trace.TracerProvider, obs auth.Observer) (*auth.Auth, error) {
	return auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}),
		auth.WithBaseURL(baseURL),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(m)),
			password.New(),
		),
		auth.WithObserver(obs),
		auth.WithTracer(authotel.Tracer(tp)),
		auth.WithLogger(logger),
	)
}
```
<!-- /ds:block hash=74ab73 -->

The HTTP transport has a logger of its own, `authhttp.Logger`, for the internal errors behind a `500`. It defaults to `slog.Default()`, not to the core's logger, so `newHandler` passes the same one to both.

The observer, `callLog`, keeps the operation id, the plugin and the outcome (`ok` or the error code) of every call, and logs it. An `auth.OperationEvent` carries no input and no output, so a password or a token cannot reach a metrics sink. A real app would add to a counter by operation and outcome instead, which is what `authotel.Observer` does with an OpenTelemetry meter.

The tracer provider is the OpenTelemetry SDK with one span processor. Here it is `logSpans`, which logs each span as it ends; in production it is a batch processor around an OTLP exporter, and the test passes the SDK's in-memory `tracetest.SpanRecorder`.

## Walkthrough

Sign up Alice, then Bob, whose address bounces. Both sign-ups succeed: mail goes out after the transaction commits, so a delivery failure cannot fail the call that caused it.

```sh
curl -s -X POST localhost:8093/auth/password/sign-up -H 'Origin: http://localhost:8093' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple","name":"Alice"}'
curl -s -X POST localhost:8093/auth/password/sign-up -H 'Origin: http://localhost:8093' \
  -d '{"identifier":"bob@bounce.example","password":"correct horse battery staple","name":"Bob"}'
```

```json
{"user":{"id":"usr_6k6acrfxzkv5m2z5gxtwkbej","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
{"user":{"id":"usr_7idtxrnj57o4dyeivroiypri","name":"Bob","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The first request through a rate limit logs a warning once, because the default rate store counts in this process only:

```text
{"time":"2026-10-09T08:39:30.10116+05:30","level":"WARN","msg":"auth: rate limits are counted per process; pass auth.WithRateStore when you run more than one instance"}
```

Bob's sign-up ends with the operation span, the observer's record, and then the logger's report of the bounced verification mail, which only the log can tell anyone about:

```text
{"time":"2026-10-09T08:39:30.275173+05:30","level":"INFO","msg":"span","name":"auth.operation password.sign-up","status":"Unset","description":"","duration":"84.109792ms"}
{"time":"2026-10-09T08:39:30.275182+05:30","level":"INFO","msg":"auth call","op":"password.sign-up","plugin":"password","transport":"http","outcome":"ok","duration":"84.115ms"}
{"time":"2026-10-09T08:39:30.275197+05:30","level":"ERROR","msg":"auth: delivery failed","kind":"email","purpose":"verify","error":"mail provider rejected the message"}
```

Sign in with a wrong password, then the right one:

```sh
curl -s -X POST localhost:8093/auth/password/sign-in -H 'Origin: http://localhost:8093' \
  -d '{"identifier":"alice@example.com","password":"wrong"}'
curl -s -X POST localhost:8093/auth/password/sign-in -H 'Origin: http://localhost:8093' \
  -d '{"identifier":"alice@example.com","password":"correct horse battery staple"}'
```

```json
{"error":{"code":"password.invalid_credentials","message":"The sign-in details are not right."}}
{"user":{"id":"usr_6k6acrfxzkv5m2z5gxtwkbej","name":"Alice","image":""},"verificationRequired":false,"secondFactorRequired":false}
```

The trace shows each statement as it ends, then the operation span around them. The refused sign-in's span has status `Error` with the error code as its description; the observer records the same code as the outcome, because both are built from the same call. The duration of both sign-ins is the same on purpose: a wrong password costs one hash, like a right one.

```text
{"time":"2026-10-09T08:39:30.289932+05:30","level":"INFO","msg":"span","name":"auth.db select auth_identity","status":"Unset","description":"","duration":"273.084µs"}
{"time":"2026-10-09T08:39:30.290071+05:30","level":"INFO","msg":"span","name":"auth.db select auth_identity","status":"Unset","description":"","duration":"82.875µs"}
{"time":"2026-10-09T08:39:30.290117+05:30","level":"INFO","msg":"span","name":"auth.db select auth_password","status":"Unset","description":"","duration":"28.583µs"}
{"time":"2026-10-09T08:39:30.367428+05:30","level":"INFO","msg":"span","name":"auth.operation password.sign-in","status":"Error","description":"password.invalid_credentials","duration":"77.857625ms"}
{"time":"2026-10-09T08:39:30.367462+05:30","level":"INFO","msg":"auth call","op":"password.sign-in","plugin":"password","transport":"http","outcome":"password.invalid_credentials","duration":"77.896ms"}
{"time":"2026-10-09T08:39:30.379099+05:30","level":"INFO","msg":"span","name":"auth.db select auth_identity","status":"Unset","description":"","duration":"185.542µs"}
{"time":"2026-10-09T08:39:30.379209+05:30","level":"INFO","msg":"span","name":"auth.db select auth_identity","status":"Unset","description":"","duration":"69.709µs"}
{"time":"2026-10-09T08:39:30.379251+05:30","level":"INFO","msg":"span","name":"auth.db select auth_password","status":"Unset","description":"","duration":"26.667µs"}
{"time":"2026-10-09T08:39:30.455616+05:30","level":"INFO","msg":"span","name":"auth.db select auth_user","status":"Unset","description":"","duration":"115.458µs"}
{"time":"2026-10-09T08:39:30.455696+05:30","level":"INFO","msg":"span","name":"auth.db select auth_user","status":"Unset","description":"","duration":"32.208µs"}
{"time":"2026-10-09T08:39:30.455771+05:30","level":"INFO","msg":"span","name":"auth.db insert auth_session","status":"Unset","description":"","duration":"51.458µs"}
{"time":"2026-10-09T08:39:30.455913+05:30","level":"INFO","msg":"span","name":"auth.operation password.sign-in","status":"Unset","description":"","duration":"77.083375ms"}
{"time":"2026-10-09T08:39:30.455925+05:30","level":"INFO","msg":"auth call","op":"password.sign-in","plugin":"password","transport":"http","outcome":"ok","duration":"77.091ms"}
```

No span, observer event or log line carries the SQL, its arguments or the password: a database span names only the statement's verb and table, and a failed span records the error code, never the error text.

## What the test proves

`TestObservability` runs the same four requests against the handler `main` serves, on a fresh SQLite file, with the logger writing JSON into a buffer and spans going to `tracetest.SpanRecorder`. It checks that the observer saw two `ok` sign-ups, a sign-in refused with `password.invalid_credentials` and an `ok` sign-in, in that order; that there are two `auth.operation password.sign-in` spans, the first with status `Error` and the code as its description; that `auth.db insert auth_session` is a child of the successful sign-in's span; that the logger recorded `auth: delivery failed` at level `ERROR` with the mailer's error; and that the password appears nowhere in the log. Removing any one of the three options makes it fail.

## Related

- [contrib/otel](../../contrib/otel/README.md): the span names, attributes and metrics `authotel` records, and `authotel.Options` for a tracer and a meter in one call.
- [Production checklist](../../docs/start/production.md): where logging fits among the other settings to review before going live.
