// Module authotel connects auth.Tracer and auth.Observer to OpenTelemetry. A
// separate module so the OpenTelemetry API reaches only the apps that use it;
// the core describes spans and call endings with no dependency at all. It
// depends on the standard otel API only, never on a wrapper such as
// github.com/ubgo/otelkit, so every app gets the same adapter whatever sits
// above the API in its own binary. The SDK is required for the tests alone.
module github.com/ubgo/auth/contrib/otel

go 1.24.0

require (
	github.com/ubgo/auth v0.1.0
	go.opentelemetry.io/otel v1.38.0
	go.opentelemetry.io/otel/metric v1.38.0
	go.opentelemetry.io/otel/sdk v1.38.0
	go.opentelemetry.io/otel/sdk/metric v1.38.0
	go.opentelemetry.io/otel/trace v1.38.0
)

require (
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/ubgo/sqlb v0.1.1 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)
