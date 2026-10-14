// Package authotel connects auth's Tracer and Observer seams to
// OpenTelemetry: one span per operation, per hook and per plugin middleware, a counter and a
// duration histogram per operation. A separate module so the OpenTelemetry
// API reaches only the apps that use it; the core describes spans and events
// and this package gives them their OpenTelemetry shape.
package authotel

import (
	"context"
	"errors"
	"fmt"

	"github.com/ubgo/auth"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// InstrumentationName is the tracer and meter name every span and metric is
// recorded under, so a backend attributes them to this library.
const InstrumentationName = "github.com/ubgo/auth"

// Attribute keys. Every span and metric carries the operation, the plugin and
// the transport; a hook span adds its stage and source; a plugin middleware
// span its route, and no operation; a failed span or
// call adds the error code and never the error text, which could hold SQL.
const (
	AttrOperation  = attribute.Key("auth.operation")
	AttrPlugin     = attribute.Key("auth.plugin")
	AttrTransport  = attribute.Key("auth.transport")
	AttrHookStage  = attribute.Key("auth.hook.stage")
	AttrHookSource = attribute.Key("auth.hook.source")
	AttrErrorCode  = attribute.Key("auth.error.code")
	// AttrRoute is the request path a plugin middleware span wraps
	// (auth.SpanMiddleware), better-auth's http.route attribute.
	AttrRoute = attribute.Key("auth.route")
	// AttrDBOperation and AttrDBTable are a database span's statement verb
	// and table (auth.SpanDatabase), or a data-hook span's stage and model
	// (auth.SpanDataHook), under OpenTelemetry's database convention keys.
	AttrDBOperation = attribute.Key("db.operation.name")
	AttrDBTable     = attribute.Key("db.collection.name")
)

// Metric names. The counter counts every call by outcome; the histogram is
// the call's duration in seconds, the unit OpenTelemetry's conventions ask
// for, measured on the clock auth was configured with.
const (
	MetricOperations = "auth.operations"
	MetricDuration   = "auth.operation.duration"
	// OutcomeOK is the AttrErrorCode value of a successful call, so one
	// attribute set tells success from each failure code.
	OutcomeOK = "ok"
)

// Tracer returns an auth.Tracer that starts OpenTelemetry spans from tp:
// pass it to auth.WithTracer. A span is a child of whatever span is in the
// context, so with an instrumented HTTP handler the operation span hangs
// under the request's. A span that ends with an error gets the error status
// and the code as its description and attribute; the text of an internal
// error stays out of the trace the way it stays out of the response.
func Tracer(tp trace.TracerProvider) auth.Tracer {
	return otelTracer{t: tp.Tracer(InstrumentationName)}
}

type otelTracer struct{ t trace.Tracer }

func (o otelTracer) Start(ctx context.Context, s auth.SpanInfo) (context.Context, auth.Span) {
	attrs := []attribute.KeyValue{
		AttrOperation.String(string(s.Op.ID)),
		AttrPlugin.String(s.Plugin),
		AttrTransport.String(string(s.Transport)),
	}
	if s.Kind == auth.SpanHook {
		attrs = append(attrs, AttrHookStage.String(string(s.Stage)), AttrHookSource.String(s.Source))
	}
	if s.Kind == auth.SpanMiddleware {
		attrs = append(attrs, AttrRoute.String(s.Route))
	}
	if s.Kind == auth.SpanDatabase || s.Kind == auth.SpanDataHook {
		attrs = append(attrs, AttrDBOperation.String(s.DBOperation), AttrDBTable.String(s.Table))
	}
	ctx, sp := o.t.Start(ctx, s.Name, trace.WithAttributes(attrs...), trace.WithSpanKind(trace.SpanKindInternal))
	return ctx, otelSpan{sp: sp}
}

type otelSpan struct{ sp trace.Span }

func (s otelSpan) End(err error) {
	if err != nil {
		code := auth.ErrorOf(err).Code
		s.sp.SetAttributes(AttrErrorCode.String(code))
		s.sp.SetStatus(codes.Error, code)
	}
	s.sp.End()
}

// Observer returns an auth.Observer that counts every call and records its
// duration through mp: pass it to auth.WithObserver. Instruments are created
// once here, so a failure to create them is this call's error and not a
// silent gap in the metrics.
func Observer(mp metric.MeterProvider) (auth.Observer, error) {
	m := mp.Meter(InstrumentationName)
	calls, err := m.Int64Counter(MetricOperations, metric.WithDescription("Calls of auth operations by outcome."))
	if err != nil {
		return nil, fmt.Errorf("authotel: %s: %w", MetricOperations, err)
	}
	dur, err := m.Float64Histogram(MetricDuration, metric.WithUnit("s"), metric.WithDescription("Duration of auth operations."))
	if err != nil {
		return nil, fmt.Errorf("authotel: %s: %w", MetricDuration, err)
	}
	return otelObserver{calls: calls, dur: dur}, nil
}

type otelObserver struct {
	calls metric.Int64Counter
	dur   metric.Float64Histogram
}

func (o otelObserver) Operation(ctx context.Context, e auth.OperationEvent) {
	outcome := OutcomeOK
	if e.Err != nil {
		outcome = auth.ErrorOf(e.Err).Code
	}
	set := metric.WithAttributes(
		AttrOperation.String(string(e.Op.ID)),
		AttrPlugin.String(e.Plugin),
		AttrTransport.String(string(e.Transport)),
		AttrErrorCode.String(outcome),
	)
	o.calls.Add(ctx, 1, set)
	o.dur.Record(ctx, e.Duration.Seconds(), set)
}

// Options returns the two options in one call: auth.WithTracer(Tracer(tp))
// and auth.WithObserver(Observer(mp)). Either provider may be nil to leave
// that side out, so an app with tracing and no metrics backend passes nil.
func Options(tp trace.TracerProvider, mp metric.MeterProvider) ([]auth.Option, error) {
	var opts []auth.Option
	if tp != nil {
		opts = append(opts, auth.WithTracer(Tracer(tp)))
	}
	if mp != nil {
		o, err := Observer(mp)
		if err != nil {
			return nil, err
		}
		opts = append(opts, auth.WithObserver(o))
	}
	if len(opts) == 0 {
		return nil, errors.New("authotel: Options needs a tracer provider, a meter provider or both")
	}
	return opts, nil
}
