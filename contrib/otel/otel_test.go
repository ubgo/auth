package authotel_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	authotel "github.com/ubgo/auth/contrib/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// A plugin with one public mutation and one that fails, plus a hook, so the
// adapter is exercised on every span kind and both outcomes.
const (
	opOK   auth.EndpointID = "p.ok"
	opFail auth.EndpointID = "p.fail"
)

type plugin struct {
	ok   *auth.Op[struct{}, struct{}]
	fail *auth.Op[struct{}, struct{}]
}

func newPlugin() *plugin {
	p := &plugin{}
	p.ok = auth.Define(auth.OpInfo{ID: opOK, Kind: auth.Mutation, Require: auth.Public, Path: "/ok"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil })
	p.fail = auth.Define(auth.OpInfo{ID: opFail, Kind: auth.Mutation, Require: auth.Public, Path: "/fail"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) {
			return struct{}{}, errors.New("pq: relation auth_user does not exist") // an internal error, whose text must stay out of the trace
		})
	return p
}

func (p *plugin) Name() string                 { return "p" }
func (p *plugin) SignsIn() bool                { return true }
func (p *plugin) Operations() []auth.Operation { return []auth.Operation{p.ok, p.fail} }
func (p *plugin) OperationHooks() []auth.OperationHook {
	return []auth.OperationHook{{Match: []auth.EndpointID{opOK}, Before: func(context.Context, *auth.Call) error { return nil }}}
}

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { return c.t }

func attr(attrs []attribute.KeyValue, k attribute.Key) string {
	for _, a := range attrs {
		if a.Key == k {
			return a.Value.AsString()
		}
	}
	return ""
}

func TestTracer_SpansCarryTheOperationAndNeverTheErrorText(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	p := newPlugin()
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(p), auth.WithTracer(authotel.Tracer(tp)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	if _, err := p.ok.Call(ctx, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.fail.Call(ctx, struct{}{}); err == nil {
		t.Fatal("fail must fail")
	}
	spans := exp.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("got %d spans, want hook, ok and fail", len(spans))
	}
	// Spans end in order: the hook, then its operation, then the failed one.
	hook, ok, fail := spans[0], spans[1], spans[2]
	if hook.Name != "auth.hook before p.ok p" || attr(hook.Attributes, authotel.AttrHookStage) != "before" || attr(hook.Attributes, authotel.AttrHookSource) != "p" {
		t.Fatalf("hook span: %s %v", hook.Name, hook.Attributes)
	}
	if hook.Parent.SpanID() != ok.SpanContext.SpanID() {
		t.Fatal("the hook span must be a child of the operation span")
	}
	if ok.Name != "auth.operation p.ok" || attr(ok.Attributes, authotel.AttrOperation) != "p.ok" || attr(ok.Attributes, authotel.AttrPlugin) != "p" || attr(ok.Attributes, authotel.AttrTransport) != "http" || ok.Status.Code != codes.Unset {
		t.Fatalf("ok span: %s %v %v", ok.Name, ok.Attributes, ok.Status)
	}
	if attr(ok.Attributes, authotel.AttrErrorCode) != "" {
		t.Fatal("a successful span carries no error code")
	}
	if fail.Status.Code != codes.Error || fail.Status.Description != "auth.internal" || attr(fail.Attributes, authotel.AttrErrorCode) != "auth.internal" {
		t.Fatalf("failed span: %v %v", fail.Status, fail.Attributes)
	}
	for _, ev := range fail.Events {
		t.Fatalf("a failed span records no event (it would carry the error text): %v", ev)
	}
	if fail.Status.Description == "pq: relation auth_user does not exist" {
		t.Fatal("the internal error's text reached the trace")
	}
}

func TestObserver_CountsCallsAndRecordsDurations(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	p := newPlugin()
	opts, err := authotel.Options(nil, mp)
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.New(append(opts, auth.WithBaseURL("https://app.example.com"), auth.WithClock(clk.Now), auth.WithPlugins(p),
		auth.WithOperationHooks(auth.OperationHook{Match: []auth.EndpointID{opOK}, Before: func(context.Context, *auth.Call) error {
			clk.t = clk.t.Add(250 * time.Millisecond)
			return nil
		}}))...)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := p.ok.Call(ctx, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.fail.Call(ctx, struct{}{}); err == nil {
		t.Fatal("fail must fail")
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	var calls map[string]int64
	var durations map[string]float64
	for _, sm := range rm.ScopeMetrics {
		if sm.Scope.Name != authotel.InstrumentationName {
			continue
		}
		for _, m := range sm.Metrics {
			switch m.Name {
			case authotel.MetricOperations:
				calls = map[string]int64{}
				for _, dp := range m.Data.(metricdata.Sum[int64]).DataPoints {
					op, _ := dp.Attributes.Value(authotel.AttrOperation)
					code, _ := dp.Attributes.Value(authotel.AttrErrorCode)
					calls[op.AsString()+" "+code.AsString()] = dp.Value
				}
			case authotel.MetricDuration:
				durations = map[string]float64{}
				for _, dp := range m.Data.(metricdata.Histogram[float64]).DataPoints {
					op, _ := dp.Attributes.Value(authotel.AttrOperation)
					durations[op.AsString()] = dp.Sum
				}
			}
		}
	}
	if calls["p.ok ok"] != 1 || calls["p.fail auth.internal"] != 1 || len(calls) != 2 {
		t.Fatalf("calls = %v", calls)
	}
	if durations["p.ok"] != 0.25 || durations["p.fail"] != 0 {
		t.Fatalf("durations = %v, want 0.25 s for ok (the hook moved the clock) and 0 for fail", durations)
	}
}

func TestOptions_NeedsAProvider(t *testing.T) {
	if _, err := authotel.Options(nil, nil); err == nil {
		t.Fatal("Options with nothing must fail")
	}
	tp := sdktrace.NewTracerProvider()
	opts, err := authotel.Options(tp, nil)
	if err != nil || len(opts) != 1 {
		t.Fatalf("tracer only: %d options, %v", len(opts), err)
	}
	both, err := authotel.Options(tp, sdkmetric.NewMeterProvider())
	if err != nil || len(both) != 2 {
		t.Fatalf("both: %d options, %v", len(both), err)
	}
}

// failingMeter refuses the named instrument, the way a meter refuses an
// instrument whose name or unit is not valid.
type failingMeter struct {
	noop.Meter
	refuse string
}

func (m failingMeter) Int64Counter(name string, o ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	if name == m.refuse {
		return nil, errors.New("refused")
	}
	return m.Meter.Int64Counter(name, o...)
}

func (m failingMeter) Float64Histogram(name string, o ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	if name == m.refuse {
		return nil, errors.New("refused")
	}
	return m.Meter.Float64Histogram(name, o...)
}

type failingProvider struct {
	noop.MeterProvider
	refuse string
}

func (p failingProvider) Meter(string, ...metric.MeterOption) metric.Meter {
	return failingMeter{refuse: p.refuse}
}

func TestObserver_ReportsAnInstrumentItCannotCreate(t *testing.T) {
	for _, name := range []string{authotel.MetricOperations, authotel.MetricDuration} {
		if _, err := authotel.Observer(failingProvider{refuse: name}); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s refused: err = %v, want it named", name, err)
		}
		if _, err := authotel.Options(nil, failingProvider{refuse: name}); err == nil {
			t.Errorf("%s refused: Options must fail too", name)
		}
	}
}

// A plugin middleware span carries its route.
func TestTracer_MiddlewareSpanCarriesTheRoute(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	a, err := auth.New(auth.WithBaseURL("https://app.example.com"), auth.WithPlugins(newPlugin()), auth.WithTracer(authotel.Tracer(tp)))
	if err != nil {
		t.Fatal(err)
	}
	_, end := a.StartSpan(context.Background(), auth.MiddlewareSpan("p", auth.TransportHTTP, "/p/ok"))
	end(nil)
	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Name != "auth.middleware p /p/ok" || attr(spans[0].Attributes, authotel.AttrRoute) != "/p/ok" || attr(spans[0].Attributes, authotel.AttrPlugin) != "p" {
		t.Fatalf("spans %v", spans)
	}
}

// A database span carries its verb and table under the database keys.
func TestTracer_DatabaseSpanCarriesTheStatement(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	tr := authotel.Tracer(tp)
	_, sp := tr.Start(context.Background(), auth.SpanInfo{Kind: auth.SpanDatabase, Name: "auth.db select auth_user", DBOperation: "select", Table: "auth_user"})
	sp.End(nil)
	spans := exp.GetSpans()
	if len(spans) != 1 || attr(spans[0].Attributes, authotel.AttrDBOperation) != "select" || attr(spans[0].Attributes, authotel.AttrDBTable) != "auth_user" {
		t.Fatalf("spans %v", spans)
	}
}
