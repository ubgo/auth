package auth

import (
	"context"
	"strings"
)

// SpanKind names what a span measures.
//
//ds:def id=core-spankind-6rn3wq8d owner=@khanakia stability=stable
type SpanKind string

// The spans the core starts. An operation span wraps one call from the first
// pipeline check to the result; a hook span wraps one Before or After hook
// inside it. Both carry the operation, so a trace shows which hook made a
// sign-in slow.
//
// A middleware span wraps one plugin's net/http middleware around a request
// (authhttp.HTTPMiddlewarer); it carries the plugin and the route, and no
// operation.
//
// A database span wraps one statement the core or a plugin runs through Exec,
// One or Each, and a data-hook span one DataHooks function; both carry
// DBOperation and Table, and the operation the call is running when there is
// one. No span carries SQL or arguments: only the statement's verb and its
// table.
const (
	SpanOperation  SpanKind = "operation"
	SpanHook       SpanKind = "hook"
	SpanMiddleware SpanKind = "middleware"
	SpanDatabase   SpanKind = "db"
	SpanDataHook   SpanKind = "db_hook"
)

// HookStage names which function of an OperationHook a hook span wraps.
type HookStage string

// The stages a hook span reports. Finally hooks run after the result and are
// not traced: they cannot change the answer, and a span inside the Finally of
// a failed call would outlive the error it reports.
const (
	HookBefore HookStage = "before"
	HookAfter  HookStage = "after"
)

// HookSourceApp is SpanInfo.Source for a hook the app registered with
// WithOperationHooks; a plugin's hooks carry the plugin's name.
const HookSourceApp = "app"

// SpanInfo describes a span to a Tracer at its start. Name is ready to show
// ("auth.operation core.session", "auth.hook before core.session app") and
// the other fields are its attributes, typed so an adapter maps them to its
// own attribute keys without parsing the name. Stage and Source are set for
// hook spans only.
//
//ds:def id=core-spaninfo-4kt7mn2b owner=@khanakia stability=stable
type SpanInfo struct {
	Kind      SpanKind
	Name      string
	Op        OpInfo
	Plugin    string
	Transport Transport
	Stage     HookStage
	Source    string
	// Route is the request path a middleware span wraps; empty otherwise.
	Route string
	// DBOperation and Table are set for database and data-hook spans: the
	// statement's verb ("select", "insert", "update", "delete", or "query"
	// for anything else) and the real table name it names first, or for a
	// data hook its stage ("before_create" …) and the core model ("user",
	// "identity", "session", "verification").
	DBOperation string
	Table       string
}

// Span is one started span. End reports how it ended: nil for success, else
// the error the call or hook returned, which an adapter records by code
// (ErrorOf) and never by text, so a database error's SQL stays out of the
// trace the same way it stays out of the response.
//
//ds:def id=core-span-8vq2hx5n owner=@khanakia stability=stable
type Span interface {
	End(err error)
}

// Tracer starts spans. It is the dependency-free seam for distributed
// tracing: the core module may depend on nothing but sqlb, so it describes
// spans and an adapter (contrib/otel) turns them into OpenTelemetry spans.
// Start returns the context the rest of the work runs in, so a child span an
// adapter creates is the parent of everything inside the call: the hooks,
// and the app's own spans started from a hook or an instrumented *sql.DB.
//
// Tracer and Observer are deliberately two things: the Observer sees every
// call end with its duration for metrics and error counting, whether or not
// a trace is being sampled; the Tracer sees the structure inside the call.
//
//ds:def id=core-tracer-3pm9kw7v owner=@khanakia stability=stable
type Tracer interface {
	Start(ctx context.Context, s SpanInfo) (context.Context, Span)
}

// WithTracer sets the tracer every call reports its spans to. Without one no
// span is started and the pipeline does no extra work.
//
//ds:def id=opt-withtracer-5xh2rq8m owner=@khanakia stability=stable
func WithTracer(t Tracer) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithTracer", t) {
			return
		}
		s.tracer = t
	}
}

// spanName joins the fixed prefix and the parts a human reads in a trace
// viewer. The prefix is fixed so every span the library emits is found with
// one filter.
const spanNamePrefix = "auth."

// startSpan starts a span when a tracer is configured and returns a no-op
// end otherwise, so call sites stay free of nil checks.
func (a *Auth) startSpan(ctx context.Context, s SpanInfo) (context.Context, func(error)) {
	if a.tracer == nil {
		return ctx, func(error) {}
	}
	ctx, sp := a.tracer.Start(ctx, s)
	return ctx, sp.End
}

// operationSpan describes the span of one call.
func operationSpan(op OpInfo, plugin string, transport Transport) SpanInfo {
	return SpanInfo{
		Kind: SpanOperation, Name: spanNamePrefix + string(SpanOperation) + " " + string(op.ID),
		Op: op, Plugin: plugin, Transport: transport,
	}
}

// hookSpan describes the span of one hook stage of one registered hook.
func hookSpan(c *Call, stage HookStage, source string) SpanInfo {
	return SpanInfo{
		Kind: SpanHook, Name: spanNamePrefix + string(SpanHook) + " " + string(stage) + " " + string(c.Op.ID) + " " + source,
		Op: c.Op, Plugin: c.Plugin, Transport: c.Transport, Stage: stage, Source: source,
	}
}

// StartSpan starts a span on the WithTracer tracer and returns the context
// to run the work in and the function that ends it; without a tracer it is
// a no-op that costs nothing. It is for a transport tracing what happens
// outside an operation, such as authhttp's plugin middleware; the pipeline
// starts its own operation and hook spans.
func (a *Auth) StartSpan(ctx context.Context, s SpanInfo) (context.Context, func(error)) {
	return a.startSpan(ctx, s)
}

// MiddlewareSpan describes the span of plugin's middleware around route.
func MiddlewareSpan(plugin string, transport Transport, route string) SpanInfo {
	return SpanInfo{
		Kind: SpanMiddleware, Name: spanNamePrefix + string(SpanMiddleware) + " " + plugin + " " + route,
		Plugin: plugin, Transport: transport, Route: route,
	}
}

// Statement verbs a database span reports. dbOther is any statement whose
// first word is none of the four.
const (
	dbSelect = "select"
	dbInsert = "insert"
	dbUpdate = "update"
	dbDelete = "delete"
	dbOther  = "query"
)

// statementShape reads the verb and the first table named from rendered
// SQL, for a database span. It reads only the words the four statement forms
// the builder renders start with (SELECT … FROM t, INSERT INTO t, UPDATE t,
// DELETE FROM t) and strips identifier quotes; anything else is dbOther with
// no table. It never returns SQL beyond one identifier.
func statementShape(sql string) (op, table string) {
	words := strings.Fields(sql)
	if len(words) == 0 {
		return dbOther, ""
	}
	after := func(word string) string {
		for i, w := range words[:len(words)-1] {
			if strings.EqualFold(w, word) {
				return strings.Trim(words[i+1], "\"`[]")
			}
		}
		return ""
	}
	switch strings.ToLower(words[0]) {
	case dbSelect:
		return dbSelect, after("FROM")
	case dbInsert:
		return dbInsert, after("INTO")
	case dbUpdate:
		if len(words) < 2 {
			return dbUpdate, ""
		}
		return dbUpdate, strings.Trim(words[1], "\"`[]")
	case dbDelete:
		return dbDelete, after("FROM")
	}
	return dbOther, ""
}

// dbSpan starts the span of one statement, when a tracer is configured; the
// SQL is rendered already, so shaping it costs one scan of the text.
func (a *Auth) dbSpan(ctx context.Context, sql string) (context.Context, func(error)) {
	if a.tracer == nil {
		return ctx, func(error) {}
	}
	op, table := statementShape(sql)
	info := SpanInfo{Kind: SpanDatabase, Name: spanNamePrefix + string(SpanDatabase) + " " + op + " " + table, DBOperation: op, Table: table}
	info.Op, _ = OperationOf(ctx)
	return a.startSpan(ctx, info)
}

// dataHookSpan starts the span of one data-hook function.
func (a *Auth) dataHookSpan(ctx context.Context, stage, model string) (context.Context, func(error)) {
	if a.tracer == nil {
		return ctx, func(error) {}
	}
	info := SpanInfo{Kind: SpanDataHook, Name: spanNamePrefix + string(SpanDataHook) + " " + stage + " " + model, DBOperation: stage, Table: model}
	info.Op, _ = OperationOf(ctx)
	return a.startSpan(ctx, info)
}
