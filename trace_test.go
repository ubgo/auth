package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ubgo/auth"
)

// recordingTracer keeps every span in start order with the error it ended
// with, and marks the context so a hook can prove it ran inside the span.
type recordingTracer struct {
	spans []auth.SpanInfo
	ends  []error
	// open counts spans started and not yet ended, to check nesting.
	open, maxOpen int
}

type spanKey struct{}

func (r *recordingTracer) Start(ctx context.Context, s auth.SpanInfo) (context.Context, auth.Span) {
	r.spans = append(r.spans, s)
	r.open++
	r.maxOpen = max(r.maxOpen, r.open)
	i := len(r.ends)
	r.ends = append(r.ends, errors.New("not ended"))
	return context.WithValue(ctx, spanKey{}, s.Name), recordedSpan{r: r, i: i}
}

type recordedSpan struct {
	r *recordingTracer
	i int
}

func (s recordedSpan) End(err error) { s.r.ends[s.i] = err; s.r.open-- }

func TestWithTracer_StartsOperationAndHookSpans(t *testing.T) {
	tr := &recordingTracer{}
	var inside any
	p := newTestPlugin(auth.OperationHook{
		Match: []auth.EndpointID{opEcho},
		Before: func(ctx context.Context, c *auth.Call) error {
			inside = ctx.Value(spanKey{})
			if in, ok := c.Input.(echoIn); ok && in.Text == "forbidden" {
				return errOpFailed
			}
			return nil
		},
		After: func(context.Context, *auth.Call, any) error { return nil },
	})
	a, err := newAuth(auth.WithPlugins(p), auth.WithTracer(tr), auth.WithOperationHooks(auth.OperationHook{
		Match: []auth.EndpointID{opEcho},
		After: func(context.Context, *auth.Call, any) error { return nil },
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.echo.Call(context.Background(), echoIn{Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	names := func() []string {
		var out []string
		for _, s := range tr.spans {
			out = append(out, s.Name)
		}
		return out
	}
	want := []string{
		"auth.operation testp.echo",
		"auth.hook before testp.echo testp",
		"auth.hook after testp.echo testp",
		"auth.hook after testp.echo app",
	}
	if got := names(); !equalStrings(got, want) {
		t.Fatalf("spans %q, want %q", got, want)
	}
	for i, e := range tr.ends {
		if e != nil {
			t.Fatalf("span %d ended with %v, want success", i, e)
		}
	}
	if tr.open != 0 || tr.maxOpen != 2 {
		t.Fatalf("open=%d maxOpen=%d: hook spans nest inside the operation span and every span ends", tr.open, tr.maxOpen)
	}
	// The hook ran in the context its span returned, so an adapter's child
	// spans have the hook span as their parent.
	if inside != "auth.hook before testp.echo testp" {
		t.Fatalf("hook ran in context %v", inside)
	}
	op, hook := tr.spans[0], tr.spans[1]
	if op.Kind != auth.SpanOperation || op.Op.ID != opEcho || op.Plugin != "testp" || op.Transport != auth.TransportGo || op.Stage != "" || op.Source != "" {
		t.Fatalf("operation span: %+v", op)
	}
	if hook.Kind != auth.SpanHook || hook.Stage != auth.HookBefore || hook.Source != "testp" || hook.Op.ID != opEcho {
		t.Fatalf("hook span: %+v", hook)
	}
	if app := tr.spans[3]; app.Source != auth.HookSourceApp {
		t.Fatalf("app hook span: %+v", app)
	}

	// A refused hook ends its span and the operation span with the error,
	// and the After hooks never start.
	tr.spans, tr.ends = nil, nil
	if _, err := p.echo.Call(context.Background(), echoIn{Text: "forbidden"}); !errors.Is(err, errOpFailed) {
		t.Fatal(err)
	}
	if got := names(); !equalStrings(got, want[:2]) {
		t.Fatalf("spans after a veto %q, want %q", got, want[:2])
	}
	if !errors.Is(tr.ends[0], errOpFailed) || !errors.Is(tr.ends[1], errOpFailed) {
		t.Fatalf("ends after a veto: %v", tr.ends)
	}

	// A call the pipeline refuses before any hook has one span, ended with
	// the refusal, carrying the request's transport.
	tr.spans, tr.ends = nil, nil
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP})
	if _, err := p.whoami.Call(ctx, struct{}{}); !errors.Is(err, auth.ErrSignedOut) {
		t.Fatal(err)
	}
	if len(tr.spans) != 1 || tr.spans[0].Transport != auth.TransportHTTP || !errors.Is(tr.ends[0], auth.ErrSignedOut) {
		t.Fatalf("refused call: %+v %v", tr.spans, tr.ends)
	}
}

func TestWithTracer_AndObserverAgreeOnTheOutcome(t *testing.T) {
	tr := &recordingTracer{}
	var events []auth.OperationEvent
	p := newTestPlugin()
	_, err := newAuth(auth.WithPlugins(p), auth.WithTracer(tr),
		auth.WithObserver(auth.ObserverFunc(func(_ context.Context, e auth.OperationEvent) { events = append(events, e) })))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.fail.Call(context.Background(), struct{}{}); !errors.Is(err, errOpFailed) {
		t.Fatal(err)
	}
	if len(events) != 1 || len(tr.ends) != 1 || !errors.Is(events[0].Err, errOpFailed) || !errors.Is(tr.ends[0], errOpFailed) {
		t.Fatalf("events %+v, span ends %v", events, tr.ends)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
