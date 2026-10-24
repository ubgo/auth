package auth_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// streamAuth is an Auth with the sinks and no database.
func streamAuth(t *testing.T, opts ...auth.Option) *auth.Auth {
	t.Helper()
	a, err := newAuth(append([]auth.Option{auth.WithPlugins(basic("s"))}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func emitN(a *auth.Auth, n int) {
	for range n {
		a.EmitSecurity(auth.SecurityEvent{Kind: auth.SecurityLockout})
	}
}

// TestSecurityStream_OffByDefault: with no sink nothing is queued and every
// call is a no-op.
func TestSecurityStream_OffByDefault(t *testing.T) {
	a := streamAuth(t)
	a.EmitSecurity(auth.SecurityEvent{Kind: auth.SecurityLockout})
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.SecurityStats() != nil {
		t.Fatalf("stats without a sink = %+v", a.SecurityStats())
	}
}

// TestSecurityStream_BatchesBySizeAndFlush: events reach the sink in batches
// of at most the batch size, in order, and a flush delivers the remainder.
func TestSecurityStream_BatchesBySizeAndFlush(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	sink := auth.SecuritySinkFunc(func(_ context.Context, b []auth.SecurityEvent) error {
		mu.Lock()
		sizes = append(sizes, len(b))
		mu.Unlock()
		return nil
	})
	a := streamAuth(t, auth.WithSecuritySink(sink, auth.SecurityQueue{BatchSize: 3, FlushEvery: time.Hour}))
	emitN(a, 7)
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 3 || sizes[0] != 3 || sizes[1] != 3 || sizes[2] != 1 {
		t.Fatalf("batch sizes = %v, want [3 3 1]", sizes)
	}
	st := a.SecurityStats()[0]
	if st.Queued != 7 || st.Delivered != 7 || st.Dropped != 0 || st.Failed != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

// TestSecurityStream_FlushesOnTheInterval: an event never waits longer than
// the interval for its batch to fill.
func TestSecurityStream_FlushesOnTheInterval(t *testing.T) {
	mem := &auth.MemorySecuritySink{}
	a := streamAuth(t, auth.WithSecuritySink(mem, auth.SecurityQueue{BatchSize: 100, FlushEvery: 5 * time.Millisecond}))
	emitN(a, 1)
	deadline := time.Now().Add(5 * time.Second)
	for len(mem.Events()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("event not delivered on the interval")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestSecurityStream_DropsNewEventsWhenFullAndNeverBlocks: a sink stuck in a
// write fills its queue, after which the NEW events are dropped and counted,
// the emitter is never held up, and what was queued is delivered once the
// sink recovers.
func TestSecurityStream_DropsNewEventsWhenFullAndNeverBlocks(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	var got []string
	sink := auth.SecuritySinkFunc(func(_ context.Context, b []auth.SecurityEvent) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		mu.Lock()
		for _, e := range b {
			got = append(got, e.Attrs["n"])
		}
		mu.Unlock()
		return nil
	})
	var buf bytes.Buffer
	a := streamAuth(t, auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))),
		auth.WithSecuritySink(sink, auth.SecurityQueue{Name: "slow", Buffer: 2, BatchSize: 1, FlushEvery: 5 * time.Millisecond}))
	emit := func(n string) {
		a.EmitSecurity(auth.SecurityEvent{Kind: auth.SecurityLockout, Attrs: map[string]string{"n": n}})
	}
	emit("a")
	<-entered // the worker holds "a" inside the write; the queue is empty
	emit("b")
	emit("c") // queue now full (2)
	start := time.Now()
	for _, n := range []string{"d", "e", "f", "g", "h"} {
		emit(n)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("emitting into a full queue took %v: it must not block", time.Since(start))
	}
	st := a.SecurityStats()[0]
	if st.Name != "slow" || st.Queued != 3 || st.Dropped != 5 {
		t.Fatalf("stats = %+v, want 3 queued and 5 dropped", st)
	}
	// The drop is reported in the log by the worker's tick, not on the
	// emitter's path.
	close(release)
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(got, "") != "abc" {
		t.Fatalf("delivered %v, want the first three in order (new events are the ones dropped)", got)
	}
	if !strings.Contains(buf.String(), "security events dropped") || !strings.Contains(buf.String(), "dropped=5") {
		t.Fatalf("no drop report in the log: %s", buf.String())
	}
}

// TestSecurityStream_AFailingOrPanickingSinkDoesNotStopTheFeed: the batch is
// counted failed and logged, not retried, and the next batch still arrives.
func TestSecurityStream_AFailingOrPanickingSinkDoesNotStopTheFeed(t *testing.T) {
	calls := 0
	var delivered int
	sink := auth.SecuritySinkFunc(func(_ context.Context, b []auth.SecurityEvent) error {
		calls++
		switch calls {
		case 1:
			return errors.New("drain down")
		case 2:
			panic("sink bug")
		}
		delivered += len(b)
		return nil
	})
	var buf bytes.Buffer
	a := streamAuth(t, auth.WithLogger(slog.New(slog.NewTextHandler(&buf, nil))), auth.WithSecuritySink(sink, auth.SecurityQueue{BatchSize: 1, FlushEvery: time.Hour}))
	for range 3 {
		emitN(a, 1)
		if err := a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	st := a.SecurityStats()[0]
	if st.Failed != 2 || st.Delivered != 1 || delivered != 1 {
		t.Fatalf("stats = %+v delivered=%d, want 2 failed and 1 delivered", st, delivered)
	}
	if !strings.Contains(buf.String(), "drain down") || !strings.Contains(buf.String(), "sink bug") {
		t.Fatalf("failures not logged: %s", buf.String())
	}
}

// TestSecurityStream_CloseDrainsThenDrops: Close hands the queued events to
// the sink; an event emitted after it is dropped, not sent on a closed channel.
func TestSecurityStream_CloseDrainsThenDrops(t *testing.T) {
	mem := &auth.MemorySecuritySink{}
	a, err := newAuth(auth.WithPlugins(basic("s")), auth.WithSecuritySink(mem, auth.SecurityQueue{BatchSize: 100, FlushEvery: time.Hour}))
	if err != nil {
		t.Fatal(err)
	}
	emitN(a, 5)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(mem.Events()); n != 5 {
		t.Fatalf("Close delivered %d events, want 5", n)
	}
	emitN(a, 1)
	if st := a.SecurityStats()[0]; st.Dropped != 1 {
		t.Fatalf("after Close: %+v, want one dropped", st)
	}
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatalf("flush after Close = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
}

// TestSecurityStream_FlushHonoursItsContext: a flush behind a stuck sink
// returns when its context ends.
func TestSecurityStream_FlushHonoursItsContext(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, 1)
	sink := auth.SecuritySinkFunc(func(context.Context, []auth.SecurityEvent) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	a := streamAuth(t, auth.WithSecuritySink(sink, auth.SecurityQueue{BatchSize: 1, FlushEvery: time.Hour}))
	emitN(a, 1)
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := a.FlushSecurity(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flush behind a stuck sink = %v, want the context's error", err)
	}
}

// TestSecurityStream_FlushHonoursItsContextWhileTheSinkWrites: the worker took
// the flush request and the sink is slow to answer; the caller still gets its
// context's error instead of waiting for the sink.
func TestSecurityStream_FlushHonoursItsContextWhileTheSinkWrites(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	entered := make(chan struct{}, 1)
	sink := auth.SecuritySinkFunc(func(context.Context, []auth.SecurityEvent) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	a := streamAuth(t, auth.WithSecuritySink(sink, auth.SecurityQueue{BatchSize: 100, FlushEvery: time.Hour}))
	emitN(a, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- a.FlushSecurity(ctx) }()
	<-entered // the worker took the request and is inside the write
	if err := <-errc; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("flush behind a slow write = %v, want the context's error", err)
	}
}

// TestSecurityStream_NewRefusesWhatCannotWork: a nil sink and a queue shape
// that could not run.
func TestSecurityStream_NewRefusesWhatCannotWork(t *testing.T) {
	ok := &auth.MemorySecuritySink{}
	cases := map[string]auth.Option{
		"nil sink":          auth.WithSecuritySink(nil, auth.SecurityQueue{}),
		"negative buffer":   auth.WithSecuritySink(ok, auth.SecurityQueue{Buffer: -1}),
		"negative batch":    auth.WithSecuritySink(ok, auth.SecurityQueue{BatchSize: -1}),
		"negative interval": auth.WithSecuritySink(ok, auth.SecurityQueue{FlushEvery: -time.Second}),
		"negative on log":   auth.WithSecurityLog(auth.SecurityQueue{Buffer: -1}),
	}
	for name, o := range cases {
		if _, err := newAuth(auth.WithPlugins(basic("s")), o); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

// TestSecurityStream_ZeroQueueTakesTheDefaultsAndSinksAreNamedInOrder: the
// zero SecurityQueue is a working queue, and unnamed sinks are sink1, sink2.
func TestSecurityStream_ZeroQueueTakesTheDefaultsAndSinksAreNamedInOrder(t *testing.T) {
	a := streamAuth(t, auth.WithSecuritySink(&auth.MemorySecuritySink{}, auth.SecurityQueue{}), auth.WithSecuritySink(&auth.MemorySecuritySink{}, auth.SecurityQueue{Name: "siem"}), auth.WithSecurityLog(auth.SecurityQueue{}))
	var names []string
	for _, st := range a.SecurityStats() {
		names = append(names, st.Name)
	}
	if strings.Join(names, ",") != "sink1,siem,log" {
		t.Fatalf("names = %v", names)
	}
	emitN(a, 1)
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, st := range a.SecurityStats() {
		if st.Delivered != 1 {
			t.Errorf("%s: %+v", st.Name, st)
		}
	}
}

// TestSecurityStream_FillsDefaultsAndHonoursNoIPTracking: At, ID and severity
// are filled, and the address is removed under WithoutIPTracking so the
// promise on SecurityEvent holds for events a plugin builds.
func TestSecurityStream_FillsDefaultsAndHonoursNoIPTracking(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, track := range []bool{true, false} {
		mem := &auth.MemorySecuritySink{}
		opts := []auth.Option{auth.WithClock(func() time.Time { return now }), auth.WithSecuritySink(mem, auth.SecurityQueue{})}
		if !track {
			opts = append(opts, auth.WithoutIPTracking())
		}
		a := streamAuth(t, opts...)
		a.EmitSecurity(auth.SecurityEvent{Kind: auth.SecurityLockout, IP: "203.0.113.1"})
		a.EmitSecurity(auth.SecurityEvent{Kind: auth.SecurityLockout})
		if err := a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		ev := mem.Events()
		if len(ev) != 2 || !ev[0].At.Equal(now) || ev[0].Severity != auth.SeverityInfo || !strings.HasPrefix(ev[0].ID, "sev_") || ev[0].ID == ev[1].ID {
			t.Fatalf("defaults not filled: %+v", ev)
		}
		if got := ev[0].IP; (got != "") != track {
			t.Fatalf("track=%v: IP = %q", track, got)
		}
	}
}

// TestSecurityLog_WritesOneLinePerEventAtItsSeverity: the zero-setup sink.
func TestSecurityLog_WritesOneLinePerEventAtItsSeverity(t *testing.T) {
	var buf bytes.Buffer
	a := streamAuth(t, auth.WithLogger(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))), auth.WithSecurityLog(auth.SecurityQueue{}))
	for _, s := range auth.SecuritySeverityValues {
		a.EmitSecurity(auth.SecurityEvent{Kind: auth.SecurityLockout, Severity: s, Attrs: map[string]string{"k": string(s)}})
	}
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"level=INFO msg=\"auth: security event\"", "level=WARN msg=\"auth: security event\"", "level=ERROR msg=\"auth: security event\"", "kind=lockout", "k=alert"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	a.EmitSecurity(auth.SecurityEvent{Kind: auth.SecurityLockout, Attrs: map[string]string{"zeta": "1", "alpha": "2", "mid": "3"}})
	if err := a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if line := buf.String()[strings.LastIndex(buf.String(), "kind=lockout"):]; !(strings.Index(line, "alpha=") < strings.Index(line, "mid=") && strings.Index(line, "mid=") < strings.Index(line, "zeta=")) {
		t.Errorf("attributes are not in key order: %s", line)
	}
	if a.SecurityStats()[0].Name != "log" {
		t.Errorf("log sink name = %q", a.SecurityStats()[0].Name)
	}
}

// TestSecurityStream_RateEventsOncePerWindow: a rate rule over its limit
// emits one SecurityRateLimit event per window (the first over the limit),
// carrying the outcome and the rule, and a log-only rule is info.
func TestSecurityStream_RateEventsOncePerWindow(t *testing.T) {
	for _, tc := range []struct {
		action  auth.RateAction
		outcome auth.RateOutcome
		sev     auth.SecuritySeverity
	}{
		{auth.RateBlock, auth.RateOutcomeBlocked, auth.SeverityWarn},
		{auth.RateLog, auth.RateOutcomeLogged, auth.SeverityInfo},
	} {
		op := seamOp()
		mem := &auth.MemorySecuritySink{}
		a := streamAuth(t, auth.WithSecuritySink(mem, auth.SecurityQueue{}), auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}}, seamRule(tc.action)))
		for range 4 {
			_ = callAs(a, op, "")
		}
		if err := a.FlushSecurity(context.Background()); err != nil {
			t.Fatal(err)
		}
		ev := mem.OfKind(auth.SecurityRateLimit)
		if len(ev) != 1 {
			t.Fatalf("%s: %d rate events for 3 calls over the limit, want 1 per window", tc.action, len(ev))
		}
		e := ev[0]
		if e.Outcome != tc.outcome || e.Severity != tc.sev || e.Op != "r.op" || e.IP != "203.0.113.9" ||
			e.Attrs[auth.AttrLimit] != "1" || e.Attrs[auth.AttrRuleKey] != string(auth.ByIP) || e.Attrs[auth.AttrCount] != "2" {
			t.Fatalf("%s: event = %+v", tc.action, e)
		}
	}
}
