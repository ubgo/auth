package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestClose_GivesUpOnAStuckSink: a sink that never returns cannot hang a
// shutdown. Close waits closeTimeout, says which sink did not drain, and
// returns.
func TestClose_GivesUpOnAStuckSink(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	sink := SecuritySinkFunc(func(context.Context, []SecurityEvent) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	var buf bytes.Buffer
	a, err := New(WithPlugins(scriptSignIn{}), WithLogger(slog.New(slog.NewTextHandler(&buf, nil))),
		WithSecuritySink(sink, SecurityQueue{Name: "stuck", BatchSize: 1, FlushEvery: time.Hour}))
	if err != nil {
		t.Fatal(err)
	}
	a.security.closeTimeout = 20 * time.Millisecond
	a.EmitSecurity(SecurityEvent{Kind: SecurityLockout})
	<-entered
	start := time.Now()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("Close took %v: a stuck sink must not hang it", time.Since(start))
	}
	if !strings.Contains(buf.String(), "did not drain") || !strings.Contains(buf.String(), "sink=stuck") {
		t.Fatalf("no report of the stuck sink: %s", buf.String())
	}
	close(release)
}

// TestSecurityOfCall_TakesTheCallersUser: an event about a signed-in call
// carries the user, and a call with none leaves the field empty.
func TestSecurityOfCall_TakesTheCallersUser(t *testing.T) {
	c := &Call{Op: OpInfo{ID: "x.op"}, Plugin: "x", Transport: TransportHTTP, Client: Client{IP: "203.0.113.1"}, User: &User{ID: "usr_1"}}
	e := securityOfCall(c, SecurityEvent{})
	if e.UserID != "usr_1" || e.Op != "x.op" || e.IP != "203.0.113.1" || e.Plugin != "x" || e.Transport != TransportHTTP {
		t.Fatalf("event = %+v", e)
	}
	if e := securityOfCall(c, SecurityEvent{UserID: "usr_2"}); e.UserID != "usr_2" {
		t.Fatalf("an event that names its user keeps it: %+v", e)
	}
	c.User = nil
	if e := securityOfCall(c, SecurityEvent{}); e.UserID != "" {
		t.Fatalf("signed-out call: %+v", e)
	}
	if e := securityOfCall(nil, SecurityEvent{Kind: SecurityLockout}); e.Kind != SecurityLockout || e.Op != "" {
		t.Fatalf("no call: %+v", e)
	}
}

// TestMemorySecuritySink_ResetForgets: Reset empties the sink, and Events
// returns a copy a caller cannot use to change it.
func TestMemorySecuritySink_ResetForgets(t *testing.T) {
	m := &MemorySecuritySink{}
	if err := m.WriteSecurity(context.Background(), []SecurityEvent{{Kind: SecurityLockout}}); err != nil {
		t.Fatal(err)
	}
	got := m.Events()
	got[0].Kind = SecurityRateLimit
	if m.Events()[0].Kind != SecurityLockout {
		t.Fatal("Events returned the sink's own slice")
	}
	m.Reset()
	if len(m.Events()) != 0 {
		t.Fatal("Reset left events behind")
	}
}

// TestSessionSignInHistory_ReportsAFailingSessionList: a deployment with no
// session list (stateless) is an error the sign-in logs, not a silent "no
// history", so a misconfigured WithTravelHistory is visible.
func TestSessionSignInHistory_ReportsAFailingSessionList(t *testing.T) {
	a, err := New(WithPlugins(scriptSignIn{}), WithStatelessSessions(sessKey))
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := SessionSignInHistory().PreviousSignIn(context.Background(), a, "usr_1")
	if found || !errors.Is(err, ErrSessionsUnavailable) {
		t.Fatalf("stateless history = found %v, err %v, want ErrSessionsUnavailable", found, err)
	}
}

// TestDrainQueued_WritesEachFullBatchAndKeepsTheRest: a flush that finds more
// events queued than one batch holds hands the sink full batches and returns
// the remainder unwritten. Called directly because through the worker the
// select between the channel and the flush request is random.
func TestDrainQueued_WritesEachFullBatchAndKeepsTheRest(t *testing.T) {
	var sizes []int
	sink := SecuritySinkFunc(func(_ context.Context, b []SecurityEvent) error {
		sizes = append(sizes, len(b))
		return nil
	})
	q := &securityQueue{cfg: SecurityQueue{BatchSize: 2}, sink: sink, ch: make(chan SecurityEvent, 8)}
	for range 5 {
		q.ch <- SecurityEvent{Kind: SecurityLockout}
	}
	rest := q.drainQueued(nil)
	if len(sizes) != 2 || sizes[0] != 2 || sizes[1] != 2 {
		t.Fatalf("written batches = %v, want [2 2]", sizes)
	}
	if len(rest) != 1 || len(q.ch) != 0 || q.delivered.Load() != 4 {
		t.Fatalf("rest = %d, queued = %d, delivered = %d, want 1, 0, 4", len(rest), len(q.ch), q.delivered.Load())
	}
}
