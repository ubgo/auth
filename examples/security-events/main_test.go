package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authtest"
	"github.com/ubgo/auth/plugin/password"
)

const (
	adaMail = "ada@example.com"
	adaPass = "correct horse battery staple"
	// sprayed is the one password an attacker tries against many accounts.
	sprayed = "Summer2026!"
	// appKind is a kind of the app's own, emitted through EmitSecurity.
	appKind auth.SecurityKind = "app.export"
	// appEvents is how many app events the batching test emits: more than two
	// batches' worth, so the drain must be called more than once.
	appEvents = 2*drainBatch + drainBatch/2
)

// testSecret is the deployment secret, exactly auth.MinSecretSize bytes.
var testSecret = []byte(strings.Repeat("s", auth.MinSecretSize))

// world is the app with the drain writing to the returned buffer, and ada
// signed up. withSinks false builds it with no sink at all.
func world(t *testing.T, withSinks bool, extra ...auth.Option) (*authtest.Env, *authtest.Browser, *bytes.Buffer) {
	t.Helper()
	drained := &bytes.Buffer{}
	opts := []auth.Option{auth.WithSecret(testSecret), auth.WithRateRules(signInRule())}
	if withSinks {
		opts = append(opts, securitySinks(drained)...)
	}
	e := authtest.New(t,
		authtest.WithOptions(append(opts, extra...)...),
		authtest.WithPlugins(func(*authtest.Env) []auth.Plugin { return plugins() }))
	b := e.Browser(newHandler(e.Auth))
	b.Post("/auth/password/sign-up", map[string]string{"identifier": adaMail, "password": adaPass, "name": "Ada"}).Expect(http.StatusOK)
	return e, b, drained
}

// signIn posts a password sign-in.
func signIn(b *authtest.Browser, identifier, pass string) *authtest.Response {
	return b.Post("/auth/password/sign-in", map[string]string{"identifier": identifier, "password": pass})
}

// stranger is the i-th address nobody signed up with, so each failed sign-in
// is a new account and a new password and only the address rule counts it.
func stranger(i int) (identifier, pass string) {
	return fmt.Sprintf("guess-%d@example.com", i), fmt.Sprintf("guess-%d-password", i)
}

// drain flushes the stream and decodes every JSON line the drain wrote.
func drain(t *testing.T, e *authtest.Env, buf *bytes.Buffer) []auth.SecurityEvent {
	t.Helper()
	if err := e.Auth.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	var out []auth.SecurityEvent
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for sc.Scan() {
		var ev auth.SecurityEvent
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("drain line %q: %v", sc.Text(), err)
		}
		out = append(out, ev)
	}
	return out
}

// ofKind keeps the events of one kind.
func ofKind(events []auth.SecurityEvent, k auth.SecurityKind) []auth.SecurityEvent {
	var out []auth.SecurityEvent
	for _, ev := range events {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

// overTheLimit makes signInsPerMinute failed sign-ins and then extra more,
// which the rule must refuse with 429. start numbers the strangers.
func overTheLimit(t *testing.T, b *authtest.Browser, start, extra int) {
	t.Helper()
	for i := range signInsPerMinute {
		id, pass := stranger(start + i)
		if code := signIn(b, id, pass).Expect(password.ErrInvalidCredentials.Status).ErrorCode(); code != password.ErrInvalidCredentials.Code {
			t.Fatalf("sign-in %d under the limit: %s", i+1, code)
		}
	}
	for i := range extra {
		id, pass := stranger(start + signInsPerMinute + i)
		if code := signIn(b, id, pass).Expect(http.StatusTooManyRequests).ErrorCode(); code != auth.ErrRateLimited.Code {
			t.Fatalf("sign-in %d over the limit: %s", i+1, code)
		}
	}
}

// TestSecurityEvents_OneRateEventPerWindow: three calls over the limit in a
// minute are one rate.limit event carrying the rule's details; the next
// window's excess is one more.
//
//ds:def id=securityevents-example-test-rate-3nw7kq5x
func TestSecurityEvents_OneRateEventPerWindow(t *testing.T) {
	e, b, buf := world(t, true)
	const refusedPerWindow = 3
	overTheLimit(t, b, 0, refusedPerWindow)
	got := ofKind(drain(t, e, buf), auth.SecurityRateLimit)
	if len(got) != 1 {
		t.Fatalf("%d rate.limit events for one window, want 1: %+v", len(got), got)
	}
	ev := got[0]
	want := map[string]string{
		auth.AttrRuleKey: string(auth.ByIP), auth.AttrLimit: strconv.Itoa(signInsPerMinute),
		auth.AttrWindow: time.Minute.String(), auth.AttrCount: strconv.Itoa(signInsPerMinute + 1),
	}
	for k, v := range want {
		if ev.Attrs[k] != v {
			t.Errorf("Attrs[%s] = %q, want %q", k, ev.Attrs[k], v)
		}
	}
	if ev.Outcome != auth.RateOutcomeBlocked || ev.Severity != auth.SeverityWarn || ev.Op != password.EndpointSignIn || ev.IP == "" || ev.ID == "" {
		t.Fatalf("event = %+v", ev)
	}

	e.Clock.Advance(time.Minute)
	overTheLimit(t, b, signInsPerMinute+refusedPerWindow, refusedPerWindow)
	if got := ofKind(drain(t, e, buf), auth.SecurityRateLimit); len(got) != 2 || got[1].ID == got[0].ID {
		t.Fatalf("after a second window: %d rate.limit events, want 2: %+v", len(got), got)
	}
}

// TestSecurityEvents_TheDrainGetsBatches: the drain is called with batches of
// at most drainBatch events, every event arrives once, and SecurityStats
// counts them per sink.
func TestSecurityEvents_TheDrainGetsBatches(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	counter := auth.SecuritySinkFunc(func(_ context.Context, batch []auth.SecurityEvent) error {
		mu.Lock()
		defer mu.Unlock()
		sizes = append(sizes, len(batch))
		return nil
	})
	e, _, buf := world(t, true, auth.WithSecuritySink(counter, auth.SecurityQueue{Name: "counter", BatchSize: drainBatch}))
	for range appEvents {
		e.Auth.EmitSecurity(auth.SecurityEvent{Kind: appKind})
	}
	if got := ofKind(drain(t, e, buf), appKind); len(got) != appEvents {
		t.Fatalf("the drain wrote %d app events, want %d", len(got), appEvents)
	}
	mu.Lock()
	defer mu.Unlock()
	total := 0
	for _, n := range sizes {
		if n > drainBatch {
			t.Fatalf("a batch of %d, over drainBatch %d: %v", n, drainBatch, sizes)
		}
		total += n
	}
	if total != appEvents || len(sizes) < appEvents/drainBatch+1 {
		t.Fatalf("batch sizes %v, want %d events in batches of at most %d", sizes, appEvents, drainBatch)
	}
	stats := e.Auth.SecurityStats()
	if len(stats) != 3 || stats[0].Name != drainName || stats[0].Delivered != appEvents || stats[0].Dropped != 0 || stats[1].Name != "log" {
		t.Fatalf("stats = %+v", stats)
	}
}

// TestSecurityEvents_SprayIsOneEventWithoutThePassword: the third failure of
// one password on three accounts crosses the guard's limit; the next sign-ins
// with it are refused before the password is checked, and the whole spray is
// one credential.stuffing event that carries no password.
//
//ds:def id=securityevents-example-test-spray-7xq2wn4k
func TestSecurityEvents_SprayIsOneEventWithoutThePassword(t *testing.T) {
	e, b, buf := world(t, true)
	for i := range sprayFailures {
		victim, _ := stranger(i)
		signIn(b, victim, sprayed).Expect(password.ErrInvalidCredentials.Status)
	}
	// Refused now for ada too, though her real password is never tried.
	if code := signIn(b, adaMail, sprayed).Expect(http.StatusTooManyRequests).ErrorCode(); code != auth.ErrRateLimited.Code {
		t.Fatalf("sprayed password after the crossing: %s", code)
	}
	events := drain(t, e, buf)
	got := ofKind(events, auth.SecurityCredentialStuffing)
	if len(got) != 1 {
		t.Fatalf("%d credential.stuffing events, want 1: %+v", len(got), got)
	}
	ev := got[0]
	if ev.Attrs[auth.AttrScope] != auth.ScopePassword || ev.Attrs[auth.AttrFailures] != strconv.Itoa(sprayFailures) ||
		ev.Severity != auth.SeverityAlert || ev.Outcome != auth.RateOutcomeBlocked || ev.Op != password.EndpointSignIn {
		t.Fatalf("event = %+v", ev)
	}
	if strings.Contains(buf.String(), sprayed) || strings.Contains(buf.String(), adaPass) {
		t.Fatalf("a password reached the drain: %s", buf)
	}
	if n := len(ofKind(events, auth.SecurityRateLimit)); n != 0 {
		t.Fatalf("%d rate.limit events; the spray stayed under the address rule", n)
	}
}

// TestSecurityEvents_NoSinkNoStream: with no sink registered the stream does
// not exist: SecurityStats is nil before and after calls over the limit, and
// EmitSecurity and FlushSecurity do nothing.
func TestSecurityEvents_NoSinkNoStream(t *testing.T) {
	e, b, _ := world(t, false)
	if s := e.Auth.SecurityStats(); s != nil {
		t.Fatalf("stats with no sink = %+v", s)
	}
	overTheLimit(t, b, 0, 1)
	e.Auth.EmitSecurity(auth.SecurityEvent{Kind: appKind})
	if err := e.Auth.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := e.Auth.SecurityStats(); s != nil {
		t.Fatalf("stats with no sink after events = %+v", s)
	}
}
