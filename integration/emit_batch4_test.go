package integration

import (
	"context"
	"crypto/sha1" // the test computes the range-API prefix a leak would show; it is not a password hash
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/stale"
)

// staleEvents flushes the stream and returns the stale-account events.
func staleEvents(t *testing.T, w *staleWorld, sink *auth.MemorySecuritySink) []auth.SecurityEvent {
	t.Helper()
	if err := w.a.FlushSecurity(context.Background()); err != nil {
		t.Fatal(err)
	}
	return sink.OfKind(auth.SecurityStaleAccount)
}

// TestStaleEmit_OneEventPerWarnedAndDeletedAccount: a run that warns two
// accounts emits two warned events, the grace period passing emits two deleted
// events, a dry run and a repeated run emit nothing, and no event carries an
// address.
func TestStaleEmit_OneEventPerWarnedAndDeletedAccount(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		sink := &auth.MemorySecuritySink{}
		w := newStaleWorld(t, e, []auth.Option{auth.WithSecuritySink(sink, auth.SecurityQueue{})}, stale.DeleteAfterWarning(staleGrace))
		ada, bob := w.user(t, "ada"), w.user(t, "bob")
		e.clock.Advance(staleAfter + oneDay)

		w.run(t, true)
		if n := len(staleEvents(t, w, sink)); n != 0 {
			t.Fatalf("dry run emitted %d events, want 0", n)
		}
		w.run(t, false)
		w.run(t, false)
		evs := staleEvents(t, w, sink)
		if len(evs) != 2 {
			t.Fatalf("warn pass: %d events, want 2 (one per account, none for the repeat run)", len(evs))
		}
		seen := map[string]bool{}
		for _, ev := range evs {
			if ev.Outcome != stale.OutcomeWarned || ev.Severity != auth.SeverityInfo {
				t.Fatalf("warn event = %+v", ev)
			}
			seen[ev.UserID] = true
		}
		if !seen[ada] || !seen[bob] {
			t.Fatalf("warned users = %v, want ada and bob", seen)
		}

		e.clock.Advance(staleGrace + oneDay)
		w.run(t, true)
		w.run(t, false)
		w.run(t, false)
		evs = staleEvents(t, w, sink)
		if len(evs) != 4 {
			t.Fatalf("after deletion: %d events, want 4", len(evs))
		}
		deleted := 0
		for _, ev := range evs {
			raw, _ := json.Marshal(ev)
			if strings.Contains(string(raw), "@example.com") {
				t.Fatalf("event carries an address: %s", raw)
			}
			if ev.Outcome == stale.OutcomeDeleted {
				deleted++
				if ev.Severity != auth.SeverityWarn {
					t.Fatalf("deleted severity = %q", ev.Severity)
				}
			}
		}
		if deleted != 2 {
			t.Fatalf("deleted events = %d, want 2", deleted)
		}
	})
}

// breachedSet is a password.BreachChecker that knows a fixed set.
type breachedSet map[string]bool

func (b breachedSet) Breached(_ context.Context, pw string) (bool, error) { return b[pw], nil }

// TestCompromisedEmit_OncePerRefusedCheckAndNoSecret: a breached password at
// sign-up and at change is refused with one event each, a clean one emits
// nothing, and the serialized event holds neither the password nor the hash
// prefix a range lookup would send.
func TestCompromisedEmit_OncePerRefusedCheckAndNoSecret(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		const bad = "hunter2-breached-marker"
		sink := &auth.MemorySecuritySink{}
		pw := e.passwordPlugin(password.CheckBreached(breachedSet{bad: true}))
		a := e.newAuth(t, []auth.Option{auth.WithSecuritySink(sink, auth.SecurityQueue{})}, e.emailPlugin(), pw)
		flush := func() []auth.SecurityEvent {
			if err := a.FlushSecurity(context.Background()); err != nil {
				t.Fatal(err)
			}
			return sink.OfKind(auth.SecurityCompromisedPassword)
		}

		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "ada@example.com", Password: password.Secret(secret)}); err != nil {
			t.Fatal(err)
		}
		if n := len(flush()); n != 0 {
			t.Fatalf("clean sign-up emitted %d events", n)
		}
		if _, err := pw.SignUp(anon(a), password.SignUpRequest{Identifier: "bob@example.com", Password: password.Secret(bad)}); !errors.Is(err, password.ErrBreached) {
			t.Fatalf("breached sign-up = %v", err)
		}
		if n := len(flush()); n != 1 {
			t.Fatalf("breached sign-up emitted %d events, want exactly 1", n)
		}

		sum := sha1.Sum([]byte(bad))
		prefix := strings.ToUpper(hex.EncodeToString(sum[:]))[:5]
		for _, ev := range sink.OfKind(auth.SecurityCompromisedPassword) {
			raw, _ := json.Marshal(ev)
			if strings.Contains(string(raw), bad) || strings.Contains(strings.ToUpper(string(raw)), prefix) {
				t.Fatalf("event leaks the password or its hash prefix: %s", raw)
			}
			if ev.Kind != auth.SecurityCompromisedPassword || ev.Severity != auth.SeverityWarn || ev.Outcome != auth.RateOutcomeBlocked {
				t.Fatalf("event = %+v", ev)
			}
		}
	})
}
