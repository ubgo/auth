package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ubgo/auth"
)

// challengerPlugin is a plugin that passes rate challenges: a call passes
// when its tenantHeader says "human".
type challengerPlugin struct{ stubPlugin }

func (*challengerPlugin) PassChallenge(_ context.Context, c *auth.Call) error {
	if c.Header(tenantHeader) == "human" {
		return nil
	}
	return auth.ErrChallengeRequired
}

// seamRule is a one-call-per-minute ByIP rule on seamOp with action.
func seamRule(action auth.RateAction) rulePlugin {
	return rulePlugin{rule: auth.RateRule{Match: "r.op", Key: auth.ByIP, Limit: 1, Window: time.Minute, Action: action}}
}

// TestRateAction_NewRefusesWhatCannotWork: an unknown action, a challenge
// rule nothing can pass, and two challengers are refused at New.
func TestRateAction_NewRefusesWhatCannotWork(t *testing.T) {
	op := seamOp()
	ops := &stubPlugin{name: "r", ops: []auth.Operation{op}}
	if _, err := newAuth(auth.WithPlugins(ops, seamRule("throttle"))); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("unknown action: %v, want ErrBadOperation", err)
	}
	if _, err := newAuth(auth.WithPlugins(ops, seamRule(auth.RateChallenge))); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("challenge without a challenger: %v, want ErrBadOperation", err)
	}
	two := auth.WithRateChallenger(auth.RateChallengerFunc(func(context.Context, *auth.Call) error { return nil }))
	if _, err := newAuth(two, auth.WithPlugins(ops, seamRule(auth.RateBlock), &challengerPlugin{stubPlugin{name: "proof"}})); !errors.Is(err, auth.ErrBadOperation) {
		t.Fatalf("two challengers: %v, want ErrBadOperation", err)
	}
	if _, err := newAuth(two, auth.WithPlugins(ops, seamRule(auth.RateChallenge))); err != nil {
		t.Fatalf("a challenge rule with WithRateChallenger: %v", err)
	}
}

// TestRateAction_ChallengeThroughAPlugin: a registered plugin that
// implements RateChallenger is the challenger without any option; under the
// limit nobody is asked.
func TestRateAction_ChallengeThroughAPlugin(t *testing.T) {
	op := seamOp()
	a, err := newAuth(auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}}, seamRule(auth.RateChallenge), &challengerPlugin{stubPlugin{name: "proof"}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := callAs(a, op, ""); err != nil {
		t.Fatalf("under the limit: %v", err)
	}
	if err := callAs(a, op, ""); !errors.Is(err, auth.ErrChallengeRequired) {
		t.Fatalf("over the limit without proof: %v, want ErrChallengeRequired", err)
	}
	if err := callAs(a, op, "human"); err != nil {
		t.Fatalf("over the limit with proof: %v", err)
	}
}

// refusingDecider refuses every call, deciding itself (RateDecider).
type refusingDecider struct{}

func (refusingDecider) Hit(context.Context, string, time.Duration) (int, error) { return 0, nil }

func (refusingDecider) Allow(context.Context, string, auth.RateRule) (bool, time.Duration, error) {
	return false, time.Second, nil
}

// TestRateAction_DeciderEventsHaveNoCount: a RateDecider reports no count,
// so its events carry Count 0 and are each FirstInWindow, and a log-only
// rule lets its refusals through.
func TestRateAction_DeciderEventsHaveNoCount(t *testing.T) {
	op := seamOp()
	var got []auth.RateEvent
	obs := rateObserver(func(e auth.RateEvent) { got = append(got, e) })
	a, err := newAuth(auth.WithRateStore(refusingDecider{}), auth.WithObserver(obs),
		auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}}, seamRule(auth.RateLog)))
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := callAs(a, op, ""); err != nil {
			t.Fatalf("log-only rule refused: %v", err)
		}
	}
	if len(got) != 2 || got[0].Count != 0 || !got[0].FirstInWindow() || !got[1].FirstInWindow() || got[0].Rule.Action != auth.RateLog {
		t.Fatalf("events = %+v", got)
	}
}

// TestRateEvent_FirstInWindow: only the call one past the limit is first.
func TestRateEvent_FirstInWindow(t *testing.T) {
	r := auth.RateRule{Limit: 3}
	for n, want := range map[int]bool{4: true, 5: false, 0: true} {
		if got := (auth.RateEvent{Rule: r, Count: n}).FirstInWindow(); got != want {
			t.Errorf("Count %d: FirstInWindow = %v, want %v", n, got, want)
		}
	}
}

// rateObserver adapts a function to an Observer that hears rate events.
type rateObserver func(auth.RateEvent)

func (rateObserver) Operation(context.Context, auth.OperationEvent) {}

func (f rateObserver) RateLimit(_ context.Context, e auth.RateEvent) { f(e) }

// TestRateAction_ChallengeThroughWithRateChallenger: a proof that is not a
// plugin is a RateChallengerFunc passed with WithRateChallenger; its error
// is the call's answer, so a rejected proof can say why.
func TestRateAction_ChallengeThroughWithRateChallenger(t *testing.T) {
	op := seamOp()
	errRejected := auth.NewError("test.proof_rejected", 403, "The proof was not accepted.")
	proof := auth.RateChallengerFunc(func(_ context.Context, c *auth.Call) error {
		switch c.Header(tenantHeader) {
		case "good":
			return nil
		case "":
			return auth.ErrChallengeRequired
		}
		return errRejected
	})
	a, err := newAuth(auth.WithRateChallenger(proof), auth.WithPlugins(&stubPlugin{name: "r", ops: []auth.Operation{op}}, seamRule(auth.RateChallenge)))
	if err != nil {
		t.Fatal(err)
	}
	if err := callAs(a, op, ""); err != nil {
		t.Fatalf("under the limit: %v", err)
	}
	if err := callAs(a, op, ""); !errors.Is(err, auth.ErrChallengeRequired) {
		t.Fatalf("no proof: %v", err)
	}
	if err := callAs(a, op, "forged"); !errors.Is(err, errRejected) {
		t.Fatalf("a rejected proof: %v, want the challenger's own error", err)
	}
	if err := callAs(a, op, "good"); err != nil {
		t.Fatalf("an accepted proof: %v", err)
	}
}
