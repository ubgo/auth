package auth

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
)

// Graded rate actions: what a rate rule does with a call over its limit.
// better-auth's Sentinel names the same three per feature (log, challenge,
// block). Block is today's behaviour and the default, so a rule written
// before actions existed refuses exactly as it did.

// RateAction says what a rule does with a call over its limit.
//
//ds:def id=core-rateaction-4kz8wq2n owner=@khanakia stability=stable
type RateAction string

// Rate actions. The zero value "" is RateBlock.
const (
	// RateBlock refuses the call with ErrRateLimited (HTTP 429 and a
	// Retry-After), as every rule did before actions existed.
	RateBlock RateAction = "block"
	// RateLog lets the call through and reports it: the observer, every
	// RateEventListener plugin (plugin/audit) and the logger hear of it. It
	// is how a new limit is measured against real traffic before it is
	// turned into a block.
	RateLog RateAction = "log"
	// RateChallenge lets the call through only when it carries a proof the
	// RateChallenger accepts (a captcha, plugin/captcha, or a proof of work,
	// plugin/pow), and
	// otherwise answers ErrChallengeRequired, so a human behind a busy
	// address is asked to prove it rather than shut out.
	RateChallenge RateAction = "challenge"
)

// RateActionValues lists every action, for a configuration screen or a test
// that walks them.
var RateActionValues = []RateAction{RateBlock, RateLog, RateChallenge}

// orDefault is the action a rule applies: its own, or RateBlock for "".
func (x RateAction) orDefault() RateAction {
	if x == "" {
		return RateBlock
	}
	return x
}

// RateOutcome is what happened to one call over a rule's limit.
//
//ds:def id=core-rateoutcome-7mq3xv5k owner=@khanakia stability=stable
type RateOutcome string

// Rate outcomes, one per RateEvent.
const (
	// RateOutcomeBlocked: a RateBlock rule refused the call.
	RateOutcomeBlocked RateOutcome = "blocked"
	// RateOutcomeLogged: a RateLog rule let the call through.
	RateOutcomeLogged RateOutcome = "logged"
	// RateOutcomeChallenged: a RateChallenge rule refused the call, because
	// it carried no proof (ErrChallengeRequired) or one the challenger
	// rejected (the challenger's error, such as captcha.ErrFailed).
	RateOutcomeChallenged RateOutcome = "challenged"
	// RateOutcomePassed: a RateChallenge rule let the call through because
	// its proof was accepted.
	RateOutcomePassed RateOutcome = "challenge_passed"
)

// RateOutcomeValues lists every outcome.
var RateOutcomeValues = []RateOutcome{RateOutcomeBlocked, RateOutcomeLogged, RateOutcomeChallenged, RateOutcomePassed}

// RateEvent describes one call over a rule's limit, whatever the rule's
// action did with it. It carries no input and no client address: like
// OperationEvent it may travel to a metrics sink. A RateEventListener plugin
// gets the Call beside it for anything more.
//
//ds:def id=core-rateevent-2vn6tq8h owner=@khanakia stability=stable
type RateEvent struct {
	Op        OpInfo
	Plugin    string
	Transport Transport
	// Rule is the rule that was over its limit, with Action resolved (never
	// ""). For WithRateLimit's blanket rule Match is the call's operation.
	Rule    RateRule
	Outcome RateOutcome
	// Count is the call's number in the rule's current window: Limit+1 for
	// the first call over it. 0 when a RateDecider store decided, since a
	// decider reports no count.
	Count int
	// Err is the error the caller got: ErrRateLimited (blocked),
	// ErrChallengeRequired or the challenger's error (challenged); nil when
	// the call went through (logged, challenge passed).
	Err error
}

// FirstInWindow reports whether the event is the first over the limit in its
// window (Count is Limit+1), or one whose count is unknown (a RateDecider).
// The logger and plugin/audit record only these, so a flood against one key
// writes one line per window instead of one per request; the observer sees
// every event and can count them all.
//
//ds:def id=core-rateevent-firstinwindow-6pk2mx9r owner=@khanakia stability=stable
func (e RateEvent) FirstInWindow() bool { return e.Count == 0 || e.Count == e.Rule.Limit+1 }

// RateObserver is the optional upgrade of the WithObserver Observer that is
// also told of every call over a rule's limit: blocked, logged, challenged
// or passed. It runs on the request's goroutine and must be quick, like
// Observer.Operation.
//
//ds:def id=core-rateobserver-9wd4kn7t owner=@khanakia stability=stable
type RateObserver interface {
	RateLimit(ctx context.Context, e RateEvent)
}

// RateEventListener is a plugin that records calls over a rule's limit:
// plugin/audit writes one audit event per FirstInWindow event. It runs on the
// request's goroutine, before the operation's transaction exists, so a write
// goes to the database directly. It returns nothing: a listener's failure is
// its own to log and never changes the call's answer.
//
//ds:def id=core-rateeventlistener-3hx7vm2q owner=@khanakia stability=stable
type RateEventListener interface {
	RateEvent(ctx context.Context, c *Call, e RateEvent)
}

// RateChallenger decides whether a call over a RateChallenge rule carries an
// accepted proof: a captcha token, a proof of work, a fresh second factor.
// PassChallenge returns nil to let the call through, ErrChallengeRequired
// when the call carries no proof (so the client knows to ask for one), and
// another error, ideally an *Error, for a proof it rejects or cannot check;
// that error is the call's answer. It sees the Call before the session is
// resolved and, for ByIP rules, before the input is decoded, so it reads
// c.Header and c.Client.
//
// plugin/captcha implements it with its Verifier, plugin/pow with a proof of
// work; registering either plugin is enough to make it the challenger, or
// WithRateChallenger sets another.
//
//ds:def id=core-ratechallenger-5qt8nw3x owner=@khanakia stability=stable
type RateChallenger interface {
	PassChallenge(ctx context.Context, c *Call) error
}

// RateChallengerFunc adapts a function to RateChallenger.
type RateChallengerFunc func(ctx context.Context, c *Call) error

// PassChallenge calls f.
func (f RateChallengerFunc) PassChallenge(ctx context.Context, c *Call) error { return f(ctx, c) }

// WithRateChallenger sets what passes a RateChallenge rule's challenge, for
// an app whose proof is not a registered plugin's (a proof of work, its own
// captcha service). Without it the one registered plugin that implements
// RateChallenger (plugin/captcha or plugin/pow) is used. New refuses two challengers (the
// option and such a plugin, or two such plugins), since which one a client
// must satisfy would be ambiguous, and refuses a RateChallenge rule with no
// challenger at all, since nothing could ever pass it.
//
//ds:def id=opt-withratechallenger-8nk3vz6m owner=@khanakia stability=stable
func WithRateChallenger(ch RateChallenger) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithRateChallenger", ch) {
			return
		}
		s.rateChallenger = ch
	}
}

// resolveRateEvents settles the challenger and the listeners at New, after
// the rules are known: one challenger at most, and one whenever a rule
// challenges.
func (l *limiter) resolveRateEvents(a *Auth, fromOption RateChallenger) error {
	l.logger = a.logger
	if o, ok := a.observer.(RateObserver); ok {
		l.observer = o
	}
	l.challenger = fromOption
	source := "auth.WithRateChallenger"
	for _, p := range a.plugins {
		if ln, ok := p.(RateEventListener); ok {
			l.listeners = append(l.listeners, ln)
		}
		ch, ok := p.(RateChallenger)
		if !ok {
			continue
		}
		if l.challenger != nil {
			return fmt.Errorf("%w: two rate challengers: %s and plugin %q; keep one", ErrBadOperation, source, p.Name())
		}
		l.challenger, source = ch, fmt.Sprintf("plugin %q", p.Name())
	}
	if l.challenger != nil {
		return nil
	}
	for _, rules := range l.rules {
		for _, r := range rules {
			if r.Action == RateChallenge {
				return fmt.Errorf("%w: rate rule for %q challenges, and no challenger is registered: add plugin/captcha, plugin/pow or auth.WithRateChallenger", ErrBadOperation, r.Match)
			}
		}
	}
	return nil
}

// validRateAction reports whether a rule's action is known; "" is RateBlock.
func validRateAction(x RateAction) bool { return x == "" || slices.Contains(RateActionValues, x) }

// exceeded applies a rule's action to a call over its limit, reports the
// event and returns the call's answer: nil to let it through. refusal is
// what a block answers (ErrRateLimited with its Retry-After); n is the
// call's count, 0 under a RateDecider.
func (l *limiter) exceeded(ctx context.Context, c *Call, r RateRule, n int, refusal error) error {
	r.Action = r.Action.orDefault()
	e := RateEvent{Rule: r, Count: n}
	if c != nil {
		e.Op, e.Plugin, e.Transport = c.Op, c.Plugin, c.Transport
	}
	switch r.Action {
	case RateLog:
		e.Outcome = RateOutcomeLogged
	case RateChallenge:
		// The challenger is settled at New: a challenge rule without one
		// is refused there.
		if err := l.challenger.PassChallenge(ctx, c); err != nil {
			e.Outcome, e.Err = RateOutcomeChallenged, err
		} else {
			e.Outcome = RateOutcomePassed
		}
	default:
		e.Outcome, e.Err = RateOutcomeBlocked, refusal
	}
	l.report(ctx, c, e)
	return e.Err
}

// report hands one event to the observer, every listener plugin and, once
// per window, the logger: a log-only rule at Warn, since being heard is its
// whole job, the others at Info. The line names the rule, never the value it
// counted (an address, an identifier).
func (l *limiter) report(ctx context.Context, c *Call, e RateEvent) {
	if l.logger != nil && e.FirstInWindow() {
		level := slog.LevelInfo
		if e.Outcome == RateOutcomeLogged {
			level = slog.LevelWarn
		}
		l.logger.Log(ctx, level, "auth: rate rule exceeded", "op", string(e.Op.ID), "key", string(e.Rule.Key),
			"limit", e.Rule.Limit, "window", e.Rule.Window, "action", string(e.Rule.Action), "outcome", string(e.Outcome))
	}
	l.a.securityOfRate(c, e)
	if l.observer != nil {
		l.observer.RateLimit(ctx, e)
	}
	for _, ln := range l.listeners {
		ln.RateEvent(ctx, c, e)
	}
}
