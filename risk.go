package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
)

// Risk signals: three questions the library cannot answer itself and an app
// or a vendor can, asked at the points where the answer matters. Is this
// address known bad (IPReputation), is this request a script (BotChecker),
// is this sign-up someone who already used the free trial
// (TrialAbuseChecker). The library ships no detector and no vendor client:
// each is an interface, and everything is off until the app passes one.
//
// A flag reuses the actions of a rate rule (RateBlock, RateLog,
// RateChallenge, the RateChallenger from plugin/captcha or plugin/pow) and
// puts exactly one event on the security stream, so a flagged call is
// handled, logged and alerted on the way every other defence is.
//
// The IP and bot checks run in the pipeline, before the credentials are
// read, for every signed-out mutation (sign-in, sign-up, a reset or code
// request: the calls a script abuses) and every operation marked
// OpInfo.SignIn. A Go call is the app's own code and is not judged. The
// trial-abuse check runs where a user's first identifier is stored, which is
// the moment a sign-up has said who it is.

// RiskVerdict is a check's answer: whether it flags the subject, and why.
//
//ds:def id=core-riskverdict-7qk3xv8m owner=@khanakia stability=stable
type RiskVerdict struct {
	// Flagged is true when the check wants the policy's action applied.
	Flagged bool
	// Reason is a short machine-readable cause ("tor-exit", "datacenter",
	// "headless-ua") recorded on the event as AttrReason. It is cut to
	// MaxRiskReasonLen bytes, and must carry nothing secret or personal.
	Reason string
}

// MaxRiskReasonLen bounds RiskVerdict.Reason on an event, so a vendor's long
// message cannot flood the stream.
const MaxRiskReasonLen = 64

// RiskErrorMode says what a check that returned an error does to the call.
//
//ds:def id=core-riskerrormode-2vn8qt5w owner=@khanakia stability=stable
type RiskErrorMode string

// Error modes. The zero value "" is RiskFailOpen.
const (
	// RiskFailOpen lets the call through and logs a warning: a vendor outage
	// must not be a sign-in outage. The default.
	RiskFailOpen RiskErrorMode = "open"
	// RiskFailClosed refuses the call with ErrRiskCheckFailed (503) when the
	// check cannot answer, for an app that would rather lock people out than
	// let an unchecked sign-up through.
	RiskFailClosed RiskErrorMode = "closed"
)

// RiskErrorModeValues lists every mode, for a configuration screen or a test.
var RiskErrorModeValues = []RiskErrorMode{RiskFailOpen, RiskFailClosed}

// RiskPolicy is what a check does when it flags a call or fails. The zero
// value blocks a flagged call and fails open.
//
//ds:def id=core-riskpolicy-5kz9wm3x owner=@khanakia stability=stable
type RiskPolicy struct {
	// Action is what a flag does: RateBlock (the default, 403), RateLog
	// (record only, to measure a detector before enforcing it) or
	// RateChallenge (the RateChallenger decides). A challenge needs a
	// challenger, as for a rate rule.
	Action RateAction
	// OnError is what a check that returns an error does; see RiskErrorMode.
	OnError RiskErrorMode
}

// IPReputation judges a client address. It runs on the request's goroutine
// before the credentials are read, so it must be fast (a local list, a cache
// in front of a lookup service with a tight timeout). The address is never
// private-range-filtered: the check decides what an unknown address means.
//
//ds:def id=core-ipreputation-8wt4nq6k owner=@khanakia stability=stable
type IPReputation interface {
	CheckIP(ctx context.Context, ip netip.Addr) (RiskVerdict, error)
}

// IPReputationFunc adapts a function to IPReputation.
type IPReputationFunc func(ctx context.Context, ip netip.Addr) (RiskVerdict, error)

// CheckIP calls f.
func (f IPReputationFunc) CheckIP(ctx context.Context, ip netip.Addr) (RiskVerdict, error) {
	return f(ctx, ip)
}

// BotSignals is what a BotChecker sees of one request. It carries no
// credential and no input: those are not the bot check's business and must not
// reach a third-party service.
//
//ds:def id=core-botsignals-3mx7kq9v owner=@khanakia stability=stable
type BotSignals struct {
	// Op is the operation being called.
	Op OpInfo
	// Transport is how it arrived.
	Transport Transport
	// Client is the caller's address, user agent, origin and fetch site; IP
	// is "" when the transport did not supply one.
	Client Client

	header func(name string) string
}

// Header reads a request header the transport passed, or "" when there is
// none.
func (s BotSignals) Header(name string) string {
	if s.header == nil {
		return ""
	}
	return s.header(name)
}

// BotChecker judges whether a request comes from a script. It runs on the
// request's goroutine before the credentials are read.
//
//ds:def id=core-botchecker-6hv2xn4t owner=@khanakia stability=stable
type BotChecker interface {
	CheckBot(ctx context.Context, s BotSignals) (RiskVerdict, error)
}

// BotCheckerFunc adapts a function to BotChecker.
type BotCheckerFunc func(ctx context.Context, s BotSignals) (RiskVerdict, error)

// CheckBot calls f.
func (f BotCheckerFunc) CheckBot(ctx context.Context, s BotSignals) (RiskVerdict, error) {
	return f(ctx, s)
}

// SignUpIdentifier is one identifier of a new account, normalized.
type SignUpIdentifier struct {
	Kind  IdentifierKindName
	Value string
}

// SignUpInfo is what a TrialAbuseChecker sees of a new account.
//
//ds:def id=core-signupinfo-9rk5wq2n owner=@khanakia stability=stable
type SignUpInfo struct {
	// UserID is the new user's id.
	UserID string
	// Identifiers are the account's first identifier, normalized (the
	// address a "+tag" or dot-trick checker compares).
	Identifiers []SignUpIdentifier
	// Client is the caller's address and user agent; empty for a Go call.
	Client Client
}

// TrialAbuseChecker judges a new account: a repeat sign-up made to reuse a
// free trial, a throwaway address, a farm of accounts behind one address. It
// runs when the user's first identifier is stored.
//
//ds:def id=core-trialabusechecker-4tq8vk7m owner=@khanakia stability=stable
type TrialAbuseChecker interface {
	CheckSignUp(ctx context.Context, s SignUpInfo) (RiskVerdict, error)
}

// TrialAbuseCheckerFunc adapts a function to TrialAbuseChecker.
type TrialAbuseCheckerFunc func(ctx context.Context, s SignUpInfo) (RiskVerdict, error)

// CheckSignUp calls f.
func (f TrialAbuseCheckerFunc) CheckSignUp(ctx context.Context, s SignUpInfo) (RiskVerdict, error) {
	return f(ctx, s)
}

// Errors of the risk checks.
var (
	// ErrSuspiciousIP: IPReputation flagged the address under RateBlock.
	ErrSuspiciousIP = NewError("auth.ip_blocked", http.StatusForbidden, "This request cannot be completed from your network.")
	// ErrBotDetected: BotChecker flagged the request under RateBlock.
	ErrBotDetected = NewError("auth.bot_blocked", http.StatusForbidden, "This request looks automated. Try again from a browser.")
	// ErrTrialAbuse: TrialAbuseChecker flagged the sign-up under RateBlock.
	ErrTrialAbuse = NewError("auth.signup_blocked", http.StatusForbidden, "We could not create this account. Contact support if you think this is a mistake.")
	// ErrRiskCheckFailed: a check returned an error under RiskFailClosed.
	ErrRiskCheckFailed = NewError("auth.risk_check_unavailable", http.StatusServiceUnavailable, "This request cannot be checked right now. Try again shortly.")
)

// WithIPReputation turns on the IP check for signed-out mutations and
// sign-in operations. The policy's zero value blocks and fails open.
//
//ds:def id=opt-withipreputation-5wn3qk8x owner=@khanakia stability=stable
func WithIPReputation(c IPReputation, p RiskPolicy) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithIPReputation", c) {
			return
		}
		s.riskIP = &riskCheck[IPReputation]{checker: c, policy: p}
	}
}

// WithBotCheck turns on the bot check for signed-out mutations and sign-in
// operations. The policy's zero value blocks and fails open.
//
//ds:def id=opt-withbotcheck-7qm4xv2k owner=@khanakia stability=stable
func WithBotCheck(c BotChecker, p RiskPolicy) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithBotCheck", c) {
			return
		}
		s.riskBot = &riskCheck[BotChecker]{checker: c, policy: p}
	}
}

// WithTrialAbuseCheck turns on the sign-up check, run when a user's first
// identifier is stored. An account made without an identifier (a pure
// provider link) is not judged. A block returns the error from
// CreateIdentity, so the sign-up that called it fails with the user it
// created rolled back when the operation runs in a transaction.
//
//ds:def id=opt-withtrialabusecheck-2xk8wt6n owner=@khanakia stability=stable
func WithTrialAbuseCheck(c TrialAbuseChecker, p RiskPolicy) Option {
	return func(s *settings) {
		if s.optErrs.RefuseNil("auth.WithTrialAbuseCheck", c) {
			return
		}
		s.riskTrial = &riskCheck[TrialAbuseChecker]{checker: c, policy: p}
	}
}

// riskCheck is one configured check with its policy.
type riskCheck[T any] struct {
	checker T
	policy  RiskPolicy
}

// riskPolicy is the resolved risk configuration.
type riskPolicy struct {
	a     *Auth
	ip    *riskCheck[IPReputation]
	bot   *riskCheck[BotChecker]
	trial *riskCheck[TrialAbuseChecker]
}

// wireRisk validates the risk options at New, after the rate limiter (a
// challenge needs its challenger).
func (a *Auth) wireRisk(s *settings) error {
	if s.riskIP == nil && s.riskBot == nil && s.riskTrial == nil {
		return nil
	}
	r := &riskPolicy{a: a, ip: s.riskIP, bot: s.riskBot, trial: s.riskTrial}
	if r.ip != nil {
		if err := a.checkRiskPolicy("auth.WithIPReputation", &r.ip.policy); err != nil {
			return err
		}
	}
	if r.bot != nil {
		if err := a.checkRiskPolicy("auth.WithBotCheck", &r.bot.policy); err != nil {
			return err
		}
	}
	if r.trial != nil {
		if err := a.checkRiskPolicy("auth.WithTrialAbuseCheck", &r.trial.policy); err != nil {
			return err
		}
	}
	a.risk = r
	return nil
}

// checkRiskPolicy refuses an unknown action or error mode and resolves the
// zero values.
func (a *Auth) checkRiskPolicy(owner string, p *RiskPolicy) error {
	if err := a.checkGeoAction(owner, p.Action); err != nil {
		return err
	}
	if p.OnError != "" && !validRiskErrorMode(p.OnError) {
		return fmt.Errorf("%w: %s: unknown error mode %q", ErrBadOperation, owner, p.OnError)
	}
	p.Action = p.Action.orDefault()
	if p.OnError == "" {
		p.OnError = RiskFailOpen
	}
	return nil
}

func validRiskErrorMode(m RiskErrorMode) bool {
	for _, v := range RiskErrorModeValues {
		if v == m {
			return true
		}
	}
	return false
}

// verdict applies one check's answer: an error fails open or closed, a flag
// applies the action and emits one event, anything else passes.
func (r *riskPolicy) verdict(ctx context.Context, call *Call, p RiskPolicy, kind SecurityKind, refusal error, userID string, v RiskVerdict, err error) error {
	if err != nil {
		r.a.logger.Warn("auth: risk check failed", "kind", string(kind), "mode", string(p.OnError), "error", err)
		if p.OnError == RiskFailClosed {
			return ErrRiskCheckFailed
		}
		return nil
	}
	if !v.Flagged {
		return nil
	}
	reason := v.Reason
	if len(reason) > MaxRiskReasonLen {
		reason = reason[:MaxRiskReasonLen]
	}
	e := SecurityEvent{Kind: kind, Severity: SeverityWarn, UserID: userID, Attrs: map[string]string{AttrReason: reason}}
	return r.a.applyRiskAction(ctx, call, p.Action, e, refusal)
}

// checkRequest runs the IP and bot checks for one call, before the
// credentials are read. A Go call, and an operation that is neither a
// signed-out mutation nor a sign-in, passes.
func (r *riskPolicy) checkRequest(ctx context.Context, c *Call) error {
	if r == nil || c.Transport == TransportGo || !(c.Op.SignIn || (c.Op.Kind == Mutation && c.Op.Require == Public)) {
		return nil
	}
	if r.ip != nil && c.Client.IP != "" {
		if ip, perr := netip.ParseAddr(c.Client.IP); perr == nil {
			v, err := r.ip.checker.CheckIP(ctx, ip.Unmap())
			if err := r.verdict(ctx, c, r.ip.policy, SecuritySuspiciousIP, ErrSuspiciousIP, "", v, err); err != nil {
				return err
			}
		}
	}
	if r.bot != nil {
		v, err := r.bot.checker.CheckBot(ctx, BotSignals{Op: c.Op, Transport: c.Transport, Client: c.Client, header: c.header})
		if err := r.verdict(ctx, c, r.bot.policy, SecurityBot, ErrBotDetected, "", v, err); err != nil {
			return err
		}
	}
	return nil
}

// checkSignUp runs the trial-abuse check when idn is the user's first
// identifier.
func (r *riskPolicy) checkSignUp(ctx context.Context, idn Identity) error {
	if r == nil || r.trial == nil {
		return nil
	}
	existing, err := r.a.Identities(ctx, idn.UserID)
	if err != nil || len(existing) > 0 {
		return err
	}
	call, _ := callOf(ctx)
	info := SignUpInfo{UserID: idn.UserID, Identifiers: []SignUpIdentifier{{Kind: idn.Kind, Value: idn.Value}}}
	if call != nil {
		info.Client = call.Client
	}
	v, cerr := r.trial.checker.CheckSignUp(ctx, info)
	return r.verdict(ctx, call, r.trial.policy, SecurityTrialAbuse, ErrTrialAbuse, idn.UserID, v, cerr)
}
