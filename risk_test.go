package auth_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/ubgo/auth"
)

// errVendor is the failure a broken check raises.
var errVendor = errors.New("reputation service down")

// riskAuth wires op, the memory sink and opts.
func riskAuth(t *testing.T, op auth.Operation, mem *auth.MemorySecuritySink, opts ...auth.Option) (*auth.Auth, error) {
	t.Helper()
	opts = append([]auth.Option{auth.WithPlugins(&stubPlugin{name: "g", ops: []auth.Operation{op}}), auth.WithSecuritySink(mem, auth.SecurityQueue{})}, opts...)
	a, err := newAuth(opts...)
	if err == nil {
		t.Cleanup(func() { _ = a.Close() })
	}
	return a, err
}

// badIP flags 203.0.113.66, fails on 203.0.113.99 and passes the rest.
var badIP = auth.IPReputationFunc(func(_ context.Context, ip netip.Addr) (auth.RiskVerdict, error) {
	switch ip.String() {
	case "203.0.113.66":
		return auth.RiskVerdict{Flagged: true, Reason: "tor-exit"}, nil
	case "203.0.113.99":
		return auth.RiskVerdict{}, errVendor
	}
	return auth.RiskVerdict{}, nil
})

// TestRisk_IPReputationActions: a flagged address is blocked, logged or
// challenged, and each emits exactly one event with the reason and never the
// address in the attributes.
func TestRisk_IPReputationActions(t *testing.T) {
	op := signInOp()
	mem := &auth.MemorySecuritySink{}
	a, err := riskAuth(t, op, mem, auth.WithIPReputation(badIP, auth.RiskPolicy{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := signInFrom(a, op, "203.0.113.66", ""); !errors.Is(err, auth.ErrSuspiciousIP) {
		t.Fatalf("flagged = %v, want ErrSuspiciousIP", err)
	}
	if err := signInFrom(a, op, "203.0.113.1", ""); err != nil {
		t.Fatalf("clean address refused: %v", err)
	}
	_ = a.FlushSecurity(context.Background())
	ev := mem.OfKind(auth.SecuritySuspiciousIP)
	if len(ev) != 1 || ev[0].Outcome != auth.RateOutcomeBlocked || ev[0].Attrs[auth.AttrReason] != "tor-exit" || ev[0].IP != "203.0.113.66" {
		t.Fatalf("events = %+v", ev)
	}

	opL := signInOp()
	memL := &auth.MemorySecuritySink{}
	aL, err := riskAuth(t, opL, memL, auth.WithIPReputation(badIP, auth.RiskPolicy{Action: auth.RateLog}))
	if err != nil {
		t.Fatal(err)
	}
	if err := signInFrom(aL, opL, "203.0.113.66", ""); err != nil {
		t.Fatalf("log action refused: %v", err)
	}
	_ = aL.FlushSecurity(context.Background())
	if ev := memL.OfKind(auth.SecuritySuspiciousIP); len(ev) != 1 || ev[0].Outcome != auth.RateOutcomeLogged {
		t.Fatalf("log events = %+v", ev)
	}

	opC := signInOp()
	memC := &auth.MemorySecuritySink{}
	aC, err := riskAuth(t, opC, memC, auth.WithIPReputation(badIP, auth.RiskPolicy{Action: auth.RateChallenge}),
		auth.WithPlugins(&challengerPlugin{stubPlugin{name: "proof"}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := signInFrom(aC, opC, "203.0.113.66", ""); !errors.Is(err, auth.ErrChallengeRequired) {
		t.Fatalf("no proof = %v", err)
	}
	if err := signInFrom(aC, opC, "203.0.113.66", "human"); err != nil {
		t.Fatalf("with proof = %v", err)
	}
	_ = aC.FlushSecurity(context.Background())
	ev = memC.OfKind(auth.SecuritySuspiciousIP)
	if len(ev) != 2 || ev[0].Outcome != auth.RateOutcomeChallenged || ev[1].Outcome != auth.RateOutcomePassed {
		t.Fatalf("challenge events = %+v", ev)
	}
}

// TestRisk_CheckErrorFailsOpenOrClosed: a check that errors lets the call
// through by default and refuses it with auth.risk_check_unavailable under
// RiskFailClosed; neither emits a flag event.
func TestRisk_CheckErrorFailsOpenOrClosed(t *testing.T) {
	for _, c := range []struct {
		name string
		mode auth.RiskErrorMode
		want error
	}{
		{"default is open", "", nil},
		{"open", auth.RiskFailOpen, nil},
		{"closed", auth.RiskFailClosed, auth.ErrRiskCheckFailed},
	} {
		t.Run(c.name, func(t *testing.T) {
			op := signInOp()
			mem := &auth.MemorySecuritySink{}
			a, err := riskAuth(t, op, mem, auth.WithIPReputation(badIP, auth.RiskPolicy{OnError: c.mode}))
			if err != nil {
				t.Fatal(err)
			}
			if err := signInFrom(a, op, "203.0.113.99", ""); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			_ = a.FlushSecurity(context.Background())
			if ev := mem.OfKind(auth.SecuritySuspiciousIP); len(ev) != 0 {
				t.Fatalf("a failed check emitted %+v", ev)
			}
		})
	}
}

// TestRisk_BotCheckSeesTheRequest: the checker gets the user agent, a header
// and the operation, and its flag blocks with auth.bot_blocked.
func TestRisk_BotCheckSeesTheRequest(t *testing.T) {
	var seen auth.BotSignals
	bot := auth.BotCheckerFunc(func(_ context.Context, s auth.BotSignals) (auth.RiskVerdict, error) {
		seen = s
		return auth.RiskVerdict{Flagged: s.Header(tenantHeader) == "scripted", Reason: strings.Repeat("x", auth.MaxRiskReasonLen+30)}, nil
	})
	op := signInOp()
	mem := &auth.MemorySecuritySink{}
	a, err := riskAuth(t, op, mem, auth.WithBotCheck(bot, auth.RiskPolicy{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := signInFrom(a, op, ipBerlin, "human"); err != nil {
		t.Fatalf("human refused: %v", err)
	}
	if err := signInFrom(a, op, ipBerlin, "scripted"); !errors.Is(err, auth.ErrBotDetected) {
		t.Fatalf("scripted = %v, want ErrBotDetected", err)
	}
	if seen.Op.ID != "g.sign-in" || seen.Client.IP != ipBerlin || seen.Transport != auth.TransportHTTP {
		t.Fatalf("signals = %+v", seen)
	}
	_ = a.FlushSecurity(context.Background())
	ev := mem.OfKind(auth.SecurityBot)
	if len(ev) != 1 || len(ev[0].Attrs[auth.AttrReason]) != auth.MaxRiskReasonLen {
		t.Fatalf("events = %+v", ev)
	}
}

// TestRisk_OnlySignedOutMutationsAndSignInsFromTheWire: a Go call and a
// signed-in or read-only operation are not judged.
func TestRisk_OnlySignedOutMutationsAndSignInsFromTheWire(t *testing.T) {
	calls := 0
	count := auth.IPReputationFunc(func(context.Context, netip.Addr) (auth.RiskVerdict, error) {
		calls++
		return auth.RiskVerdict{}, nil
	})
	op := signInOp()
	query := auth.Define(auth.OpInfo{ID: "g.read", Kind: auth.Query, Require: auth.Public, Path: "/read"},
		func(context.Context, *auth.Call, struct{}) (struct{}, error) { return struct{}{}, nil })
	a, err := riskAuth(t, op, &auth.MemorySecuritySink{}, auth.WithIPReputation(count, auth.RiskPolicy{}),
		auth.WithPlugins(&stubPlugin{name: "q", ops: []auth.Operation{query}}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Call(context.Background(), struct{}{}); err != nil {
		t.Fatal(err)
	}
	ctx := a.WithRequest(context.Background(), auth.Request{Transport: auth.TransportHTTP, Client: auth.Client{IP: ipBerlin}})
	if _, err := query.Call(ctx, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("checker ran %d times for a Go call and a query, want 0", calls)
	}
	if err := signInFrom(a, op, ipBerlin, ""); err != nil || calls != 1 {
		t.Fatalf("err = %v, calls = %d, want one judged sign-in", err, calls)
	}
}

// TestRisk_NewRefusesWhatCannotWork: nil checkers, unknown actions and modes,
// and a challenge with no challenger fail at New naming the option.
func TestRisk_NewRefusesWhatCannotWork(t *testing.T) {
	op := signInOp()
	plug := auth.WithPlugins(&stubPlugin{name: "g", ops: []auth.Operation{op}})
	trial := auth.TrialAbuseCheckerFunc(func(context.Context, auth.SignUpInfo) (auth.RiskVerdict, error) { return auth.RiskVerdict{}, nil })
	cases := []struct {
		name string
		opt  auth.Option
		want string
	}{
		{"nil ip", auth.WithIPReputation(nil, auth.RiskPolicy{}), "WithIPReputation"},
		{"nil bot", auth.WithBotCheck(nil, auth.RiskPolicy{}), "WithBotCheck"},
		{"nil trial", auth.WithTrialAbuseCheck(nil, auth.RiskPolicy{}), "WithTrialAbuseCheck"},
		{"unknown action", auth.WithIPReputation(badIP, auth.RiskPolicy{Action: "throttle"}), "unknown action"},
		{"unknown mode", auth.WithTrialAbuseCheck(trial, auth.RiskPolicy{OnError: "maybe"}), "unknown error mode"},
		{"challenge without challenger", auth.WithIPReputation(badIP, auth.RiskPolicy{Action: auth.RateChallenge}), "no challenger"},
		{"unknown bot action", auth.WithBotCheck(auth.BotCheckerFunc(func(context.Context, auth.BotSignals) (auth.RiskVerdict, error) {
			return auth.RiskVerdict{}, nil
		}), auth.RiskPolicy{Action: "throttle"}), "unknown action"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := newAuth(plug, c.opt)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestRisk_BotSignalsWithoutATransportHaveNoHeaders: signals built outside a
// request answer every header with "", not a panic.
func TestRisk_BotSignalsWithoutATransportHaveNoHeaders(t *testing.T) {
	if got := (auth.BotSignals{}).Header("User-Agent"); got != "" {
		t.Fatalf("Header = %q, want empty", got)
	}
}
