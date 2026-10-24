package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/password"
)

// Addresses the risk tests come from; documentation space.
const (
	riskBadIP  = "203.0.113.66"
	riskGoodIP = "203.0.113.67"
	riskDownIP = "203.0.113.99"
)

var errRiskVendor = errors.New("reputation service down")

// riskTable flags riskBadIP, fails on riskDownIP and passes the rest.
var riskTable = auth.IPReputationFunc(func(_ context.Context, ip netip.Addr) (auth.RiskVerdict, error) {
	switch ip.String() {
	case riskBadIP:
		return auth.RiskVerdict{Flagged: true, Reason: "datacenter"}, nil
	case riskDownIP:
		return auth.RiskVerdict{}, errRiskVendor
	}
	return auth.RiskVerdict{}, nil
})

// TestRisk_FlaggedSignInIsBlockedWithOneEvent: a real password sign-in from a
// flagged address is refused before the credentials are read (right and wrong
// password alike), the clean address signs in, and the stream holds one event.
func TestRisk_FlaggedSignInIsBlockedWithOneEvent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithIPReputation(riskTable, auth.RiskPolicy{}), auth.WithSecuritySink(mem, auth.SecurityQueue{})}, em, pw)
		signUpVerified(t, e, a, pw, em)
		for _, pass := range []password.Secret{secret, "not-the-password"} {
			_, err := pw.SignIn(fromIP(a, riskBadIP), password.SignInRequest{Identifier: alice, Password: pass})
			if !errors.Is(err, auth.ErrSuspiciousIP) {
				t.Fatalf("flagged address, password %q: %v, want ErrSuspiciousIP", pass, err)
			}
		}
		if _, err := pw.SignIn(fromIP(a, riskGoodIP), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("clean address: %v", err)
		}
		flushSecurity(t, a)
		ev := mem.OfKind(auth.SecuritySuspiciousIP)
		if len(ev) != 2 || ev[0].Outcome != auth.RateOutcomeBlocked || ev[0].Op != password.EndpointSignIn || ev[0].Attrs[auth.AttrReason] != "datacenter" {
			t.Fatalf("events = %+v", ev)
		}
	})
}

// TestRisk_LogActionLetsASignInThroughWithOneEvent: under RateLog the flagged
// sign-in succeeds and still emits exactly one event.
func TestRisk_LogActionLetsASignInThroughWithOneEvent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithIPReputation(riskTable, auth.RiskPolicy{Action: auth.RateLog}), auth.WithSecuritySink(mem, auth.SecurityQueue{})}, em, pw)
		signUpVerified(t, e, a, pw, em)
		if _, err := pw.SignIn(fromIP(a, riskBadIP), password.SignInRequest{Identifier: alice, Password: secret}); err != nil {
			t.Fatalf("logged sign-in refused: %v", err)
		}
		flushSecurity(t, a)
		if ev := mem.OfKind(auth.SecuritySuspiciousIP); len(ev) != 1 || ev[0].Outcome != auth.RateOutcomeLogged {
			t.Fatalf("events = %+v", ev)
		}
	})
}

// TestRisk_FailClosedRefusesWhenTheCheckIsDown: with the check erroring, the
// default signs in and RiskFailClosed refuses.
func TestRisk_FailClosedRefusesWhenTheCheckIsDown(t *testing.T) {
	for mode, wantErr := range map[auth.RiskErrorMode]error{auth.RiskFailOpen: nil, auth.RiskFailClosed: auth.ErrRiskCheckFailed} {
		t.Run(string(mode), func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				em, pw := e.emailPlugin(), e.passwordPlugin()
				a := e.newAuth(t, []auth.Option{auth.WithIPReputation(riskTable, auth.RiskPolicy{OnError: mode})}, em, pw)
				signUpVerified(t, e, a, pw, em)
				_, err := pw.SignIn(fromIP(a, riskDownIP), password.SignInRequest{Identifier: alice, Password: secret})
				if !errors.Is(err, wantErr) || (wantErr == nil && err != nil) {
					t.Fatalf("mode %q: %v, want %v", mode, err, wantErr)
				}
			})
		})
	}
}

// TestRisk_TrialAbuseBlocksTheSignUpAndLeavesNoUser: a flagged sign-up fails
// with auth.signup_blocked, emits one event naming the new user and the
// identifier kind but not its value, and leaves nobody behind.
func TestRisk_TrialAbuseBlocksTheSignUpAndLeavesNoUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		mem := &auth.MemorySecuritySink{}
		var seen auth.SignUpInfo
		check := auth.TrialAbuseCheckerFunc(func(_ context.Context, s auth.SignUpInfo) (auth.RiskVerdict, error) {
			seen = s
			return auth.RiskVerdict{Flagged: true, Reason: "repeat-address"}, nil
		})
		em, pw := e.emailPlugin(), e.passwordPlugin()
		a := e.newAuth(t, []auth.Option{auth.WithTrialAbuseCheck(check, auth.RiskPolicy{}), auth.WithSecuritySink(mem, auth.SecurityQueue{})}, em, pw)
		_, err := pw.SignUp(fromIP(a, riskGoodIP), password.SignUpRequest{Identifier: aliceRaw, Password: secret, Name: "Alice"})
		if !errors.Is(err, auth.ErrTrialAbuse) {
			t.Fatalf("sign-up = %v, want ErrTrialAbuse", err)
		}
		if len(seen.Identifiers) != 1 || seen.Identifiers[0].Value != alice || seen.Client.IP != riskGoodIP || seen.UserID == "" {
			t.Fatalf("checker saw %+v", seen)
		}
		if _, err := a.FindIdentity(context.Background(), "email", aliceRaw, false); err == nil {
			t.Fatal("the refused sign-up left an identity behind")
		}
		if _, err := a.User(context.Background(), seen.UserID); err == nil {
			t.Fatal("the refused sign-up left its user row behind")
		}
		flushSecurity(t, a)
		ev := mem.OfKind(auth.SecurityTrialAbuse)
		if len(ev) != 1 || ev[0].UserID != seen.UserID || ev[0].Attrs[auth.AttrReason] != "repeat-address" {
			t.Fatalf("events = %+v", ev)
		}
		for k, v := range ev[0].Attrs {
			if v == alice || v == aliceRaw {
				t.Fatalf("attribute %q carries the identifier", k)
			}
		}
	})
}

// TestRisk_TrialCheckFailsWhenTheIdentityLookupFails: the check needs to know
// whether this is the user's first identifier, and when the database cannot
// say it must not guess: the write fails and the checker is never asked.
func TestRisk_TrialCheckFailsWhenTheIdentityLookupFails(t *testing.T) {
	e := newFaultEnv(t)
	asked := false
	check := auth.TrialAbuseCheckerFunc(func(context.Context, auth.SignUpInfo) (auth.RiskVerdict, error) {
		asked = true
		return auth.RiskVerdict{}, nil
	})
	a := e.newAuth(t, []auth.Option{auth.WithTrialAbuseCheck(check, auth.RiskPolicy{})}, e.emailPlugin(), e.passwordPlugin())
	ctx := context.Background()
	u, err := a.CreateUser(ctx, auth.NewUser{Name: "Ada"})
	if err != nil {
		t.Fatal(err)
	}
	e.f.arm(1)
	_, err = a.CreateIdentity(ctx, auth.NewIdentity{UserID: u.ID, Kind: "email", Raw: aliceRaw})
	if !e.f.disarm() || err == nil || asked {
		t.Fatalf("err = %v, asked = %v: the lookup failure must fail the write before the checker runs", err, asked)
	}
}
