package integration

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/ubgo/auth/plugin/agentauth"
)

// OnEvent receives the audit events after the commit:
// host.created, agent.created, capability.requested, approval.created,
// capability.approved, approval.approved, capability.executed (success and
// error), agent.revoked.
func TestAgentAuth_Events(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var mu sync.Mutex
		var events []agentauth.Event
		x := newAAEnv(t, e, agentauth.OnEvent(func(_ context.Context, ev agentauth.Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		bearer := func() agentauth.Bearer { return agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)} }
		if _, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: bearer(), Capability: aaRead, Arguments: map[string]any{"id": "1"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: bearer(), Capability: aaTransfer}); err == nil {
			t.Fatal("ungranted execute succeeded")
		}
		req, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: bearer(), Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: req.Approval.UserCode}); err != nil {
			t.Fatal(err)
		}
		if _, err := x.ag.Revoke(request(x.a, x.alice.Token), agentauth.RevokeRequest{AgentID: reg.AgentID}); err != nil {
			t.Fatal(err)
		}
		x.a.WaitDeliveries()
		mu.Lock()
		defer mu.Unlock()
		var types []string
		var executed []agentauth.Event
		for _, ev := range events {
			types = append(types, ev.Type)
			if ev.Type == agentauth.EventCapabilityExecuted {
				executed = append(executed, ev)
			}
		}
		for _, want := range []string{agentauth.EventHostCreated, agentauth.EventAgentCreated, agentauth.EventCapabilityRequested, agentauth.EventApprovalCreated, agentauth.EventCapabilityApproved, agentauth.EventApprovalApproved, agentauth.EventAgentRevoked} {
			if !slices.Contains(types, want) {
				t.Fatalf("no %s in %v", want, types)
			}
		}
		statuses := []string{}
		for _, ev := range executed {
			statuses = append(statuses, ev.Status)
		}
		slices.Sort(statuses)
		if len(executed) != 2 || statuses[0] != agentauth.ExecutionError || statuses[1] != agentauth.ExecutionSuccess {
			t.Fatalf("executed events = %+v", executed)
		}
		for _, ev := range events {
			if ev.Type == agentauth.EventHostCreated && (ev.HostID != h.HostID || ev.ActorID != x.alice.User.ID) {
				t.Fatalf("host.created = %+v", ev)
			}
			if ev.Type == agentauth.EventAgentRevoked && ev.AgentID != reg.AgentID {
				t.Fatalf("agent.revoked = %+v", ev)
			}
		}
	})
}
