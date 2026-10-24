package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/agentauth"
)

// Round 38: the operations that produce the states the plugin already
// refused (a revoked host, a revoked grant, a claimed agent, agent
// metadata): revoke host, revoke capability, claim agent and update
// agent.

// autonomousEnv is newAAEnv with dynamic hosts, both modes, a read budget
// and a bot user for autonomous agents.
func autonomousEnv(t *testing.T, e *env, opts ...agentauth.Option) *aaEnv {
	t.Helper()
	return newAAEnv(t, e, append([]agentauth.Option{
		agentauth.AllowDynamicHostRegistration(), agentauth.Modes(agentauth.ModeDelegated, agentauth.ModeAutonomous),
		agentauth.DefaultHostCapabilities(aaRead), agentauth.AutonomousUser(func(_ context.Context, hostID, _ string) (*agentauth.SessionUser, error) {
			return &agentauth.SessionUser{ID: "bot:" + hostID}, nil
		}),
	}, opts...)...)
}

// A host revokes itself, or its owner revokes it: every agent under it is
// revoked with its grants, and the host's key is refused for good, by its
// own tokens, by dynamic registration and by CreateHost.
func TestAgentAuth_RevokeHost(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.OnEvent(ev.fn))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		_, reg2 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		if _, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg2.AgentID}); err != nil {
			t.Fatal(err)
		}
		revokeAs := func(b agentauth.Bearer, hostID string) (agentauth.RevokeHostResult, error) {
			return x.ag.RevokeHost(anon(x.a), agentauth.RevokeHostRequest{Bearer: b, HostID: hostID})
		}
		_, err := x.ag.RevokeHost(anon(x.a), agentauth.RevokeHostRequest{HostID: h.HostID})
		aaWant(t, "no credential", err, agentauth.ErrAuthenticationRequired)
		ok2, h2 := x.host(t)
		_, err = revokeAs(x.hostTok(t, ok2, h2.HostID), h.HostID)
		aaWant(t, "another host's id", err, agentauth.ErrUnauthorized)
		_, err = revokeAs(x.hostTok(t, aaNewKey(t), h.HostID), "")
		aaWant(t, "forged host token", err, agentauth.ErrInvalidJWT)

		res, err := revokeAs(x.hostTok(t, hk, h.HostID), "")
		if err != nil || res.HostID != h.HostID || res.Status != agentauth.HostRevoked || res.AgentsRevoked != 1 {
			t.Fatalf("host revokes itself: %+v %v", res, err)
		}
		_, err = x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID))
		aaWant(t, "agent of a revoked host", err, agentauth.ErrAgentRevoked)
		_, err = revokeAs(x.hostTok(t, hk, h.HostID), "")
		aaWant(t, "revoked host's own token", err, agentauth.ErrHostRevoked)
		_, err = x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg.AgentID})
		aaWant(t, "revoked host reads status", err, agentauth.ErrHostRevoked)
		_, err = x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{PublicKey: hk.pub})
		aaWant(t, "revoked key created again", err, agentauth.ErrHostRevoked)
		_, err = x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Bearer: x.dynTok(t, hk, nil)})
		aaWant(t, "revoked key registering dynamically", err, agentauth.ErrHostRevoked)
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventHostRevoked); len(got) != 1 || got[0].ActorType != agentauth.ActorHost || got[0].ActorID != h.HostID || got[0].HostID != h.HostID {
			t.Fatalf("host.revoked by the host: %+v", got)
		}

		// The owner revokes by id; nobody else can, and a second call is a
		// no-op.
		bob := x.signUp(t, aaBob)
		_, err = x.ag.RevokeHost(request(x.a, bob.Token), agentauth.RevokeHostRequest{HostID: h2.HostID})
		aaWant(t, "another user's host", err, agentauth.ErrHostNotFound)
		_, err = x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{})
		aaWant(t, "user without a host id", err, agentauth.ErrInvalidRequest)
		_, err = x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{HostID: "agh_nobody"})
		aaWant(t, "unknown host", err, agentauth.ErrHostNotFound)
		// A dynamic host nobody owns is nobody's to revoke.
		dk := aaNewKey(t)
		_, dreg := x.register(t, dk, "", agentauth.RegisterRequest{})
		_, err = x.ag.RevokeHost(request(x.a, bob.Token), agentauth.RevokeHostRequest{HostID: dreg.HostID})
		aaWant(t, "unowned host", err, agentauth.ErrHostNotFound)
		if res, err := x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{HostID: h2.HostID}); err != nil || res.AgentsRevoked != 0 || res.Status != agentauth.HostRevoked {
			t.Fatalf("owner revokes: %+v %v", res, err)
		}
		if res, err := x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{HostID: h.HostID}); err != nil || res.AgentsRevoked != 0 || res.Status != agentauth.HostRevoked {
			t.Fatalf("revoking a revoked host again: %+v %v", res, err)
		}
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventHostRevoked); len(got) != 3 || got[1].ActorType != agentauth.ActorUser || got[1].ActorID != x.alice.User.ID || got[1].HostID != h2.HostID {
			t.Fatalf("host.revoked by the owner: %+v", got)
		}

		// Over HTTP, with the host's JWT.
		hk3, h3 := x.host(t)
		code, body := aaHTTP(t, x.ag.Handler(), http.MethodPost, agentauth.PathRevokeHost, "Bearer "+x.hostTok(t, hk3, h3.HostID).Token, strings.NewReader(`{}`), "")
		if code != http.StatusOK || body["host_id"] != h3.HostID || body["status"] != string(agentauth.HostRevoked) {
			t.Fatalf("revoke over HTTP: %d %v", code, body)
		}
	})
}

// An agent, its host or its owner revokes single capabilities: every
// active or pending grant of the name is revoked, executing it answers
// grant_revoked, the budget does not grant it again, and nobody else can.
func TestAgentAuth_RevokeCapability(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.OnEvent(ev.fn))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		if pending, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capabilities: caps(aaTransfer)}); err != nil || pending.Approval == nil {
			t.Fatalf("request transfer: %+v %v", pending, err)
		}
		revoke := func(b agentauth.Bearer, ctx context.Context, agentID string, names ...string) (agentauth.RevokeCapabilityResult, error) {
			return x.ag.RevokeCapability(ctx, agentauth.RevokeCapabilityRequest{Bearer: b, AgentID: agentID, Capabilities: names})
		}
		_, err := revoke(x.agentTok(t, ak, reg.AgentID), anon(x.a), "")
		aaWant(t, "no capability", err, agentauth.ErrInvalidRequest)
		_, err = revoke(agentauth.Bearer{}, anon(x.a), reg.AgentID, aaRead)
		aaWant(t, "no credential", err, agentauth.ErrAuthenticationRequired)

		// The agent drops read itself, and names it twice.
		res, err := revoke(x.agentTok(t, ak, reg.AgentID), anon(x.a), "", aaRead, aaRead)
		if err != nil || res.AgentID != reg.AgentID || len(res.Revoked) != 1 || res.Revoked[0] != aaRead || len(res.GrantIDs) != 1 {
			t.Fatalf("agent revokes read: %+v %v", res, err)
		}
		_, err = x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capability: aaRead})
		aaWant(t, "executing a revoked capability", err, agentauth.ErrGrantRevoked)
		again, err := revoke(x.agentTok(t, ak, reg.AgentID), anon(x.a), "", aaRead)
		if err != nil || len(again.Revoked) != 0 || len(again.GrantIDs) != 0 {
			t.Fatalf("revoking again: %+v %v", again, err)
		}
		_, err = revoke(x.agentTok(t, ak, reg.AgentID), anon(x.a), "agt_other", aaRead)
		aaWant(t, "agent naming another", err, agentauth.ErrUnauthorized)

		// The host revokes the pending transfer request; another host cannot.
		ok2, h2 := x.host(t)
		_, err = revoke(x.hostTok(t, ok2, h2.HostID), anon(x.a), reg.AgentID, aaTransfer)
		aaWant(t, "another host", err, agentauth.ErrUnauthorized)
		res, err = revoke(x.hostTok(t, hk, h.HostID), anon(x.a), reg.AgentID, aaTransfer)
		if err != nil || len(res.Revoked) != 1 || res.Revoked[0] != aaTransfer {
			t.Fatalf("host revokes the pending grant: %+v %v", res, err)
		}
		st, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg.AgentID})
		if err != nil || len(st.Grants) != 2 || st.Grants[0].Status != agentauth.GrantRevoked || st.Grants[1].Status != agentauth.GrantRevoked {
			t.Fatalf("status after both revocations: %+v %v", st, err)
		}

		// The owner revokes a new agent's read; another user cannot; a
		// revoked agent has nothing left to revoke.
		_, reg3 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		bob := x.signUp(t, aaBob)
		_, err = revoke(agentauth.Bearer{}, request(x.a, bob.Token), reg3.AgentID, aaRead)
		aaWant(t, "another user", err, agentauth.ErrUnauthorized)
		_, err = revoke(agentauth.Bearer{}, request(x.a, bob.Token), "agt_nobody", aaRead)
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)
		if res, err := revoke(agentauth.Bearer{}, request(x.a, x.alice.Token), reg3.AgentID, aaRead); err != nil || len(res.Revoked) != 1 {
			t.Fatalf("owner revokes: %+v %v", res, err)
		}
		if _, err := x.ag.Revoke(request(x.a, x.alice.Token), agentauth.RevokeRequest{AgentID: reg3.AgentID}); err != nil {
			t.Fatal(err)
		}
		_, err = revoke(x.hostTok(t, hk, h.HostID), anon(x.a), reg3.AgentID, aaRead)
		aaWant(t, "revoked agent", err, agentauth.ErrAgentRevoked)
		_, err = revoke(x.hostTok(t, hk, h.HostID), anon(x.a), "agt_nobody", aaRead)
		aaWant(t, "host naming an unknown agent", err, agentauth.ErrAgentNotFound)
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventCapabilityRevoked); len(got) != 3 || got[2].ActorType != agentauth.ActorUser || got[2].Capabilities[0] != aaRead {
			t.Fatalf("capability.revoked: %+v", got)
		}

		// Over HTTP, with the agent's JWT.
		bk, breg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		code, body := aaHTTP(t, x.ag.Handler(), http.MethodPost, agentauth.PathRevokeCapability, "Bearer "+x.agentJWT(t, bk, breg.AgentID, nil), strings.NewReader(`{"capabilities":["read_data"]}`), "")
		if code != http.StatusOK || body["agent_id"] != breg.AgentID {
			t.Fatalf("revoke capability over HTTP: %d %v", code, body)
		}
	})
}

// A host starts the claim of an autonomous agent; the user who enters the
// claim's code owns the agent, which is claimed and authenticates nothing
// more, and its unowned host. Only the claim's own code claims, and every
// state that cannot be claimed is refused.
func TestAgentAuth_Claim(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := autonomousEnv(t, e, agentauth.OnEvent(ev.fn))
		ak, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Name: "Deployer", Mode: agentauth.ModeAutonomous})
		ck, ch := x.host(t)
		claim := func(b agentauth.Bearer, agentID string) (agentauth.ClaimResult, error) {
			return x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: b, AgentID: agentID})
		}
		_, err := claim(agentauth.Bearer{}, reg.AgentID)
		aaWant(t, "no token", err, agentauth.ErrAuthenticationRequired)
		_, err = claim(x.hostTok(t, ck, ch.HostID), "agt_nobody")
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)
		_, dreg := x.register(t, ck, ch.HostID, agentauth.RegisterRequest{})
		_, err = claim(x.hostTok(t, ck, ch.HostID), dreg.AgentID)
		aaWant(t, "delegated agent", err, agentauth.ErrUnsupportedMode)
		_, err = claim(agentauth.Bearer{Token: aaNewKey(t).jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": "agh_nobody"})}, reg.AgentID)
		aaWant(t, "unknown host without its key", err, agentauth.ErrInvalidJWT)

		// Without a claim request, approving an active autonomous agent
		// claims nothing.
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: "ABCD-EFGH"})
		aaWant(t, "approval without a claim request", err, agentauth.ErrInvalidUserCode)

		res, err := claim(x.hostTok(t, ck, ch.HostID), reg.AgentID)
		if err != nil || res.AgentID != reg.AgentID || res.HostID != reg.HostID || res.Mode != agentauth.ModeAutonomous || res.Status != agentauth.AgentActive ||
			len(res.Grants) != 1 || res.Approval == nil || res.Approval.Method != agentauth.MethodDeviceAuthorization || res.Approval.UserCode == "" {
			t.Fatalf("claim: %+v %v", res, err)
		}
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventApprovalCreated); len(got) != 1 || got[0].BindingMessage != `Claim autonomous agent "Deployer"` {
			t.Fatalf("approval.created for the claim: %+v", got)
		}

		// A wrong code, named or not, claims nothing.
		bob := x.signUp(t, aaBob)
		bobCtx := request(x.a, bob.Token)
		_, err = x.ag.ApproveCapability(bobCtx, agentauth.ApproveRequest{ApprovalID: res.Approval.DeviceCode, Action: agentauth.ActionApprove, UserCode: "WRONG-CODE"})
		aaWant(t, "wrong code on the named claim", err, agentauth.ErrInvalidUserCode)
		_, err = x.ag.ApproveCapability(bobCtx, agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: "WRONG-CODE"})
		aaWant(t, "wrong code", err, agentauth.ErrInvalidUserCode)

		// A denial resolves the claim and leaves the agent working.
		out, err := x.ag.ApproveCapability(bobCtx, agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionDeny, UserCode: res.Approval.UserCode})
		if err != nil || out.Status != agentauth.ApprovalDenied || out.Claimed {
			t.Fatalf("deny: %+v %v", out, err)
		}
		_, err = x.ag.ApproveCapability(bobCtx, agentauth.ApproveRequest{ApprovalID: res.Approval.DeviceCode, Action: agentauth.ActionApprove, UserCode: res.Approval.UserCode})
		aaWant(t, "a denied claim", err, agentauth.ErrApprovalResolved)
		if _, err := x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID)); err != nil {
			t.Fatalf("agent after a denied claim: %v", err)
		}

		// A new claim, approved by Bob with its code.
		res, err = claim(x.hostTok(t, ck, ch.HostID), reg.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		out, err = x.ag.ApproveCapability(bobCtx, agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: res.Approval.UserCode})
		if err != nil || out.Status != agentauth.ApprovalApproved || !out.Claimed || out.AgentID != reg.AgentID {
			t.Fatalf("approve the claim: %+v %v", out, err)
		}
		_, err = x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID))
		aaWant(t, "claimed agent", err, agentauth.ErrAgentClaimed)
		_, err = claim(x.hostTok(t, ck, ch.HostID), reg.AgentID)
		aaWant(t, "claiming a claimed agent", err, agentauth.ErrAgentClaimed)
		// Bob now owns the host: he revokes it, Alice cannot.
		_, err = x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{HostID: reg.HostID})
		aaWant(t, "Alice revokes Bob's host", err, agentauth.ErrHostNotFound)
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventAgentClaimed); len(got) != 1 || got[0].ActorID != bob.User.ID || got[0].AgentID != reg.AgentID {
			t.Fatalf("agent.claimed: %+v", got)
		}

		// The claimed agent is revoked with the host.
		if res, err := x.ag.RevokeHost(request(x.a, bob.Token), agentauth.RevokeHostRequest{HostID: reg.HostID}); err != nil || res.AgentsRevoked != 1 {
			t.Fatalf("Bob revokes the claimed host: %+v %v", res, err)
		}
	})
}

// The claim's edges: a dynamic host claiming on first contact, a second
// claim after the first was approved, a host already owned, an agent
// revoked before the approval, an expired claim, and the endpoint over
// HTTP.
func TestAgentAuth_ClaimEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := autonomousEnv(t, e)
		hk := aaNewKey(t)
		_, reg := x.register(t, hk, "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
		dyn := aaNewKey(t)
		// A dynamic host that has never registered claims, as a client SDK
		// does on its first contact.
		first, err := x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.dynTok(t, dyn, map[string]any{"agent_public_key": nil}), AgentID: reg.AgentID,
			ApprovalHints: agentauth.ApprovalHints{BindingMessage: "Take over the site"}})
		if err != nil || first.Approval == nil {
			t.Fatalf("dynamic host claims: %+v %v", first, err)
		}
		second, err := x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.dynTok(t, dyn, map[string]any{"agent_public_key": nil}), AgentID: reg.AgentID})
		if err != nil {
			t.Fatal(err)
		}
		bob := x.signUp(t, aaBob)
		if out, err := x.ag.ApproveCapability(request(x.a, bob.Token), agentauth.ApproveRequest{ApprovalID: first.Approval.DeviceCode, Action: agentauth.ActionApprove, UserCode: first.Approval.UserCode}); err != nil || !out.Claimed {
			t.Fatalf("first claim: %+v %v", out, err)
		}
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: second.Approval.DeviceCode, Action: agentauth.ActionApprove, UserCode: second.Approval.UserCode})
		aaWant(t, "second claim after the first", err, agentauth.ErrApprovalResolved)

		// An autonomous agent whose dynamic host a user has since taken with
		// CreateHost.
		h2 := aaNewKey(t)
		_, reg2 := x.register(t, h2, "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
		if _, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{PublicKey: h2.pub}); err != nil {
			t.Fatal(err)
		}
		_, err = x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.dynTok(t, dyn, map[string]any{"agent_public_key": nil}), AgentID: reg2.AgentID})
		aaWant(t, "host owned by someone", err, agentauth.ErrAgentClaimed)

		// Revoked between the claim and the approval.
		h3 := aaNewKey(t)
		_, reg3 := x.register(t, h3, "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
		c3, err := x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.dynTok(t, dyn, map[string]any{"agent_public_key": nil}), AgentID: reg3.AgentID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: x.hostTok(t, h3, reg3.HostID), AgentID: reg3.AgentID}); err != nil {
			t.Fatal(err)
		}
		_, err = x.ag.ApproveCapability(request(x.a, bob.Token), agentauth.ApproveRequest{AgentID: reg3.AgentID, Action: agentauth.ActionApprove, UserCode: c3.Approval.UserCode})
		aaWant(t, "revoked before approval", err, agentauth.ErrApprovalResolved)
		_, err = x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.dynTok(t, dyn, map[string]any{"agent_public_key": nil}), AgentID: reg3.AgentID})
		aaWant(t, "claiming a revoked agent", err, agentauth.ErrAgentNotFound)

		// Expired: the code is refused after the approval lifetime.
		h5 := aaNewKey(t)
		_, reg5 := x.register(t, h5, "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
		c5, err := x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.dynTok(t, dyn, map[string]any{"agent_public_key": nil}), AgentID: reg5.AgentID})
		if err != nil {
			t.Fatal(err)
		}
		e.clock.Advance(agentauth.DefaultApprovalTTL + time.Second)
		carol := x.signUp(t, "carol@example.com")
		_, err = x.ag.ApproveCapability(request(x.a, carol.Token), agentauth.ApproveRequest{AgentID: reg5.AgentID, Action: agentauth.ActionApprove, UserCode: c5.Approval.UserCode})
		aaWant(t, "expired claim", err, agentauth.ErrApprovalExpired)

		// Over HTTP, with a host JWT; discovery lists the endpoint.
		hk6, h6 := x.host(t)
		_, reg6 := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
		body := `{"agent_id":"` + reg6.AgentID + `","binding_message":"Claim it"}`
		code, m := aaHTTP(t, x.ag.Handler(), http.MethodPost, agentauth.PathClaim, "Bearer "+x.hostTok(t, hk6, h6.HostID).Token, strings.NewReader(body), "")
		if code != http.StatusOK || m["agent_id"] != reg6.AgentID || m["approval"] == nil {
			t.Fatalf("claim over HTTP: %d %v", code, m)
		}
		c, err := x.ag.Configuration(anon(x.a))
		if err != nil || c.Endpoints["claim"] != testBaseURL+agentauth.PathClaim || c.Endpoints["revoke_host"] != testBaseURL+agentauth.PathRevokeHost {
			t.Fatalf("discovery: %+v %v", c.Endpoints, err)
		}
	})
}

// The owner renames an agent and sets its metadata, which the agent's
// session carries; nobody else sees the agent; malformed metadata and an
// empty name are refused.
func TestAgentAuth_UpdateAgent(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.OnEvent(ev.fn))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Name: "Old"})
		ctx := request(x.a, x.alice.Token)
		update := func(ctx context.Context, in agentauth.UpdateAgentRequest) (agentauth.UpdateAgentResult, error) {
			return x.ag.UpdateAgent(ctx, in)
		}
		name := "  <i>Ops bot</i> "
		res, err := update(ctx, agentauth.UpdateAgentRequest{AgentID: reg.AgentID, Name: &name, Metadata: json.RawMessage(`{"team":"ops","tier":2,"on":true,"note":null}`)})
		if err != nil || res.Name != "Ops bot" || string(res.Metadata) != `{"note":null,"on":true,"team":"ops","tier":2}` || !res.UpdatedAt.Equal(x.a.Now()) {
			t.Fatalf("update: %+v %v", res, err)
		}
		s, err := x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID))
		if err != nil || s.Agent.Name != "Ops bot" || string(s.Agent.Metadata) != `{"note":null,"on":true,"team":"ops","tier":2}` {
			t.Fatalf("session after update: %+v %v", s.Agent, err)
		}
		// Neither field: the stored values stay.
		if res, err := update(ctx, agentauth.UpdateAgentRequest{AgentID: reg.AgentID}); err != nil || res.Name != "Ops bot" || string(res.Metadata) != `{"note":null,"on":true,"team":"ops","tier":2}` {
			t.Fatalf("empty update: %+v %v", res, err)
		}
		// {} clears the metadata.
		if res, err := update(ctx, agentauth.UpdateAgentRequest{AgentID: reg.AgentID, Metadata: json.RawMessage(`{}`)}); err != nil || string(res.Metadata) != `{}` {
			t.Fatalf("clear: %+v %v", res, err)
		}
		_, fresh := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		if res, err := update(ctx, agentauth.UpdateAgentRequest{AgentID: fresh.AgentID}); err != nil || res.Metadata != nil {
			t.Fatalf("no metadata: %+v %v", res, err)
		}

		blank := " <b></b> "
		bad := map[string]agentauth.UpdateAgentRequest{
			"empty name":  {AgentID: reg.AgentID, Name: &blank},
			"array":       {AgentID: reg.AgentID, Metadata: json.RawMessage(`["a"]`)},
			"nested":      {AgentID: reg.AgentID, Metadata: json.RawMessage(`{"a":{"b":1}}`)},
			"list value":  {AgentID: reg.AgentID, Metadata: json.RawMessage(`{"a":[1]}`)},
			"null":        {AgentID: reg.AgentID, Metadata: json.RawMessage(`null`)},
			"two objects": {AgentID: reg.AgentID, Metadata: json.RawMessage(`{}{}`)},
			"not json":    {AgentID: reg.AgentID, Metadata: json.RawMessage(`{"a":`)},
			"over 4 KiB":  {AgentID: reg.AgentID, Metadata: json.RawMessage(`{"a":"` + strings.Repeat("x", 4<<10) + `"}`)},
		}
		for what, in := range bad {
			_, err := update(ctx, in)
			aaWant(t, what, err, agentauth.ErrInvalidRequest)
		}
		bob := x.signUp(t, aaBob)
		_, err = update(request(x.a, bob.Token), agentauth.UpdateAgentRequest{AgentID: reg.AgentID, Name: &name})
		aaWant(t, "another user's agent", err, agentauth.ErrAgentNotFound)
		_, err = update(ctx, agentauth.UpdateAgentRequest{AgentID: "agt_nobody"})
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)
		_, err = update(anon(x.a), agentauth.UpdateAgentRequest{AgentID: reg.AgentID})
		if err == nil {
			t.Fatal("an anonymous caller updated an agent")
		}
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventAgentUpdated); len(got) != 4 || got[0].ActorID != x.alice.User.ID || got[0].AgentID != reg.AgentID {
			t.Fatalf("agent.updated: %+v", got)
		}
	})
}

// The new endpoints refuse a body that is not JSON, like every other.
func TestAgentAuthHTTP_Round38MalformedBodies(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		h := newAAEnv(t, e).ag.Handler()
		for _, path := range []string{agentauth.PathRevokeHost, agentauth.PathRevokeCapability, agentauth.PathClaim} {
			code, body := aaHTTP(t, h, http.MethodPost, path, "", strings.NewReader(`{not json`), "")
			if code != http.StatusBadRequest || body["error"] != "invalid_request" {
				t.Errorf("%s with a malformed body: %d %v", path, code, body)
			}
		}
	})
}

// Every database failure inside the new operations reaches the caller.
func TestAgentAuthFaults_Round38(t *testing.T) {
	auto := []agentauth.Option{
		agentauth.AllowDynamicHostRegistration(), agentauth.Modes(agentauth.ModeDelegated, agentauth.ModeAutonomous), agentauth.DefaultHostCapabilities(aaRead),
	}
	t.Run("revoke host", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
			return func() error {
				_, err := x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{HostID: h.HostID})
				return err
			}
		})
	})
	t.Run("revoke capability", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
			return func() error {
				_, err := x.ag.RevokeCapability(request(x.a, x.alice.Token), agentauth.RevokeCapabilityRequest{AgentID: reg.AgentID, Capabilities: []string{aaRead}})
				return err
			}
		})
	})
	t.Run("claim", func(t *testing.T) {
		aaSweep(t, auto, func(t *testing.T, x *aaEnv) func() error {
			_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
			ck, ch := x.host(t)
			return func() error {
				_, err := x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.hostTok(t, ck, ch.HostID), AgentID: reg.AgentID})
				return err
			}
		})
	})
	t.Run("approve a claim", func(t *testing.T) {
		aaSweep(t, auto, func(t *testing.T, x *aaEnv) func() error {
			_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
			ck, ch := x.host(t)
			res, err := x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.hostTok(t, ck, ch.HostID), AgentID: reg.AgentID})
			if err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: res.Approval.UserCode})
				return err
			}
		})
	})
	t.Run("deny a claim", func(t *testing.T) {
		aaSweep(t, auto, func(t *testing.T, x *aaEnv) func() error {
			_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
			ck, ch := x.host(t)
			res, err := x.ag.Claim(anon(x.a), agentauth.ClaimRequest{Bearer: x.hostTok(t, ck, ch.HostID), AgentID: reg.AgentID})
			if err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionDeny, UserCode: res.Approval.UserCode})
				return err
			}
		})
	})
	t.Run("update agent", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
			return func() error {
				_, err := x.ag.UpdateAgent(request(x.a, x.alice.Token), agentauth.UpdateAgentRequest{AgentID: reg.AgentID, Metadata: json.RawMessage(`{"a":1}`)})
				return err
			}
		})
	})
}
