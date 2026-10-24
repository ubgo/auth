package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/auth/plugin/agentauth/agentclient"
	"github.com/ubgo/auth/plugin/passkey"
)

// aaEvents collects OnEvent deliveries.
type aaEvents struct {
	mu  sync.Mutex
	all []agentauth.Event
}

func (r *aaEvents) fn(_ context.Context, e agentauth.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.all = append(r.all, e)
}

func (r *aaEvents) of(typ string) []agentauth.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []agentauth.Event
	for _, e := range r.all {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// Round 34, CIBA: an agent that prefers CIBA gets a request addressed to
// the host's owner, who finds it in the inbox and answers it by id; nobody
// else can, and the agent polls status until it is active.
func TestAgentAuth_CIBAFromRegistration(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.OnEvent(ev.fn))
		hk, h := x.host(t)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{
			Capabilities:  []agentauth.CapabilityRequest{{Name: aaTransfer}},
			ApprovalHints: agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA, BindingMessage: "Pay the <b>rent</b>"},
		})
		if reg.Status != agentauth.AgentPending || reg.Approval == nil || reg.Approval.Method != agentauth.MethodCIBA || reg.Approval.UserCode != "" || reg.Approval.ExpiresIn != 300 {
			t.Fatalf("register: %+v %+v", reg, reg.Approval)
		}
		inbox, err := x.ag.PendingApprovalsFor(request(x.a, x.alice.Token))
		if err != nil || len(inbox.Requests) != 1 {
			t.Fatalf("inbox: %+v %v", inbox, err)
		}
		req := inbox.Requests[0]
		if req.Method != agentauth.MethodCIBA || req.AgentID != reg.AgentID || req.AgentName == nil || *req.AgentName != "Agent" ||
			req.BindingMessage == nil || *req.BindingMessage != "Pay the rent" || !slices.Equal(req.Capabilities, []string{aaTransfer}) {
			t.Fatalf("inbox entry: %+v", req)
		}
		x.a.WaitDeliveries()
		created := ev.of(agentauth.EventApprovalCreated)
		if len(created) != 1 || created[0].Method != agentauth.MethodCIBA || created[0].UserID == nil || *created[0].UserID != x.alice.User.ID || created[0].ApprovalID != req.ApprovalID {
			t.Fatalf("approval.created: %+v", created)
		}

		// Bob is signed in too, but the request was not addressed to him.
		bob := x.signUp(t, aaBob)
		_, err = x.ag.ApproveCapability(request(x.a, bob.Token), agentauth.ApproveRequest{ApprovalID: req.ApprovalID, Action: agentauth.ActionApprove})
		aaWant(t, "another user", err, agentauth.ErrApprovalOwnerMismatch)
		if inbox, _ := x.ag.PendingApprovalsFor(request(x.a, bob.Token)); len(inbox.Requests) != 0 {
			t.Fatalf("bob's inbox: %+v", inbox)
		}
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: "aap_missing", Action: agentauth.ActionApprove})
		aaWant(t, "unknown approval id", err, agentauth.ErrApprovalNotFound)
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{Action: agentauth.ActionApprove})
		aaWant(t, "neither id", err, agentauth.ErrInvalidRequest)

		res, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: req.ApprovalID, Action: agentauth.ActionApprove})
		if err != nil || res.Status != agentauth.ApprovalApproved || !slices.Equal(res.Added, []string{aaTransfer}) {
			t.Fatalf("approve: %+v %v", res, err)
		}
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: req.ApprovalID, Action: agentauth.ActionApprove})
		aaWant(t, "answered twice", err, agentauth.ErrApprovalResolved)
		st, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID})}, AgentID: reg.AgentID})
		if err != nil || st.Status != agentauth.AgentActive {
			t.Fatalf("status: %+v %v", st, err)
		}
		if _, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}, Capability: aaTransfer}); err != nil {
			t.Fatalf("execute: %v", err)
		}

		// Without a preference, or with CIBA switched off, the code flow.
		_, dev := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		if dev.Approval == nil || dev.Approval.Method != agentauth.MethodDeviceAuthorization || dev.Approval.UserCode == "" {
			t.Fatalf("default method: %+v", dev.Approval)
		}
	})
}

// A CIBA request is answered with the code-less path only by its user, and
// an agent owned by nobody yet cannot get one (no user to address).
func TestAgentAuth_CIBAAuthorizeEndpoint(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t)
		hostJWT := func() agentauth.Bearer {
			return agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID})}
		}
		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})

		real, err := x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{Bearer: hostJWT(), LoginHint: alice, AgentID: reg.AgentID, Capabilities: []string{aaTransfer}, BindingMessage: "ok?"})
		if err != nil || real.AuthReqID == "" || real.ExpiresIn != 300 || real.Interval != 5 {
			t.Fatalf("authorize: %+v %v", real, err)
		}
		fake, err := x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{Bearer: hostJWT(), LoginHint: "nobody@example.com", AgentID: reg.AgentID})
		if err != nil || fake.AuthReqID == "" || fake.ExpiresIn != real.ExpiresIn || fake.Interval != real.Interval {
			t.Fatalf("unknown hint must look the same: %+v %v", fake, err)
		}
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: fake.AuthReqID, Action: agentauth.ActionApprove})
		aaWant(t, "the fake request", err, agentauth.ErrApprovalOwnerMismatch)

		// Another host's agent is not this host's to ask about.
		ok, oh := x.host(t)
		_, otherReg := x.register(t, ok, oh.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		_, err = x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{Bearer: hostJWT(), LoginHint: alice, AgentID: otherReg.AgentID})
		aaWant(t, "another host's agent", err, agentauth.ErrAgentNotFound)
		_, err = x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{LoginHint: alice, AgentID: reg.AgentID})
		aaWant(t, "no host JWT", err, agentauth.ErrAuthenticationRequired)
		_, err = x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{Bearer: hostJWT(), LoginHint: alice, AgentID: reg.AgentID, Capabilities: []string{"unheard_of"}})
		aaWant(t, "unknown capability", err, agentauth.ErrInvalidCapabilities)

		res, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: real.AuthReqID, Action: agentauth.ActionApprove})
		if err != nil || res.Status != agentauth.ApprovalApproved {
			t.Fatalf("approve the real request: %+v %v", res, err)
		}

		// An agent no user owns yet (ForceApproval): the request itself is
		// what names Alice, so Bob cannot answer it.
		_, forced := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}, ForceApproval: true})
		toAlice, err := x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{Bearer: hostJWT(), LoginHint: alice, AgentID: forced.AgentID})
		if err != nil {
			t.Fatal(err)
		}
		bob := x.signUp(t, aaBob)
		_, err = x.ag.ApproveCapability(request(x.a, bob.Token), agentauth.ApproveRequest{ApprovalID: toAlice.AuthReqID, Action: agentauth.ActionApprove})
		aaWant(t, "bob answers alice's request", err, agentauth.ErrApprovalOwnerMismatch)
		if res, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: toAlice.AuthReqID, Action: agentauth.ActionApprove}); err != nil || res.Status != agentauth.ApprovalApproved {
			t.Fatalf("alice answers: %+v %v", res, err)
		}

	})
}

// Device authorization only: a CIBA preference falls back and the
// endpoint is closed.
func TestAgentAuth_CIBAOff(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		y := newAAEnv(t, e, agentauth.ApprovalMethods(agentauth.MethodDeviceAuthorization))
		yk, yh := y.host(t)
		_, yreg := y.register(t, yk, yh.HostID, agentauth.RegisterRequest{
			Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}, ApprovalHints: agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA},
		})
		if yreg.Approval.Method != agentauth.MethodDeviceAuthorization {
			t.Fatalf("unsupported preference: %+v", yreg.Approval)
		}
		_, err := y.ag.CIBAAuthorize(anon(y.a), agentauth.CIBAAuthorizeRequest{Bearer: agentauth.Bearer{Token: yk.jwt(t, y.a, agentauth.TypeHostJWT, map[string]any{"iss": yh.HostID})}, LoginHint: alice, AgentID: yreg.AgentID})
		aaWant(t, "ciba off", err, agentauth.ErrInvalidRequest)
	})
}

// ResolveApprovalMethod chooses per request; DefaultHostCapabilitiesFunc
// budgets per host.
func TestAgentAuth_ResolveMethodAndHostBudgetFunc(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var seen agentauth.ApprovalMethodContext
		var hosts []agentauth.HostCapabilitiesContext
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(),
			agentauth.ResolveApprovalMethod(func(_ context.Context, mc agentauth.ApprovalMethodContext) (string, error) {
				seen = mc
				if slices.Contains(mc.Capabilities, aaTransfer) {
					return agentauth.MethodCIBA, nil
				}
				return "sms", nil // not supported: falls back
			}),
			agentauth.DefaultHostCapabilitiesFunc(func(_ context.Context, hc agentauth.HostCapabilitiesContext) ([]string, error) {
				hosts = append(hosts, hc)
				if hc.UserID == nil {
					return []string{}, nil
				}
				return []string{aaRead}, nil
			}))
		hk, h := x.host(t)
		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Name: "Pay bot", Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		if reg.Approval.Method != agentauth.MethodCIBA || seen.AgentName != "Pay bot" || seen.UserID == nil || seen.HostID != h.HostID || !slices.Equal(seen.SupportedMethods, agentauth.ApprovalMethodValues) {
			t.Fatalf("resolved: %+v %+v", reg.Approval, seen)
		}
		if !slices.Equal(h.DefaultCapabilities, []string{aaRead}) || len(hosts) != 1 || hosts[0].UserID == nil || hosts[0].HostName != "Laptop" {
			t.Fatalf("created host budget: %v %+v", h.DefaultCapabilities, hosts)
		}

		// A dynamic host nobody owns: the function says nothing, and the
		// agent's approval cannot be CIBA, because nobody is addressed.
		dyn := aaNewKey(t)
		_, dreg := x.register(t, dyn, "", agentauth.RegisterRequest{Name: "Read bot", Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}}})
		if dreg.Status != agentauth.AgentPending || dreg.Approval.Method != agentauth.MethodDeviceAuthorization {
			t.Fatalf("dynamic host: %+v", dreg)
		}
		if last := hosts[len(hosts)-1]; last.UserID != nil || last.Mode != agentauth.ModeDelegated {
			t.Fatalf("dynamic host context: %+v", last)
		}
		// Approving links the host to Alice and recomputes its budget.
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: dreg.AgentID, UserCode: dreg.Approval.UserCode, Action: agentauth.ActionApprove}); err != nil {
			t.Fatal(err)
		}
		if last := hosts[len(hosts)-1]; last.UserID == nil || *last.UserID != x.alice.User.ID || last.HostID != dreg.HostID {
			t.Fatalf("claimed host context: %+v", last)
		}
	})
}

// Over HTTP: TrustProxy lets a request-bound token name the public URL
// behind a TLS-terminating proxy; RequireAuthForCapabilities answers the
// challenge; the CIBA endpoint is served.
func TestAgentAuth_HTTPProxyAndChallenge(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.TrustProxy(), agentauth.RequireAuthForCapabilities())
		srv := httptest.NewServer(x.ag.Handler())
		defer srv.Close()
		do := func(method, path, bearer string, body string, hdr map[string]string) (*http.Response, map[string]any) {
			req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
			}
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var m map[string]any
			_ = json.NewDecoder(res.Body).Decode(&m)
			return res, m
		}
		res, body := do(http.MethodGet, agentauth.PathListCapabilities, "", "", nil)
		if res.StatusCode != http.StatusUnauthorized || body["error"] != "authentication_required" ||
			res.Header.Get("WWW-Authenticate") != `AgentAuth discovery="`+testBaseURL+agentauth.WellKnownConfiguration+`"` {
			t.Fatalf("challenge: %d %v %v", res.StatusCode, body, res.Header)
		}
		hk, h := x.host(t, aaRead)
		agentKey, agentReg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}}})
		public := "https://app.example.com" + agentauth.PathListCapabilities
		proxy := map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com"}
		res, body = do(http.MethodGet, agentauth.PathListCapabilities, x.agentJWT(t, agentKey, agentReg.AgentID, map[string]any{"htu": public}), "", proxy)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("behind the proxy: %d %v", res.StatusCode, body)
		}
		res, body = do(http.MethodGet, agentauth.PathListCapabilities, x.agentJWT(t, agentKey, agentReg.AgentID, map[string]any{"htu": public}), "", nil)
		if res.StatusCode != http.StatusOK {
			// Without the headers the URL is the server's own, so the
			// public htu does not match: list ignores an invalid optional
			// token only without RequireAuthForCapabilities.
			if body["error"] != "request_binding_mismatch" {
				t.Fatalf("direct: %d %v", res.StatusCode, body)
			}
		} else {
			t.Fatal("a token bound to the public URL must not match the direct URL")
		}
		res, body = do(http.MethodPost, agentauth.PathCIBAAuthorize, hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID}),
			`{"login_hint":"`+alice+`","agent_id":"`+agentReg.AgentID+`"}`, map[string]string{"Content-Type": "application/json"})
		if res.StatusCode != http.StatusOK || body["auth_req_id"] == nil {
			t.Fatalf("ciba over http: %d %v", res.StatusCode, body)
		}
	})
}

// WebAuthn approval through plugin/passkey: a capability marked
// StrengthWebAuthn waits for an assertion from the approving user's own
// passkey; a session alone, another device or another agent's ceremony is
// refused.
func TestAgentAuth_WebAuthnApproval(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		pk := passkey.New(passkey.DisplayName("Acme"))
		x := &aaEnv{e: e}
		x.ag = agentauth.New(agentauth.ProofOfPresence(pk), agentauth.Capabilities(
			agentauth.Capability{Name: aaRead, Description: "Read"},
			agentauth.Capability{Name: aaTransfer, Description: "Pay", ApprovalStrength: agentauth.StrengthWebAuthn},
		), agentauth.OnExecute(func(context.Context, agentauth.Execution) (any, error) { return "ok", nil }))
		x.em, x.pw = e.emailPlugin(), e.passwordPlugin()
		x.a = e.newAuth(t, nil, x.em, x.pw, pk, x.ag)
		x.alice = signUpVerified(t, e, x.a, x.pw, x.em)
		ctx := request(x.a, x.alice.Token)
		hk, h := x.host(t, aaRead)

		// A new agent under an approved host needs the session only.
		_, plain := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}}, ForceApproval: true})
		if res, err := x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: plain.AgentID, UserCode: plain.Approval.UserCode, Action: agentauth.ActionApprove}); err != nil || res.Status != agentauth.ApprovalApproved {
			t.Fatalf("session strength: %+v %v", res, err)
		}

		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		approve := agentauth.ApproveRequest{AgentID: reg.AgentID, UserCode: reg.Approval.UserCode, Action: agentauth.ActionApprove}
		_, err := x.ag.ApproveCapability(ctx, approve)
		aaWant(t, "no passkey yet", err, agentauth.ErrWebAuthnNotEnrolled)

		dev := newAuthenticator(t)
		begin := must[passkey.BeginResult](t)(pk.RegisterBegin(ctx))
		if _, err := pk.RegisterFinish(ctx, passkey.FinishRequest{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options)}); err != nil {
			t.Fatal(err)
		}
		res, err := x.ag.ApproveCapability(ctx, approve)
		if err != nil || res.Status != agentauth.ApprovalWebAuthnRequired || res.WebAuthn == nil || len(res.Added) != 0 {
			t.Fatalf("challenge: %+v %v", res, err)
		}
		// Nothing was approved by the challenge.
		if inbox := must[agentauth.PendingApprovals](t)(x.ag.PendingApprovalsFor(ctx)); len(inbox.Requests) != 1 || inbox.Requests[0].AgentID != reg.AgentID {
			t.Fatalf("still pending: %+v", inbox)
		}

		// Another device signing the right challenge.
		other := newAuthenticator(t)
		other.credID = dev.credID
		approve.WebAuthn = &agentauth.PresenceResponse{Ceremony: res.WebAuthn.Ceremony, Credential: other.assert(t, res.WebAuthn.Options, x.alice.User.ID)}
		_, err = x.ag.ApproveCapability(ctx, approve)
		aaWant(t, "forged assertion", err, agentauth.ErrWebAuthnFailed)

		// A ceremony begun for another agent's approval.
		_, reg2 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		res2 := must[agentauth.ApproveResult](t)(x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg2.AgentID, UserCode: reg2.Approval.UserCode, Action: agentauth.ActionApprove}))
		res = must[agentauth.ApproveResult](t)(x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg.AgentID, UserCode: reg.Approval.UserCode, Action: agentauth.ActionApprove}))
		approve.WebAuthn = &agentauth.PresenceResponse{Ceremony: res2.WebAuthn.Ceremony, Credential: dev.assert(t, res2.WebAuthn.Options, x.alice.User.ID)}
		_, err = x.ag.ApproveCapability(ctx, approve)
		aaWant(t, "another agent's ceremony", err, agentauth.ErrWebAuthnFailed)

		// An authenticator that skipped user verification.
		dev.noUV = true
		approve.WebAuthn = &agentauth.PresenceResponse{Ceremony: res.WebAuthn.Ceremony, Credential: dev.assert(t, res.WebAuthn.Options, x.alice.User.ID)}
		_, err = x.ag.ApproveCapability(ctx, approve)
		aaWant(t, "no user verification", err, agentauth.ErrWebAuthnFailed)

		dev.noUV = false
		res = must[agentauth.ApproveResult](t)(x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg.AgentID, UserCode: reg.Approval.UserCode, Action: agentauth.ActionApprove}))
		approve.WebAuthn = &agentauth.PresenceResponse{Ceremony: res.WebAuthn.Ceremony, Credential: dev.assert(t, res.WebAuthn.Options, x.alice.User.ID)}
		done, err := x.ag.ApproveCapability(ctx, approve)
		if err != nil || done.Status != agentauth.ApprovalApproved || !slices.Equal(done.Added, []string{aaTransfer}) {
			t.Fatalf("approved with presence: %+v %v", done, err)
		}
		_, err = x.ag.ApproveCapability(ctx, approve)
		if !errors.Is(err, agentauth.ErrApprovalResolved) && !errors.Is(err, agentauth.ErrInvalidUserCode) {
			t.Fatalf("replay: %v", err)
		}
		// Deny never needs presence.
		_, reg3 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		if res, err := x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg3.AgentID, UserCode: reg3.Approval.UserCode, Action: agentauth.ActionDeny}); err != nil || res.Status != agentauth.ApprovalDenied {
			t.Fatalf("deny: %+v %v", res, err)
		}
	})
}

// An OpenAPI-derived provider end to end: the agent executes a capability
// that the plugin proxies upstream with the user's credentials.
func TestAgentAuth_OpenAPIProxy(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		var auths []string
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auths = append(auths, r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"balance":` + strings.TrimPrefix(r.URL.Path, "/accounts/") + `}`))
		}))
		defer api.Close()
		spec := `{"info":{"title":"Bank"},"paths":{"/accounts/{id}":{"get":{"operationId":"getBalance","parameters":[{"name":"id","in":"path","required":true}]}}}}`
		opts, err := agentauth.FromOpenAPISpec([]byte(spec), agentauth.OpenAPIOptions{
			OpenAPIHandlerOptions: agentauth.OpenAPIHandlerOptions{BaseURL: api.URL, Headers: func(_ context.Context, _ string, s agentauth.AgentSession) (http.Header, error) {
				return http.Header{"Authorization": {"Bearer for-" + s.User.ID}}, nil
			}},
			HostCapabilities: agentauth.OperationsWithMethod(http.MethodGet),
		})
		if err != nil {
			t.Fatal(err)
		}
		x := &aaEnv{e: e}
		x.ag = agentauth.New(opts...)
		x.em, x.pw = e.emailPlugin(), e.passwordPlugin()
		x.a = e.newAuth(t, nil, x.em, x.pw, x.ag)
		x.alice = signUpVerified(t, e, x.a, x.pw, x.em)
		cfg := must[agentauth.Configuration](t)(x.ag.Configuration(anon(x.a)))
		if cfg.ProviderName != "Bank" {
			t.Fatalf("provider: %+v", cfg)
		}
		hk, h := x.host(t)
		if !slices.Equal(h.DefaultCapabilities, []string{"getBalance"}) {
			t.Fatalf("budget from the GET filter: %v", h.DefaultCapabilities)
		}
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: "getBalance"}}})
		out, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}, Capability: "getBalance", Arguments: map[string]any{"id": "42"}})
		if err != nil {
			t.Fatal(err)
		}
		if raw, _ := json.Marshal(out); string(raw) != `{"data":{"balance":42}}` {
			t.Fatalf("answer: %s", raw)
		}
		if !slices.Equal(auths, []string{"Bearer for-" + x.alice.User.ID}) {
			t.Fatalf("upstream credentials: %v", auths)
		}
	})
}

// toServer sends every request to srv as if through a TLS-terminating
// proxy at the provider's public origin.
type toServer struct{ srv *httptest.Server }

func (p toServer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
	r.Header.Set("X-Forwarded-Host", r.URL.Host)
	r.URL.Scheme, r.URL.Host = "http", strings.TrimPrefix(p.srv.URL, "http://")
	r.Host = ""
	return http.DefaultTransport.RoundTrip(r)
}

// The Go agent client against the real handler: discover, connect, wait
// for the user, execute with request-bound tokens, and the same through
// the MCP-style tools.
func TestAgentAuth_AgentClient(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.TrustProxy())
		srv := httptest.NewServer(x.ag.Handler())
		defer srv.Close()
		hostKey, err := agentclient.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{Name: "CLI", PublicKey: hostKey.Public, DefaultCapabilities: []string{aaRead}}); err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		c := agentclient.New(hostKey, agentclient.WithHTTPClient(&http.Client{Transport: toServer{srv}}), agentclient.WithClock(x.a.Now))
		p, err := c.Discover(ctx, testBaseURL+"/whatever")
		if err != nil || p.Issuer != testBaseURL {
			t.Fatalf("discover: %+v %v", p, err)
		}
		agent, reg, err := c.Connect(ctx, p, agentclient.ConnectRequest{Name: "Go agent", Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}}})
		if err != nil || reg.Status != agentauth.AgentActive || agent.ID == "" {
			t.Fatalf("connect: %+v %v", reg, err)
		}
		out, err := c.Execute(ctx, agent, aaRead, "", map[string]any{"id": "1"})
		if err != nil || !strings.Contains(string(out), `"capability":"read_data"`) {
			t.Fatalf("execute: %s %v", out, err)
		}
		var pe *agentclient.Error
		if _, err := c.Execute(ctx, agent, aaTransfer, "", nil); !errors.As(err, &pe) || pe.Code != "capability_not_granted" {
			t.Fatalf("not yet granted: %v", err)
		}
		list, err := c.ListCapabilities(ctx, p, &agent)
		if err != nil || len(list.Capabilities) != 2 || list.Capabilities[0].GrantStatus != "granted" {
			t.Fatalf("list: %+v %v", list, err)
		}
		if d, err := c.DescribeCapability(ctx, p, aaRead); err != nil || d.Name != aaRead {
			t.Fatalf("describe: %+v %v", d, err)
		}
		req, err := c.RequestCapability(ctx, agent, []agentauth.CapabilityRequest{{Name: aaTransfer}}, "pay rent", agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA})
		if err != nil || req.Approval == nil || req.Approval.Method != agentauth.MethodCIBA {
			t.Fatalf("request: %+v %v", req, err)
		}
		inbox := must[agentauth.PendingApprovals](t)(x.ag.PendingApprovalsFor(request(x.a, x.alice.Token)))
		must[agentauth.ApproveResult](t)(x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{ApprovalID: inbox.Requests[0].ApprovalID, Action: agentauth.ActionApprove}))
		if st, err := c.WaitForApproval(ctx, agent, time.Millisecond); err != nil || st.Status != agentauth.AgentActive {
			t.Fatalf("wait: %+v %v", st, err)
		}
		if _, err := c.Execute(ctx, agent, aaTransfer, "", nil); err != nil {
			t.Fatalf("granted now: %v", err)
		}

		// The tools, as an MCP server would call them.
		store := &agentclient.MemoryStore{}
		tools := map[string]agentclient.Tool{}
		for _, tool := range c.Tools(store) {
			tools[tool.Name] = tool
		}
		res, err := tools[agentclient.ToolConnectAgent].Call(ctx, json.RawMessage(`{"provider":"`+testBaseURL+`","name":"MCP agent","capabilities":["`+aaRead+`"]}`))
		if err != nil {
			t.Fatalf("connect_agent: %v", err)
		}
		mcpAgent, _ := res.(agentauth.RegisterResult)
		args := json.RawMessage(`{"agent_id":"` + mcpAgent.AgentID + `","capability":"` + aaRead + `","arguments":{"id":"2"}}`)
		if out, err := tools[agentclient.ToolExecuteCapability].Call(ctx, args); err != nil || !strings.Contains(string(out.(json.RawMessage)), "read_data") {
			t.Fatalf("execute_capability: %v %v", out, err)
		}
		if _, err := tools[agentclient.ToolAgentStatus].Call(ctx, json.RawMessage(`{"agent_id":"`+mcpAgent.AgentID+`"}`)); err != nil {
			t.Fatalf("agent_status: %v", err)
		}
		if _, err := tools[agentclient.ToolDisconnectAgent].Call(ctx, json.RawMessage(`{"agent_id":"`+mcpAgent.AgentID+`"}`)); err != nil {
			t.Fatalf("disconnect_agent: %v", err)
		}
		if _, err := tools[agentclient.ToolExecuteCapability].Call(ctx, args); !errors.As(err, &pe) || pe.Code != "agent_revoked" {
			t.Fatalf("after disconnect: %v", err)
		}
		if err := c.Disconnect(ctx, agent); err != nil {
			t.Fatal(err)
		}
		cr, err := c.CIBAAuthorize(ctx, agent, alice, "hi", nil)
		if err != nil || cr.AuthReqID == "" {
			t.Fatalf("ciba: %+v %v", cr, err)
		}
	})
}
