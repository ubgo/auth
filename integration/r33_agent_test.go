package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

// Fixtures of the agent auth tests.
const (
	aaRead     = "read_data"
	aaTransfer = "transfer_money"
	aaBob      = "bob@example.com"
)

// aaKey is an Ed25519 key pair in the protocol's JWK form.
type aaKey struct {
	pub  agentauth.PublicKey
	priv ed25519.PrivateKey
}

func aaNewKey(t *testing.T) aaKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return aaKey{pub: agentauth.PublicKey{KeyType: "OKP", Curve: agentauth.AlgEd25519, X: base64.RawURLEncoding.EncodeToString(pub)}, priv: priv}
}

// jwt signs a token of typ. Fresh iat, exp, jti and aud are filled in
// unless claims sets them; a nil claim value removes the claim.
func (k aaKey) jwt(t *testing.T, a *auth.Auth, typ string, claims map[string]any) string {
	t.Helper()
	return k.jwtAlg(t, a, "EdDSA", typ, claims)
}

func (k aaKey) jwtAlg(t *testing.T, a *auth.Auth, alg, typ string, claims map[string]any) string {
	t.Helper()
	now := a.Now()
	jti := make([]byte, 12)
	_, _ = rand.Read(jti)
	all := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": base64.RawURLEncoding.EncodeToString(jti), "aud": testBaseURL}
	for key, v := range claims {
		if v == nil {
			delete(all, key)
			continue
		}
		all[key] = v
	}
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": alg, "typ": typ})
	c, _ := json.Marshal(all)
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	return in + "." + enc.EncodeToString(ed25519.Sign(k.priv, []byte(in)))
}

// aaEnv is one app with email, password and agentauth, and a signed-in
// user, Alice.
type aaEnv struct {
	e        *env
	a        *auth.Auth
	pw       *password.Plugin
	em       *email.Plugin
	ag       *agentauth.Plugin
	alice    password.SignInResult
	executed []agentauth.Execution
}

func newAAEnv(t *testing.T, e *env, opts ...agentauth.Option) *aaEnv {
	t.Helper()
	return newAAEnvExec(t, e, true, opts...)
}

// newAAEnvExec is newAAEnv, with the recording OnExecute only when exec is
// true: OnExecute(nil) is refused (auth.ErrNilOption), so a test of the
// plugin without an execute handler leaves the option out.
func newAAEnvExec(t *testing.T, e *env, exec bool, opts ...agentauth.Option) *aaEnv {
	t.Helper()
	x := &aaEnv{e: e}
	caps := agentauth.Capabilities(
		agentauth.Capability{Name: aaRead, Description: "Read user data", Input: json.RawMessage(`{"type":"object","properties":{"id":{"type":"string"}}}`)},
		agentauth.Capability{Name: aaTransfer, Description: "Transfer funds"},
	)
	base := []agentauth.Option{caps}
	if exec {
		base = append(base, agentauth.OnExecute(func(_ context.Context, ex agentauth.Execution) (any, error) {
			x.executed = append(x.executed, ex)
			return map[string]any{"ok": true, "capability": ex.Capability.Name}, nil
		}))
	}
	x.ag = agentauth.New(append(base, opts...)...)
	x.em, x.pw = e.emailPlugin(), e.passwordPlugin()
	x.a = e.newAuth(t, nil, x.em, x.pw, x.ag)
	x.alice = signUpVerified(t, e, x.a, x.pw, x.em)
	return x
}

// signUp signs up and verifies another user.
func (x *aaEnv) signUp(t *testing.T, addr string) password.SignInResult {
	t.Helper()
	x.a.WaitDeliveries()
	res, err := x.pw.SignUp(anon(x.a), password.SignUpRequest{Identifier: addr, Password: secret, Name: "Bob"})
	if err != nil {
		t.Fatalf("sign up: %v", err)
	}
	if _, err := x.em.Verify(anon(x.a), x.e.mail.LastToken(t, x.a, addr)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return res
}

// host creates a host owned by Alice with budget.
func (x *aaEnv) host(t *testing.T, budget ...string) (aaKey, agentauth.CreateHostResult) {
	t.Helper()
	k := aaNewKey(t)
	res, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{Name: "Laptop", PublicKey: k.pub, DefaultCapabilities: budget})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	return k, res
}

// register registers a new agent under host.
func (x *aaEnv) register(t *testing.T, host aaKey, hostID string, in agentauth.RegisterRequest) (aaKey, agentauth.RegisterResult) {
	t.Helper()
	agent := aaNewKey(t)
	claims := map[string]any{"agent_public_key": agent.pub}
	if hostID != "" {
		claims["iss"] = hostID
	} else {
		claims["host_public_key"] = host.pub
	}
	in.Token = host.jwt(t, x.a, agentauth.TypeHostJWT, claims)
	if in.Name == "" {
		in.Name = "Agent"
	}
	res, err := x.ag.Register(anon(x.a), in)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return agent, res
}

// agentJWT is a fresh agent token for agentID.
func (x *aaEnv) agentJWT(t *testing.T, k aaKey, agentID string, claims map[string]any) string {
	t.Helper()
	c := map[string]any{"sub": agentID}
	for key, v := range claims {
		c[key] = v
	}
	return k.jwt(t, x.a, agentauth.TypeAgentJWT, c)
}

func aaWant(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

// Slice 1: a host created by a user registers an agent inside its budget;
// the agent's JWT resolves its session once; every check on the token
// refuses what it must; revocation ends the agent.
func TestAgentAuth_RegisterSessionAndRevoke(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Name: "<b>Claude</b>", Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}}})
		if reg.Status != agentauth.AgentActive || reg.Approval != nil || len(reg.Grants) != 1 || reg.Grants[0].Status != agentauth.GrantActive || reg.Name != "Claude" {
			t.Fatalf("register: %+v", reg)
		}
		tok := x.agentJWT(t, ak, reg.AgentID, nil)
		s, err := x.ag.Session(anon(x.a), agentauth.Bearer{Token: tok})
		if err != nil || s.AgentID != reg.AgentID || s.User.ID != x.alice.User.ID || s.Host == nil || s.Host.ID != h.HostID {
			t.Fatalf("session: %+v %v", s, err)
		}
		if _, ok := s.HasGrant(aaRead); !ok {
			t.Fatal("grant missing from the session")
		}
		_, err = x.ag.Session(anon(x.a), agentauth.Bearer{Token: tok})
		aaWant(t, "replayed jti", err, agentauth.ErrJTIReplay)

		// Every check on the token, one at a time.
		other := aaNewKey(t)
		bad := map[string]string{
			"wrong audience": x.agentJWT(t, ak, reg.AgentID, map[string]any{"aud": "https://evil.example"}),
			"no audience":    x.agentJWT(t, ak, reg.AgentID, map[string]any{"aud": nil}),
			"expired":        x.agentJWT(t, ak, reg.AgentID, map[string]any{"exp": x.a.Now().Add(-time.Second).Unix()}),
			"too old":        x.agentJWT(t, ak, reg.AgentID, map[string]any{"iat": x.a.Now().Add(-2 * time.Minute).Unix(), "exp": x.a.Now().Add(time.Hour).Unix()}),
			"host typ":       ak.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"sub": reg.AgentID}),
			"forged":         x.agentJWT(t, other, reg.AgentID, nil),
			"alg none":       ak.jwtAlg(t, x.a, "none", agentauth.TypeAgentJWT, map[string]any{"sub": reg.AgentID}),
			"wrong host":     x.agentJWT(t, ak, reg.AgentID, map[string]any{"iss": "agh_other"}),
			"no jti":         x.agentJWT(t, ak, reg.AgentID, map[string]any{"jti": nil}),
			"bound to GET":   x.agentJWT(t, ak, reg.AgentID, map[string]any{"htm": "GET"}),
		}
		for name, tok := range bad {
			_, err := x.ag.Session(anon(x.a), agentauth.Bearer{Token: tok, Method: http.MethodPost})
			if !errors.Is(err, agentauth.ErrInvalidJWT) && !errors.Is(err, agentauth.ErrRequestBindingMismatch) {
				t.Errorf("%s: %v", name, err)
			}
		}
		_, err = x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, "agt_nobody", nil)})
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)

		// The same key on the same host is the same agent.
		dup := hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": ak.pub})
		_, err = x.ag.Register(anon(x.a), agentauth.RegisterRequest{Bearer: agentauth.Bearer{Token: dup}, Name: "Again"})
		aaWant(t, "same key twice", err, agentauth.ErrAgentExists)

		// The agent revokes itself; nothing it signs works after.
		rev, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}})
		if err != nil || rev.Status != agentauth.AgentRevoked {
			t.Fatalf("revoke: %+v %v", rev, err)
		}
		_, err = x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)})
		aaWant(t, "revoked agent", err, agentauth.ErrAgentRevoked)
		st, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID})}, AgentID: reg.AgentID})
		if err != nil || st.Status != agentauth.AgentRevoked || st.Grants[0].Status != agentauth.GrantRevoked {
			t.Fatalf("status after revoke: %+v %v", st, err)
		}
	})
}

// Only the agent, its host or its owner revokes an agent.
func TestAgentAuth_RevokeOwnership(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t, aaRead)
		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		bob := x.signUp(t, aaBob)
		_, err := x.ag.Revoke(request(x.a, bob.Token), agentauth.RevokeRequest{AgentID: reg.AgentID})
		aaWant(t, "another user", err, agentauth.ErrUnauthorized)
		ok2, h2 := x.host(t)
		_, err = x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: agentauth.Bearer{Token: ok2.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h2.HostID})}, AgentID: reg.AgentID})
		aaWant(t, "another host", err, agentauth.ErrUnauthorized)
		_, err = x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{AgentID: reg.AgentID})
		aaWant(t, "nobody", err, agentauth.ErrAuthenticationRequired)
		if _, err := x.ag.Revoke(request(x.a, x.alice.Token), agentauth.RevokeRequest{AgentID: reg.AgentID}); err != nil {
			t.Fatalf("owner: %v", err)
		}
		// A host JWT revokes its own agent.
		_, reg2 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		if _, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID})}, AgentID: reg2.AgentID}); err != nil {
			t.Fatalf("host: %v", err)
		}
	})
}

// An unknown host registers only under AllowDynamicHostRegistration; its
// delegated agent waits for a user, who approves it with the user code.
func TestAgentAuth_DynamicHostAndDeviceApproval(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		closed := newAAEnv(t, e)
		hk := aaNewKey(t)
		tok := hk.jwt(t, closed.a, agentauth.TypeHostJWT, map[string]any{"host_public_key": hk.pub, "agent_public_key": aaNewKey(t).pub})
		_, err := closed.ag.Register(anon(closed.a), agentauth.RegisterRequest{Bearer: agentauth.Bearer{Token: tok}, Name: "A"})
		aaWant(t, "dynamic registration off", err, agentauth.ErrDynamicHostRegistration)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration())
		hk := aaNewKey(t)
		ak, reg := x.register(t, hk, "", agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}}})
		if reg.Status != agentauth.AgentPending || reg.Approval == nil || reg.Approval.UserCode == "" || reg.Grants[0].Status != agentauth.GrantPending {
			t.Fatalf("register: %+v", reg)
		}
		if !strings.HasPrefix(reg.Approval.VerificationURIComplete, testBaseURL+agentauth.DefaultDeviceAuthorizationPage+"?agent_id="+reg.AgentID) {
			t.Fatalf("approval: %+v", reg.Approval)
		}
		_, err := x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)})
		aaWant(t, "pending agent", err, agentauth.ErrAgentPending)
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: "AAAA-AAAA"})
		aaWant(t, "wrong code", err, agentauth.ErrInvalidUserCode)
		_, err = x.ag.ApproveCapability(anon(x.a), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode})
		if err == nil {
			t.Fatal("approval without a session")
		}
		res, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: strings.ToLower(reg.Approval.UserCode)})
		if err != nil || res.Status != agentauth.ApprovalApproved || len(res.Added) != 1 {
			t.Fatalf("approve: %+v %v", res, err)
		}
		s, err := x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)})
		if err != nil || s.User.ID != x.alice.User.ID || s.Host.UserID == nil || *s.Host.UserID != x.alice.User.ID {
			t.Fatalf("session after approval: %+v %v", s, err)
		}
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove})
		aaWant(t, "nothing pending", err, agentauth.ErrApprovalResolved)
		// The agent now belongs to Alice: Bob cannot answer for it.
		bob := x.signUp(t, aaBob)
		_, err = x.ag.ApproveCapability(request(x.a, bob.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionDeny})
		aaWant(t, "another user", err, agentauth.ErrApprovalOwnerMismatch)

		// A denied registration rejects the agent.
		_, reg2 := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{})
		if _, err := x.ag.ApproveCapability(request(x.a, bob.Token), agentauth.ApproveRequest{AgentID: reg2.AgentID, Action: agentauth.ActionDeny, UserCode: reg2.Approval.UserCode}); err != nil {
			t.Fatalf("deny: %v", err)
		}
		// The code expires.
		_, reg3 := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{})
		e.clock.Advance(agentauth.DefaultApprovalTTL + time.Second)
		_, err = x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg3.AgentID, Action: agentauth.ActionApprove, UserCode: reg3.Approval.UserCode})
		aaWant(t, "expired code", err, agentauth.ErrApprovalExpired)
	})
}

// Slice 2: the catalogue, capability requests, approval and execution
// under grants and constraints.
func TestAgentAuth_CapabilitiesAndExecute(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		list, err := x.ag.ListCapabilities(anon(x.a), agentauth.ListCapabilitiesRequest{})
		if err != nil || len(list.Capabilities) != 2 || list.Capabilities[0].GrantStatus != "" || list.Capabilities[0].InputFields[0].Name != "id" {
			t.Fatalf("anonymous list: %+v %v", list, err)
		}
		page, err := x.ag.ListCapabilities(anon(x.a), agentauth.ListCapabilitiesRequest{Limit: 1})
		if err != nil || !page.HasMore || page.NextCursor != "1" {
			t.Fatalf("page: %+v %v", page, err)
		}
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		mine, err := x.ag.ListCapabilities(anon(x.a), agentauth.ListCapabilitiesRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}})
		if err != nil || mine.Capabilities[0].GrantStatus != "granted" || mine.Capabilities[1].GrantStatus != "not_granted" {
			t.Fatalf("agent list: %+v %v", mine, err)
		}
		d, err := x.ag.DescribeCapability(anon(x.a), agentauth.DescribeCapabilityRequest{Name: aaRead})
		if err != nil || len(d.Input) == 0 {
			t.Fatalf("describe: %+v %v", d, err)
		}
		_, err = x.ag.DescribeCapability(anon(x.a), agentauth.DescribeCapabilityRequest{Name: "nope"})
		aaWant(t, "describe unknown", err, agentauth.ErrCapabilityNotFound)

		exec := func(capability string, args map[string]any) (agentauth.ExecuteResult, error) {
			return x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}, Capability: capability, Arguments: args})
		}
		out, err := exec(aaRead, map[string]any{"id": "1"})
		if err != nil || len(x.executed) != 1 || x.executed[0].Session.User.ID != x.alice.User.ID {
			t.Fatalf("execute: %+v %v", out, err)
		}
		_, err = exec(aaTransfer, nil)
		aaWant(t, "not granted", err, agentauth.ErrCapabilityNotGranted)
		_, err = exec("nope", nil)
		aaWant(t, "unknown capability", err, agentauth.ErrCapabilityNotFound)
		_, err = x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, map[string]any{"capabilities": []string{aaTransfer}})}, Capability: aaRead})
		if err != nil {
			// A token narrowed to another capability holds no grant of
			// this one; the host budget grants it again, as better-auth's
			// execute does.
			t.Fatalf("narrowed token: %v", err)
		}

		// Requesting a capability outside the budget waits for Alice.
		req, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{
			Bearer:       agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)},
			Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer, Constraints: agentauth.Constraints{"amount": {Max: ptr(1000.0)}, "currency": {In: []agentauth.Primitive{agentauth.String("USD")}}}}},
		})
		if err != nil || req.Status != agentauth.AgentPending || req.Approval == nil {
			t.Fatalf("request: %+v %v", req, err)
		}
		_, err = exec(aaTransfer, map[string]any{"amount": 10, "currency": "USD"})
		aaWant(t, "pending grant", err, agentauth.ErrCapabilityNotGranted)
		_, err = x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}, Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}}})
		aaWant(t, "already granted", err, agentauth.ErrAlreadyGranted)
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: req.Approval.UserCode}); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if _, err := exec(aaTransfer, map[string]any{"amount": "999", "currency": "USD"}); err != nil {
			t.Fatalf("within constraints: %v", err)
		}
		_, err = exec(aaTransfer, map[string]any{"amount": 1001, "currency": "USD"})
		aaWant(t, "over max", err, agentauth.ErrConstraintViolated)
		_, err = exec(aaTransfer, map[string]any{"amount": 5, "currency": "BTC"})
		aaWant(t, "currency", err, agentauth.ErrConstraintViolated)

	})
}

func ptr[T any](v T) *T { return &v }

// A grant spent by ConsumeGrant authorizes nothing more; a capability the
// user granted outside the host's budget is not granted again by it.
func TestAgentAuth_ConsumeGrant(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		consume := agentauth.OnExecute(func(ctx context.Context, ex agentauth.Execution) (any, error) {
			return "paid", ex.ConsumeGrant(ctx)
		})
		x := newAAEnv(t, e, consume)
		hk, h := x.host(t)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer}}})
		if reg.Status != agentauth.AgentPending {
			t.Fatalf("outside the budget: %+v", reg)
		}
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode}); err != nil {
			t.Fatalf("approve: %v", err)
		}
		run := func() error {
			_, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}, Capability: aaTransfer})
			return err
		}
		if err := run(); err != nil {
			t.Fatalf("first: %v", err)
		}
		aaWant(t, "spent grant", run(), agentauth.ErrCapabilityNotGranted)
	})
}

// Slice 3: an autonomous agent on a dynamic host acts under the host's
// budget; the host polls status, a resource server introspects, and the
// host rotates its key.
func TestAgentAuth_AutonomousStatusIntrospectRotate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.DefaultHostCapabilities(aaRead),
			agentauth.AutonomousUser(func(_ context.Context, hostID, _ string) (*agentauth.SessionUser, error) {
				return &agentauth.SessionUser{ID: "bot:" + hostID, Name: "Bot"}, nil
			}))
		hk := aaNewKey(t)
		ak, reg := x.register(t, hk, "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous, Capabilities: []agentauth.CapabilityRequest{{Name: aaRead}, {Name: aaTransfer}}})
		if reg.Status != agentauth.AgentActive || len(reg.Grants) != 1 || reg.Grants[0].Capability != aaRead {
			t.Fatalf("autonomous register: %+v", reg)
		}
		if _, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}, Capability: aaRead}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := x.executed[0].Session.User.ID; got != "bot:"+reg.HostID {
			t.Fatalf("autonomous user %q", got)
		}
		hostTok := func(k aaKey) string {
			return k.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": reg.HostID})
		}
		st, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: agentauth.Bearer{Token: hostTok(hk)}, AgentID: reg.AgentID})
		if err != nil || st.Mode != agentauth.ModeAutonomous || st.LastUsedAt == nil {
			t.Fatalf("status: %+v %v", st, err)
		}
		_, err = x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: agentauth.Bearer{Token: hostTok(hk)}})
		aaWant(t, "host status without agent", err, agentauth.ErrInvalidRequest)

		tok := x.agentJWT(t, ak, reg.AgentID, nil)
		in, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: tok})
		if err != nil || !in.Active || in.AgentID != reg.AgentID || len(in.Grants) != 1 {
			t.Fatalf("introspect: %+v %v", in, err)
		}
		again, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: tok})
		if err != nil || again.Active {
			t.Fatalf("introspect replay: %+v %v", again, err)
		}
		forged, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: x.agentJWT(t, aaNewKey(t), reg.AgentID, nil)})
		if err != nil || forged.Active {
			t.Fatalf("introspect forged: %+v %v", forged, err)
		}

		next := aaNewKey(t)
		rot, err := x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{Bearer: agentauth.Bearer{Token: hostTok(hk)}, PublicKey: next.pub})
		if err != nil || rot.HostID != reg.HostID {
			t.Fatalf("rotate: %+v %v", rot, err)
		}
		_, err = x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: agentauth.Bearer{Token: hostTok(hk)}, AgentID: reg.AgentID})
		aaWant(t, "old host key", err, agentauth.ErrInvalidJWT)
		if _, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: agentauth.Bearer{Token: hostTok(next)}, AgentID: reg.AgentID}); err != nil {
			t.Fatalf("new host key: %v", err)
		}
	})
}

// Lifetimes: the sliding session TTL and the absolute lifetime refuse an
// agent once they pass.
func TestAgentAuth_Lifetimes(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AgentSessionTTL(time.Hour), agentauth.AbsoluteLifetime(3*time.Hour))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		e.clock.Advance(50 * time.Minute)
		if _, err := x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}); err != nil {
			t.Fatalf("within the TTL: %v", err)
		}
		e.clock.Advance(50 * time.Minute)
		if _, err := x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)}); err != nil {
			t.Fatalf("the heartbeat slid the TTL: %v", err)
		}
		e.clock.Advance(61 * time.Minute)
		_, err := x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)})
		aaWant(t, "idle past the TTL", err, agentauth.ErrAgentExpired)
		e.clock.Advance(time.Hour)
		_, err = x.ag.Session(anon(x.a), agentauth.Bearer{Token: x.agentJWT(t, ak, reg.AgentID, nil)})
		aaWant(t, "past the absolute lifetime", err, agentauth.ErrAbsoluteLifetimeExceeded)
	})
}

// The HTTP surface: discovery, registration and execution with a
// request-bound JWT, and the protocol's error shape with its challenge.
func TestAgentAuth_HTTP(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		srv := httptest.NewServer(x.ag.Handler())
		defer srv.Close()
		get := func(path, bearer string) (*http.Response, map[string]any) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
			if bearer != "" {
				req.Header.Set("Authorization", "Bearer "+bearer)
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
		res, doc := get(agentauth.WellKnownConfiguration, "")
		if res.StatusCode != http.StatusOK || doc["issuer"] != testBaseURL || res.Header.Get("Cache-Control") != "public, max-age=3600" {
			t.Fatalf("discovery: %d %v", res.StatusCode, doc)
		}
		res, body := get(agentauth.PathSession, "")
		if res.StatusCode != http.StatusUnauthorized || body["error"] != "authentication_required" || !strings.Contains(res.Header.Get("WWW-Authenticate"), "AgentAuth discovery=") {
			t.Fatalf("challenge: %d %v %v", res.StatusCode, body, res.Header)
		}

		hk, h := x.host(t, aaRead)
		ak := aaNewKey(t)
		post := func(path, bearer string, payload any) (*http.Response, map[string]any) {
			b, _ := json.Marshal(payload)
			req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(string(b)))
			req.Header.Set("Authorization", "Bearer "+bearer)
			req.Header.Set("Content-Type", "application/json")
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			return res, m
		}
		res, reg := post(agentauth.PathRegister, hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": ak.pub}), map[string]any{"name": "HTTP agent", "capabilities": []any{aaRead}})
		if res.StatusCode != http.StatusOK || reg["status"] != "active" {
			t.Fatalf("register: %d %v", res.StatusCode, reg)
		}
		agentID, _ := reg["agent_id"].(string)
		payload := map[string]any{"capability": aaRead, "arguments": map[string]any{"id": "7"}}
		raw, _ := json.Marshal(payload)
		sum := sha256.Sum256(raw)
		bound := x.agentJWT(t, ak, agentID, map[string]any{"htm": "POST", "htu": srv.URL + agentauth.PathExecute, "ath": base64.RawURLEncoding.EncodeToString(sum[:])})
		res, out := post(agentauth.PathExecute, bound, payload)
		if res.StatusCode != http.StatusOK || out["data"] == nil {
			t.Fatalf("execute: %d %v", res.StatusCode, out)
		}
		wrongURL := x.agentJWT(t, ak, agentID, map[string]any{"htu": srv.URL + "/elsewhere"})
		res, out = post(agentauth.PathExecute, wrongURL, payload)
		if res.StatusCode != http.StatusUnauthorized || out["error"] != "request_binding_mismatch" {
			t.Fatalf("binding: %d %v", res.StatusCode, out)
		}
		res, _ = get(agentauth.PathExecute, "")
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET execute: %d", res.StatusCode)
		}

		// An app route verifies the agent with VerifyAgentRequest.
		r := httptest.NewRequest(http.MethodGet, testBaseURL+"/custom", nil)
		r.Header.Set("Authorization", "Bearer "+x.agentJWT(t, ak, agentID, nil))
		s, err := x.ag.VerifyAgentRequest(r)
		if err != nil || s.AgentID != agentID {
			t.Fatalf("VerifyAgentRequest: %+v %v", s, err)
		}
	})
}
