package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/sqlb"
)

// Round c3: every database failure inside an agentauth operation reaches
// the caller, and every branch the earlier rounds left unasserted.

// aaSweep runs a fault sweep over op on a fresh agentauth app (Alice signed
// in) per step: prep builds what op needs, and op must fail whenever a
// database call it makes fails.
func aaSweep(t *testing.T, opts []agentauth.Option, prep func(t *testing.T, x *aaEnv) func() error, swallowOK ...int) {
	t.Helper()
	sweepFaults(t, func(t *testing.T, e *faultEnv) func(context.Context) error {
		op := prep(t, newAAEnv(t, e.env, opts...))
		return func(context.Context) error { return op() }
	}, swallowOK...)
}

// hostTok is a host JWT naming hostID, for the operations a host signs.
func (x *aaEnv) hostTok(t *testing.T, k aaKey, hostID string) agentauth.Bearer {
	t.Helper()
	return agentauth.Bearer{Token: k.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": hostID})}
}

// agentTok is a fresh agent JWT as a bearer.
func (x *aaEnv) agentTok(t *testing.T, k aaKey, agentID string) agentauth.Bearer {
	t.Helper()
	return agentauth.Bearer{Token: x.agentJWT(t, k, agentID, nil)}
}

func caps(names ...string) []agentauth.CapabilityRequest {
	out := make([]agentauth.CapabilityRequest, 0, len(names))
	for _, n := range names {
		out = append(out, agentauth.CapabilityRequest{Name: n})
	}
	return out
}

func TestAgentAuthFaults_HostsAndRegistration(t *testing.T) {
	dynamic := []agentauth.Option{agentauth.AllowDynamicHostRegistration()}
	t.Run("create host", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			k := aaNewKey(t)
			return func() error {
				_, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{Name: "Laptop", PublicKey: k.pub, DefaultCapabilities: []string{aaRead}})
				return err
			}
		})
	})
	t.Run("claim a dynamic host", func(t *testing.T) {
		aaSweep(t, dynamic, func(t *testing.T, x *aaEnv) func() error {
			hk := aaNewKey(t)
			x.register(t, hk, "", agentauth.RegisterRequest{})
			return func() error {
				_, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{PublicKey: hk.pub})
				return err
			}
		})
	})
	t.Run("register within the budget", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			return func() error {
				_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Capabilities: caps(aaRead, aaTransfer),
					Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub})}})
				return err
			}
		})
	})
	t.Run("register under a CIBA approval", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t)
			return func() error {
				_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Capabilities: caps(aaTransfer),
					ApprovalHints: agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA},
					Bearer:        agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub})}})
				return err
			}
		})
	})
	t.Run("register on a new dynamic host", func(t *testing.T) {
		aaSweep(t, dynamic, func(t *testing.T, x *aaEnv) func() error {
			hk := aaNewKey(t)
			return func() error {
				_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Capabilities: caps(aaRead),
					Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"host_public_key": hk.pub, "agent_public_key": aaNewKey(t).pub})}})
				return err
			}
		})
	})
	t.Run("register again on a known dynamic host", func(t *testing.T) {
		aaSweep(t, dynamic, func(t *testing.T, x *aaEnv) func() error {
			hk := aaNewKey(t)
			x.register(t, hk, "", agentauth.RegisterRequest{})
			return func() error {
				_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "B",
					Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"host_public_key": hk.pub, "agent_public_key": aaNewKey(t).pub})}})
				return err
			}
		})
	})
	t.Run("re-register a pending agent", func(t *testing.T) {
		aaSweep(t, dynamic, func(t *testing.T, x *aaEnv) func() error {
			hk, ak := aaNewKey(t), aaNewKey(t)
			tok := func() string {
				return hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"host_public_key": hk.pub, "agent_public_key": ak.pub})
			}
			if _, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Capabilities: caps(aaRead), Bearer: agentauth.Bearer{Token: tok()}}); err != nil {
				t.Fatal(err)
			}
			again := tok()
			return func() error {
				_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Capabilities: caps(aaRead), Bearer: agentauth.Bearer{Token: again}})
				return err
			}
		})
	})
	t.Run("register an autonomous agent", func(t *testing.T) {
		aaSweep(t, append(dynamic, agentauth.Modes(agentauth.ModeDelegated, agentauth.ModeAutonomous), agentauth.DefaultHostCapabilities(aaRead)), func(t *testing.T, x *aaEnv) func() error {
			hk := aaNewKey(t)
			return func() error {
				_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Mode: agentauth.ModeAutonomous, Capabilities: caps(aaRead),
					Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"host_public_key": hk.pub, "agent_public_key": aaNewKey(t).pub})}})
				return err
			}
		})
	})
	t.Run("autonomous agent activating a pending host", func(t *testing.T) {
		aaSweep(t, append(dynamic, agentauth.Modes(agentauth.ModeDelegated, agentauth.ModeAutonomous)), func(t *testing.T, x *aaEnv) func() error {
			hk := aaNewKey(t)
			x.register(t, hk, "", agentauth.RegisterRequest{})
			b := x.dynTok(t, hk, nil)
			return func() error {
				_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "B", Mode: agentauth.ModeAutonomous, Bearer: b})
				return err
			}
		})
	})
	t.Run("delete a user with agents", func(t *testing.T) {
		aaSweep(t, dynamic, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
			x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead), ForceApproval: true})
			return func() error { return x.a.DeleteUser(context.Background(), x.alice.User.ID) }
		})
	})
	t.Run("rotate a host key", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t)
			b := x.hostTok(t, hk, h.HostID)
			return func() error {
				_, err := x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{Bearer: b, PublicKey: aaNewKey(t).pub})
				return err
			}
		})
	})
}

func TestAgentAuthFaults_SessionsAndStatus(t *testing.T) {
	// active is a registered agent holding aaRead under a budget of aaRead
	// and aaTransfer.
	active := func(t *testing.T, x *aaEnv) (aaKey, agentauth.CreateHostResult, aaKey, agentauth.RegisterResult) {
		hk, h := x.host(t, aaRead, aaTransfer)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		return hk, h, ak, reg
	}
	t.Run("session", func(t *testing.T) {
		aaSweep(t, []agentauth.Option{agentauth.AgentSessionTTL(time.Hour)}, func(t *testing.T, x *aaEnv) func() error {
			_, _, ak, reg := active(t, x)
			b := x.agentTok(t, ak, reg.AgentID)
			return func() error { _, err := x.ag.Session(anon(x.a), b); return err }
		})
	})
	t.Run("status by the host", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h, _, reg := active(t, x)
			b := x.hostTok(t, hk, h.HostID)
			return func() error {
				_, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: b, AgentID: reg.AgentID})
				return err
			}
		})
	})
	t.Run("status by the agent", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			_, _, ak, reg := active(t, x)
			b := x.agentTok(t, ak, reg.AgentID)
			return func() error { _, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: b}); return err }
		})
	})
	t.Run("introspect", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			_, _, ak, reg := active(t, x)
			tok := x.agentJWT(t, ak, reg.AgentID, nil)
			return func() error {
				_, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: tok})
				return err
			}
		})
	})
	for _, by := range []string{"agent", "host", "owner"} {
		t.Run("revoke by the "+by, func(t *testing.T) {
			aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
				hk, h, ak, reg := active(t, x)
				var in agentauth.RevokeRequest
				ctx := anon(x.a)
				switch by {
				case "agent":
					in.Bearer = x.agentTok(t, ak, reg.AgentID)
				case "host":
					in.Bearer, in.AgentID = x.hostTok(t, hk, h.HostID), reg.AgentID
				default:
					in.AgentID, ctx = reg.AgentID, request(x.a, x.alice.Token)
				}
				return func() error { _, err := x.ag.Revoke(ctx, in); return err }
			})
		})
	}
	t.Run("request a capability inside the budget", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			_, _, ak, reg := active(t, x)
			b := x.agentTok(t, ak, reg.AgentID)
			return func() error {
				_, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: b, Capabilities: caps(aaTransfer)})
				return err
			}
		})
	})
	t.Run("request a capability outside the budget", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
			b := x.agentTok(t, ak, reg.AgentID)
			return func() error {
				_, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: b, Capabilities: caps(aaTransfer)})
				return err
			}
		})
	})
	t.Run("ask again for a pending capability", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
			if _, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capabilities: caps(aaTransfer)}); err != nil {
				t.Fatal(err)
			}
			b := x.agentTok(t, ak, reg.AgentID)
			return func() error {
				_, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: b, Capabilities: caps(aaTransfer)})
				return err
			}
		})
	})
	t.Run("execute under the host budget", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			_, _, ak, reg := active(t, x)
			b := x.agentTok(t, ak, reg.AgentID)
			return func() error {
				_, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: b, Capability: aaTransfer})
				return err
			}
		})
	})
}

func TestAgentAuthFaults_Approvals(t *testing.T) {
	dynamic := []agentauth.Option{agentauth.AllowDynamicHostRegistration()}
	for _, action := range []string{agentauth.ActionApprove, agentauth.ActionDeny} {
		t.Run(action+" a pending agent", func(t *testing.T) {
			aaSweep(t, dynamic, func(t *testing.T, x *aaEnv) func() error {
				_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Capabilities: caps(aaRead, aaTransfer)})
				return func() error {
					_, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: action, UserCode: reg.Approval.UserCode, Capabilities: []string{aaRead}})
					return err
				}
			})
		})
	}
	// One pending grant, approved under another name: the denial is the
	// only grant write, at a fixed step (two pending grants of one agent
	// come back in id order, which is random).
	t.Run("approve narrowed past every pending grant", func(t *testing.T) {
		aaSweep(t, dynamic, func(t *testing.T, x *aaEnv) func() error {
			_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Capabilities: caps(aaTransfer)})
			return func() error {
				_, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode, Capabilities: []string{aaRead}})
				return err
			}
		})
	})
	t.Run("approve a pending agent with proof of presence", func(t *testing.T) {
		aaSweep(t, append(dynamic, agentauth.ProofOfPresence(c3Presence{})), func(t *testing.T, x *aaEnv) func() error {
			_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{})
			return func() error {
				_, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode})
				return err
			}
		})
	})
	t.Run("approve a requested capability", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead, aaTransfer)})
			return func() error {
				_, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode, TTLSeconds: 60})
				return err
			}
		})
	})
	t.Run("ciba authorize", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
			b := x.hostTok(t, hk, h.HostID)
			return func() error {
				_, err := x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{Bearer: b, LoginHint: alice, AgentID: reg.AgentID, Capabilities: []string{aaTransfer}})
				return err
			}
		})
	})
	t.Run("pending approvals", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t)
			x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaRead, Constraints: agentauth.Constraints{"id": agentauth.Eq(agentauth.String("1"))}}},
				Reason: "needs it", ApprovalHints: agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA}})
			return func() error { _, err := x.ag.PendingApprovalsFor(request(x.a, x.alice.Token)); return err }
		})
	})
	t.Run("sweep", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			return func() error { _, err := x.ag.Sweep(context.Background(), x.a.Now()); return err }
		})
	})
}

// aaHTTP sends one request to the plugin's handler and decodes the answer.
func aaHTTP(t *testing.T, h http.Handler, method, path, bearer string, body io.Reader, cookie auth.Token) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, testBaseURL+path, body)
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: string(cookie)})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

// Every POST endpoint refuses a body that is not JSON; introspection and
// host key rotation answer over HTTP; an unknown path is a 404; an
// oversized body, a non-Bearer credential and a database failure each get
// their own answer.
func TestAgentAuthHTTP_EdgesOfEveryEndpoint(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		h := x.ag.Handler()
		for _, path := range []string{agentauth.PathRegister, agentauth.PathRevoke, agentauth.PathIntrospect, agentauth.PathRequestCapability,
			agentauth.PathExecute, agentauth.PathRotateHostKey, agentauth.PathCIBAAuthorize} {
			code, body := aaHTTP(t, h, http.MethodPost, path, "", strings.NewReader(`{not json`), "")
			if code != http.StatusBadRequest || body["error"] != "invalid_request" {
				t.Errorf("%s with a malformed body: %d %v", path, code, body)
			}
		}
		if code, _ := aaHTTP(t, h, http.MethodGet, "/agent/nothing-here", "", nil, ""); code != http.StatusNotFound {
			t.Fatalf("unknown path: %d", code)
		}
		big := strings.NewReader(`{"name":"` + strings.Repeat("a", 1<<20) + `"}`)
		if code, body := aaHTTP(t, h, http.MethodPost, agentauth.PathRegister, "", big, ""); code != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Fatalf("oversized body: %d %v", code, body)
		}
		if code, body := aaHTTP(t, h, http.MethodPost, agentauth.PathRegister, "Basic YTpi", strings.NewReader(`{}`), ""); code != http.StatusUnauthorized || body["error"] != "invalid_jwt" {
			t.Fatalf("basic credential: %d %v", code, body)
		}

		hk, host := x.host(t, aaRead)
		ak, reg := x.register(t, hk, host.HostID, agentauth.RegisterRequest{})
		in, _ := json.Marshal(agentauth.IntrospectRequest{Token: x.agentJWT(t, ak, reg.AgentID, nil)})
		if code, body := aaHTTP(t, h, http.MethodPost, agentauth.PathIntrospect, "", bytes.NewReader(in), ""); code != http.StatusOK || body["active"] != true || body["agent_id"] != reg.AgentID {
			t.Fatalf("introspect: %d %v", code, body)
		}
		next := aaNewKey(t)
		rot, _ := json.Marshal(map[string]any{"public_key": next.pub})
		code, body := aaHTTP(t, h, http.MethodPost, agentauth.PathRotateHostKey, "Bearer "+x.hostTok(t, hk, host.HostID).Token, bytes.NewReader(rot), "")
		if code != http.StatusOK || body["host_id"] != host.HostID {
			t.Fatalf("rotate: %d %v", code, body)
		}
		if _, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, next, host.HostID), AgentID: reg.AgentID}); err != nil {
			t.Fatalf("the rotated key: %v", err)
		}
	})
}

// VerifyAgentRequest refuses a request with no credential or another
// scheme, reads a body without consuming it for the route, and fails
// closed when the request cannot be read.
func TestAgentAuthHTTP_VerifyAgentRequest(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		r := httptest.NewRequest(http.MethodGet, testBaseURL+"/app/thing", nil)
		_, err := x.ag.VerifyAgentRequest(r)
		aaWant(t, "no credential", err, agentauth.ErrAuthenticationRequired)
		r.Header.Set("Authorization", "Basic YTpi")
		_, err = x.ag.VerifyAgentRequest(r)
		aaWant(t, "basic credential", err, agentauth.ErrInvalidJWT)
		r = httptest.NewRequest(http.MethodPost, testBaseURL+"/app/thing", iotest.ErrReader(errors.New("connection reset")))
		_, err = x.ag.VerifyAgentRequest(r)
		aaWant(t, "unreadable body", err, agentauth.ErrInvalidRequest)

		hk, host := x.host(t, aaRead)
		ak, reg := x.register(t, hk, host.HostID, agentauth.RegisterRequest{})
		payload := []byte(`{"id":"7"}`)
		sum := sha256.Sum256(payload)
		tok := x.agentJWT(t, ak, reg.AgentID, map[string]any{"htm": "POST", "htu": testBaseURL + "/app/thing", "ath": base64.RawURLEncoding.EncodeToString(sum[:])})
		r = httptest.NewRequest(http.MethodPost, testBaseURL+"/app/thing", bytes.NewReader(payload))
		r.Header.Set("Authorization", "Bearer "+tok)
		s, err := x.ag.VerifyAgentRequest(r)
		if err != nil || s.AgentID != reg.AgentID {
			t.Fatalf("bound request: %+v %v", s, err)
		}
		if rest, _ := io.ReadAll(r.Body); !bytes.Equal(rest, payload) {
			t.Fatalf("the route lost the body: %q", rest)
		}
	})
}

// A database failure answers 500 (and is logged) rather than a client
// error, both inside an operation and while resolving a session cookie;
// VerifyAgentRequest drops the cookie, so its failure is the agent
// lookup's.
func TestAgentAuthHTTP_DatabaseFailures(t *testing.T) {
	fe := newFaultEnv(t)
	x := newAAEnv(t, fe.env)
	h := x.ag.Handler()
	hk, host := x.host(t, aaRead)
	ak, reg := x.register(t, hk, host.HostID, agentauth.RegisterRequest{})

	fe.f.arm(1)
	code, body := aaHTTP(t, h, http.MethodGet, agentauth.PathStatus+"?agent_id="+reg.AgentID, "Bearer "+x.hostTok(t, hk, host.HostID).Token, nil, "")
	if !fe.f.disarm() || code != http.StatusInternalServerError || body["error"] != "internal_error" {
		t.Fatalf("operation fault: %d %v", code, body)
	}
	fe.f.arm(1)
	code, body = aaHTTP(t, h, http.MethodPost, agentauth.PathRevoke, "", strings.NewReader(`{"agent_id":"`+reg.AgentID+`"}`), x.alice.Token)
	if !fe.f.disarm() || code != http.StatusInternalServerError {
		t.Fatalf("session cookie fault: %d %v", code, body)
	}
	r := httptest.NewRequest(http.MethodGet, testBaseURL+"/app/thing", nil)
	r.Header.Set("Authorization", "Bearer "+x.agentJWT(t, ak, reg.AgentID, nil))
	r.AddCookie(&http.Cookie{Name: authhttp.CookieName, Value: string(x.alice.Token)})
	fe.f.arm(1)
	_, err := x.ag.VerifyAgentRequest(r)
	if !fe.f.disarm() || !errors.Is(err, errFault) {
		t.Fatalf("VerifyAgentRequest: %v", err)
	}
}

// c3Env is newAAEnv with auth options as well.
func c3Env(t *testing.T, e *env, authOpts []auth.Option, opts ...agentauth.Option) *aaEnv {
	t.Helper()
	x := &aaEnv{e: e}
	exec := agentauth.OnExecute(func(_ context.Context, ex agentauth.Execution) (any, error) {
		x.executed = append(x.executed, ex)
		return map[string]any{"ok": true}, nil
	})
	x.ag = agentauth.New(append([]agentauth.Option{agentauth.Capabilities(
		agentauth.Capability{Name: aaRead, Description: "Read user data"},
		agentauth.Capability{Name: aaTransfer, Description: "Transfer funds"},
	), exec}, opts...)...)
	x.em, x.pw = e.emailPlugin(), e.passwordPlugin()
	x.a = e.newAuth(t, authOpts, x.em, x.pw, x.ag)
	x.alice = signUpVerified(t, e, x.a, x.pw, x.em)
	return x
}

// setRow writes one column of the rows where matches, for a state no
// operation produces (a host status the plugin does not know) and for rows
// corrupted outside the library. Revoked hosts and grants, claimed agents
// and metadata come from their operations (round 38).
func setRow[T any](t *testing.T, x *aaEnv, table sqlb.Table, col sqlb.Expr[T], v T, where sqlb.Predicate) {
	t.Helper()
	if _, err := x.a.Exec(context.Background(), sqlb.NewUpdate(x.a.Dialect()).Table(table).Set(sqlb.Set(col, v)).Where(where)); err != nil {
		t.Fatal(err)
	}
}

// rawToken is a token whose header says typ and whose payload is not
// base64.
func rawToken(typ string) string {
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": typ})
	return base64.RawURLEncoding.EncodeToString(h) + ".!!.AAAA"
}

// dynTok is a dynamic host's registration token for a new agent key.
func (x *aaEnv) dynTok(t *testing.T, hk aaKey, claims map[string]any) agentauth.Bearer {
	t.Helper()
	c := map[string]any{"host_public_key": hk.pub, "agent_public_key": aaNewKey(t).pub}
	for k, v := range claims {
		c[k] = v
	}
	return agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, c)}
}

// Registration refuses each malformed request with its own error.
func TestAgentAuth_RegistrationRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration())
		hk, h := x.host(t, aaRead)
		reg := func(name string, b agentauth.Bearer, in agentauth.RegisterRequest) error {
			in.Name, in.Bearer = name, b
			_, err := x.ag.Register(anon(x.a), in)
			return err
		}
		known := func(claims map[string]any) agentauth.Bearer {
			c := map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub}
			for k, v := range claims {
				c[k] = v
			}
			return agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, c)}
		}
		aaWant(t, "no token", reg("A", agentauth.Bearer{}, agentauth.RegisterRequest{}), agentauth.ErrInvalidJWT)
		aaWant(t, "no name", reg("", known(nil), agentauth.RegisterRequest{}), agentauth.ErrInvalidRequest)
		aaWant(t, "unknown capability", reg("A", known(nil), agentauth.RegisterRequest{Capabilities: caps("launch_rockets")}), agentauth.ErrInvalidCapabilities)
		aaWant(t, "unreadable token", reg("A", agentauth.Bearer{Token: rawToken(agentauth.TypeHostJWT)}, agentauth.RegisterRequest{}), agentauth.ErrInvalidJWT)
		aaWant(t, "no agent key", reg("A", known(map[string]any{"agent_public_key": nil}), agentauth.RegisterRequest{}), agentauth.ErrInvalidPublicKey)
		inf := math.Inf(1)
		if err := reg("A", known(nil), agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaRead, Constraints: agentauth.Constraints{"amount": {Max: &inf}}}}}); err == nil {
			t.Fatal("a grant with an unencodable bound registered")
		}
		badKey := agentauth.PublicKey{KeyType: "OKP", Curve: agentauth.AlgEd25519, X: "AAAA"}
		if err := reg("A", known(map[string]any{"agent_public_key": badKey}), agentauth.RegisterRequest{}); err == nil {
			t.Fatal("a malformed agent key registered")
		}

		// A dynamic host proves its key in the token itself.
		dk := aaNewKey(t)
		aaWant(t, "dynamic without its key", reg("A", x.dynTok(t, dk, map[string]any{"host_public_key": nil}), agentauth.RegisterRequest{}), agentauth.ErrInvalidJWT)
		if err := reg("A", x.dynTok(t, dk, map[string]any{"host_public_key": badKey}), agentauth.RegisterRequest{}); err == nil {
			t.Fatal("a malformed host key registered")
		}
		aaWant(t, "dynamic expired", reg("A", x.dynTok(t, dk, map[string]any{"exp": x.a.Now().Add(-time.Second).Unix()}), agentauth.RegisterRequest{}), agentauth.ErrInvalidJWT)

		// A dynamic host naming itself by its thumbprint (as agentclient
		// does) registers, under the name in its token.
		if err := reg("A", x.dynTok(t, dk, map[string]any{"iss": dk.pub.Thumbprint(), "host_name": "CI runner"}), agentauth.RegisterRequest{HostName: "ignored"}); err != nil {
			t.Fatalf("dynamic with a thumbprint iss: %v", err)
		}
		var name *string
		if err := x.a.One(context.Background(), x.a.Select().Columns(sqlb.Bind(agentauth.HostName, &name)).From(agentauth.TableHost).Where(sqlb.Eq(agentauth.HostKid, dk.pub.Thumbprint()))); err != nil || name == nil || *name != "CI runner" {
			t.Fatalf("host name: %v %v", name, err)
		}
		// Its kid now belongs to that key: another key claiming it is refused.
		impostor := aaNewKey(t)
		impostor.pub.KeyID = dk.pub.Thumbprint()
		aaWant(t, "another key under a known kid", reg("A", x.dynTok(t, impostor, nil), agentauth.RegisterRequest{}), agentauth.ErrInvalidJWT)
		// A pending host cannot rotate its key.
		_, err := x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{Bearer: x.hostTok(t, dk, dk.pub.Thumbprint()), PublicKey: aaNewKey(t).pub})
		aaWant(t, "pending host rotating", err, agentauth.ErrUnauthorized)
	})
}

// An autonomous agent registers only on a host nobody owns, and its first
// registration activates a pending one.
func TestAgentAuth_AutonomousRegistration(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.Modes(agentauth.ModeDelegated, agentauth.ModeAutonomous))
		hk, h := x.host(t, aaRead)
		_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Mode: agentauth.ModeAutonomous,
			Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub})}})
		aaWant(t, "autonomous on a user's host", err, agentauth.ErrUnsupportedMode)

		dk := aaNewKey(t)
		x.register(t, dk, "", agentauth.RegisterRequest{}) // delegated: the host stays pending
		rotate := func() error {
			_, err := x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{Bearer: x.hostTok(t, dk, dk.pub.Thumbprint()), PublicKey: dk.pub})
			return err
		}
		aaWant(t, "pending host", rotate(), agentauth.ErrUnauthorized)
		if _, reg := x.register(t, dk, "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous}); reg.Status != agentauth.AgentActive {
			t.Fatalf("autonomous: %+v", reg)
		}
		if err := rotate(); err != nil {
			t.Fatalf("the host is active now: %v", err)
		}
	})
}

// A server serving delegated agents only refuses an autonomous one.
func TestAgentAuth_ModeNotServed(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.Modes(agentauth.ModeDelegated))
		_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Mode: agentauth.ModeAutonomous, Bearer: x.dynTok(t, aaNewKey(t), nil)})
		aaWant(t, "autonomous", err, agentauth.ErrUnsupportedMode)
	})
}

// MaxAgentsPerUser counts a user's active agents.
func TestAgentAuth_MaxAgentsPerUser(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.MaxAgentsPerUser(1))
		hk, h := x.host(t, aaRead)
		x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "Second",
			Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub})}})
		aaWant(t, "second agent", err, agentauth.ErrAgentLimitReached)
	})
}

// CreateHost refuses a bad key, an unknown capability, a key another user
// claimed, a kid another key holds, and a revoked host; a budget function's
// error reaches the caller.
func TestAgentAuth_CreateHostRefusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		errBudget := errors.New("budget service down")
		failBudget := false
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.DefaultHostCapabilitiesFunc(func(context.Context, agentauth.HostCapabilitiesContext) ([]string, error) {
			if failBudget {
				return nil, errBudget
			}
			return []string{aaRead}, nil
		}))
		create := func(tok auth.Token, in agentauth.CreateHostRequest) error {
			_, err := x.ag.CreateHost(request(x.a, tok), in)
			return err
		}
		aaWant(t, "bad key", create(x.alice.Token, agentauth.CreateHostRequest{PublicKey: agentauth.PublicKey{KeyType: "OKP", Curve: agentauth.AlgEd25519, X: "AAAA"}}), agentauth.ErrInvalidPublicKey)
		aaWant(t, "unknown capability", create(x.alice.Token, agentauth.CreateHostRequest{PublicKey: aaNewKey(t).pub, DefaultCapabilities: []string{"launch_rockets"}}), agentauth.ErrInvalidCapabilities)
		failBudget = true
		aaWant(t, "budget function", create(x.alice.Token, agentauth.CreateHostRequest{PublicKey: aaNewKey(t).pub}), errBudget)
		_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Bearer: x.dynTok(t, aaNewKey(t), nil)})
		aaWant(t, "budget function on a dynamic host", err, errBudget)
		failBudget = false

		// Bob claims a dynamic host first; Alice cannot take it.
		dk := aaNewKey(t)
		_, dreg := x.register(t, dk, "", agentauth.RegisterRequest{})
		bob := x.signUp(t, aaBob)
		if err := create(bob.Token, agentauth.CreateHostRequest{PublicKey: dk.pub}); err != nil {
			t.Fatalf("bob claims: %v", err)
		}
		aaWant(t, "claimed by another user", create(x.alice.Token, agentauth.CreateHostRequest{PublicKey: dk.pub}), agentauth.ErrHostAlreadyLinked)
		other := aaNewKey(t)
		other.pub.KeyID = dk.pub.Thumbprint()
		aaWant(t, "a kid another key holds", create(x.alice.Token, agentauth.CreateHostRequest{PublicKey: other.pub}), agentauth.ErrHostAlreadyLinked)

		// Its owner revokes it; the revoked key refuses everything.
		if _, err := x.ag.RevokeHost(request(x.a, bob.Token), agentauth.RevokeHostRequest{HostID: dreg.HostID}); err != nil {
			t.Fatal(err)
		}
		aaWant(t, "revoked host claimed again", create(bob.Token, agentauth.CreateHostRequest{PublicKey: dk.pub}), agentauth.ErrHostRevoked)
		_, err = x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Bearer: x.dynTok(t, dk, nil)})
		aaWant(t, "revoked dynamic host registering", err, agentauth.ErrHostRevoked)
	})
}

// A host row in a state no operation produces, or with a key the server
// no longer accepts, refuses its tokens.
func TestAgentAuth_StoredHostStates(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		status := func(b agentauth.Bearer) error {
			_, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: b, AgentID: reg.AgentID})
			return err
		}
		aaWant(t, "unreadable host token", status(agentauth.Bearer{Token: rawToken(agentauth.TypeHostJWT)}), agentauth.ErrInvalidJWT)
		aaWant(t, "host token without iss", status(agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, nil)}), agentauth.ErrInvalidJWT)
		aaWant(t, "unknown host", status(x.hostTok(t, hk, "agh_nobody")), agentauth.ErrHostNotFound)
		_, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: "agt_nobody"})
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)
		_, err = x.ag.Status(anon(x.a), agentauth.StatusRequest{})
		aaWant(t, "no token", err, agentauth.ErrAuthenticationRequired)
		// Another host's agent is not this host's to read.
		ok2, h2 := x.host(t)
		aaWant(t, "another host's agent", status(x.hostTok(t, ok2, h2.HostID)), agentauth.ErrUnauthorized)

		// The server stops accepting Ed25519: the stored keys no longer verify.
		p256 := &aaEnv{e: e, ag: agentauth.New(agentauth.Capabilities(agentauth.Capability{Name: aaRead}), agentauth.AllowedKeyAlgorithms(agentauth.AlgP256))}
		p256.a = e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), p256.ag)
		_, err = p256.ag.Status(anon(p256.a), agentauth.StatusRequest{Bearer: p256.hostTok(t, hk, h.HostID), AgentID: reg.AgentID})
		aaWant(t, "host key of a dropped algorithm", err, agentauth.ErrInvalidJWT)
		_, err = p256.ag.Session(anon(p256.a), p256.agentTok(t, ak, reg.AgentID))
		aaWant(t, "agent key of a dropped algorithm", err, agentauth.ErrInvalidPublicKey)
		if in, err := p256.ag.Introspect(anon(p256.a), agentauth.IntrospectRequest{Token: p256.agentJWT(t, ak, reg.AgentID, nil)}); err != nil || in.Active {
			t.Fatalf("introspect, dropped algorithm: %+v %v", in, err)
		}

		// A status the plugin does not know refuses like a revoked one
		// (RevokeHost, round 38, produces the revoked one).
		setRow(t, x, agentauth.TableHost, agentauth.HostStatusCol, "suspended", sqlb.Eq(agentauth.HostID, h.HostID))
		aaWant(t, "host suspended", status(x.hostTok(t, hk, h.HostID)), agentauth.ErrHostRevoked)
		setRow(t, x, agentauth.TableHost, agentauth.HostStatusCol, string(agentauth.HostActive), sqlb.Eq(agentauth.HostID, h.HostID))
		setRow(t, x, agentauth.TableHost, agentauth.HostPublicKey, "{not json", sqlb.Eq(agentauth.HostID, h.HostID))
		aaWant(t, "corrupt host key", status(x.hostTok(t, hk, h.HostID)), agentauth.ErrInvalidPublicKey)
	})
}

// The id generator's failure reaches the caller of every insert.
func TestAgentAuth_IDGeneratorFailure(t *testing.T) {
	errIDs := errors.New("id service down")
	failing := ""
	ids := auth.WithIDs(func(prefix string) (string, error) {
		if prefix == failing {
			return "", errIDs
		}
		return auth.NewID(prefix)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		x := c3Env(t, e, []auth.Option{ids}, agentauth.AllowDynamicHostRegistration())
		hk, h := x.host(t)
		failing = "agh"
		_, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{PublicKey: aaNewKey(t).pub})
		aaWant(t, "host id", err, errIDs)
		failing = "agt"
		_, err = x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub})}})
		aaWant(t, "agent id", err, errIDs)
		failing = "aga"
		_, err = x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Bearer: x.dynTok(t, aaNewKey(t), nil)})
		aaWant(t, "approval id", err, errIDs)
		failing = "agg"
		_, err = x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Capabilities: caps(aaRead), Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub})}})
		aaWant(t, "grant id", err, errIDs)
		failing = ""
	})
}

// c3Presence is a PresenceVerifier whose user is enrolled.
type c3Presence struct{}

func (c3Presence) PresenceEnrolled(context.Context, string) (bool, error) { return true, nil }

func (c3Presence) BeginPresence(context.Context, string, string) (string, json.RawMessage, error) {
	return "cer", json.RawMessage(`{}`), nil
}

func (c3Presence) VerifyPresence(context.Context, string, string, string, json.RawMessage) error {
	return nil
}

// An agent's session refuses each stored state no operation lets it act
// in, carries its metadata, and slides its expiry no further than its
// lifetimes allow.
func TestAgentAuth_SessionStates(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.AgentSessionTTL(2*time.Hour), agentauth.AgentMaxLifetime(time.Hour))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		session := func() (agentauth.AgentSession, error) { return x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID)) }
		where := sqlb.Eq(agentauth.AgentID, reg.AgentID)

		if _, err := x.ag.UpdateAgent(request(x.a, x.alice.Token), agentauth.UpdateAgentRequest{AgentID: reg.AgentID, Metadata: json.RawMessage(`{"team":"ops"}`)}); err != nil {
			t.Fatal(err)
		}
		s, err := session()
		if err != nil || string(s.Agent.Metadata) != `{"team":"ops"}` {
			t.Fatalf("metadata: %s %v", s.Agent.Metadata, err)
		}
		// The two-hour TTL is capped by the one-hour lifetime from activation.
		st, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.agentTok(t, ak, reg.AgentID)})
		if err != nil || !c3After(t, st.ActivatedAt, st.ExpiresAt, time.Hour) {
			t.Fatalf("expiry capped by the lifetime: %+v %v", st, err)
		}

		// A claimed agent's session is refused in TestAgentAuth_Claim, where
		// Claim produces one (round 38).
		setRow(t, x, agentauth.TableAgent, agentauth.AgentPublicKey, "{not json", where)
		_, err = session()
		aaWant(t, "corrupt agent key", err, agentauth.ErrInvalidPublicKey)
		if in, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: x.agentJWT(t, ak, reg.AgentID, nil)}); err != nil || in.Active {
			t.Fatalf("introspect, corrupt key: %+v %v", in, err)
		}

		// A denied registration leaves a rejected agent.
		dk := aaNewKey(t)
		rk, rejected := x.register(t, dk, "", agentauth.RegisterRequest{})
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: rejected.AgentID, Action: agentauth.ActionDeny, UserCode: rejected.Approval.UserCode}); err != nil {
			t.Fatal(err)
		}
		_, err = x.ag.Session(anon(x.a), x.agentTok(t, rk, rejected.AgentID))
		aaWant(t, "rejected agent", err, agentauth.ErrAgentRejected)
	})
	// The absolute lifetime caps the slide too.
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AgentSessionTTL(2*time.Hour), agentauth.AbsoluteLifetime(30*time.Minute))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		st, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.agentTok(t, ak, reg.AgentID)})
		if err != nil || !c3After(t, st.CreatedAt, st.ExpiresAt, 30*time.Minute) {
			t.Fatalf("expiry capped by the absolute lifetime: %+v %v", st, err)
		}
	})
}

// c3After reports whether the RFC 3339 time to is d after from, to the
// second the status view carries.
func c3After(t *testing.T, from, to *string, d time.Duration) bool {
	t.Helper()
	if from == nil || to == nil {
		return false
	}
	f, err1 := time.Parse(time.RFC3339, *from)
	e, err2 := time.Parse(time.RFC3339, *to)
	if err1 != nil || err2 != nil {
		t.Fatalf("status times: %v %v", err1, err2)
	}
	return e.Sub(f).Truncate(time.Second) == d
}

// Deleting a user removes every agent of the user's hosts, the pending ones
// that belong to nobody yet included, with their grants and approval
// requests: nothing of the account outlives it.
func TestAgentAuth_DeleteUserRemovesTheHostsAgents(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t, aaRead)
		_, active := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		_, pending := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead), ForceApproval: true})
		if pending.Status != agentauth.AgentPending {
			t.Fatalf("pending: %+v", pending)
		}
		bob := x.signUp(t, aaBob)
		if err := x.a.DeleteUser(context.Background(), bob.User.ID); err != nil {
			t.Fatalf("a user with no agents: %v", err)
		}
		if err := x.a.DeleteUser(context.Background(), x.alice.User.ID); err != nil {
			t.Fatal(err)
		}
		count := func(table sqlb.Table, p sqlb.Predicate) int64 {
			var n int64
			if err := x.a.One(context.Background(), x.a.Select().Columns(sqlb.Bind(sqlb.Count(), &n)).From(table).Where(p)); err != nil {
				t.Fatal(err)
			}
			return n
		}
		for _, id := range []string{active.AgentID, pending.AgentID} {
			if n := count(agentauth.TableAgent, sqlb.Eq(agentauth.AgentID, id)) + count(agentauth.TableGrant, sqlb.Eq(agentauth.GrantAgent, id)) +
				count(agentauth.TableApproval, sqlb.Eq(agentauth.ApprovalAgent, id)); n != 0 {
				t.Errorf("agent %s left %d rows behind", id, n)
			}
		}
		if n := count(agentauth.TableHost, sqlb.Eq(agentauth.HostID, h.HostID)); n != 0 {
			t.Errorf("host left behind")
		}
	})
}

// The user an agent acts for: an AutonomousUser that fails or answers
// nobody, and no AutonomousUser at all each refuse.
func TestAgentAuth_SessionUser(t *testing.T) {
	errOwners := errors.New("owner directory down")
	for name, fn := range map[string]agentauth.AutonomousUserFunc{
		"no function": nil,
		"nobody":      func(context.Context, string, string) (*agentauth.SessionUser, error) { return nil, nil },
		"failing":     func(context.Context, string, string) (*agentauth.SessionUser, error) { return nil, errOwners },
	} {
		t.Run(name, func(t *testing.T) {
			eachEngine(t, func(t *testing.T, e *env) {
				opts := []agentauth.Option{agentauth.AllowDynamicHostRegistration(), agentauth.Modes(agentauth.ModeDelegated, agentauth.ModeAutonomous), agentauth.DefaultHostCapabilities(aaRead)}
				if fn != nil {
					opts = append(opts, agentauth.AutonomousUser(fn))
				}
				x := newAAEnv(t, e, opts...)
				ak, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
				_, err := x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID))
				if name == "failing" {
					aaWant(t, name, err, errOwners)
				} else {
					aaWant(t, name, err, agentauth.ErrAutonomousOwnerRequired)
				}
			})
		})
	}
}

// Revocation, status, introspection and key rotation refuse what they must.
func TestAgentAuth_RevokeStatusIntrospectRotate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration())
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		_, other := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		_, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: x.agentTok(t, ak, reg.AgentID), AgentID: other.AgentID})
		aaWant(t, "an agent revoking another", err, agentauth.ErrUnauthorized)
		_, err = x.ag.Revoke(request(x.a, x.alice.Token), agentauth.RevokeRequest{AgentID: "agt_nobody"})
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)

		// A pending agent on a host Alice claimed afterwards is hers through
		// the host: she can revoke it.
		dk := aaNewKey(t)
		_, pending := x.register(t, dk, "", agentauth.RegisterRequest{})
		if _, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{PublicKey: dk.pub}); err != nil {
			t.Fatal(err)
		}
		if _, err := x.ag.Revoke(request(x.a, x.alice.Token), agentauth.RevokeRequest{AgentID: pending.AgentID}); err != nil {
			t.Fatalf("owner through the host: %v", err)
		}

		// Introspection answers inactive for anything it cannot vouch for.
		inactive := map[string]string{
			"unreadable": rawToken(agentauth.TypeAgentJWT),
			"unknown":    x.agentJWT(t, ak, "agt_nobody", nil),
			"revoked":    x.agentJWT(t, dk, pending.AgentID, nil),
		}
		for name, tok := range inactive {
			if in, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: tok}); err != nil || in.Active {
				t.Errorf("introspect %s: %+v %v", name, in, err)
			}
		}
		_, err = x.ag.Session(anon(x.a), agentauth.Bearer{Token: ak.jwt(t, x.a, agentauth.TypeAgentJWT, nil)})
		aaWant(t, "agent token without sub", err, agentauth.ErrAgentNotFound)
		in, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: x.agentJWT(t, ak, reg.AgentID, map[string]any{"capabilities": []string{aaRead}})})
		if err != nil || !in.Active {
			t.Fatalf("introspect naming one capability: %+v %v", in, err)
		}

		_, err = x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{PublicKey: aaNewKey(t).pub})
		aaWant(t, "rotate without a token", err, agentauth.ErrAuthenticationRequired)
		_, err = x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{Bearer: x.hostTok(t, hk, h.HostID), PublicKey: agentauth.PublicKey{KeyType: "OKP", Curve: agentauth.AlgEd25519, X: "AAAA"}})
		aaWant(t, "rotate to a bad key", err, agentauth.ErrInvalidPublicKey)
		ok2, _ := x.host(t)
		_, err = x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{Bearer: x.hostTok(t, hk, h.HostID), PublicKey: ok2.pub})
		aaWant(t, "rotate to another host's key", err, agentauth.ErrHostAlreadyLinked)
	})
	// An agent past its lifetime introspects inactive.
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AgentMaxLifetime(time.Hour))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		e.clock.Advance(2 * time.Hour)
		if in, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: x.agentJWT(t, ak, reg.AgentID, nil)}); err != nil || in.Active {
			t.Fatalf("introspect, expired: %+v %v", in, err)
		}
	})
}

// Requesting capabilities refuses a malformed request, re-asks the user
// for one already pending, and the catalogue reads as anonymous for a
// token it cannot verify unless authentication is required.
func TestAgentAuth_RequestAndListEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		request := func(b agentauth.Bearer, c []agentauth.CapabilityRequest) (agentauth.RequestCapabilityResult, error) {
			return x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: b, Capabilities: c})
		}
		_, err := request(agentauth.Bearer{}, caps(aaTransfer))
		aaWant(t, "no token", err, agentauth.ErrAuthenticationRequired)
		_, err = request(x.agentTok(t, ak, reg.AgentID), nil)
		aaWant(t, "nothing requested", err, agentauth.ErrInvalidRequest)
		_, err = request(x.agentTok(t, ak, reg.AgentID), caps("launch_rockets"))
		aaWant(t, "unknown capability", err, agentauth.ErrInvalidCapabilities)
		first, err := request(x.agentTok(t, ak, reg.AgentID), caps(aaTransfer))
		if err != nil || first.Approval == nil {
			t.Fatalf("first request: %+v %v", first, err)
		}
		again, err := request(x.agentTok(t, ak, reg.AgentID), caps(aaTransfer))
		if err != nil || again.Status != agentauth.AgentPending || again.Approval == nil || len(again.Grants) != 1 || again.Grants[0].Status != agentauth.GrantPending {
			t.Fatalf("asking again: %+v %v", again, err)
		}

		forged := agentauth.Bearer{Token: x.agentJWT(t, aaNewKey(t), reg.AgentID, nil)}
		list, err := x.ag.ListCapabilities(anon(x.a), agentauth.ListCapabilitiesRequest{Bearer: forged})
		if err != nil || len(list.Capabilities) != 2 || list.Capabilities[0].GrantStatus != "" {
			t.Fatalf("a forged token lists as anonymous: %+v %v", list, err)
		}
		for _, cursor := range []string{"x", "-1"} {
			_, err := x.ag.ListCapabilities(anon(x.a), agentauth.ListCapabilitiesRequest{Cursor: cursor})
			aaWant(t, "cursor "+cursor, err, agentauth.ErrInvalidRequest)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.RequireAuthForCapabilities())
		_, err := x.ag.DescribeCapability(anon(x.a), agentauth.DescribeCapabilityRequest{Bearer: agentauth.Bearer{Token: x.agentJWT(t, aaNewKey(t), "agt_nobody", nil)}, Name: aaRead})
		aaWant(t, "describe with a bad token", err, agentauth.ErrAgentNotFound)
	})
}

// An autonomous agent with no owner asks nobody for a capability outside
// its budget: there is no one to approve it.
func TestAgentAuth_AutonomousRequestOutsideTheBudget(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.Modes(agentauth.ModeDelegated, agentauth.ModeAutonomous),
			agentauth.DefaultHostCapabilities(aaRead), agentauth.AutonomousUser(func(_ context.Context, hostID, _ string) (*agentauth.SessionUser, error) {
				return &agentauth.SessionUser{ID: "bot:" + hostID}, nil
			}))
		ak, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Mode: agentauth.ModeAutonomous})
		res, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capabilities: caps(aaTransfer)})
		if err != nil || res.Status != agentauth.AgentActive || res.Approval != nil || len(res.Grants) != 0 {
			t.Fatalf("autonomous request: %+v %v", res, err)
		}
	})
}

// Approval refuses a malformed answer and a capability blocked since it was
// requested; a denied grant shows its reason; a budget function failing
// while a pending agent is activated fails the approval.
func TestAgentAuth_ApproveEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		ctx := request(x.a, x.alice.Token)
		hk, h := x.host(t, aaRead)
		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead, aaTransfer), Reason: "rent is due"})
		_, err := x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg.AgentID, Action: "maybe"})
		aaWant(t, "unknown action", err, agentauth.ErrInvalidRequest)

		// Blocked by a deployment after the request was made.
		blocked := &aaEnv{e: e, ag: agentauth.New(agentauth.Capabilities(agentauth.Capability{Name: aaRead}, agentauth.Capability{Name: aaTransfer}), agentauth.BlockedCapabilities(aaTransfer))}
		blocked.a = e.newAuth(t, nil, e.emailPlugin(), e.passwordPlugin(), blocked.ag)
		_, err = blocked.ag.ApproveCapability(request(blocked.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode})
		aaWant(t, "blocked since requested", err, agentauth.ErrCapabilityBlocked)

		if _, err := x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionDeny, UserCode: reg.Approval.UserCode}); err != nil {
			t.Fatal(err)
		}
		st, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg.AgentID})
		if err != nil || st.Status != agentauth.AgentRejected || len(st.Grants) != 2 {
			t.Fatalf("status: %+v %v", st, err)
		}
		for _, g := range st.Grants {
			if g.Capability == aaTransfer && (g.Status != agentauth.GrantDenied || g.Reason == nil || *g.Reason != "rent is due") {
				t.Fatalf("denied grant: %+v", g)
			}
		}

		// An approval id answers for its own agent only.
		_, cibaReg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaTransfer), ApprovalHints: agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA}})
		inbox, err := x.ag.PendingApprovalsFor(ctx)
		if err != nil || len(inbox.Requests) != 1 {
			t.Fatalf("inbox: %+v %v", inbox, err)
		}
		_, err = x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{ApprovalID: inbox.Requests[0].ApprovalID, AgentID: reg.AgentID, Action: agentauth.ActionApprove})
		aaWant(t, "approval id of another agent", err, agentauth.ErrApprovalNotFound)
		// The CIBA request expires, and so does a device request for an agent
		// nobody owns yet.
		_, forced := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead), ForceApproval: true})
		e.clock.Advance(agentauth.DefaultApprovalTTL + time.Second)
		_, err = x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: cibaReg.AgentID, Action: agentauth.ActionApprove})
		aaWant(t, "expired CIBA request", err, agentauth.ErrApprovalExpired)
		// Swept, nothing addresses the request any more: only the owner may
		// answer, and nobody else's code-less answer is taken.
		if _, err := x.ag.Sweep(context.Background(), x.a.Now()); err != nil {
			t.Fatal(err)
		}
		bob := x.signUp(t, aaBob)
		_, err = x.ag.ApproveCapability(request(x.a, bob.Token), agentauth.ApproveRequest{AgentID: forced.AgentID, Action: agentauth.ActionApprove})
		aaWant(t, "a stranger after the sweep", err, agentauth.ErrInvalidUserCode)
		if res, err := x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: forced.AgentID, Action: agentauth.ActionApprove}); err != nil || len(res.Added) != 1 {
			t.Fatalf("the owner after the sweep: %+v %v", res, err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		errBudget := errors.New("budget service down")
		var named string
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.DefaultHostCapabilitiesFunc(func(_ context.Context, hc agentauth.HostCapabilitiesContext) ([]string, error) {
			if hc.UserID != nil {
				named = hc.HostName
				return nil, errBudget
			}
			return nil, nil
		}))
		_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{HostName: "Build box"})
		_, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode})
		aaWant(t, "budget failing on activation", err, errBudget)
		if named != "Build box" {
			t.Fatalf("the budget function was told host name %q", named)
		}
	})
	// With proof of presence, a pending agent on a pending host needs it.
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.ProofOfPresence(c3Presence{}))
		_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{})
		res, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode})
		if err != nil || res.Status != agentauth.ApprovalWebAuthnRequired {
			t.Fatalf("presence: %+v %v", res, err)
		}
	})
}

// A grant that lapsed by its GrantTTL can be asked for again, and approving
// the new request grants it again: the lapsed grant does not count as
// covering it.
func TestAgentAuth_RegrantAfterTheGrantLapsed(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := c3Env(t, e, nil, agentauth.Capabilities(
			agentauth.Capability{Name: aaRead},
			agentauth.Capability{Name: aaTransfer, GrantTTL: time.Minute},
		))
		ctx := request(x.a, x.alice.Token)
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaTransfer)})
		if res, err := x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: reg.Approval.UserCode}); err != nil || len(res.Added) != 1 {
			t.Fatalf("approve: %+v %v", res, err)
		}
		exec := func() error {
			_, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capability: aaTransfer})
			return err
		}
		if err := exec(); err != nil {
			t.Fatalf("execute: %v", err)
		}
		e.clock.Advance(2 * time.Minute)
		aaWant(t, "lapsed grant", exec(), agentauth.ErrCapabilityNotGranted)
		again, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capabilities: caps(aaTransfer)})
		if err != nil || again.Approval == nil {
			t.Fatalf("ask again: %+v %v", again, err)
		}
		res, err := x.ag.ApproveCapability(ctx, agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: again.Approval.UserCode})
		if err != nil || len(res.Added) != 1 {
			t.Fatalf("approve again: %+v %v", res, err)
		}
		if err := exec(); err != nil {
			t.Fatalf("execute after the second approval: %v", err)
		}
	})
}

// Execution refuses without a token or a handler, keeps a handler's
// protocol error, hides any other as internal, and never regrants from the
// budget a capability whose grant was revoked or is unreadable.
func TestAgentAuth_ExecuteEdges(t *testing.T) {
	errPlain := errors.New("ledger down")
	errProto := auth.NewError("app.insufficient_funds", http.StatusPaymentRequired, "Insufficient funds.")
	var answer error
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e, agentauth.OnExecute(func(context.Context, agentauth.Execution) (any, error) { return nil, answer }))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		exec := func(capability string, args map[string]any) error {
			_, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capability: capability, Arguments: args})
			return err
		}
		_, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Capability: aaRead})
		aaWant(t, "no token", err, agentauth.ErrAuthenticationRequired)
		answer = errProto
		aaWant(t, "protocol error", exec(aaRead, nil), errProto)
		answer = errPlain
		if err := exec(aaRead, nil); !errors.Is(err, auth.ErrInternal) || !errors.Is(err, errPlain) {
			t.Fatalf("plain error: %v", err)
		}
		answer = nil

		// A grant revoked on its own is not granted again from the budget.
		if _, err := x.ag.RevokeCapability(request(x.a, x.alice.Token), agentauth.RevokeCapabilityRequest{AgentID: reg.AgentID, Capabilities: []string{aaRead}}); err != nil {
			t.Fatal(err)
		}
		aaWant(t, "revoked grant", exec(aaRead, nil), agentauth.ErrGrantRevoked)

		// A constrained grant whose stored constraints cannot be read
		// authorizes nothing.
		ck, cons := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: []agentauth.CapabilityRequest{{Name: aaTransfer, Constraints: agentauth.Constraints{"id": agentauth.Eq(agentauth.String("1"))}}}})
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: cons.AgentID, Action: agentauth.ActionApprove, UserCode: cons.Approval.UserCode}); err != nil {
			t.Fatal(err)
		}
		setRow(t, x, agentauth.TableGrant, agentauth.GrantConstraints, ptr("{not json"), sqlb.Eq(agentauth.GrantAgent, cons.AgentID))
		_, err = x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: x.agentTok(t, ck, cons.AgentID), Capability: aaTransfer, Arguments: map[string]any{"id": "1"}})
		aaWant(t, "unreadable constraints", err, agentauth.ErrCapabilityNotGranted)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnvExec(t, e, false)
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		_, err := x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capability: aaRead})
		aaWant(t, "no handler", err, agentauth.ErrExecuteNotConfigured)
	})
}

// A failing approval-method resolver fails the registration; a CIBA login
// hint that names no identifier kind addresses nobody.
func TestAgentAuth_CIBAEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		errMethod := errors.New("policy service down")
		x := newAAEnv(t, e, agentauth.ResolveApprovalMethod(func(context.Context, agentauth.ApprovalMethodContext) (string, error) { return "", errMethod }))
		hk, h := x.host(t)
		_, err := x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Capabilities: caps(aaRead),
			Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_public_key": aaNewKey(t).pub})}})
		aaWant(t, "resolver failing", err, errMethod)
	})
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t, aaRead)
		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		res, err := x.ag.CIBAAuthorize(anon(x.a), agentauth.CIBAAuthorizeRequest{Bearer: x.hostTok(t, hk, h.HostID), LoginHint: "%%%", AgentID: reg.AgentID})
		if err != nil || res.AuthReqID == "" {
			t.Fatalf("unaddressable hint: %+v %v", res, err)
		}
		if inbox, err := x.ag.PendingApprovalsFor(request(x.a, x.alice.Token)); err != nil || len(inbox.Requests) != 0 {
			t.Fatalf("alice's inbox: %+v %v", inbox, err)
		}
	})
}

// Events: a rotated host key, a denial, an execution refused before its
// input was read (none), and an OnEvent that panics (recovered).
func TestAgentAuth_EventEdges(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		panicking := false
		x := newAAEnv(t, e, agentauth.AllowDynamicHostRegistration(), agentauth.OnEvent(func(ctx context.Context, got agentauth.Event) {
			if panicking {
				panic("listener bug")
			}
			ev.fn(ctx, got)
		}))
		hk, h := x.host(t, aaRead)
		if _, err := x.ag.RotateHostKey(anon(x.a), agentauth.RotateHostKeyRequest{Bearer: x.hostTok(t, hk, h.HostID), PublicKey: aaNewKey(t).pub}); err != nil {
			t.Fatal(err)
		}
		_, reg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{Capabilities: caps(aaTransfer)})
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionDeny, UserCode: reg.Approval.UserCode}); err != nil {
			t.Fatal(err)
		}
		hk2, h2 := x.host(t, aaRead)
		ak, active := x.register(t, hk2, h2.HostID, agentauth.RegisterRequest{})
		if _, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: x.agentTok(t, ak, active.AgentID)}); err != nil {
			t.Fatal(err)
		}
		var execute auth.Operation
		for _, op := range x.ag.Operations() {
			if op.Info().ID == agentauth.EndpointExecute {
				execute = op
			}
		}
		if _, err := execute.Invoke(x.a.WithRequest(context.Background(), auth.Request{}), func(any) error { return errors.New("bad body") }); err == nil {
			t.Fatal("an undecodable execution ran")
		}
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventHostKeyRotated); len(got) != 1 || got[0].HostID != h.HostID {
			t.Fatalf("host.key_rotated: %+v", got)
		}
		for _, typ := range []string{agentauth.EventCapabilityDenied, agentauth.EventApprovalDenied} {
			if got := ev.of(typ); len(got) != 1 || got[0].AgentID != reg.AgentID || got[0].ActorID != x.alice.User.ID {
				t.Fatalf("%s: %+v", typ, got)
			}
		}
		if got := ev.of(agentauth.EventAgentRevoked); len(got) != 1 || got[0].ActorType != agentauth.ActorAgent || got[0].ActorID != "" || got[0].AgentID != active.AgentID {
			t.Fatalf("agent.revoked by the agent itself: %+v", got)
		}
		if got := ev.of(agentauth.EventCapabilityExecuted); len(got) != 0 {
			t.Fatalf("an execution that never read its input reported: %+v", got)
		}
		panicking = true
		if _, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{PublicKey: aaNewKey(t).pub}); err != nil {
			t.Fatalf("a panicking listener failed the operation: %v", err)
		}
		x.a.WaitDeliveries()
	})
}
