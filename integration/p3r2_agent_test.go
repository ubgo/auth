package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/agentauth"
)

// Round p3r2: the agent-auth operations better-auth has that the port did
// not: agent reactivation and key rotation, host update and enrollment,
// and JWKS URLs in place of stored keys.

// An expired agent is reactivated by its host: every grant it held is
// revoked and the host's budget granted again, so an approved escalation is
// lost; an agent that has not expired is answered as it is; another host,
// a revoked agent and an agent past its absolute lifetime are refused.
func TestP3R2Agent_Reactivate(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.AgentSessionTTL(time.Hour), agentauth.AbsoluteLifetime(10*time.Hour), agentauth.OnEvent(ev.fn))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		req, err := x.ag.RequestCapability(anon(x.a), agentauth.RequestCapabilityRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capabilities: caps(aaTransfer)})
		if err != nil || req.Approval == nil {
			t.Fatalf("request transfer: %+v %v", req, err)
		}
		if _, err := x.ag.ApproveCapability(request(x.a, x.alice.Token), agentauth.ApproveRequest{AgentID: reg.AgentID, Action: agentauth.ActionApprove, UserCode: req.Approval.UserCode}); err != nil {
			t.Fatalf("approve transfer: %v", err)
		}
		reactivate := func(b agentauth.Bearer, agentID string) (agentauth.AgentStatusView, error) {
			return x.ag.Reactivate(anon(x.a), agentauth.ReactivateRequest{Bearer: b, AgentID: agentID})
		}
		live := func(v agentauth.AgentStatusView) []string {
			var out []string
			for _, g := range v.Grants {
				if g.Status == agentauth.GrantActive {
					out = append(out, g.Capability)
				}
			}
			return out
		}

		// Not expired: the status as it is, nothing revoked.
		same, err := reactivate(x.hostTok(t, hk, h.HostID), reg.AgentID)
		if err != nil || same.Status != agentauth.AgentActive || len(live(same)) != 2 {
			t.Fatalf("live agent: %+v %v", same, err)
		}
		_, err = reactivate(agentauth.Bearer{}, reg.AgentID)
		aaWant(t, "no token", err, agentauth.ErrAuthenticationRequired)
		ok2, h2 := x.host(t)
		_, err = reactivate(x.hostTok(t, ok2, h2.HostID), reg.AgentID)
		aaWant(t, "another host", err, agentauth.ErrUnauthorized)
		_, err = reactivate(x.hostTok(t, hk, h.HostID), "agt_nobody")
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)

		e.clock.Advance(61 * time.Minute)
		_, err = x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID))
		aaWant(t, "expired", err, agentauth.ErrAgentExpired)
		back, err := reactivate(x.hostTok(t, hk, h.HostID), reg.AgentID)
		if got := live(back); err != nil || back.Status != agentauth.AgentActive || len(got) != 1 || got[0] != aaRead || back.ExpiresAt == nil {
			t.Fatalf("reactivated: %+v %v", back, err)
		}
		s, err := x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID))
		if err != nil || len(s.Agent.CapabilityGrants) != 1 || s.Agent.CapabilityGrants[0].Capability != aaRead {
			t.Fatalf("session after reactivation: %+v %v", s, err)
		}
		_, err = x.ag.Execute(anon(x.a), agentauth.ExecuteRequest{Bearer: x.agentTok(t, ak, reg.AgentID), Capability: aaTransfer})
		aaWant(t, "the escalation is gone", err, agentauth.ErrGrantRevoked)

		// Past the absolute lifetime: refused, even by its host.
		e.clock.Advance(10 * time.Hour)
		_, err = reactivate(x.hostTok(t, hk, h.HostID), reg.AgentID)
		aaWant(t, "absolute lifetime", err, agentauth.ErrAbsoluteLifetimeExceeded)

		// Retired agents stay retired.
		_, reg2 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		if _, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg2.AgentID}); err != nil {
			t.Fatal(err)
		}
		_, err = reactivate(x.hostTok(t, hk, h.HostID), reg2.AgentID)
		aaWant(t, "revoked agent", err, agentauth.ErrAgentRevoked)

		// Over HTTP, and its event.
		ak3, reg3 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		_ = ak3
		e.clock.Advance(2 * time.Hour)
		code, body := aaHTTP(t, x.ag.Handler(), http.MethodPost, agentauth.PathReactivate, "Bearer "+x.hostTok(t, hk, h.HostID).Token, strings.NewReader(`{"agent_id":"`+reg3.AgentID+`"}`), "")
		if code != http.StatusOK || body["status"] != string(agentauth.AgentActive) || body["agent_id"] != reg3.AgentID {
			t.Fatalf("reactivate over HTTP: %d %v", code, body)
		}
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventAgentReactivated); len(got) != 2 || got[0].AgentID != reg.AgentID || got[0].ActorType != agentauth.ActorHost || len(got[0].Capabilities) != 1 {
			t.Fatalf("agent.reactivated: %+v", got)
		}
	})
}

// A host rotates its agent's key: the old key stops at once, the new one
// works; only the agent's own host may, only for a live agent, and never to
// a key a sibling agent holds.
func TestP3R2Agent_RotateAgentKey(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.OnEvent(ev.fn))
		hk, h := x.host(t, aaRead)
		ak, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		sib, _ := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		rotate := func(b agentauth.Bearer, agentID string, key agentauth.PublicKey) (agentauth.RotateAgentKeyResult, error) {
			return x.ag.RotateAgentKey(anon(x.a), agentauth.RotateAgentKeyRequest{Bearer: b, AgentID: agentID, PublicKey: key})
		}
		next := aaNewKey(t)
		_, err := rotate(agentauth.Bearer{}, reg.AgentID, next.pub)
		aaWant(t, "no token", err, agentauth.ErrAuthenticationRequired)
		_, err = rotate(x.hostTok(t, hk, h.HostID), reg.AgentID, agentauth.PublicKey{KeyType: "OKP"})
		aaWant(t, "bad key", err, agentauth.ErrInvalidPublicKey)
		ok2, h2 := x.host(t)
		_, err = rotate(x.hostTok(t, ok2, h2.HostID), reg.AgentID, next.pub)
		aaWant(t, "another host", err, agentauth.ErrUnauthorized)
		_, err = rotate(x.hostTok(t, hk, h.HostID), "agt_nobody", next.pub)
		aaWant(t, "unknown agent", err, agentauth.ErrAgentNotFound)
		_, err = rotate(x.hostTok(t, hk, h.HostID), reg.AgentID, sib.pub)
		aaWant(t, "a sibling's key", err, agentauth.ErrAgentExists)

		res, err := rotate(x.hostTok(t, hk, h.HostID), reg.AgentID, next.pub)
		if err != nil || res.AgentID != reg.AgentID || res.Status != agentauth.AgentActive {
			t.Fatalf("rotate: %+v %v", res, err)
		}
		_, err = x.ag.Session(anon(x.a), x.agentTok(t, ak, reg.AgentID))
		aaWant(t, "the old key", err, agentauth.ErrInvalidJWT)
		if _, err := x.ag.Session(anon(x.a), x.agentTok(t, next, reg.AgentID)); err != nil {
			t.Fatalf("the new key: %v", err)
		}
		if _, err := x.ag.Revoke(anon(x.a), agentauth.RevokeRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg.AgentID}); err != nil {
			t.Fatal(err)
		}
		_, err = rotate(x.hostTok(t, hk, h.HostID), reg.AgentID, aaNewKey(t).pub)
		aaWant(t, "revoked agent", err, agentauth.ErrAgentRevoked)

		_, reg3 := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		k4 := aaNewKey(t)
		raw, _ := json.Marshal(map[string]any{"agent_id": reg3.AgentID, "public_key": k4.pub})
		code, body := aaHTTP(t, x.ag.Handler(), http.MethodPost, agentauth.PathRotateAgentKey, "Bearer "+x.hostTok(t, hk, h.HostID).Token, strings.NewReader(string(raw)), "")
		if code != http.StatusOK || body["agent_id"] != reg3.AgentID || body["host_id"] != nil {
			t.Fatalf("rotate over HTTP: %d %v", code, body)
		}
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventAgentKeyRotated); len(got) != 2 || got[0].AgentID != reg.AgentID || got[0].HostID != h.HostID {
			t.Fatalf("agent.key_rotated: %+v", got)
		}
	})
}

// The owner updates a host's name, budget and key; nobody else can, a
// revoked host cannot change, and the key cannot be one another host holds.
func TestP3R2Agent_UpdateHost(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.OnEvent(ev.fn))
		hk, h := x.host(t, aaRead)
		update := func(tok auth.Token, in agentauth.UpdateHostRequest) (agentauth.UpdateHostResult, error) {
			return x.ag.UpdateHost(request(x.a, tok), in)
		}
		name := "Desk"
		res, err := update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, Name: &name, DefaultCapabilities: []string{aaRead, aaTransfer}})
		if err != nil || res.HostID != h.HostID || res.Name == nil || *res.Name != name || len(res.DefaultCapabilities) != 2 || res.Status != agentauth.HostActive {
			t.Fatalf("update: %+v %v", res, err)
		}
		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{Capabilities: caps(aaTransfer)})
		if reg.Status != agentauth.AgentActive || reg.Grants[0].Status != agentauth.GrantActive {
			t.Fatalf("the new budget grants transfer: %+v", reg)
		}
		_, err = update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, DefaultCapabilities: []string{"launch_rockets"}})
		aaWant(t, "unknown capability", err, agentauth.ErrInvalidCapabilities)

		other, _ := x.host(t)
		_, err = update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, PublicKey: &other.pub})
		aaWant(t, "another host's key", err, agentauth.ErrHostAlreadyLinked)
		_, err = update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, PublicKey: &agentauth.PublicKey{KeyType: "OKP"}})
		aaWant(t, "bad key", err, agentauth.ErrInvalidPublicKey)
		u := "https://keys.example.com/jwks"
		_, err = update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, PublicKey: &other.pub, JWKSURL: &u})
		aaWant(t, "a key and a URL", err, agentauth.ErrInvalidRequest)
		_, err = update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, JWKSURL: &u})
		aaWant(t, "JWKS URLs off", err, agentauth.ErrJWKSURLsDisabled)

		next := aaNewKey(t)
		if _, err := update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, PublicKey: &next.pub}); err != nil {
			t.Fatalf("new key: %v", err)
		}
		_, err = x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg.AgentID})
		aaWant(t, "the old host key", err, agentauth.ErrInvalidJWT)
		if _, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, next, h.HostID), AgentID: reg.AgentID}); err != nil {
			t.Fatalf("the new host key: %v", err)
		}

		bob := x.signUp(t, aaBob)
		_, err = update(bob.Token, agentauth.UpdateHostRequest{HostID: h.HostID, Name: &name})
		aaWant(t, "another user's host", err, agentauth.ErrHostNotFound)
		_, err = update(x.alice.Token, agentauth.UpdateHostRequest{HostID: "agh_nobody", Name: &name})
		aaWant(t, "unknown host", err, agentauth.ErrHostNotFound)
		if _, err := x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{HostID: h.HostID}); err != nil {
			t.Fatal(err)
		}
		_, err = update(x.alice.Token, agentauth.UpdateHostRequest{HostID: h.HostID, Name: &name})
		aaWant(t, "revoked host", err, agentauth.ErrHostRevoked)
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventHostUpdated); len(got) != 2 || got[0].HostID != h.HostID || got[0].ActorID != x.alice.User.ID {
			t.Fatalf("host.updated: %+v", got)
		}
	})
	// A dynamic host nobody owns is nobody's to edit.
	eachEngine(t, func(t *testing.T, e *env) {
		x := autonomousEnv(t, e)
		_, dreg := x.register(t, aaNewKey(t), "", agentauth.RegisterRequest{})
		name := "Mine now"
		_, err := x.ag.UpdateHost(request(x.a, x.alice.Token), agentauth.UpdateHostRequest{HostID: dreg.HostID, Name: &name})
		aaWant(t, "unowned host", err, agentauth.ErrHostNotFound)
	})
}

// A user creates a host without a key, and a device enrolls with the
// one-time token and its own key; the token works once and expires, the
// host authenticates nothing before, and a key another host holds is
// refused.
func TestP3R2Agent_Enrollment(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		ev := &aaEvents{}
		x := newAAEnv(t, e, agentauth.OnEvent(ev.fn))
		created, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{Name: "Server", DefaultCapabilities: []string{aaRead}})
		if err != nil || created.Status != agentauth.HostPendingEnrollment || created.EnrollmentToken == "" || created.EnrollmentTokenExpiresAt == nil {
			t.Fatalf("create for enrollment: %+v %v", created, err)
		}
		dev := aaNewKey(t)
		_, err = x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: x.hostTok(t, dev, created.HostID), AgentID: "agt_x"})
		aaWant(t, "a host before enrollment", err, agentauth.ErrHostRevoked)
		name := "Box"
		_, err = x.ag.UpdateHost(request(x.a, x.alice.Token), agentauth.UpdateHostRequest{HostID: created.HostID, PublicKey: &dev.pub})
		aaWant(t, "a key by update before enrollment", err, agentauth.ErrInvalidRequest)
		if _, err := x.ag.UpdateHost(request(x.a, x.alice.Token), agentauth.UpdateHostRequest{HostID: created.HostID, Name: &name}); err != nil {
			t.Fatalf("rename before enrollment: %v", err)
		}

		enroll := func(tok string, key agentauth.PublicKey) (agentauth.EnrollHostResult, error) {
			return x.ag.EnrollHost(anon(x.a), agentauth.EnrollHostRequest{Token: tok, PublicKey: key, Name: "Rack 4"})
		}
		_, err = enroll("", dev.pub)
		aaWant(t, "no token", err, agentauth.ErrEnrollmentTokenInvalid)
		_, err = enroll(created.EnrollmentToken+"x", dev.pub)
		aaWant(t, "wrong token", err, agentauth.ErrEnrollmentTokenInvalid)
		_, err = enroll(created.EnrollmentToken, agentauth.PublicKey{KeyType: "OKP"})
		aaWant(t, "bad key", err, agentauth.ErrInvalidPublicKey)
		taken, _ := x.host(t)
		_, err = enroll(created.EnrollmentToken, taken.pub)
		aaWant(t, "a key another host holds", err, agentauth.ErrHostAlreadyLinked)

		res, err := enroll(created.EnrollmentToken, dev.pub)
		if err != nil || res.HostID != created.HostID || res.Status != agentauth.HostActive || res.Name == nil || *res.Name != "Rack 4" || len(res.DefaultCapabilities) != 1 {
			t.Fatalf("enroll: %+v %v", res, err)
		}
		_, reg := x.register(t, dev, created.HostID, agentauth.RegisterRequest{Capabilities: caps(aaRead)})
		if reg.Status != agentauth.AgentActive {
			t.Fatalf("an agent of the enrolled host: %+v", reg)
		}
		_, err = enroll(created.EnrollmentToken, aaNewKey(t).pub)
		aaWant(t, "the token again", err, agentauth.ErrEnrollmentTokenInvalid)
		// The token's hash is gone from the row, not only refused by status.
		var stored []byte
		if err := e.db.QueryRow("SELECT "+agentauth.ColEnrollmentHash+" FROM "+tbl(agentauth.TableNameHost)+" WHERE id = "+aaPlaceholder(e)+"", created.HostID).Scan(&stored); err != nil || stored != nil {
			t.Fatalf("enrollment hash after enrolling: %x %v", stored, err)
		}

		// Over HTTP, with no other credential.
		h3, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{})
		if err != nil {
			t.Fatal(err)
		}
		// Creating a host again with a key the user's host already has is
		// a reactivation, reported as one.
		if _, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{PublicKey: dev.pub}); err != nil {
			t.Fatal(err)
		}
		late, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(map[string]any{"token": h3.EnrollmentToken, "public_key": aaNewKey(t).pub})
		code, body := aaHTTP(t, x.ag.Handler(), http.MethodPost, agentauth.PathEnrollHost, "", strings.NewReader(string(raw)), "")
		if code != http.StatusOK || body["host_id"] != h3.HostID || body["status"] != string(agentauth.HostActive) {
			t.Fatalf("enroll over HTTP: %d %v", code, body)
		}
		// The token expires.
		e.clock.Advance(agentauth.DefaultEnrollmentTokenTTL)
		_, err = enroll(late.EnrollmentToken, aaNewKey(t).pub)
		aaWant(t, "expired token", err, agentauth.ErrEnrollmentTokenExpired)
		x.a.WaitDeliveries()
		if got := ev.of(agentauth.EventHostEnrolled); len(got) != 2 || got[0].HostID != created.HostID {
			t.Fatalf("host.enrolled: %+v", got)
		}
		if got := ev.of(agentauth.EventHostReactivated); len(got) != 1 || got[0].HostID != created.HostID {
			t.Fatalf("host.reactivated: %+v", got)
		}
	})
}

// p3r2JWKS serves key sets by path over TLS, as a key server would.
type p3r2JWKS struct {
	mu   sync.Mutex
	sets map[string][]agentauth.PublicKey
	srv  *httptest.Server
}

func newP3R2JWKS(t *testing.T) *p3r2JWKS {
	t.Helper()
	j := &p3r2JWKS{sets: map[string][]agentauth.PublicKey{}}
	j.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.mu.Lock()
		keys, ok := j.sets[r.URL.Path]
		j.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(j.srv.Close)
	return j
}

// url is the JWKS URL of path, under a name the test certificate holds.
func (j *p3r2JWKS) url(path string) string { return "https://example.com" + path }

func (j *p3r2JWKS) set(path string, keys ...agentauth.PublicKey) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.sets[path] = keys
}

// client dials the test server whatever the URL names.
func (j *p3r2JWKS) client() *http.Client {
	tr := j.srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, j.srv.Listener.Addr().String())
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// kidJWT signs claims as typ with k under header kid, with fresh times.
func kidJWT(t *testing.T, x *aaEnv, k aaKey, typ, kid string, claims map[string]any) string {
	t.Helper()
	now := x.a.Now()
	jti := make([]byte, 12)
	_, _ = rand.Read(jti)
	all := map[string]any{"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": base64.RawURLEncoding.EncodeToString(jti), "aud": testBaseURL}
	for key, v := range claims {
		all[key] = v
	}
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": typ, "kid": kid})
	c, _ := json.Marshal(all)
	in := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	return in + "." + enc.EncodeToString(ed25519.Sign(k.priv, []byte(in)))
}

// A host and an agent sign with keys from their JWKS URLs: the key whose
// kid the header names verifies, a rotated key is picked up, a kid the set
// lacks verifies nothing, and without AllowJWKSURLs no URL is accepted.
func TestP3R2Agent_JWKSURLs(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		j := newP3R2JWKS(t)
		x := newAAEnv(t, e, agentauth.AllowJWKSURLs(), agentauth.JWKSClient(j.client()))
		hostKey, agentKey := aaNewKey(t), aaNewKey(t)
		hpub, apub := hostKey.pub, agentKey.pub
		hpub.KeyID, apub.KeyID = "h1", "a1"
		j.set("/host", hpub)
		j.set("/agent", apub)

		_, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{JWKSURL: "http://example.com/host"})
		aaWant(t, "an http URL", err, agentauth.ErrInvalidJWKSURL)
		_, err = x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{JWKSURL: j.url("/host"), PublicKey: hostKey.pub})
		aaWant(t, "a key and a URL", err, agentauth.ErrInvalidRequest)
		h, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{JWKSURL: j.url("/host"), DefaultCapabilities: []string{aaRead}})
		if err != nil || h.Status != agentauth.HostActive || h.EnrollmentToken != "" {
			t.Fatalf("create with a JWKS URL: %+v %v", h, err)
		}
		register := func(kid string, claims map[string]any) (agentauth.RegisterResult, error) {
			c := map[string]any{"iss": h.HostID}
			for k, v := range claims {
				c[k] = v
			}
			return x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "JWKS agent", Bearer: agentauth.Bearer{Token: kidJWT(t, x, hostKey, agentauth.TypeHostJWT, kid, c)}})
		}
		_, err = register("nope", map[string]any{"agent_jwks_url": j.url("/agent")})
		aaWant(t, "a kid the host's set lacks", err, agentauth.ErrInvalidJWT)
		_, err = register("h1", map[string]any{"agent_jwks_url": "https://127.0.0.1/agent"})
		aaWant(t, "a private agent URL", err, agentauth.ErrInvalidJWKSURL)
		reg, err := register("h1", map[string]any{"agent_jwks_url": j.url("/agent")})
		if err != nil || reg.Status != agentauth.AgentActive {
			t.Fatalf("register a JWKS agent: %+v %v", reg, err)
		}
		_, err = register("h1", map[string]any{"agent_jwks_url": j.url("/agent")})
		aaWant(t, "the same JWKS agent again", err, agentauth.ErrAgentExists)

		agentTok := func(k aaKey, kid string) agentauth.Bearer {
			return agentauth.Bearer{Token: kidJWT(t, x, k, agentauth.TypeAgentJWT, kid, map[string]any{"sub": reg.AgentID})}
		}
		if _, err := x.ag.Session(anon(x.a), agentTok(agentKey, "a1")); err != nil {
			t.Fatalf("a JWKS agent's session: %v", err)
		}
		_, err = x.ag.Session(anon(x.a), agentTok(agentKey, ""))
		aaWant(t, "no kid", err, agentauth.ErrInvalidJWT)
		if in, err := x.ag.Introspect(anon(x.a), agentauth.IntrospectRequest{Token: agentTok(agentKey, "a1").Token}); err != nil || !in.Active {
			t.Fatalf("introspect a JWKS agent: %+v %v", in, err)
		}
		// The agent rotates its key at the URL; after the refetch interval
		// the new kid verifies and the old one, gone from the set, does not.
		next := aaNewKey(t)
		npub := next.pub
		npub.KeyID = "a2"
		j.set("/agent", npub)
		e.clock.Advance(agentauth.DefaultJWKSRefetchInterval)
		if _, err := x.ag.Session(anon(x.a), agentTok(next, "a2")); err != nil {
			t.Fatalf("a rotated JWKS key: %v", err)
		}
		e.clock.Advance(agentauth.DefaultJWKSCacheTTL)
		_, err = x.ag.Session(anon(x.a), agentTok(agentKey, "a1"))
		aaWant(t, "a key removed from the set", err, agentauth.ErrInvalidJWT)

		// The host moves to a stored key, and the agent too.
		if _, err := x.ag.UpdateHost(request(x.a, x.alice.Token), agentauth.UpdateHostRequest{HostID: h.HostID, PublicKey: &hostKey.pub}); err != nil {
			t.Fatalf("host to a stored key: %v", err)
		}
		if _, err := x.ag.RotateAgentKey(anon(x.a), agentauth.RotateAgentKeyRequest{Bearer: x.hostTok(t, hostKey, h.HostID), AgentID: reg.AgentID, PublicKey: agentKey.pub}); err != nil {
			t.Fatalf("agent to a stored key: %v", err)
		}
		if _, err := x.ag.Session(anon(x.a), x.agentTok(t, agentKey, reg.AgentID)); err != nil {
			t.Fatalf("stored key after JWKS: %v", err)
		}
		// And back to a URL.
		u := j.url("/host")
		if res, err := x.ag.UpdateHost(request(x.a, x.alice.Token), agentauth.UpdateHostRequest{HostID: h.HostID, JWKSURL: &u}); err != nil || res.JWKSURL == nil {
			t.Fatalf("host back to a URL: %+v %v", res, err)
		}
		if _, err := x.ag.Status(anon(x.a), agentauth.StatusRequest{Bearer: agentauth.Bearer{Token: kidJWT(t, x, hostKey, agentauth.TypeHostJWT, "h1", map[string]any{"iss": h.HostID})}, AgentID: reg.AgentID}); err != nil {
			t.Fatalf("host signs from its URL again: %v", err)
		}
	})
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		_, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{JWKSURL: "https://keys.example.com/jwks"})
		aaWant(t, "JWKS URLs off at create", err, agentauth.ErrJWKSURLsDisabled)
		hk, h := x.host(t)
		_, err = x.ag.Register(anon(x.a), agentauth.RegisterRequest{Name: "A", Bearer: agentauth.Bearer{Token: hk.jwt(t, x.a, agentauth.TypeHostJWT, map[string]any{"iss": h.HostID, "agent_jwks_url": "https://keys.example.com/jwks"})}})
		aaWant(t, "JWKS URLs off at register", err, agentauth.ErrJWKSURLsDisabled)
	})
}

// The refusals the walks above do not reach: a forged host token on the
// host-signed operations, a malformed body over HTTP, and the token of a
// host revoked before it enrolled.
func TestP3R2Agent_Refusals(t *testing.T) {
	eachEngine(t, func(t *testing.T, e *env) {
		x := newAAEnv(t, e)
		hk, h := x.host(t, aaRead)
		_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
		forged := x.hostTok(t, aaNewKey(t), h.HostID)
		_, err := x.ag.Reactivate(anon(x.a), agentauth.ReactivateRequest{Bearer: forged, AgentID: reg.AgentID})
		aaWant(t, "reactivate with a forged host token", err, agentauth.ErrInvalidJWT)
		_, err = x.ag.RotateAgentKey(anon(x.a), agentauth.RotateAgentKeyRequest{Bearer: x.hostTok(t, aaNewKey(t), h.HostID), AgentID: reg.AgentID, PublicKey: aaNewKey(t).pub})
		aaWant(t, "rotate with a forged host token", err, agentauth.ErrInvalidJWT)
		_, err = x.ag.RotateAgentKey(anon(x.a), agentauth.RotateAgentKeyRequest{AgentID: reg.AgentID, PublicKey: aaNewKey(t).pub})
		aaWant(t, "rotate without a token", err, agentauth.ErrAuthenticationRequired)

		for _, path := range []string{agentauth.PathReactivate, agentauth.PathRotateAgentKey, agentauth.PathEnrollHost} {
			code, body := aaHTTP(t, x.ag.Handler(), http.MethodPost, path, "Bearer "+x.hostTok(t, hk, h.HostID).Token, strings.NewReader(`{"agent_id":`), "")
			if code != http.StatusBadRequest || body["error"] != "invalid_request" {
				t.Fatalf("%s with a malformed body: %d %v", path, code, body)
			}
		}

		pending, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.ag.RevokeHost(request(x.a, x.alice.Token), agentauth.RevokeHostRequest{HostID: pending.HostID}); err != nil {
			t.Fatal(err)
		}
		_, err = x.ag.EnrollHost(anon(x.a), agentauth.EnrollHostRequest{Token: pending.EnrollmentToken, PublicKey: aaNewKey(t).pub})
		aaWant(t, "the token of a revoked host", err, agentauth.ErrEnrollmentTokenInvalid)
	})
}

// aaEnvWith is newAAEnv with auth options, for an id generator that fails.
func aaEnvWith(t *testing.T, e *env, authOpts []auth.Option, opts ...agentauth.Option) *aaEnv {
	t.Helper()
	x := &aaEnv{e: e}
	x.ag = agentauth.New(append([]agentauth.Option{agentauth.Capabilities(
		agentauth.Capability{Name: aaRead, Description: "Read user data"},
		agentauth.Capability{Name: aaTransfer, Description: "Transfer funds"},
	)}, opts...)...)
	x.em, x.pw = e.emailPlugin(), e.passwordPlugin()
	x.a = e.newAuth(t, authOpts, x.em, x.pw, x.ag)
	x.alice = signUpVerified(t, e, x.a, x.pw, x.em)
	return x
}

// Every database call of the new operations fails the operation, and a
// host id that cannot be made fails a keyless create.
func TestP3R2Agent_Faults(t *testing.T) {
	ttl := []agentauth.Option{agentauth.AgentSessionTTL(time.Hour)}
	t.Run("reactivate", func(t *testing.T) {
		aaSweep(t, ttl, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t, aaRead)
			_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
			x.e.clock.Advance(2 * time.Hour)
			return func() error {
				_, err := x.ag.Reactivate(anon(x.a), agentauth.ReactivateRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg.AgentID})
				return err
			}
		})
	})
	t.Run("rotate an agent key", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			hk, h := x.host(t)
			_, reg := x.register(t, hk, h.HostID, agentauth.RegisterRequest{})
			return func() error {
				_, err := x.ag.RotateAgentKey(anon(x.a), agentauth.RotateAgentKeyRequest{Bearer: x.hostTok(t, hk, h.HostID), AgentID: reg.AgentID, PublicKey: aaNewKey(t).pub})
				return err
			}
		})
	})
	t.Run("update a host", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			_, h := x.host(t)
			k := aaNewKey(t)
			return func() error {
				_, err := x.ag.UpdateHost(request(x.a, x.alice.Token), agentauth.UpdateHostRequest{HostID: h.HostID, PublicKey: &k.pub, DefaultCapabilities: []string{aaRead}})
				return err
			}
		})
	})
	t.Run("create for enrollment, and enroll", func(t *testing.T) {
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			return func() error {
				_, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{})
				return err
			}
		})
		aaSweep(t, nil, func(t *testing.T, x *aaEnv) func() error {
			h, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{})
			if err != nil {
				t.Fatal(err)
			}
			return func() error {
				_, err := x.ag.EnrollHost(anon(x.a), agentauth.EnrollHostRequest{Token: h.EnrollmentToken, PublicKey: aaNewKey(t).pub})
				return err
			}
		})
	})
	eachEngine(t, func(t *testing.T, e *env) {
		x := aaEnvWith(t, e, []auth.Option{auth.WithIDs(func(p string) (string, error) {
			if p == "agh" {
				return "", errFactorsIDs
			}
			return auth.NewID(p)
		})})
		_, err := x.ag.CreateHost(request(x.a, x.alice.Token), agentauth.CreateHostRequest{})
		if !errors.Is(err, errFactorsIDs) {
			t.Fatalf("a host id that cannot be made: %v", err)
		}
	})
}

// aaPlaceholder is the first bind parameter in e's engine.
func aaPlaceholder(e *env) string {
	if e.engine == auth.EnginePostgres {
		return "$1"
	}
	return "?"
}
