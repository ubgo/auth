package agentclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/agentauth"
)

// decodeJWT checks the signature against key and returns header and claims.
func decodeJWT(t *testing.T, tok string, key agentauth.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %s", tok)
	}
	pub, _ := b64.DecodeString(key.X)
	sig, _ := b64.DecodeString(parts[2])
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("signature")
	}
	var h, c map[string]any
	hb, _ := b64.DecodeString(parts[0])
	cb, _ := b64.DecodeString(parts[1])
	_ = json.Unmarshal(hb, &h)
	_ = json.Unmarshal(cb, &c)
	return h, c
}

func TestKeys(t *testing.T) {
	k, err := NewKey()
	if err != nil || k.Public.Curve != agentauth.AlgEd25519 || k.Public.KeyType != "OKP" {
		t.Fatalf("%+v %v", k, err)
	}
	again := KeyFrom(k.PrivateKey())
	if again.Public != k.Public {
		t.Fatal("KeyFrom keeps the key")
	}
	if _, err := (Key{}).sign(agentauth.TypeAgentJWT, nil); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no private key: %v", err)
	}
}

func TestSignAgentJWT_BindsTheRequest(t *testing.T) {
	k, _ := NewKey()
	now := time.Unix(1_700_000_000, 0)
	a := Agent{ID: "ag1", Key: k}
	tok, err := SignAgentJWT(a, now, "https://api.example.com", http.MethodPost, "https://api.example.com/run?x=1#f", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	h, c := decodeJWT(t, tok, k.Public)
	sum := sha256.Sum256([]byte(`{}`))
	if h["typ"] != agentauth.TypeAgentJWT || h["alg"] != "EdDSA" || c["sub"] != "ag1" || c["aud"] != "https://api.example.com" ||
		c["htm"] != "POST" || c["htu"] != "https://api.example.com/run" || c["ath"] != b64.EncodeToString(sum[:]) ||
		c["iat"] != float64(now.Unix()) || c["exp"] != float64(now.Add(tokenLifetime).Unix()) || c["jti"] == "" {
		t.Fatalf("claims: %v %v", h, c)
	}
	plain, _ := SignAgentJWT(a, now, "aud", "", "", nil)
	if _, c := decodeJWT(t, plain, k.Public); c["htm"] != nil || c["htu"] != nil || c["ath"] != nil {
		t.Fatalf("unbound: %v", c)
	}
	if _, err := SignAgentJWT(a, now, "aud", "", "%zz", nil); err == nil {
		t.Fatal("a bad target URL")
	}
}

func TestHostJWT(t *testing.T) {
	k, _ := NewKey()
	c := New(k, WithHostName("Laptop"), WithClock(func() time.Time { return time.Unix(10, 0) }))
	tok, err := c.hostJWT("https://p", map[string]any{"agent_public_key": "x"})
	if err != nil {
		t.Fatal(err)
	}
	h, cl := decodeJWT(t, tok, k.Public)
	if h["typ"] != agentauth.TypeHostJWT || cl["iss"] != k.Public.Thumbprint() || cl["sub"] != cl["iss"] || cl["host_name"] != "Laptop" || cl["agent_public_key"] != "x" || cl["host_public_key"] == nil {
		t.Fatalf("%v %v", h, cl)
	}
	k.Public.KeyID = "mine"
	tok, _ = New(k).hostJWT("https://p", nil)
	if _, cl := decodeJWT(t, tok, k.Public); cl["iss"] != "mine" || cl["host_name"] != nil {
		t.Fatalf("kid: %v", cl)
	}
}

func TestSend_ErrorsAndAnswers(t *testing.T) {
	ctx := context.Background()
	var lastAuth, lastCT, lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth, lastCT = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		lastBody = string(b)
		switch r.URL.Path {
		case agentauth.WellKnownConfiguration:
			_, _ = io.WriteString(w, `{"issuer":"https://p","endpoints":{"register":"x"}}`)
		case "/protocol":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"agent_revoked","message":"Agent has been revoked."}`)
		case "/plain":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "upstream down\n")
		default:
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer srv.Close()
	k, _ := NewKey()
	c := New(k, WithHTTPClient(srv.Client()))
	p, err := c.Discover(ctx, srv.URL+"/anything/here")
	if err != nil || p.Issuer != "https://p" || p.Endpoints["register"] != "x" || lastAuth != "" {
		t.Fatalf("discover: %+v %v", p, err)
	}
	if _, err := c.Discover(ctx, "not a url"); err == nil {
		t.Fatal("relative provider")
	}
	var e *Error
	if err := c.do(ctx, http.MethodGet, srv.URL+"/protocol", "tok", nil, nil); !errors.As(err, &e) || e.Status != 403 || e.Code != "agent_revoked" || !strings.Contains(e.Error(), "403 agent_revoked") {
		t.Fatalf("protocol error: %v", err)
	}
	if lastAuth != "Bearer tok" || lastCT != "" {
		t.Fatalf("headers: %q %q", lastAuth, lastCT)
	}
	if err := c.do(ctx, http.MethodGet, srv.URL+"/plain", "", nil, nil); !errors.As(err, &e) || e.Code != "Bad Gateway" || e.Message != "upstream down" {
		t.Fatalf("plain error: %v", err)
	}
	var out map[string]bool
	if err := c.do(ctx, http.MethodPost, srv.URL+"/ok", "", map[string]int{"a": 1}, &out); err != nil || !out["ok"] || lastBody != `{"a":1}` || lastCT != jsonCT {
		t.Fatalf("ok: %v %v %q", out, err, lastBody)
	}
	if err := c.do(ctx, http.MethodPost, srv.URL+"/ok", "", func() {}, nil); err == nil {
		t.Fatal("unencodable body")
	}
	if err := c.send(ctx, http.MethodGet, "", "", nil, nil); err == nil {
		t.Fatal("no endpoint")
	}
	if err := c.send(ctx, "BAD METHOD", srv.URL, "", nil, nil); err == nil {
		t.Fatal("bad method")
	}
	if err := New(k, WithHTTPClient(srv.Client())).send(ctx, http.MethodGet, "http://127.0.0.1:1", "", nil, nil); err == nil {
		t.Fatal("unreachable")
	}
}

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	var m MemoryStore
	if _, err := m.LoadAgent(ctx, "x"); !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("empty: %v", err)
	}
	_ = m.SaveAgent(ctx, Agent{ID: "x"})
	if a, err := m.LoadAgent(ctx, "x"); err != nil || a.ID != "x" {
		t.Fatalf("saved: %+v %v", a, err)
	}
}

func TestTools_ShapesAndUnknownAgents(t *testing.T) {
	ctx := context.Background()
	k, _ := NewKey()
	tools := New(k).Tools(&MemoryStore{})
	want := []string{ToolDiscoverProvider, ToolListCapabilities, ToolDescribeCapability, ToolConnectAgent, ToolAgentStatus, ToolRequestCapability, ToolExecuteCapability, ToolDisconnectAgent}
	if len(tools) != len(want) {
		t.Fatalf("%d tools", len(tools))
	}
	for i, tool := range tools {
		if tool.Name != want[i] || tool.Description == "" || !json.Valid(tool.InputSchema) {
			t.Fatalf("tool %d: %+v", i, tool)
		}
		if _, err := tool.Call(ctx, json.RawMessage(`{`)); err == nil {
			t.Fatalf("%s: malformed arguments", tool.Name)
		}
		_, err := tool.Call(ctx, json.RawMessage(`{"agent_id":"nobody","provider":"not a url"}`))
		if err == nil {
			t.Fatalf("%s: want an error", tool.Name)
		}
		if strings.Contains(string(tool.InputSchema), `"agent_id"`) && !errors.Is(err, ErrUnknownAgent) {
			t.Fatalf("%s: %v", tool.Name, err)
		}
	}
}

func TestWaitForApproval_StopsWithTheContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"status":"pending"}`)
	}))
	defer srv.Close()
	k, _ := NewKey()
	c := New(k)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	a := Agent{ID: "a", Key: k, Provider: Provider{Issuer: srv.URL, Endpoints: map[string]string{"status": srv.URL + "/status"}}}
	st, err := c.WaitForApproval(ctx, a, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || (st.Status != "" && st.Status != agentauth.AgentPending) {
		t.Fatalf("%+v %v", st, err)
	}
}
