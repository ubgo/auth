package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ubgo/auth/plugin/agentauth"
)

// fakeProvider answers every endpoint with a canned JSON body and records
// the path and token of each request.
type fakeProvider struct {
	mu     sync.Mutex
	paths  []string
	tokens []string
	srv    *httptest.Server
}

func newFakeProvider(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *fakeProvider {
	t.Helper()
	f := &fakeProvider{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		f.tokens = append(f.tokens, strings.TrimPrefix(r.Header.Get(headerAuth), "Bearer "))
		f.mu.Unlock()
		if r.URL.Path == agentauth.WellKnownConfiguration {
			_ = json.NewEncoder(w).Encode(f.provider())
			return
		}
		answer(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeProvider) provider() Provider {
	u := f.srv.URL
	return Provider{Issuer: u, DefaultLocation: u + "/execute", Endpoints: map[string]string{
		"register": u + "/register", "status": u + "/status", "capabilities": u + "/capabilities",
		"describe_capability": u + "/describe", "request_capability": u + "/request", "revoke": u + "/revoke",
	}}
}

func (f *fakeProvider) last() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.paths[len(f.paths)-1], f.tokens[len(f.tokens)-1]
}

// A host key without its private half signs nothing: every host-signed
// call fails with ErrNoKey before a request is sent, and so does every
// agent-signed call of an agent without one.
func TestClient_RefusesToSignWithoutAPrivateKey(t *testing.T) {
	ctx := context.Background()
	f := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) })
	full, _ := NewKey()
	public := Key{Public: full.Public}
	c := New(public)
	p := f.provider()
	a := Agent{ID: "agt_1", Key: public, Provider: p}
	calls := map[string]func() error{
		"connect":    func() error { _, _, err := c.Connect(ctx, p, ConnectRequest{Name: "A"}); return err },
		"status":     func() error { _, err := c.Status(ctx, a); return err },
		"list":       func() error { _, err := c.ListCapabilities(ctx, p, nil); return err },
		"describe":   func() error { _, err := c.DescribeCapability(ctx, p, "x"); return err },
		"ciba":       func() error { _, err := c.CIBAAuthorize(ctx, a, "alice@example.com", "", nil); return err },
		"execute":    func() error { _, err := c.Execute(ctx, a, "x", "", nil); return err },
		"disconnect": func() error { return c.Disconnect(ctx, a) },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, ErrNoKey) {
			t.Errorf("%s: %v, want ErrNoKey", name, err)
		}
	}
	if len(f.paths) != 0 {
		t.Fatalf("a request went out: %v", f.paths)
	}
}

func TestClient_CallsAndAnswers(t *testing.T) {
	ctx := context.Background()
	f := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"dynamic_host_registration_disabled","message":"no"}`)
		case "/capabilities":
			_, _ = io.WriteString(w, `{"capabilities":[{"name":"read_data"}]}`)
		default:
			_, _ = io.WriteString(w, `{"data":{"path":"`+r.URL.Path+`"}}`)
		}
	})
	host, _ := NewKey()
	c := New(host)
	p := f.provider()

	// A refused registration is the provider's protocol error.
	var pe *Error
	if _, _, err := c.Connect(ctx, p, ConnectRequest{Name: "A"}); !errors.As(err, &pe) || pe.Code != "dynamic_host_registration_disabled" {
		t.Fatalf("connect: %v", err)
	}

	// Without an agent, the catalogue is read with a host JWT.
	list, err := c.ListCapabilities(ctx, p, nil)
	if err != nil || len(list.Capabilities) != 1 || list.Capabilities[0].Name != "read_data" {
		t.Fatalf("list: %+v %v", list, err)
	}
	if _, tok := f.last(); tok == "" {
		t.Fatal("list sent no token")
	} else if h, _ := decodeJWT(t, tok, host.Public); h["typ"] != agentauth.TypeHostJWT {
		t.Fatalf("list token: %v", h)
	}

	// Execute goes to the capability's own location when it has one.
	agentKey, _ := NewKey()
	a := Agent{ID: "agt_1", Key: agentKey, Provider: p}
	data, err := c.Execute(ctx, a, "read_data", f.srv.URL+"/elsewhere", map[string]any{"id": "1"})
	if err != nil || !strings.Contains(string(data), "/elsewhere") {
		t.Fatalf("execute at a location: %s %v", data, err)
	}
	if _, err := c.Execute(ctx, a, "read_data", "", map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("unencodable arguments")
	}
	if path, _ := f.last(); path != "/elsewhere" {
		t.Fatalf("unencodable arguments were sent: %s", path)
	}
}

// WaitForApproval polls at the default interval when given none, and
// stops with the context between polls.
func TestWaitForApproval_DefaultIntervalAndCancelBetweenPolls(t *testing.T) {
	host, _ := NewKey()
	c := New(host)
	active := newFakeProvider(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"status":"active"}`) })
	st, err := c.WaitForApproval(context.Background(), Agent{ID: "a", Provider: active.provider()}, 0)
	if err != nil || st.Status != agentauth.AgentActive {
		t.Fatalf("active: %+v %v", st, err)
	}

	// The answer is pending and the caller gives up before the next poll.
	// The transport answers from memory, so the cancel cannot cut the
	// answer itself short.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pending := New(host, WithHTTPClient(&http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		cancel()
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"status":"pending"}`)), Request: r}, nil
	})}))
	st, err = pending.WaitForApproval(ctx, Agent{ID: "a", Provider: active.provider()}, time.Hour)
	if !errors.Is(err, context.Canceled) || st.Status != agentauth.AgentPending {
		t.Fatalf("cancelled: %+v %v", st, err)
	}
}

// roundTrip is an http.RoundTripper from a function.
type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// An answer cut short is an error, not a half-decoded success.
func TestSend_TruncatedAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, `{"status":`)
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no hijacker")
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer srv.Close()
	k, _ := NewKey()
	var out map[string]any
	if err := New(k).send(context.Background(), http.MethodGet, srv.URL, "", nil, &out); err == nil {
		t.Fatalf("truncated answer accepted: %v", out)
	}
}

// The MCP tools reach the provider: list and describe with a host JWT,
// connect reporting a refusal, request with the stored agent.
func TestTools_ReachTheProvider(t *testing.T) {
	ctx := context.Background()
	f := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":"unauthorized","message":"no"}`)
		case "/capabilities":
			_, _ = io.WriteString(w, `{"capabilities":[{"name":"read_data"}]}`)
		case "/describe":
			_, _ = io.WriteString(w, `{"name":"`+r.URL.Query().Get("name")+`"}`)
		case "/request":
			_, _ = io.WriteString(w, `{"agent_id":"agt_1","status":"pending"}`)
		}
	})
	host, _ := NewKey()
	agentKey, _ := NewKey()
	store := &MemoryStore{}
	_ = store.SaveAgent(ctx, Agent{ID: "agt_1", Key: agentKey, Provider: f.provider()})
	tools := map[string]Tool{}
	for _, tool := range New(host).Tools(store) {
		tools[tool.Name] = tool
	}
	prov := `{"provider":"` + f.srv.URL + `"}`
	out, err := tools[ToolListCapabilities].Call(ctx, json.RawMessage(prov))
	if list, ok := out.(agentauth.CapabilityList); err != nil || !ok || len(list.Capabilities) != 1 {
		t.Fatalf("list: %+v %v", out, err)
	}
	out, err = tools[ToolDescribeCapability].Call(ctx, json.RawMessage(`{"provider":"`+f.srv.URL+`","name":"read_data"}`))
	if v, ok := out.(agentauth.CapabilityView); err != nil || !ok || v.Name != "read_data" {
		t.Fatalf("describe: %+v %v", out, err)
	}
	var pe *Error
	if _, err := tools[ToolConnectAgent].Call(ctx, json.RawMessage(`{"provider":"`+f.srv.URL+`","name":"A"}`)); !errors.As(err, &pe) || pe.Status != http.StatusForbidden {
		t.Fatalf("connect: %v", err)
	}
	if _, err := store.LoadAgent(ctx, ""); !errors.Is(err, ErrUnknownAgent) {
		t.Fatal("a refused connect stored an agent")
	}
	out, err = tools[ToolRequestCapability].Call(ctx, json.RawMessage(`{"agent_id":"agt_1","capabilities":["read_data"]}`))
	if r, ok := out.(agentauth.RequestCapabilityResult); err != nil || !ok || r.Status != agentauth.AgentPending {
		t.Fatalf("request: %+v %v", out, err)
	}
	if path, tok := f.last(); path != "/request" || tok == "" {
		t.Fatalf("request went to %s", path)
	} else if h, c := decodeJWT(t, tok, agentKey.Public); h["typ"] != agentauth.TypeAgentJWT || c["sub"] != "agt_1" {
		t.Fatalf("request token: %v %v", h, c)
	}
}
