package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/agentauth"
	"github.com/ubgo/auth/plugin/agentauth/agentclient"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
	// hostName is what the test's host calls itself.
	hostName = "Laptop CLI"
	// agentName is what the test's agent calls itself.
	agentName = "Bookkeeping assistant"
	// pollInterval is how often the test's agent asks whether it was approved.
	pollInterval = 10 * time.Millisecond
)

// TestAgentOpenAPI_OperationsBecomeCapabilities: the catalogue comes from
// the document; a new host's budget holds the GET operation, so an agent
// lists invoices at once and the call reaches the API as Alice; paying
// needs her approval, after which the POST reaches the API with the path
// parameter filled in.
func TestAgentOpenAPI_OperationsBecomeCapabilities(t *testing.T) {
	api := newInvoicesAPI()
	upstream := httptest.NewServer(api)
	t.Cleanup(upstream.Close)
	a, ag := newTestAuth(t, upstream.URL)
	srv := httptest.NewServer(newHandler(a, ag))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	// Discovery: the provider's name and every operation, from the document.
	cfg := getJSON[agentauth.Configuration](t, srv, "/.well-known/agent-configuration")
	if cfg.ProviderName != "Invoices" {
		t.Fatalf("configuration = %+v", cfg)
	}
	c := agentclient.New(mustKey(t), agentclient.WithHostName(hostName), agentclient.WithHTTPClient(&http.Client{Transport: toServer{srv}}))
	p, err := c.Discover(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	list, err := c.ListCapabilities(ctx, p, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, cv := range list.Capabilities {
		names = append(names, cv.Name)
	}
	if !slices.Contains(names, opListInvoices) || !slices.Contains(names, opPayInvoice) {
		t.Fatalf("capabilities = %v", names)
	}

	// Alice registers the host with no budget of her own: the GET
	// operations are its budget.
	alice := userSession(t, srv)
	hostKey := mustKey(t)
	post(t, alice, "/auth/agentauth/create-host", agentauth.CreateHostRequest{Name: hostName, PublicKey: hostKey.Public}, http.StatusOK)
	c = agentclient.New(hostKey, agentclient.WithHostName(hostName), agentclient.WithHTTPClient(&http.Client{Transport: toServer{srv}}))
	agent, reg, err := c.Connect(ctx, p, agentclient.ConnectRequest{Name: agentName, Capabilities: []agentauth.CapabilityRequest{{Name: opListInvoices}}})
	if err != nil || reg.Status != agentauth.AgentActive {
		t.Fatalf("connect = %+v %v", reg, err)
	}
	out, err := c.Execute(ctx, agent, opListInvoices, "", nil)
	var got []invoice
	if err != nil || json.Unmarshal(out, &got) != nil || len(got) != len(seedInvoices) || got[0].Paid {
		t.Fatalf("list = %s %v", out, err)
	}

	// Paying is a POST: not in the budget, so Alice approves it.
	var pe *agentclient.Error
	if _, err := c.Execute(ctx, agent, opPayInvoice, "", map[string]any{"id": "inv_1"}); !errors.As(err, &pe) || pe.Code != "capability_not_granted" {
		t.Fatalf("pay before approval = %v", err)
	}
	asked, err := c.RequestCapability(ctx, agent, []agentauth.CapabilityRequest{{Name: opPayInvoice}}, "pay your invoices", agentauth.ApprovalHints{})
	if err != nil || asked.Approval == nil {
		t.Fatalf("request = %+v %v", asked, err)
	}
	post(t, alice, "/auth/agentauth/approve-capability", agentauth.ApproveRequest{AgentID: agent.ID, UserCode: asked.Approval.UserCode, Action: agentauth.ActionApprove}, http.StatusOK)
	if st, err := c.WaitForApproval(ctx, agent, pollInterval); err != nil || st.Status != agentauth.AgentActive {
		t.Fatalf("status = %+v %v", st, err)
	}
	out, err = c.Execute(ctx, agent, opPayInvoice, "", map[string]any{"id": "inv_1"})
	var paid invoice
	if err != nil || json.Unmarshal(out, &paid) != nil || paid.ID != "inv_1" || !paid.Paid {
		t.Fatalf("pay = %s %v", out, err)
	}
	// The API recorded the payment for Alice, the user the agent acts for.
	out, err = c.Execute(ctx, agent, opListInvoices, "", nil)
	if err != nil || json.Unmarshal(out, &got) != nil || !got[0].Paid || got[1].Paid {
		t.Fatalf("list after paying = %s %v", out, err)
	}
	if len(api.paid) != 1 {
		t.Fatalf("payments = %v", api.paid)
	}
	for k := range api.paid {
		if !strings.HasPrefix(k, "usr_") {
			t.Fatalf("the API did not see the acting user: %q", k)
		}
	}
}

// TestNewAgentAuth_RefusesABadBaseURL: an API URL that is not absolute
// fails at start, not at the first call.
func TestNewAgentAuth_RefusesABadBaseURL(t *testing.T) {
	if _, err := newAgentAuth("invoices.internal", nil); !errors.Is(err, agentauth.ErrBadOpenAPI) {
		t.Fatalf("relative base URL = %v", err)
	}
}

// mustKey is a fresh host key.
func mustKey(t *testing.T) agentclient.Key {
	t.Helper()
	k, err := agentclient.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newTestAuth builds the app on a fresh SQLite file, proxying to apiBase.
func newTestAuth(t *testing.T, apiBase string) (*auth.Auth, *agentauth.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ag, err := newAgentAuth(apiBase, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, err := newAuth(db, logMailer{}, ag)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, ag
}

// toServer sends every request for baseURL to the test server and keeps
// the Host header, so the server sees the URL the agent signed: agent tokens
// are bound to the request's method and URL (htm, htu).
type toServer struct{ srv *httptest.Server }

// RoundTrip rewrites the request's address and sends it.
func (p toServer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = r.URL.Host
	r.URL.Host = strings.TrimPrefix(p.srv.URL, "http://")
	return http.DefaultTransport.RoundTrip(r)
}

// session is a signed-in user's bearer token. The test server is plain
// HTTP, where a browser would not keep the __Host- cookie, so the user's
// calls use bearer mode, as a mobile app does.
type session struct {
	srv   *httptest.Server
	token string
}

// userSession signs Alice up in bearer mode and returns her session.
func userSession(t *testing.T, srv *httptest.Server) session {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"identifier": testEmail, "password": testPassword, "name": testName})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+authPrefix+"/password/sign-up", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authhttp.TokenModeHeader, "bearer")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	tok := res.Header.Get(authhttp.SetTokenHeader)
	if res.StatusCode != http.StatusOK || tok == "" {
		t.Fatalf("sign-up = %d, token %q", res.StatusCode, tok)
	}
	return session{srv: srv, token: tok}
}

// post sends in as JSON with the session's token and returns the body.
func post[In any](t *testing.T, s session, path string, in In, status int) string {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("POST %s: %d %s, want %d", path, res.StatusCode, buf.String(), status)
	}
	return buf.String()
}

// getJSON GETs path from srv and decodes the answer.
func getJSON[Out any](t *testing.T, srv *httptest.Server, path string) Out {
	t.Helper()
	res, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out Out
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", path, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
