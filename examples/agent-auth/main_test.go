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
	// paymentLimit is the most the agent asks to pay at once: enough for
	// the small invoice, not for the large one.
	paymentLimit = 100
	// pollInterval is how often the test's agent asks whether it was approved.
	pollInterval = 10 * time.Millisecond
)

// TestAgentAuth_HostAgentApprovalAndCapabilities runs the whole protocol
// over HTTP: Alice registers a host, the host's agent connects with the
// host's budget, asks to pay invoices up to a limit, Alice approves with
// the agent's code, the agent pays within the limit and is refused above
// it, and once it disconnects it can do nothing.
func TestAgentAuth_HostAgentApprovalAndCapabilities(t *testing.T) {
	a, ag := newTestAuth(t)
	srv := httptest.NewServer(newHandler(a, ag))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	// Discovery: the catalogue at the well-known URL.
	cfg := getJSON[agentauth.Configuration](t, srv, "/.well-known/agent-configuration")
	if cfg.Issuer != baseURL || cfg.Endpoints["register"] != baseURL+agentauth.PathRegister {
		t.Fatalf("configuration = %+v", cfg)
	}

	// Alice signs up, then registers the program her agents run in: its
	// public key, and a budget its agents get without asking.
	alice := userSession(t, srv)
	hostKey, err := agentclient.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	host := post(t, alice, "/auth/agentauth/create-host", agentauth.CreateHostRequest{
		Name: hostName, PublicKey: hostKey.Public, DefaultCapabilities: []string{capListInvoices},
	}, http.StatusOK)
	var created agentauth.CreateHostResult
	decodeInto(t, host, &created)
	if created.HostID == "" {
		t.Fatalf("host = %s", host)
	}

	// The agent connects with the host's key; the budget covers what it
	// asks for, so it is active at once.
	c := agentclient.New(hostKey, agentclient.WithHostName(hostName), agentclient.WithHTTPClient(&http.Client{Transport: toServer{srv}}))
	agent, reg, err := agentConnect(ctx, c, baseURL)
	if err != nil || reg.Status != agentauth.AgentActive || reg.Approval != nil {
		t.Fatalf("connect = %+v %v", reg, err)
	}
	out, err := c.Execute(ctx, agent, capListInvoices, "", nil)
	if err != nil || !strings.Contains(string(out), `"id":"inv_1"`) {
		t.Fatalf("list = %s %v", out, err)
	}

	// Paying is not in the budget.
	var pe *agentclient.Error
	if _, err := agentPay(ctx, c, agent, seedInvoices[0]); !errors.As(err, &pe) || pe.Code != "capability_not_granted" {
		t.Fatalf("pay before approval = %v", err)
	}
	// Asking without a limit is refused: amount is a required constraint.
	if _, err := c.RequestCapability(ctx, agent, []agentauth.CapabilityRequest{{Name: capPayInvoice}}, "", agentauth.ApprovalHints{}); !errors.As(err, &pe) || pe.Code != "invalid_request" {
		t.Fatalf("request without a limit = %v", err)
	}
	asked, err := agentAskToPay(ctx, c, agent, paymentLimit)
	if err != nil || asked.Approval == nil || asked.Approval.UserCode == "" || asked.Approval.Method != agentauth.MethodDeviceAuthorization {
		t.Fatalf("request = %+v %v", asked, err)
	}
	if !strings.HasPrefix(asked.Approval.VerificationURI, baseURL+agentauth.DefaultDeviceAuthorizationPage) {
		t.Fatalf("verification uri = %s", asked.Approval.VerificationURI)
	}

	// A wrong code approves nothing; Alice types the right one.
	post(t, alice, "/auth/agentauth/approve-capability", agentauth.ApproveRequest{AgentID: agent.ID, UserCode: "WRONGCOD", Action: agentauth.ActionApprove}, http.StatusForbidden)
	approved := post(t, alice, "/auth/agentauth/approve-capability", agentauth.ApproveRequest{AgentID: agent.ID, UserCode: asked.Approval.UserCode, Action: agentauth.ActionApprove}, http.StatusOK)
	if !strings.Contains(approved, capPayInvoice) {
		t.Fatalf("approve = %s", approved)
	}
	if st, err := c.WaitForApproval(ctx, agent, pollInterval); err != nil || st.Status != agentauth.AgentActive {
		t.Fatalf("status = %+v %v", st, err)
	}

	// Within the limit it pays, as this agent; above it the plugin refuses
	// before OnExecute runs.
	paid, err := agentPay(ctx, c, agent, seedInvoices[0])
	if err != nil || !strings.Contains(paid, `"paid_by":"`+agent.ID+`"`) {
		t.Fatalf("pay = %s %v", paid, err)
	}
	if _, err := agentPay(ctx, c, agent, seedInvoices[1]); !errors.As(err, &pe) || pe.Code != "constraint_violated" {
		t.Fatalf("pay above the limit = %v", err)
	}

	// The agent disconnects (revokes itself); its key is refused from then on.
	if err := c.Disconnect(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Execute(ctx, agent, capListInvoices, "", nil); !errors.As(err, &pe) || pe.Code != "agent_revoked" {
		t.Fatalf("after disconnect = %v", err)
	}
}

// TestAgentAuth_UnknownHostIsRefused: without AllowDynamicHostRegistration
// a host nobody created cannot register agents.
func TestAgentAuth_UnknownHostIsRefused(t *testing.T) {
	a, ag := newTestAuth(t)
	srv := httptest.NewServer(newHandler(a, ag))
	t.Cleanup(srv.Close)
	stranger, err := agentclient.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	c := agentclient.New(stranger, agentclient.WithHTTPClient(&http.Client{Transport: toServer{srv}}))
	var pe *agentclient.Error
	if _, _, err := agentConnect(context.Background(), c, baseURL); !errors.As(err, &pe) || pe.Code != "dynamic_host_registration_disabled" {
		t.Fatalf("unknown host = %v", err)
	}
}

// newTestAuth builds the app on a fresh SQLite file.
func newTestAuth(t *testing.T) (*auth.Auth, *agentauth.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ag := newAgentAuth(newLedger())
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

// decodeInto decodes a JSON body.
func decodeInto[Out any](t *testing.T, body string, out *Out) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), out); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
}

// TestLedger_MistypedArgumentsAreRefused: a pay_invoice call whose amount
// is not a number, or whose invoice_id is missing, is refused and pays
// nothing, rather than being read as an amount of 0 or an empty id.
func TestLedger_MistypedArgumentsAreRefused(t *testing.T) {
	l := newLedger()
	for name, args := range map[string]map[string]any{
		"amount as a string": {argInvoiceID: seedInvoices[0].ID, argAmount: "40"},
		"no invoice id":      {argAmount: seedInvoices[0].Amount},
	} {
		ex := agentauth.Execution{Capability: agentauth.Capability{Name: capPayInvoice}, Arguments: args}
		ex.Session.User.ID = testName
		if _, err := l.execute(context.Background(), ex); !errors.Is(err, errBadArguments) {
			t.Fatalf("%s: got %v, want errBadArguments", name, err)
		}
	}
	if len(l.paid) != 0 {
		t.Fatalf("a refused call paid: %v", l.paid)
	}
}
