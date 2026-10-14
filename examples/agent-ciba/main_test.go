package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/ubgo/auth/plugin/passkey"
)

const (
	testEmail    = "alice@example.com"
	testPassword = "correct horse battery staple"
	testName     = "Alice"
	// hostName is what the test's host calls itself.
	hostName = "Laptop CLI"
	// deviceName names Alice's passkey.
	deviceName = "Laptop"
	// connectMessage and transferMessage are the binding messages the agent
	// sends, which the notification and the inbox show.
	connectMessage  = "Check the balance before paying rent"
	transferMessage = "Pay the rent"
	// transferLimit is the most the agent asks to move at once.
	transferLimit = 100.0
	// pollInterval is how often the test's agent asks whether it was approved.
	pollInterval = 10 * time.Millisecond
	// notifyWait bounds the wait for a notification, which is sent in the
	// background after the commit.
	notifyWait = 5 * time.Second
)

// notification is one call of the test's notifyFunc.
type notification struct {
	userID, approvalID, message string
}

// TestAgentCIBA_InboxApprovalThenPasskey runs the protocol over HTTP: the
// agent asks for read_balance by CIBA, so no code exists; the app notifies
// Alice, her inbox lists the request with the agent's message, and one
// click approves it. Then the agent asks to transfer money: the click alone
// approves nothing (webauthn_required), an assertion from another device is
// refused, and her passkey's assertion approves it; the agent transfers
// within the limit and is refused above it.
func TestAgentCIBA_InboxApprovalThenPasskey(t *testing.T) {
	notes := make(chan notification, 4)
	a, ag := newTestAuth(t, func(_ context.Context, userID, approvalID, message string) {
		notes <- notification{userID, approvalID, message}
	})
	srv := httptest.NewServer(newHandler(a, ag))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	// Alice signs up, adds a passkey, and registers her laptop as a host
	// with no budget, so every capability waits for her.
	alice := userSession(t, srv)
	dev := newAuthenticator(t)
	begin := call[passkey.BeginResult](t, alice, http.MethodPost, "/auth/passkey/register-begin", struct{}{}, http.StatusOK)
	call[passkey.Passkey](t, alice, http.MethodPost, "/auth/passkey/register-finish", finishBody{Ceremony: begin.Ceremony, Credential: dev.register(t, begin.Options), Name: deviceName}, http.StatusOK)
	hostKey, err := agentclient.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	call[agentauth.CreateHostResult](t, alice, http.MethodPost, "/auth/agentauth/create-host", agentauth.CreateHostRequest{Name: hostName, PublicKey: hostKey.Public}, http.StatusOK)

	// The agent connects by CIBA: pending, and no code to show anyone.
	c := agentclient.New(hostKey, agentclient.WithHostName(hostName), agentclient.WithHTTPClient(&http.Client{Transport: toServer{srv}}))
	agent, reg, err := agentConnect(ctx, c, baseURL, connectMessage)
	if err != nil || reg.Status != agentauth.AgentPending || reg.Approval == nil || reg.Approval.Method != agentauth.MethodCIBA || reg.Approval.UserCode != "" {
		t.Fatalf("connect = %+v %v", reg, err)
	}
	note := waitNote(t, notes)
	if note.userID != alice.userID || note.message != connectMessage {
		t.Fatalf("notification = %+v", note)
	}

	// The inbox lists it; Alice approves it by its approval_id.
	inbox := call[agentauth.PendingApprovals](t, alice, http.MethodGet, "/auth/agentauth/pending-approvals", struct{}{}, http.StatusOK)
	if len(inbox.Requests) != 1 || inbox.Requests[0].ApprovalID != note.approvalID || inbox.Requests[0].BindingMessage == nil || *inbox.Requests[0].BindingMessage != connectMessage {
		t.Fatalf("inbox = %+v", inbox)
	}
	approved := call[agentauth.ApproveResult](t, alice, http.MethodPost, "/auth/agentauth/approve-capability", agentauth.ApproveRequest{ApprovalID: note.approvalID, Action: agentauth.ActionApprove}, http.StatusOK)
	if approved.Status != agentauth.ApprovalApproved {
		t.Fatalf("approve = %+v", approved)
	}
	if st, err := c.WaitForApproval(ctx, agent, pollInterval); err != nil || st.Status != agentauth.AgentActive {
		t.Fatalf("status = %+v %v", st, err)
	}
	if out, err := c.Execute(ctx, agent, capReadBalance, "", nil); err != nil || !strings.Contains(string(out), `"balance":1000`) {
		t.Fatalf("read balance = %s %v", out, err)
	}

	// Transferring needs a passkey.
	limit := transferLimit
	asked, err := c.RequestCapability(ctx, agent, []agentauth.CapabilityRequest{{Name: capTransfer, Constraints: agentauth.Constraints{argAmount: {Max: &limit}}}},
		"pay the rent", agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA, BindingMessage: transferMessage})
	if err != nil || asked.Approval == nil || asked.Approval.Method != agentauth.MethodCIBA {
		t.Fatalf("request = %+v %v", asked, err)
	}
	note = waitNote(t, notes)
	answer := agentauth.ApproveRequest{ApprovalID: note.approvalID, Action: agentauth.ActionApprove}
	challenge := call[agentauth.ApproveResult](t, alice, http.MethodPost, "/auth/agentauth/approve-capability", answer, http.StatusOK)
	if challenge.Status != agentauth.ApprovalWebAuthnRequired || challenge.WebAuthn == nil {
		t.Fatalf("approve without a passkey = %+v", challenge)
	}
	var pe *agentclient.Error
	if _, err := agentTransfer(ctx, c, agent, 1); !errors.As(err, &pe) || pe.Code != "capability_not_granted" {
		t.Fatalf("transfer before the passkey = %v", err)
	}

	// An assertion from a device Alice never registered is refused.
	forged := answer
	forged.WebAuthn = &agentauth.PresenceResponse{Ceremony: challenge.WebAuthn.Ceremony, Credential: newAuthenticator(t).assert(t, challenge.WebAuthn.Options, alice.userID)}
	call[errorAnswer](t, alice, http.MethodPost, "/auth/agentauth/approve-capability", forged, http.StatusForbidden)

	// Her passkey, on a fresh challenge, approves it.
	challenge = call[agentauth.ApproveResult](t, alice, http.MethodPost, "/auth/agentauth/approve-capability", answer, http.StatusOK)
	answer.WebAuthn = &agentauth.PresenceResponse{Ceremony: challenge.WebAuthn.Ceremony, Credential: dev.assert(t, challenge.WebAuthn.Options, alice.userID)}
	if res := call[agentauth.ApproveResult](t, alice, http.MethodPost, "/auth/agentauth/approve-capability", answer, http.StatusOK); res.Status != agentauth.ApprovalApproved {
		t.Fatalf("approve with the passkey = %+v", res)
	}
	if _, err := c.WaitForApproval(ctx, agent, pollInterval); err != nil {
		t.Fatal(err)
	}
	if out, err := agentTransfer(ctx, c, agent, 60); err != nil || !strings.Contains(string(out), `"balance":940`) {
		t.Fatalf("transfer = %s %v", out, err)
	}
	if _, err := agentTransfer(ctx, c, agent, 2*transferLimit); !errors.As(err, &pe) || pe.Code != "constraint_violated" {
		t.Fatalf("transfer above the limit = %v", err)
	}
}

// TestAgentCIBA_PasskeyNeededBeforeApproval: a user with no passkey cannot
// approve a capability that needs one.
func TestAgentCIBA_PasskeyNeededBeforeApproval(t *testing.T) {
	notes := make(chan notification, 4)
	a, ag := newTestAuth(t, func(_ context.Context, userID, approvalID, message string) {
		notes <- notification{userID, approvalID, message}
	})
	srv := httptest.NewServer(newHandler(a, ag))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	alice := userSession(t, srv)
	hostKey, err := agentclient.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	call[agentauth.CreateHostResult](t, alice, http.MethodPost, "/auth/agentauth/create-host", agentauth.CreateHostRequest{Name: hostName, PublicKey: hostKey.Public, DefaultCapabilities: []string{capReadBalance}}, http.StatusOK)
	c := agentclient.New(hostKey, agentclient.WithHTTPClient(&http.Client{Transport: toServer{srv}}))
	agent, _, err := agentConnect(ctx, c, baseURL, connectMessage)
	if err != nil {
		t.Fatal(err)
	}
	limit := transferLimit
	if _, err := c.RequestCapability(ctx, agent, []agentauth.CapabilityRequest{{Name: capTransfer, Constraints: agentauth.Constraints{argAmount: {Max: &limit}}}},
		"", agentauth.ApprovalHints{PreferredMethod: agentauth.MethodCIBA}); err != nil {
		t.Fatal(err)
	}
	note := waitNote(t, notes)
	refused := call[errorAnswer](t, alice, http.MethodPost, "/auth/agentauth/approve-capability", agentauth.ApproveRequest{ApprovalID: note.approvalID, Action: agentauth.ActionApprove}, http.StatusForbidden)
	if refused.Error.Code != "agentauth.webauthn_not_enrolled" {
		t.Fatalf("approve with no passkey = %+v", refused)
	}
}

// agentTransfer moves amount as the agent. The map[string]any is
// agentclient.Execute's argument type: capability arguments are free-form
// JSON.
func agentTransfer(ctx context.Context, c *agentclient.Client, a agentclient.Agent, amount float64) (json.RawMessage, error) {
	return c.Execute(ctx, a, capTransfer, "", map[string]any{argAmount: amount})
}

// waitNote waits for the next notification.
func waitNote(t *testing.T, notes <-chan notification) notification {
	t.Helper()
	select {
	case n := <-notes:
		return n
	case <-time.After(notifyWait):
		t.Fatal("no notification")
		return notification{}
	}
}

// finishBody is the body of register-finish.
type finishBody struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
	Name       string          `json:"name,omitempty"`
}

// errorAnswer is the library's error body.
type errorAnswer struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

// newTestAuth builds the app on a fresh SQLite file with notify as the
// notification channel.
func newTestAuth(t *testing.T, notify notifyFunc) (*auth.Auth, *agentauth.Plugin) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pk := passkey.New(passkey.DisplayName(appName))
	ag := newAgentAuth(pk, notify, newBank())
	a, err := newAuth(db, logMailer{}, pk, ag)
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

// session is a signed-in user's bearer token and user id. The test server
// is plain HTTP, where a browser would not keep the __Host- cookie, so the
// user's calls use bearer mode, as a mobile app does.
type session struct {
	srv    *httptest.Server
	token  string
	userID string
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
	var up struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	tok := res.Header.Get(authhttp.SetTokenHeader)
	if res.StatusCode != http.StatusOK || tok == "" || json.NewDecoder(res.Body).Decode(&up) != nil || up.User.ID == "" {
		t.Fatalf("sign-up = %d, token %q, user %q", res.StatusCode, tok, up.User.ID)
	}
	return session{srv: srv, token: tok, userID: up.User.ID}
}

// call sends in as JSON (no body for GET) with the session's token, checks
// the status, and decodes the answer as Out.
func call[Out, In any](t *testing.T, s session, method, path string, in In, status int) Out {
	t.Helper()
	var body io.Reader = http.NoBody
	if method != http.MethodGet {
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
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
		t.Fatalf("%s %s: %d %s, want %d", method, path, res.StatusCode, buf.String(), status)
	}
	var out Out
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", method, path, buf.String(), err)
	}
	return out
}
