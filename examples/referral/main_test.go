package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/referral"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	carolEmail   = "carol@example.com"
	daveEmail    = "dave@example.com"
	testPassword = "correct horse battery staple"
	// unknownCode is shaped like a code but names nobody.
	unknownCode = "ZZZZZZZZ"
)

// TestReferral_FirstPurchaseCompletesAndRewardsOnce: Alice shares her code;
// Bob signs up with it in the header, Carol through the remembered cookie;
// a code that names nobody refuses Dave's sign-up; Bob's first purchase
// completes his referral and credits Alice once, his second changes nothing;
// Alice's dashboard and list show both referrals with Bob's address masked.
func TestReferral_FirstPurchaseCompletesAndRewardsOnce(t *testing.T) {
	x := newTestApp(t)
	h := x.handler()

	alice := newBrowser(t, h)
	post[json.RawMessage](t, alice, "/auth/password/sign-up", signUp(aliceEmail, "Alice"), nil, http.StatusOK)
	dash := get[referral.Dashboard](t, alice, "/auth/referral/dashboard", nil, http.StatusOK)
	if len(dash.Code) != referral.CodeLength || dash.Stats.Total != 0 {
		t.Fatalf("alice's dashboard = %+v", dash)
	}

	// Bob brings the code in the header, typed in lower case.
	bob := newBrowser(t, h)
	post[json.RawMessage](t, bob, "/auth/password/sign-up", signUp(bobEmail, "Bob"), http.Header{referral.ReferralHeader: {strings.ToLower(dash.Code)}}, http.StatusOK)

	// Carol's page remembers the code first, as an OAuth sign-up would need.
	carol := newBrowser(t, h)
	post[auth.Done](t, carol, "/auth/referral/remember", referral.CodeRequest{Code: dash.Code}, nil, http.StatusOK)
	post[json.RawMessage](t, carol, "/auth/password/sign-up", signUp(carolEmail, "Carol"), nil, http.StatusOK)

	// A code that names nobody refuses the sign-up, and remember says so first.
	dave := newBrowser(t, h)
	if e := post[errorAnswer](t, dave, "/auth/referral/remember", referral.CodeRequest{Code: unknownCode}, nil, http.StatusBadRequest); e.Error.Code != referral.ErrInvalidCode.Code {
		t.Fatalf("remember of an unknown code: %+v", e.Error)
	}
	if e := post[errorAnswer](t, dave, "/auth/password/sign-up", signUp(daveEmail, "Dave"), http.Header{referral.ReferralHeader: {unknownCode}}, http.StatusBadRequest); e.Error.Code != referral.ErrInvalidCode.Code {
		t.Fatalf("sign-up with an unknown code: %+v", e.Error)
	}

	dash = get[referral.Dashboard](t, alice, "/auth/referral/dashboard", nil, http.StatusOK)
	if dash.Stats.Total != 2 || dash.Stats.Pending != 2 || dash.Stats.Completed != 0 {
		t.Fatalf("stats after two sign-ups = %+v", dash.Stats)
	}

	// Bob's first purchase completes the referral and credits Alice; his
	// second records nothing new and credits nothing.
	if p := post[purchaseResponse](t, bob, "/purchase", purchaseRequest{Item: "book"}, nil, http.StatusOK); !p.ReferralCompleted || p.ReferralStatus != referral.StatusCompleted {
		t.Fatalf("first purchase = %+v", p)
	}
	if p := post[purchaseResponse](t, bob, "/purchase", purchaseRequest{Item: "pen"}, nil, http.StatusOK); p.ReferralCompleted {
		t.Fatalf("second purchase completed again: %+v", p)
	}
	if c := get[creditResponse](t, alice, "/credit", nil, http.StatusOK); c.Cents != rewardCents {
		t.Fatalf("alice's credit = %d, want %d", c.Cents, rewardCents)
	}

	// Alice was referred by nobody: her purchase is just a purchase.
	if p := post[purchaseResponse](t, alice, "/purchase", purchaseRequest{Item: "lamp"}, nil, http.StatusOK); p.ReferralStatus != "" {
		t.Fatalf("unreferred purchase = %+v", p)
	}

	list := get[referral.ListResult](t, alice, "/auth/referral/list", nil, http.StatusOK)
	if list.Total != 2 {
		t.Fatalf("alice's list = %+v", list)
	}
	var sawBob bool
	for _, r := range list.Referrals {
		if r.ReferredUser.Name != "Bob" {
			continue
		}
		sawBob = true
		if r.Status != referral.StatusCompleted || !r.Progress.IsCompleted || r.ReferredUser.Email != referral.MaskEmail(bobEmail) {
			t.Fatalf("bob's referral = %+v", r)
		}
	}
	if !sawBob {
		t.Fatalf("bob missing from %+v", list.Referrals)
	}
}

// TestReferral_MarkStepGuards: MarkStep refuses a step the plugin was not
// given, and a user nobody referred.
func TestReferral_MarkStepGuards(t *testing.T) {
	x := newTestApp(t)
	alice := newBrowser(t, x.handler())
	up := post[signUpAnswer](t, alice, "/auth/password/sign-up", signUp(aliceEmail, "Alice"), nil, http.StatusOK)
	ctx := context.Background()
	if _, err := x.referrals.MarkStep(ctx, up.User.ID, "made_up", nil); !errors.Is(err, referral.ErrUnknownStep) {
		t.Fatalf("unknown step: %v", err)
	}
	if _, err := x.referrals.MarkStep(ctx, up.User.ID, StepFirstPurchase, nil); !errors.Is(err, referral.ErrNotFound) {
		t.Fatalf("unreferred user: %v", err)
	}
}

// signUpAnswer is the part of the sign-up answer the test reads.
type signUpAnswer struct {
	User auth.UserView `json:"user"`
}

// signUp is a password sign-up body.
func signUp(addr, name string) fields {
	return fields{"identifier": addr, "password": testPassword, "name": name}
}

// newTestApp builds the app on a fresh SQLite file with a mailbox that
// records mail instead of printing it.
func newTestApp(t *testing.T) *app {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, appSchema); err != nil {
		t.Fatal(err)
	}
	x, err := newApp(db, &mailbox{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.auth.Close() })
	if _, err := x.auth.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return x
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records m.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session and referral cookies are
// __Host- and Secure, and a cookie jar keeps such a cookie only for https.
func newBrowser(t *testing.T, h http.Handler) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client, origin: baseURL}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin and extra headers, checks
// the status and decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, extra http.Header, status int) Out {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", b.origin)
	return do[Out](t, b, req, extra, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, extra http.Header, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, extra, status)
}

// do sends req with extra headers, checks the status and decodes the answer.
func do[Out any](t *testing.T, b *browser, req *http.Request, extra http.Header, status int) Out {
	t.Helper()
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	var out Out
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: decode %q: %v", req.Method, req.URL.Path, buf.String(), err)
	}
	return out
}
