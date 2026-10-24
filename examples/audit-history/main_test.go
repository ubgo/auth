package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/audit"
	"github.com/ubgo/auth/plugin/email"
)

const (
	aliceEmail    = "alice@example.com"
	testPassword  = "correct horse battery staple"
	wrongPassword = "not it"
	// signInOp is the password plugin's sign-in operation.
	signInOp auth.EndpointID = "password.sign-in"
)

// TestAuditHistory_Table runs the history on the audit_event table.
func TestAuditHistory_Table(t *testing.T) { runHistory(t, nil) }

// TestAuditHistory_QuerierSink runs the same history on a sink that
// implements audit.Querier: every read answers as it does from the table.
func TestAuditHistory_QuerierSink(t *testing.T) { runHistory(t, &memoryLog{}) }

// runHistory: Alice signs up, fails one sign-in, signs in, and asks for an
// export. Her own history has each event under its type, the export under
// the app's type name; the security page lists only her successful sign-ins;
// the failed attempt is found by the address typed, with no user id; and a
// second user's history holds none of Alice's events.
func runHistory(t *testing.T, sink audit.Sink) {
	x := newTestApp(t, sink)
	h := x.handler()

	alice := newBrowser(t, h)
	post[json.RawMessage](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	post[errorAnswer](t, newBrowser(t, h), "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": wrongPassword}, http.StatusUnauthorized)
	post[json.RawMessage](t, alice, "/auth/password/sign-in", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	post[auth.Done](t, alice, "/auth/exports/request", fields{}, http.StatusOK)

	mine := get[audit.Page](t, alice, "/auth/audit/my-events", http.StatusOK)
	var types []audit.EventType
	for _, e := range mine.Events {
		types = append(types, e.Type)
	}
	want := []audit.EventType{TypeDataExportRequested, audit.TypeUserSignedIn, audit.TypeUserSignedUp}
	if !slices.Equal(types, want) {
		t.Fatalf("my-events types = %v, want %v", types, want)
	}

	if p := get[audit.Page](t, alice, "/auth/audit/my-events?type="+string(TypeDataExportRequested), http.StatusOK); p.Total != 1 || p.Events[0].Op != EndpointExport {
		t.Fatalf("my-events by the app's type = %+v", p)
	}

	if p := get[audit.Page](t, alice, "/security/sign-ins", http.StatusOK); p.Total != 1 || !p.Events[0].OK || p.Limit != signInsLimit {
		t.Fatalf("security page = %+v", p)
	}

	failed, err := x.audit.Events(context.Background(), audit.Query{Identifier: aliceEmail, Op: signInOp})
	if err != nil {
		t.Fatal(err)
	}
	if failed.Total != 2 {
		t.Fatalf("sign-in attempts at the address = %+v", failed)
	}
	for _, e := range failed.Events {
		if !e.OK && (e.ActorID != "" || e.Code != "password.invalid_credentials") {
			t.Fatalf("a failed attempt names an account or the wrong code: %+v", e)
		}
	}

	bob := newBrowser(t, h)
	post[json.RawMessage](t, bob, "/auth/password/sign-up", fields{"identifier": "bob@example.com", "password": testPassword, "name": "Bob"}, http.StatusOK)
	if p := get[audit.Page](t, bob, "/auth/audit/my-events", http.StatusOK); p.Total != 1 || p.Events[0].Type != audit.TypeUserSignedUp {
		t.Fatalf("bob's history = %+v", p)
	}

	// Signed out, my-events is refused.
	get[errorAnswer](t, newBrowser(t, h), "/auth/audit/my-events", http.StatusUnauthorized)
}

// TestAuditHistory_SinkWithoutQuerier: a sink with no read side records
// events, and every read answers 501 audit.no_query_backend rather than an
// empty page that would read as "nothing happened".
func TestAuditHistory_SinkWithoutQuerier(t *testing.T) {
	var mu sync.Mutex
	var recorded int
	x := newTestApp(t, audit.SinkFunc(func(context.Context, audit.Event) error {
		mu.Lock()
		defer mu.Unlock()
		recorded++
		return nil
	}))
	alice := newBrowser(t, x.handler())
	post[json.RawMessage](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword, "name": "Alice"}, http.StatusOK)
	if e := get[errorAnswer](t, alice, "/auth/audit/my-events", http.StatusNotImplemented); e.Error.Code != audit.ErrNoQueryBackend.Code {
		t.Fatalf("my-events with a write-only sink: %+v", e.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if recorded != 1 {
		t.Fatalf("the sink recorded %d events, want the sign-up", recorded)
	}
}

// newTestApp builds the app on a fresh SQLite file; sink nil keeps events in
// the table.
func newTestApp(t *testing.T, sink audit.Sink) *app {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	x, err := newApp(db, &mailbox{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = x.auth.Close() })
	if _, err := x.auth.Migrate(context.Background()); err != nil {
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

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for https.
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

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out any](t *testing.T, b *browser, path string, in fields, status int) Out {
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
	return do[Out](t, b, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return do[Out](t, b, req, status)
}

// do sends req, checks the status and decodes the answer.
func do[Out any](t *testing.T, b *browser, req *http.Request, status int) Out {
	t.Helper()
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
