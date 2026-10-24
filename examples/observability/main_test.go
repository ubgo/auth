package main

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	authotel "github.com/ubgo/auth/contrib/otel"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const (
	// testEmail is the account the test signs up and signs in.
	testEmail = "alice@example.com"
	// bouncedEmail is an address whose mail logMailer refuses.
	bouncedEmail = "bob" + bounceDomain
	// testPassword is the account's password; the test checks that no
	// observer, span or log line ever carries it.
	testPassword = "correct horse battery staple"
	// wrongPassword is a password the account does not have.
	wrongPassword = "wrong password!"
	// signUpPath and signInPath are the password plugin's routes.
	signUpPath = "/auth/password/sign-up"
	signInPath = "/auth/password/sign-in"
	// signUpOp and signInOp are the operation ids those routes run.
	signUpOp auth.EndpointID = "password.sign-up"
	signInOp auth.EndpointID = "password.sign-in"
	// deliveryFailedMsg is the message the core logs when a mail could not
	// be delivered after the call committed.
	deliveryFailedMsg = "auth: delivery failed"
)

// TestObservability signs up twice (once to an address whose mail bounces),
// signs in with a wrong and then the right password, and checks what each
// seam saw: the observer every call's outcome by code, the tracer a span per
// operation with database spans inside it, and the logger the bounced mail.
func TestObservability(t *testing.T) {
	app := newTestApp(t)
	b := newBrowser(t, newHandler(app.auth, app.logger))

	post[password.SignInResult](t, b, signUpPath, fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	post[password.SignInResult](t, b, signUpPath, fields{"identifier": bouncedEmail, "password": testPassword}, http.StatusOK)
	bad := post[errorAnswer](t, b, signInPath, fields{"identifier": testEmail, "password": wrongPassword}, http.StatusUnauthorized)
	if bad.Error.Code != password.ErrInvalidCredentials.Code {
		t.Fatalf("wrong password = %+v", bad.Error)
	}
	post[password.SignInResult](t, b, signInPath, fields{"identifier": testEmail, "password": testPassword}, http.StatusOK)
	app.auth.WaitDeliveries()

	// The observer saw every call end, the refusal by its code.
	want := []callRecord{
		{Op: signUpOp, Plugin: password.PluginName, Outcome: authotel.OutcomeOK},
		{Op: signUpOp, Plugin: password.PluginName, Outcome: authotel.OutcomeOK},
		{Op: signInOp, Plugin: password.PluginName, Outcome: password.ErrInvalidCredentials.Code},
		{Op: signInOp, Plugin: password.PluginName, Outcome: authotel.OutcomeOK},
	}
	if got := app.calls.records(); !slices.Equal(got, want) {
		t.Fatalf("observer saw %+v, want %+v", got, want)
	}

	// The tracer recorded one span per operation, the refused one with the
	// error status and code, and the statements as its children.
	spans := app.spans.Ended()
	ops := spansNamed(spans, "auth.operation "+string(signInOp))
	if len(ops) != 2 {
		t.Fatalf("%d sign-in spans, want 2", len(ops))
	}
	if st := ops[0].Status(); st.Code != codes.Error || st.Description != password.ErrInvalidCredentials.Code {
		t.Fatalf("refused sign-in span status = %+v", st)
	}
	if st := ops[1].Status(); st.Code != codes.Unset {
		t.Fatalf("good sign-in span status = %+v", st)
	}
	if !hasChild(spans, ops[1], "auth.db insert auth_session") {
		t.Fatal("the session insert is not a child of the sign-in span")
	}

	// The logger got the bounced mail, which no response could report.
	lines := app.logs.lines(t)
	failed := slices.IndexFunc(lines, func(l logLine) bool { return l.Msg == deliveryFailedMsg })
	if failed < 0 || lines[failed].Level != slog.LevelError.String() || lines[failed].Error != errBounced.Error() {
		t.Fatalf("no delivery failure logged: %+v", lines)
	}

	// No seam ever carried the password.
	if strings.Contains(app.logs.String(), testPassword) {
		t.Fatal("the password reached the log")
	}
}

// testApp is the app as main builds it, with every seam pointed at a
// recorder the test can read.
type testApp struct {
	auth   *auth.Auth
	logger *slog.Logger
	logs   *syncBuffer
	calls  *callLog
	spans  *tracetest.SpanRecorder
}

// newTestApp builds the app on a fresh SQLite file: logs as JSON into a
// buffer, spans into an in-memory recorder, and mail through logMailer, so
// the bounce domain fails the same way it does under main.
func newTestApp(t *testing.T) testApp {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	spans := tracetest.NewSpanRecorder()
	tp := newTracerProvider(spans)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	calls := &callLog{logger: logger}
	a, err := newAuth(db, logMailer{logger: logger}, logger, tp, calls)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return testApp{auth: a, logger: logger, logs: logs, calls: calls, spans: spans}
}

// spansNamed returns the spans called name, in the order they ended.
func spansNamed(spans []sdktrace.ReadOnlySpan, name string) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.Name() == name {
			out = append(out, s)
		}
	}
	return out
}

// hasChild reports whether a span called name has parent as its parent.
func hasChild(spans []sdktrace.ReadOnlySpan, parent sdktrace.ReadOnlySpan, name string) bool {
	return slices.ContainsFunc(spans, func(s sdktrace.ReadOnlySpan) bool {
		return s.Name() == name && s.Parent().SpanID() == parent.SpanContext().SpanID()
	})
}

// syncBuffer is a bytes.Buffer safe for the logger's writes from the
// delivery goroutine and the test's reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends p.
func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// logLine is the part of a JSON log line the test reads.
type logLine struct {
	Level string `json:"level"`
	Msg   string `json:"msg"`
	Error string `json:"error"`
}

// lines decodes every log line written so far.
func (b *syncBuffer) lines(t *testing.T) []logLine {
	t.Helper()
	var out []logLine
	sc := bufio.NewScanner(strings.NewReader(b.String()))
	for sc.Scan() {
		var l logLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		out = append(out, l)
	}
	return out
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the Origin a page of the app would, like a real browser on the app.
type browser struct {
	srv    *httptest.Server
	client *http.Client
	origin string
}

// newBrowser serves h over TLS, because the session cookie is __Host- and
// Secure, and a cookie jar keeps such a cookie only for an https URL.
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

// fields is a JSON request body as a client writes it. The library's own
// request types are not used to send: their secrets (auth.Token) encode as
// "[redacted]" on purpose, so a logged struct never leaks one.
type fields map[string]string

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the browser's Origin, checks the status and
// decodes the answer as Out.
func post[Out, In any](t *testing.T, b *browser, path string, in In, status int) Out {
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
		t.Fatalf("POST %s: status %d, want %d: %s", path, res.StatusCode, status, buf.String())
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("POST %s: decode %q: %v", path, buf.String(), err)
	}
	return out
}

// logMailer must stay an email.Mailer, the type email.WithMailer takes.
var _ email.Mailer = logMailer{}
