package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
)

const testPassword = "correct horse battery staple"

// TestPendingTask_ReachesOnlyWhatTheTaskAllows: a new user's session lists
// the task, refuses every operation and app route the task does not allow
// with auth.session_task_pending, and still reads itself and signs out.
func TestPendingTask_ReachesOnlyWhatTheTaskAllows(t *testing.T) {
	app := newTestApp(t, nil)
	tok := app.signUp(t, "alice@example.com")
	if got := app.session(t, tok).Tasks; !slices.Equal(got, auth.SessionTasks{taskChooseWorkspace}) {
		t.Fatalf("session tasks = %v", got)
	}
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/auth/sessions"},
		{http.MethodPost, "/auth/profile"},
		{http.MethodPost, "/auth/sign-out-all"},
		{http.MethodPost, "/auth/sessions/revoke"},
		{http.MethodGet, "/me"},
	} {
		res := app.call(t, r.method, r.path, tok, []byte("{}"), http.StatusForbidden)
		if code := errorCode(t, res); code != auth.ErrSessionTaskPending.Code {
			t.Errorf("%s %s: code %q, want %q", r.method, r.path, code, auth.ErrSessionTaskPending.Code)
		}
	}
	// A Public operation sees a signed-out caller: signing up again from
	// the same client is not mistaken for the pending user.
	app.call(t, http.MethodPost, "/auth/sign-out", tok, []byte("{}"), http.StatusOK)
	app.call(t, http.MethodGet, "/auth/session", tok, nil, http.StatusUnauthorized)
}

// TestCompletingTheTask_IssuesAnOrdinarySession: choosing a workspace hands
// out a new token whose session has no task, and the token that carried the
// task stops working, in bearer mode.
func TestCompletingTheTask_IssuesAnOrdinarySession(t *testing.T) {
	app := newTestApp(t, nil)
	pending := app.signUp(t, "alice@example.com")
	res := app.call(t, http.MethodPost, "/auth/workspace/choose", pending, chooseBody("Acme"), http.StatusOK)
	full := res.Header.Get(authhttp.SetTokenHeader)
	if full == "" || full == pending {
		t.Fatalf("completing the task issued %q", full)
	}
	if got := app.session(t, full).Tasks; len(got) != 0 {
		t.Fatalf("tasks after completion = %v", got)
	}
	app.call(t, http.MethodGet, "/me", full, nil, http.StatusOK)
	app.call(t, http.MethodGet, "/auth/sessions", full, nil, http.StatusOK)
	app.call(t, http.MethodGet, "/me", pending, nil, http.StatusUnauthorized)
	// The next sign-in asks again and finds the workspace: no task.
	again := app.signIn(t, "alice@example.com")
	if got := app.session(t, again).Tasks; len(got) != 0 {
		t.Fatalf("tasks on the next sign-in = %v", got)
	}
}

// TestCompletingTheTask_IsOneSessionsOwnBusiness: Bob finishing his task
// changes nothing about Alice's pending session, and an operation another
// task allows cannot complete this one.
func TestCompletingTheTask_IsOneSessionsOwnBusiness(t *testing.T) {
	rogue := newRogue()
	app := newTestApp(t, []auth.Plugin{rogue})
	alice := app.signUp(t, "alice@example.com")
	bob := app.signUp(t, "bob@example.com")
	app.call(t, http.MethodPost, "/auth/workspace/choose", bob, chooseBody("Bobco"), http.StatusOK)
	if got := app.session(t, alice).Tasks; !slices.Contains(got, taskChooseWorkspace) {
		t.Fatalf("Alice's tasks after Bob finished his = %v", got)
	}
	app.call(t, http.MethodGet, "/me", alice, nil, http.StatusForbidden)

	// rogue.complete is allowed by rogue's own task, and tries to complete
	// the workspace task: refused, and the session keeps both tasks.
	app.call(t, http.MethodPost, "/auth/rogue/complete", alice, []byte("{}"), http.StatusInternalServerError)
	if got := app.session(t, alice).Tasks; !slices.Equal(got, auth.SessionTasks{taskChooseWorkspace, taskRogue}) {
		t.Fatalf("tasks after a rogue completion = %v", got)
	}
}

// TestAStoreThatDropsTasks_FailsTheSignIn: a session store that does not
// keep Session.Tasks would hand out a session that skips the task, so the
// sign-in fails instead and no token is issued.
func TestAStoreThatDropsTasks_FailsTheSignIn(t *testing.T) {
	app := newTestApp(t, nil, auth.WithSessionStore(droppingTasks{auth.NewMemorySessionStore()}))
	res := app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials("alice@example.com"), http.StatusInternalServerError)
	if tok := res.Header.Get(authhttp.SetTokenHeader); tok != "" {
		t.Fatal("a token was issued for a session that lost its task")
	}
}

// droppingTasks loses Session.Tasks on Insert, as a store written before
// session tasks existed would.
type droppingTasks struct{ auth.SessionStore }

func (d droppingTasks) Insert(ctx context.Context, s auth.Session, h []byte) error {
	s.Tasks = nil
	return d.SessionStore.Insert(ctx, s, h)
}

// The rogue plugin's names.
const (
	taskRogue     auth.SessionTaskID = "rogue"
	endpointRogue auth.EndpointID    = "rogue.complete"
	rogueName                        = "rogue"
	rogueRoute                       = "/complete"
	sessionPath                      = "/auth/session"
)

// rogue declares a task of its own whose operation tries to complete the
// workspace task, which it does not serve.
type rogue struct{ op *auth.Op[struct{}, auth.Done] }

func newRogue() *rogue {
	r := &rogue{}
	r.op = auth.Define(auth.OpInfo{ID: endpointRogue, Kind: auth.Mutation, Require: auth.SignedIn, Path: rogueRoute},
		func(ctx context.Context, c *auth.Call, _ struct{}) (auth.Done, error) {
			_, err := c.Auth.CompleteSessionTask(ctx, c, taskChooseWorkspace)
			return auth.Done{OK: err == nil}, err
		})
	return r
}

func (*rogue) Name() string                   { return rogueName }
func (r *rogue) Operations() []auth.Operation { return []auth.Operation{r.op} }
func (*rogue) SessionTasks() []auth.SessionTask {
	return []auth.SessionTask{{ID: taskRogue, Allow: []auth.EndpointID{endpointRogue}}}
}
func (*rogue) SessionTasksFor(context.Context, auth.SignInAttempt) ([]auth.SessionTaskID, error) {
	return []auth.SessionTaskID{taskRogue}, nil
}

// testApp is the app on httptest, with its Auth for direct Go calls.
type testApp struct {
	srv  *httptest.Server
	auth *auth.Auth
}

// newTestApp builds and migrates the app, with extra plugins and options, on
// a fresh SQLite file.
func newTestApp(t *testing.T, extra []auth.Plugin, opts ...auth.Option) *testApp {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	a, err := newAuth(db, newWorkspaces(), extra, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(a))
	t.Cleanup(srv.Close)
	return &testApp{srv: srv, auth: a}
}

func credentials(email string) []byte {
	raw, _ := json.Marshal(map[string]string{"identifier": email, "password": testPassword}) // a map of strings always encodes
	return raw
}

func chooseBody(name string) []byte {
	raw, _ := json.Marshal(ChooseRequest{Name: name}) // a struct of strings always encodes
	return raw
}

func (app *testApp) signUp(t *testing.T, email string) string {
	t.Helper()
	return app.call(t, http.MethodPost, "/auth/password/sign-up", "", credentials(email), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
}

func (app *testApp) signIn(t *testing.T, email string) string {
	t.Helper()
	return app.call(t, http.MethodPost, "/auth/password/sign-in", "", credentials(email), http.StatusOK).Header.Get(authhttp.SetTokenHeader)
}

// session reads GET /auth/session with tok.
func (app *testApp) session(t *testing.T, tok string) auth.SessionResult {
	t.Helper()
	var out auth.SessionResult
	if err := json.NewDecoder(app.call(t, http.MethodGet, sessionPath, tok, nil, http.StatusOK).Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// errorCode reads the code of an error answer.
func errorCode(t *testing.T, res *http.Response) string {
	t.Helper()
	var e struct {
		Error auth.ErrorInfo `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	return e.Error.Code
}

// call sends a bearer-mode request and checks the status.
func (app *testApp) call(t *testing.T, method, path, token string, body []byte, status int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, app.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := app.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, status, strings.TrimSpace(buf.String()))
	}
	res.Body = readCloser{bytes.NewReader(buf.Bytes())}
	return res
}

// readCloser lets call hand back a body it already read.
type readCloser struct{ *bytes.Reader }

// Close does nothing: the body is in memory.
func (readCloser) Close() error { return nil }
