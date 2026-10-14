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
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/authhttp"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/passkey"
	"github.com/ubgo/auth/plugin/password"
	"github.com/ubgo/auth/plugin/twofactor"
	"github.com/ubgo/sqlb"
)

// TestRequireEnrolment_SessionWaitsForAFactor: with
// twofactor.RequireEnrolment, a user without a factor gets a session with
// setup-mfa pending, which reaches the enrolment operations and nothing
// else. Turning a factor on, by an authenticator app or by a security key,
// issues a new token whose session has no task, and the old token stops
// working.
func TestRequireEnrolment_SessionWaitsForAFactor(t *testing.T) {
	clk := newClock()
	srv := newRequiredServer(t, clk)

	// An authenticator app finishes the task.
	tok := bearer(t, srv, http.MethodPost, "/auth/password/sign-up", "", fields{"identifier": alice, "password": testPassword}, http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	if got := sessionTasks(t, srv, tok); !slices.Equal(got, auth.SessionTasks{auth.TaskSetupMFA}) {
		t.Fatalf("tasks after sign-up = %v", got)
	}
	if code := errCode(t, bearer(t, srv, http.MethodGet, "/auth/sessions", tok, nil, http.StatusForbidden)); code != auth.ErrSessionTaskPending.Code {
		t.Fatalf("a call the task does not allow = %s", code)
	}
	// The app's own routes refuse it too, naming the task.
	bearer(t, srv, http.MethodGet, "/me", tok, nil, http.StatusForbidden)
	bearer(t, srv, http.MethodGet, "/auth/twofactor/status", tok, nil, http.StatusOK)
	var enr twofactor.EnrollResult
	decode(t, bearer(t, srv, http.MethodPost, "/auth/twofactor/enroll", tok, none{}, http.StatusOK), &enr)
	confirmed := bearer(t, srv, http.MethodPost, "/auth/twofactor/confirm", tok, fields{"code": totp(t, enr.Secret, clk.Now())}, http.StatusOK)
	next := confirmed.Header.Get(authhttp.SetTokenHeader)
	if next == "" || next == tok {
		t.Fatal("finishing the task must issue a new token")
	}
	if got := sessionTasks(t, srv, next); len(got) != 0 {
		t.Fatalf("tasks after enrolment = %v", got)
	}
	bearer(t, srv, http.MethodGet, "/me", next, nil, http.StatusOK)
	bearer(t, srv, http.MethodGet, "/auth/session", tok, nil, http.StatusUnauthorized)

	// A security key as the first factor finishes it too.
	btok := bearer(t, srv, http.MethodPost, "/auth/password/sign-up", "", fields{"identifier": bob, "password": testPassword}, http.StatusOK).Header.Get(authhttp.SetTokenHeader)
	var reg twofactor.SecurityKeyChallenge
	decode(t, bearer(t, srv, http.MethodPost, "/auth/twofactor/security-key/register-begin", btok, none{}, http.StatusOK), &reg)
	key := newAuthenticator(t)
	done := bearer(t, srv, http.MethodPost, "/auth/twofactor/security-key/register-finish", btok, obj{"ceremony": reg.Ceremony, "credential": key.register(t, reg.Options)}, http.StatusOK)
	bnext := done.Header.Get(authhttp.SetTokenHeader)
	if bnext == "" || len(sessionTasks(t, srv, bnext)) != 0 {
		t.Fatalf("after a key: token %q, tasks %v", bnext, sessionTasks(t, srv, bnext))
	}
	bearer(t, srv, http.MethodGet, "/auth/session", btok, nil, http.StatusUnauthorized)

	// With a factor on, the next sign-in asks for it and has no task.
	clk.Advance(twofactor.Step)
	in := bearer(t, srv, http.MethodPost, "/auth/password/sign-in", "", fields{"identifier": alice, "password": testPassword}, http.StatusOK)
	var res password.SignInResult
	decode(t, in, &res)
	if !res.SecondFactorRequired {
		t.Fatal("a user with a factor must be asked for it")
	}
	ptok := in.Header.Get(authhttp.SetTokenHeader)
	verified := bearer(t, srv, http.MethodPost, "/auth/twofactor/verify", ptok, fields{"code": totp(t, enr.Secret, clk.Now())}, http.StatusOK)
	if got := sessionTasks(t, srv, verified.Header.Get(authhttp.SetTokenHeader)); len(got) != 0 {
		t.Fatalf("tasks after the second factor = %v", got)
	}
}

// newRequiredServer is the example's app with every user required to enrol.
func newRequiredServer(t *testing.T, clk *clock) *httptest.Server {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pk := passkey.New(passkey.DisplayName(appName))
	everyone := func(context.Context, *auth.Auth, string) (bool, error) { return true, nil }
	a, err := auth.New(
		auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithBaseURL(baseURL), auth.WithSecret(testSecret), auth.WithClock(clk.Now),
		auth.WithPlugins(
			email.New(email.Login(), email.Recover(), email.WithMailer(email.MailerFunc(func(context.Context, email.Mail) error { return nil }))),
			password.New(), pk,
			twofactor.New(twofactor.Issuer(appName), twofactor.WithSecurityKeys(pk.SecurityKeys()), twofactor.RequireEnrolment(everyone)),
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(a))
	t.Cleanup(srv.Close)
	return srv
}

// bearer sends a bearer-mode request with the app's Origin and checks the
// status; the answer's body is read into memory.
func bearer(t *testing.T, srv *httptest.Server, method, path, token string, body any, status int) *http.Response {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	req.Header.Set(authhttp.TokenModeHeader, authhttp.TokenModeBearer)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(res.Body); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, status, buf.String())
	}
	res.Body = memBody{bytes.NewReader(buf.Bytes())}
	return res
}

// memBody is a response body already read into memory.
type memBody struct{ *bytes.Reader }

// Close does nothing: the body is in memory.
func (memBody) Close() error { return nil }

// decode reads a JSON answer into out.
func decode(t *testing.T, res *http.Response, out any) {
	t.Helper()
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatal(err)
	}
}

// errCode is the code of an error answer.
func errCode(t *testing.T, res *http.Response) string {
	t.Helper()
	var e errorAnswer
	decode(t, res, &e)
	return e.Error.Code
}

// sessionTasks reads GET /auth/session's tasks for tok.
func sessionTasks(t *testing.T, srv *httptest.Server, tok string) auth.SessionTasks {
	t.Helper()
	var out auth.SessionResult
	decode(t, bearer(t, srv, http.MethodGet, "/auth/session", tok, nil, http.StatusOK), &out)
	return out.Tasks
}
