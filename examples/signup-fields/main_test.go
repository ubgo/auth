package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/sqlb"
)

// defaultPlan is the plan column's SQL default, as /me reads it.
const defaultPlan = "free"

// TestSignupFields_FieldsAreWritten: the fields object and the same columns at
// the top level of the body both land on the new account, and a column left
// out keeps its default.
func TestSignupFields_FieldsAreWritten(t *testing.T) {
	a := newTestAuth(t)

	b := newBrowser(t, newHandler(a))
	b.post(t, "/auth/password/sign-up", `{"identifier":"alice@example.com","password":"correct horse battery staple","fields":{"app_company":"Acme","app_seats":5,"app_newsletter":true}}`, http.StatusOK)
	if me := b.me(t); me.Company != "Acme" || me.Seats != 5 || !me.Newsletter || me.Plan != defaultPlan {
		t.Fatalf("/me = %+v", me)
	}

	top := newBrowser(t, newHandler(a))
	top.post(t, "/auth/password/sign-up", `{"identifier":"bob@example.com","password":"correct horse battery staple","app_company":"Globex"}`, http.StatusOK)
	if me := top.me(t); me.Company != "Globex" || me.Seats != 1 || me.Newsletter || me.Plan != defaultPlan {
		t.Fatalf("/me with top-level fields = %+v, want the defaults for what was not sent", me)
	}
}

// TestSignupFields_Refusals: an unlisted column, a core column, a wrong type,
// null on a NOT NULL column and the same column twice are all refused, and
// none of them creates an account.
func TestSignupFields_Refusals(t *testing.T) {
	for _, c := range []struct{ name, body, code string }{
		{"unlisted column", `"fields":{"app_plan":"enterprise"}`, auth.ErrFieldInvalid.Code},
		{"core column", `"fields":{"name":"Mallory"}`, auth.ErrFieldInvalid.Code},
		{"wrong type", `"fields":{"app_seats":"five"}`, auth.ErrFieldInvalid.Code},
		{"null on NOT NULL", `"fields":{"app_company":null}`, auth.ErrFieldInvalid.Code},
		{"sent twice", `"app_company":"A","fields":{"app_company":"B"}`, auth.ErrFieldInvalid.Code},
		{"unknown top-level key", `"app_plan":"enterprise"`, auth.ErrBadRequest.Code},
	} {
		t.Run(c.name, func(t *testing.T) {
			// A fresh app per case keeps the sign-up rate limit out of it.
			b := newBrowser(t, newHandler(newTestAuth(t)))
			body := `{"identifier":"carol@example.com","password":"correct horse battery staple",` + c.body + `}`
			got := decode[errorAnswer](t, b.post(t, "/auth/password/sign-up", body, http.StatusBadRequest))
			if got.Error.Code != c.code {
				t.Fatalf("%+v, want %s", got.Error, c.code)
			}
			// The address is still free: the refusal came before any row.
			b.post(t, "/auth/password/sign-up", `{"identifier":"carol@example.com","password":"correct horse battery staple"}`, http.StatusOK)
			if me := b.me(t); me.Plan != defaultPlan {
				t.Fatalf("/me = %+v", me)
			}
		})
	}
}

// TestSignupFields_NewRefusesUndeclared: a sign-up field that is not an app
// column stops auth.New, so a typo cannot open a core column to strangers.
func TestSignupFields_NewRefusesUndeclared(t *testing.T) {
	db := openDB(t)
	_, err := auth.New(auth.WithDB(db, sqlb.SQLiteDialect{}), auth.WithUserColumns(appColumns...), auth.WithSignUpFields("name"))
	if err == nil {
		t.Fatal("auth.New accepted a core column as a sign-up field")
	}
}

// openDB opens a fresh SQLite file in the test's temp dir.
func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newTestAuth builds the app's Auth on a fresh SQLite file, mail discarded.
func newTestAuth(t *testing.T) *auth.Auth {
	t.Helper()
	a, err := newAuth(openDB(t), email.MailerFunc(func(context.Context, email.Mail) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a
}

// browser is an HTTPS test server and a client with a cookie jar that sends
// the app's Origin, like a page of the app would.
type browser struct {
	srv    *httptest.Server
	client *http.Client
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
	return &browser{srv: srv, client: client}
}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends a raw JSON body, because sign-up fields are typed JSON values a
// map of strings cannot carry, checks the status and returns the answer.
func (b *browser) post(t *testing.T, path, body string, status int) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, b.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", baseURL)
	return b.do(t, req, status)
}

// me reads /me.
func (b *browser) me(t *testing.T) meResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+"/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	return decode[meResponse](t, b.do(t, req, http.StatusOK))
}

// do sends req and fails the test on any other status.
func (b *browser) do(t *testing.T, req *http.Request, status int) []byte {
	t.Helper()
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != status {
		t.Fatalf("%s %s: status %d, want %d: %s", req.Method, req.URL.Path, res.StatusCode, status, raw)
	}
	return raw
}

// decode reads raw as Out.
func decode[Out any](t *testing.T, raw []byte) Out {
	t.Helper()
	var out Out
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return out
}
