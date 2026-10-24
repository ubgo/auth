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
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/password"
)

const (
	aliceEmail   = "alice@example.com"
	bobEmail     = "bob@example.com"
	carolEmail   = "carol@example.com"
	testPassword = "correct horse battery staple"
)

// TestAdminPlan lists users with their plan and project count in one query,
// refuses a non-admin, and bans and unbans through the admin plugin.
func TestAdminPlan(t *testing.T) {
	a, ad, box := newTestApp(t)
	ctx := context.Background()

	alice := newBrowser(t, newHandler(a))
	aliceUp := post[password.SignInResult](t, alice, "/auth/password/sign-up", fields{"identifier": aliceEmail, "password": testPassword}, http.StatusOK)
	if _, err := grantByEmail(ctx, a, ad, aliceEmail); !errors.Is(err, auth.ErrIdentityNotFound) {
		t.Fatalf("grant to an unverified address: %v, want ErrIdentityNotFound", err)
	}
	post[none](t, alice, "/auth/email/verify", fields{"token": box.lastToken(t, a, aliceEmail)}, http.StatusOK)
	if id, err := grantByEmail(ctx, a, ad, aliceEmail); err != nil || id != aliceUp.User.ID {
		t.Fatalf("grant = %q, %v", id, err)
	}

	bob := newBrowser(t, newHandler(a))
	bobUp := post[password.SignInResult](t, bob, "/auth/password/sign-up", fields{"identifier": bobEmail, "password": testPassword}, http.StatusOK)
	post[planRequest](t, bob, "/plan", fields{"plan": string(PlanPro)}, http.StatusOK)
	post[projectResponse](t, bob, "/projects", none{}, http.StatusOK)
	post[projectResponse](t, bob, "/projects", none{}, http.StatusOK)
	if e := post[errorAnswer](t, bob, "/plan", fields{"plan": "platinum"}, http.StatusBadRequest); e.Error.Code != errBadPlan.Code {
		t.Fatalf("unknown plan = %+v", e.Error)
	}

	carol := newBrowser(t, newHandler(a))
	post[none](t, carol, "/auth/password/sign-up", fields{"identifier": carolEmail, "password": testPassword}, http.StatusOK)

	if e := get[errorAnswer](t, bob, "/admin/users", http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("non-admin list = %+v", e.Error)
	}

	page := get[UsersPage](t, alice, "/admin/users", http.StatusOK)
	if len(page.Users) != 3 {
		t.Fatalf("users = %+v", page.Users)
	}
	newest, mid, oldest := page.Users[0], page.Users[1], page.Users[2]
	if oldest.ID != aliceUp.User.ID || oldest.Email == nil || *oldest.Email != aliceEmail || oldest.Plan != nil || oldest.Projects != 0 {
		t.Fatalf("alice row = %+v", oldest)
	}
	if mid.ID != bobUp.User.ID || mid.Plan == nil || *mid.Plan != PlanPro || mid.Projects != 2 || mid.Email != nil {
		t.Fatalf("bob row = %+v (email is null until verified)", mid)
	}
	if newest.Plan != nil || newest.Projects != 0 {
		t.Fatalf("carol row = %+v", newest)
	}
	if p := get[UsersPage](t, alice, "/admin/users?page=2&limit=2", http.StatusOK); len(p.Users) != 1 || p.Users[0].ID != aliceUp.User.ID {
		t.Fatalf("page 2 of 2 = %+v", p)
	}
	get[errorAnswer](t, alice, "/admin/users?page=0", http.StatusBadRequest)

	post[auth.Done](t, alice, "/auth/admin/ban", fields{"userId": bobUp.User.ID, "reason": "chargeback"}, http.StatusOK)
	get[errorAnswer](t, bob, "/auth/session", http.StatusUnauthorized)
	if p := get[UsersPage](t, alice, "/admin/users?limit=2", http.StatusOK); !p.Users[1].Banned {
		t.Fatalf("bob after the ban = %+v", p.Users[1])
	}
	post[auth.Done](t, alice, "/auth/admin/unban", fields{"userId": bobUp.User.ID}, http.StatusOK)
	post[none](t, bob, "/auth/password/sign-in", fields{"identifier": bobEmail, "password": testPassword}, http.StatusOK)
	get[auth.SessionResult](t, bob, "/auth/session", http.StatusOK)
}

// TestUsersQuery_IsOneStatement pins the shape of the admin query: one SELECT
// with both LEFT JOINs, grouped, newest first. -v prints it.
func TestUsersQuery_IsOneStatement(t *testing.T) {
	a, _, _ := newTestApp(t)
	var dst userScan
	q, err := usersQuery(a, &dst, 1, defaultPageSize)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`LEFT JOIN "app_plan" AS "pl"`, `LEFT JOIN "app_project" AS "pj"`, "GROUP BY", `ORDER BY "u"."created_at" DESC`} {
		if !strings.Contains(q.SQL, want) {
			t.Fatalf("query lacks %q:\n%s", want, q.SQL)
		}
	}
	t.Log(q.SQL)
}

// newTestApp builds the app on a fresh SQLite file with a recording mailbox.
func newTestApp(t *testing.T) (*auth.Auth, *admin.Plugin, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, ad, err := newAuth(db, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := migrate(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	return a, ad, box
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

// lastToken returns the token of the newest link mailed to addr. Mail goes
// out after the transaction commits, so it waits for deliveries first.
func (m *mailbox) lastToken(t *testing.T, a *auth.Auth, addr string) string {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To != addr {
			continue
		}
		for _, field := range strings.Fields(m.sent[i].Text) {
			if u, err := url.Parse(field); err == nil && u.Query().Get("token") != "" {
				return u.Query().Get("token")
			}
		}
	}
	t.Fatalf("no link mailed to %s", addr)
	return ""
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

// none is the request body of a route that takes no input, and the answer
// of a call whose body the test does not read.
type none struct{}

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

// do sends req, checks the status and decodes the answer as Out.
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
