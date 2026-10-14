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
	"github.com/ubgo/auth/plugin/access"
	"github.com/ubgo/auth/plugin/admin"
	"github.com/ubgo/auth/plugin/apikey"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
	"github.com/ubgo/auth/plugin/password"
)

const (
	alice        = "alice@example.com"
	bob          = "bob@example.com"
	carol        = "carol@example.com"
	sam          = "sam@example.com"
	testPassword = "correct horse battery staple"
)

// TestAuthorizer_SupportRole: an admin gives Sam the support role that the
// accessadmin adapter added; Sam may list users but not ban one, and a role
// the authorizer does not define cannot be given.
func TestAuthorizer_SupportRole(t *testing.T) {
	w := newWorld(t)
	aliceB, samB := w.browser(t), w.browser(t)
	aliceID := w.signUp(t, aliceB, alice, "Alice")
	samID := w.signUp(t, samB, sam, "Sam")
	admins, err := auth.PluginOf[*admin.Plugin](w.a)
	if err != nil {
		t.Fatal(err)
	}
	if err := admins.Grant(context.Background(), aliceID); err != nil {
		t.Fatal(err)
	}

	post[auth.Done](t, aliceB, "/auth/admin/set-role", admin.SetRoleRequest{UserID: samID, Role: admin.Roles{roleSupport}}, http.StatusOK)
	if got := get[admin.UsersResult](t, samB, "/auth/admin/users", http.StatusOK); got.Total != 2 {
		t.Fatalf("support listing users = %+v", got)
	}
	if e := post[errorAnswer](t, samB, "/auth/admin/ban", admin.BanRequest{UserID: aliceID, Reason: "test"}, http.StatusForbidden); e.Error.Code != admin.ErrForbidden.Code {
		t.Fatalf("support banning: %+v", e.Error)
	}
	if e := post[errorAnswer](t, aliceB, "/auth/admin/set-role", admin.SetRoleRequest{UserID: samID, Role: admin.Roles{"auditor"}}, http.StatusBadRequest); e.Error.Code != admin.ErrBadRole.Code {
		t.Fatalf("a role nobody defined: %+v", e.Error)
	}
}

// TestAuthorizer_OrganizationPolicy: under the app's policy a plain member
// may invite, which the built-in roles refuse, still may not remove a
// member, and nobody may change a frozen organization.
func TestAuthorizer_OrganizationPolicy(t *testing.T) {
	w := newWorld(t)
	aliceB, bobB := w.browser(t), w.browser(t)
	w.signUp(t, aliceB, alice, "Alice")
	org := post[organization.Org](t, aliceB, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	post[none](t, aliceB, "/auth/organization/invite", organization.InviteRequest{OrgID: org.ID, Email: bob, Role: organization.RoleMember}, http.StatusOK)
	w.signUp(t, bobB, bob, "Bob")
	inv := get[organization.InvitesResult](t, bobB, "/auth/organization/invites", http.StatusOK).Invites
	post[organization.Org](t, bobB, "/auth/organization/accept", organization.AcceptRequest{InviteID: inv[0].ID}, http.StatusOK)

	post[none](t, bobB, "/auth/organization/invite", organization.InviteRequest{OrgID: org.ID, Email: carol, Role: organization.RoleMember}, http.StatusOK)
	check := organization.PermissionRequest{OrgID: org.ID, Permissions: access.Permissions{organization.ResourceMember: {organization.ActionDelete}}}
	if got := post[organization.PermissionResult](t, bobB, "/auth/organization/has-permission", check, http.StatusOK); got.Success {
		t.Fatal("a member may remove members under the policy")
	}

	w.frozen.Freeze(org.ID)
	frozenName := "Acme Frozen"
	rename := organization.UpdateRequest{OrgID: org.ID, Data: organization.OrgUpdate{Name: &frozenName}}
	if e := post[errorAnswer](t, aliceB, "/auth/organization/update", rename, http.StatusForbidden); e.Error.Code != organization.ErrForbidden.Code {
		t.Fatalf("the owner changing a frozen organization: %+v", e.Error)
	}
	get[organization.Org](t, aliceB, "/auth/organization/get-organization?orgId="+url.QueryEscape(org.ID), http.StatusOK)
}

// TestAuthorizer_KeyPermissions: keys carry permissions from the app's own
// vocabulary; /deploy accepts only a key allowed to deploy, and a permission
// outside the vocabulary cannot be given to a key at all.
func TestAuthorizer_KeyPermissions(t *testing.T) {
	w := newWorld(t)
	aliceID := w.signUp(t, w.browser(t), alice, "Alice")
	keys, err := auth.PluginOf[*apikey.Plugin](w.a)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ci, err := keys.CreateFor(ctx, aliceID, apikey.CreateRequest{Name: "ci", Permissions: apikey.Permissions{resourceProject: {actionDeploy}}}, apikey.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := keys.CreateFor(ctx, aliceID, apikey.CreateRequest{Name: "dashboard", Permissions: apikey.Permissions{resourceProject: {actionRead}}}, apikey.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.CreateFor(ctx, aliceID, apikey.CreateRequest{Name: "typo", Permissions: apikey.Permissions{resourceProject: {"delete"}}}, apikey.Limits{}); !errors.Is(err, apikey.ErrBadPermissions) {
		t.Fatalf("a permission outside the vocabulary: %v", err)
	}
	// The app declares no scopes, so a key cannot be given one.
	if _, err := keys.CreateFor(ctx, aliceID, apikey.CreateRequest{Name: "scoped", Scopes: []string{"projects"}}, apikey.Limits{}); !errors.Is(err, apikey.ErrUnknownScope) {
		t.Fatalf("a scope with none declared: %v", err)
	}

	h, err := newHandler(w.a)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if got := callDeploy[deployResponse](t, srv, ci.Secret, http.StatusOK); !got.Deployed || got.By != aliceID {
		t.Fatalf("deploy with the ci key = %+v", got)
	}
	if e := callDeploy[errorAnswer](t, srv, reader.Secret, http.StatusForbidden); e.Error.Code != apikey.ErrPermissionDenied.Code {
		t.Fatalf("deploy with a read-only key: %+v", e.Error)
	}
	if e := callDeploy[errorAnswer](t, srv, "not-a-key", http.StatusUnauthorized); e.Error.Code != auth.ErrSignedOut.Code {
		t.Fatalf("deploy with no valid key: %+v", e.Error)
	}
}

// callDeploy posts to /deploy with key in the Deploy-Key header.
func callDeploy[Out any](t *testing.T, srv *httptest.Server, key string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/deploy", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(deployKeyHeader, key)
	return decode[Out](t, srv.Client(), req, status)
}

// world is one app under test: its Auth, handler, outbox and frozen set.
type world struct {
	a      *auth.Auth
	h      http.Handler
	box    *mailbox
	frozen *frozenOrgs
}

// newWorld builds the app on a fresh SQLite file.
func newWorld(t *testing.T) *world {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	w := &world{box: &mailbox{}, frozen: &frozenOrgs{}}
	if w.a, err = newAuth(db, w.box, w.frozen); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.a.Close() })
	if _, err := w.a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w.h, err = newHandler(w.a); err != nil {
		t.Fatal(err)
	}
	return w
}

// signUp signs name up in b, verifies the address and returns the user id.
func (w *world) signUp(t *testing.T, b *browser, addr, name string) string {
	t.Helper()
	up := post[password.SignInResult](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword, "name": name}, http.StatusOK)
	post[none](t, b, "/auth/email/verify", fields{"token": w.box.lastToken(t, w.a, addr)}, http.StatusOK)
	return up.User.ID
}

// mailbox records every mail sent.
type mailbox struct {
	mu   sync.Mutex
	sent []email.Mail
}

// Send records mail.
func (m *mailbox) Send(_ context.Context, mail email.Mail) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, mail)
	return nil
}

// lastToken returns the token of the newest link mailed to addr.
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
// the Origin a page of the app would. HTTPS, because the session cookie is
// __Host- and Secure.
type browser struct {
	srv    *httptest.Server
	client *http.Client
}

// browser opens a new browser on the world's handler.
func (w *world) browser(t *testing.T) *browser {
	t.Helper()
	srv := httptest.NewTLSServer(w.h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.Jar = jar
	return &browser{srv: srv, client: client}
}

// fields is a JSON request body as a client writes it.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
type none struct{}

// errorAnswer is the JSON shape of every error the library answers.
type errorAnswer struct {
	Error auth.ErrorInfo `json:"error"`
}

// post sends in as JSON with the app's Origin, checks the status and decodes
// the answer as Out.
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
	req.Header.Set("Origin", baseURL)
	return decode[Out](t, b.client, req, status)
}

// get fetches path, checks the status and decodes the answer as Out.
func get[Out any](t *testing.T, b *browser, path string, status int) Out {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, b.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return decode[Out](t, b.client, req, status)
}

// decode sends req, checks the status and decodes the answer as Out.
func decode[Out any](t *testing.T, c *http.Client, req *http.Request, status int) Out {
	t.Helper()
	var out Out
	res, err := c.Do(req)
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
