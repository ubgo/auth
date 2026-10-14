package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ubgo/auth"
	"github.com/ubgo/auth/plugin/email"
	"github.com/ubgo/auth/plugin/organization"
)

const (
	alice        = "alice@example.com"
	bob          = "bob@example.com"
	carol        = "carol@example.com"
	testPassword = "correct horse battery staple"
)

// TestOrganizations_InviteAcceptAndRoles walks the team flow: Alice creates
// an organization and invites Bob; Bob sees the invitation only once his
// address is verified, accepts, and reaches the members' page but not the
// admins'; Carol, a stranger, cannot tell the organization exists.
func TestOrganizations_InviteAcceptAndRoles(t *testing.T) {
	a, box := newTestAuth(t)
	h, err := newHandler(a)
	if err != nil {
		t.Fatal(err)
	}
	aliceB, bobB, carolB := newBrowser(t, h), newBrowser(t, h), newBrowser(t, h)

	signUpVerified(t, a, box, aliceB, alice, "Alice")
	org := post[organization.Org](t, aliceB, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	if org.ID == "" || org.Slug != "acme" {
		t.Fatalf("created = %+v", org)
	}
	if e := post[errorAnswer](t, aliceB, "/auth/organization/create", organization.CreateRequest{Name: "Acme again", Slug: "acme"}, http.StatusConflict); e.Error.Code != organization.ErrSlugTaken.Code {
		t.Fatalf("a taken slug: %+v", e.Error)
	}
	post[none](t, aliceB, "/auth/organization/invite", organization.InviteRequest{OrgID: org.ID, Email: bob, Role: organization.RoleMember}, http.StatusOK)
	invite := box.last(t, a, bob)
	if invite.Subject != inviteSubject || !strings.Contains(invite.Text, baseURL+organization.DefaultInvitePage) {
		t.Fatalf("invitation mail = %+v", invite)
	}

	// Bob signs up with the invited address. Until he verifies it, the
	// invitation is not his: anyone can type an address at sign-up.
	post[none](t, bobB, "/auth/password/sign-up", fields{"identifier": bob, "password": testPassword, "name": "Bob"}, http.StatusOK)
	if got := get[organization.InvitesResult](t, bobB, "/auth/organization/invites", http.StatusOK); len(got.Invites) != 0 {
		t.Fatalf("invitations before verifying = %+v", got.Invites)
	}
	post[none](t, bobB, "/auth/email/verify", fields{"token": box.lastToken(t, a, bob)}, http.StatusOK)
	pending := get[organization.InvitesResult](t, bobB, "/auth/organization/invites", http.StatusOK).Invites
	if len(pending) != 1 || pending[0].OrgName != "Acme" || pending[0].Role != organization.RoleMember {
		t.Fatalf("invitations after verifying = %+v", pending)
	}
	if joined := post[organization.Org](t, bobB, "/auth/organization/accept", organization.AcceptRequest{InviteID: pending[0].ID}, http.StatusOK); joined.ID != org.ID {
		t.Fatalf("accepted into %+v", joined)
	}

	members := get[organization.MembersResult](t, aliceB, "/auth/organization/members?orgId="+url.QueryEscape(org.ID), http.StatusOK).Members
	if len(members) != 2 {
		t.Fatalf("members = %+v", members)
	}

	dash := "/orgs/" + org.ID + "/dashboard"
	billing := "/orgs/" + org.ID + "/billing"
	if got := get[pageResponse](t, bobB, dash, http.StatusOK); got.User != "Bob" || got.OrgID != org.ID {
		t.Fatalf("bob's dashboard = %+v", got)
	}
	if e := get[errorAnswer](t, bobB, billing, http.StatusForbidden); e.Error.Code != organization.ErrForbidden.Code {
		t.Fatalf("bob on billing: %+v", e.Error)
	}
	get[pageResponse](t, aliceB, billing, http.StatusOK)

	// A stranger gets 404 on both, the same as for an organization that does
	// not exist.
	signUpVerified(t, a, box, carolB, carol, "Carol")
	if e := get[errorAnswer](t, carolB, dash, http.StatusNotFound); e.Error.Code != organization.ErrNotMember.Code {
		t.Fatalf("carol on the dashboard: %+v", e.Error)
	}
	get[errorAnswer](t, carolB, "/orgs/org_doesnotexist/dashboard", http.StatusNotFound)

	// Promoted to admin, Bob reaches billing.
	bobID := memberID(t, members, "Bob")
	post[none](t, aliceB, "/auth/organization/set-role", organization.SetRoleRequest{OrgID: org.ID, UserID: bobID, Role: organization.RoleAdmin}, http.StatusOK)
	get[pageResponse](t, bobB, billing, http.StatusOK)
}

// TestOrganizations_InvitationIsForTheVerifiedAddressOnly: a user whose
// verified address is not the invited one cannot accept by guessing the
// invitation id.
func TestOrganizations_InvitationIsForTheVerifiedAddressOnly(t *testing.T) {
	a, box := newTestAuth(t)
	h, err := newHandler(a)
	if err != nil {
		t.Fatal(err)
	}
	aliceB, bobB, carolB := newBrowser(t, h), newBrowser(t, h), newBrowser(t, h)
	signUpVerified(t, a, box, aliceB, alice, "Alice")
	org := post[organization.Org](t, aliceB, "/auth/organization/create", organization.CreateRequest{Name: "Acme", Slug: "acme"}, http.StatusOK)
	post[none](t, aliceB, "/auth/organization/invite", organization.InviteRequest{OrgID: org.ID, Email: bob, Role: organization.RoleMember}, http.StatusOK)
	signUpVerified(t, a, box, bobB, bob, "Bob")
	id := get[organization.InvitesResult](t, bobB, "/auth/organization/invites", http.StatusOK).Invites[0].ID

	signUpVerified(t, a, box, carolB, carol, "Carol")
	if e := post[errorAnswer](t, carolB, "/auth/organization/accept", organization.AcceptRequest{InviteID: id}, http.StatusNotFound); e.Error.Code != organization.ErrInviteInvalid.Code {
		t.Fatalf("carol accepting bob's invitation: %+v", e.Error)
	}
}

// signUpVerified signs name up in b and verifies the address from the mail.
func signUpVerified(t *testing.T, a *auth.Auth, box *mailbox, b *browser, addr, name string) {
	t.Helper()
	post[none](t, b, "/auth/password/sign-up", fields{"identifier": addr, "password": testPassword, "name": name}, http.StatusOK)
	post[none](t, b, "/auth/email/verify", fields{"token": box.lastToken(t, a, addr)}, http.StatusOK)
}

// memberID finds a member's user id by name.
func memberID(t *testing.T, members []organization.MemberView, name string) string {
	t.Helper()
	for _, m := range members {
		if m.User.Name == name {
			return m.User.ID
		}
	}
	t.Fatalf("no member named %s in %+v", name, members)
	return ""
}

// newTestAuth builds the app's Auth on a fresh SQLite file with a mailbox
// that records mail instead of printing it.
func newTestAuth(t *testing.T) (*auth.Auth, *mailbox) {
	t.Helper()
	db, err := sql.Open("sqlite", sqliteDSN(filepath.Join(t.TempDir(), dbFile)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	box := &mailbox{}
	a, err := newAuth(db, box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, err := a.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, box
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

// last returns the newest mail sent to addr, after every delivery in flight.
func (m *mailbox) last(t *testing.T, a *auth.Auth, addr string) email.Mail {
	t.Helper()
	a.WaitDeliveries()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.sent) - 1; i >= 0; i-- {
		if m.sent[i].To == addr {
			return m.sent[i]
		}
	}
	t.Fatalf("no mail sent to %s", addr)
	return email.Mail{}
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

// fields is a JSON request body as a client writes it. The library's request
// types that carry a secret (auth.Token) encode it as "[redacted]" on
// purpose, so those bodies are written as plain maps.
type fields map[string]string

// none is the answer of a call whose body the test does not read.
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
